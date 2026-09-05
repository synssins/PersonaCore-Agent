"""AudioSession state machine per design section 4.11.

States
------
IDLE       No wake word / PTT; audio is recorded but not transcribed.
LISTENING  Wake / PTT fired; we are streaming audio to STT.
THINKING   STT transcript delivered; waiting for LLM to produce a reply.
SPEAKING   TTS audio is playing.

Transitions
-----------
IDLE      --[wake/ptt]--> LISTENING
LISTENING --[transcript]--> THINKING
LISTENING --[silence-timeout]--> IDLE
THINKING  --[llm-reply]--> SPEAKING
SPEAKING  --[done]--> IDLE (single_shot) or LISTENING (persistent)
SPEAKING  --[wake/ptt barge-in]--> LISTENING  (abort TTS, immediate re-listen)

Modes
-----
single_shot  One wake -> one reply, then IDLE.
persistent   One wake -> reply, then back to LISTENING automatically.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import time
from collections.abc import AsyncIterator, Callable
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from workstation_agent.audio.mic import AudioFrame
    from workstation_agent.audio.ptt import PttEvent
    from workstation_agent.audio.sink import Speaker
    from workstation_agent.audio.stt import WyomingSTTClient
    from workstation_agent.audio.tts import AbortableTask, WyomingTTSClient
    from workstation_agent.audio.wake import WakeEvent

log = logging.getLogger(__name__)


class SessionMode(enum.Enum):
    """How the session behaves after one complete turn."""

    SINGLE_SHOT = "single_shot"
    """Wake -> transcribe -> reply -> IDLE."""
    PERSISTENT = "persistent"
    """Wake -> transcribe -> reply -> LISTENING (loops)."""


class _State(enum.Enum):
    IDLE = "idle"
    LISTENING = "listening"
    THINKING = "thinking"
    SPEAKING = "speaking"


class AudioEvent(NamedTuple):
    """Emitted to the UI for every state change."""

    state: str
    ts_ms: int


AudioEventCallback = Callable[[AudioEvent], None]
TranscribedCallback = Callable[[str], "asyncio.Future[str]"]


class AudioSession:
    """Orchestrates the full listen -> transcribe -> speak pipeline.

    Parameters
    ----------
    stt:
        Wyoming STT client.
    tts:
        Wyoming TTS client.
    speaker:
        PCM output device.
    on_transcribed:
        Async callable that receives the transcript and returns a future
        that resolves to the text the LLM produced.  Injected by SPEC-05.
    on_event:
        Called on every state transition for UI updates.
    mode:
        Whether to loop back to LISTENING after speaking or stop at IDLE.
    silence_timeout:
        Seconds of no transcript before returning to IDLE from LISTENING.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        stt: WyomingSTTClient,
        tts: WyomingTTSClient,
        speaker: Speaker,
        on_transcribed: TranscribedCallback,
        on_event: AudioEventCallback | None = None,
        mode: SessionMode = SessionMode.PERSISTENT,
        silence_timeout: float = 8.0,
    ) -> None:
        self._stt = stt
        self._tts = tts
        self._speaker = speaker
        self._on_transcribed = on_transcribed
        self._on_event = on_event
        self._mode = mode
        self._silence_timeout = silence_timeout

        self._state: _State = _State.IDLE
        self._current_tts_task: AbortableTask | None = None
        self._wake_trigger: asyncio.Event = asyncio.Event()
        self._frame_queue: asyncio.Queue[AudioFrame | None] = asyncio.Queue(maxsize=200)
        # Set to True by _barge_in(); causes the main loop to skip _run_idle
        # and proceed directly to LISTENING on the next iteration.
        self._barge_in_pending: bool = False

    # ------------------------------------------------------------------
    # External triggers (from WakeDetector / PushToTalk callbacks)
    # ------------------------------------------------------------------

    def on_wake(self, event: WakeEvent) -> None:
        """Called by WakeDetector or PushToTalk when wake/PTT fires."""
        log.info("wake_triggered source=%s state=%s", event.model_name, self._state.value)
        if self._state == _State.SPEAKING:
            self._barge_in()
        elif self._state == _State.IDLE:
            self._wake_trigger.set()

    def on_ptt(self, event: PttEvent) -> None:
        """Convenience alias for PushToTalk callback."""
        from workstation_agent.audio.wake import WakeEvent as _WakeEvent  # noqa: PLC0415

        self.on_wake(
            _WakeEvent(model_name=event.model_name, confidence=event.confidence, ts_ms=event.ts_ms),
        )

    def push_frame(self, frame: AudioFrame) -> None:
        """Feed a captured audio frame into the session (thread-safe via Queue)."""
        with contextlib.suppress(asyncio.QueueFull):
            self._frame_queue.put_nowait(frame)

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the state machine until the task is cancelled."""
        self._emit(_State.IDLE)
        while True:
            # If a barge-in fired during SPEAKING, skip IDLE entirely and go
            # straight to LISTENING so the agent picks up the new utterance.
            if self._barge_in_pending:
                self._barge_in_pending = False
            else:
                await self._run_idle()
            await self._run_listening()
            transcript = await self._run_thinking()
            if transcript is None:
                continue
            await self._run_speaking(transcript)
            if self._mode == SessionMode.SINGLE_SHOT:
                self._transition(_State.IDLE)
                return  # done
            # PERSISTENT: loop back to IDLE, wait for next wake

    # ------------------------------------------------------------------
    # State handlers
    # ------------------------------------------------------------------

    async def _run_idle(self) -> None:
        self._transition(_State.IDLE)
        self._wake_trigger.clear()
        await self._wake_trigger.wait()
        # Do NOT clear here — _run_listening will consume the event naturally.
        # Clearing is deferred to the top of the next _run_idle call above.

    async def _run_listening(self) -> None:
        self._transition(_State.LISTENING)
        # Drain stale frames
        while not self._frame_queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._frame_queue.get_nowait()

        transcript: str | None = None
        try:
            async with asyncio.timeout(self._silence_timeout):
                frame_iter = self._frame_source()
                stt_iter = await self._stt.transcribe(frame_iter)
                async for text in stt_iter:
                    if text:
                        transcript = text
                        break  # take the first non-empty result
        except TimeoutError:
            log.info("stt_silence_timeout")
        except asyncio.CancelledError:
            raise

        with contextlib.suppress(asyncio.QueueFull):
            self._frame_queue.put_nowait(None)  # sentinel to stop frame_source
        self._last_transcript = transcript

    async def _run_thinking(self) -> str | None:
        transcript = getattr(self, "_last_transcript", None)
        if not transcript:
            return None
        self._transition(_State.THINKING)
        try:
            future = self._on_transcribed(transcript)
            return await future
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("llm_error error=%s", repr(exc))
            return None

    async def _run_speaking(self, text: str) -> None:
        self._transition(_State.SPEAKING)
        tts_task = await self._tts.speak(text)
        self._current_tts_task = tts_task
        try:
            async for chunk in self._tts.audio_chunks(tts_task):
                self._speaker.enqueue(chunk)
        except asyncio.CancelledError:
            tts_task.abort()
            raise
        finally:
            self._current_tts_task = None

    def _barge_in(self) -> None:
        """Cancel active TTS and arrange for the next loop tick to be LISTENING.

        Instead of relying on _wake_trigger (which _run_idle clears on entry),
        we set _barge_in_pending so run() skips _run_idle altogether and jumps
        directly to _run_listening on the next iteration.
        """
        log.info("barge_in")
        if self._current_tts_task is not None:
            self._current_tts_task.abort()
            self._speaker.abort()
        self._barge_in_pending = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _frame_source(self) -> AsyncIterator[AudioFrame]:
        """Async iterator of frames from the queue, stopping on None sentinel."""
        while True:
            frame = await self._frame_queue.get()
            if frame is None:
                return
            yield frame

    def _transition(self, new_state: _State) -> None:
        if self._state != new_state:
            log.info(
                "audio_state_transition from=%s to=%s",
                self._state.value,
                new_state.value,
            )
            self._state = new_state
            self._emit(new_state)

    def _emit(self, state: _State) -> None:
        if self._on_event is not None:
            with contextlib.suppress(Exception):
                self._on_event(AudioEvent(state=state.value, ts_ms=int(time.time() * 1000)))

    @property
    def state(self) -> str:
        """Current state name as a string."""
        return self._state.value
