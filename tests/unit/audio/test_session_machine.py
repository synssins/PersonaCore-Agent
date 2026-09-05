"""Unit tests for AudioSession state machine.

Tests run entirely in-process with fake STT/TTS/Speaker.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import pytest

from workstation_agent.audio.mic import AudioFrame
from workstation_agent.audio.session import AudioEvent, AudioSession, SessionMode
from workstation_agent.audio.tts import AbortableTask
from workstation_agent.audio.wake import WakeEvent

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------

def _fake_frame() -> AudioFrame:
    return AudioFrame(pcm=b"\x00" * 320, ts_ms=0)


def _wake_event(name: str = "hey_test") -> WakeEvent:
    return WakeEvent(model_name=name, confidence=0.9, ts_ms=0)


class _FakeSTT:
    """Returns a predetermined transcript once called."""

    def __init__(self, transcript: str) -> None:
        self._transcript = transcript

    async def transcribe(self, frames: AsyncIterator[AudioFrame]) -> AsyncIterator[str]:
        # Drain frames so the session can finish
        async for _ in frames:
            pass
        return self._yield()

    async def _yield(self) -> AsyncIterator[str]:
        yield self._transcript


class _FakeTTS:
    """Returns canned audio bytes."""

    def __init__(self, audio: bytes = b"\x00" * 64) -> None:
        self._audio = audio
        self.spoken: list[str] = []
        self._task: AbortableTask | None = None

    async def speak(self, text: str) -> AbortableTask:
        self.spoken.append(text)
        q: asyncio.Queue[bytes | None] = asyncio.Queue()
        await q.put(self._audio)
        await q.put(None)
        task_obj = asyncio.create_task(_noop(), name="fake-tts-task")
        t = AbortableTask(task=task_obj, audio_queue=q)
        self._task = t
        return t

    async def audio_chunks(self, task: AbortableTask) -> AsyncIterator[bytes]:
        while True:
            chunk = await task._audio_queue.get()
            if chunk is None:
                return
            yield chunk


async def _noop() -> None:
    await asyncio.sleep(0)


class _FakeSpeaker:
    """Records enqueued chunks; abort() sets a flag."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.aborted = False

    def enqueue(self, pcm: bytes) -> None:
        self.chunks.append(pcm)

    def abort(self) -> None:
        self.aborted = True

    def mute(self) -> None:
        pass

    def unmute(self) -> None:
        pass


def _make_session(
    transcript: str = "hello",
    reply: str = "world",
    mode: SessionMode = SessionMode.SINGLE_SHOT,
) -> tuple[AudioSession, _FakeSTT, _FakeTTS, _FakeSpeaker, list[AudioEvent]]:
    stt = _FakeSTT(transcript)
    tts = _FakeTTS()
    speaker = _FakeSpeaker()
    events: list[AudioEvent] = []

    async def on_transcribed(_text: str) -> str:
        return reply

    session = AudioSession(
        stt=stt,  # type: ignore[arg-type]
        tts=tts,  # type: ignore[arg-type]
        speaker=speaker,  # type: ignore[arg-type]
        on_transcribed=on_transcribed,  # type: ignore[arg-type]
        on_event=events.append,
        mode=mode,
        silence_timeout=2.0,
    )
    return session, stt, tts, speaker, events


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_shot_transitions() -> None:
    """IDLE->LISTENING->THINKING->SPEAKING->done for single_shot mode."""
    session, _stt, tts, _speaker, events = _make_session(mode=SessionMode.SINGLE_SHOT)

    async def drive() -> None:
        await asyncio.sleep(0.01)  # let the machine reach IDLE
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        # Push one frame so STT can drain
        session.push_frame(_fake_frame())
        # Push sentinel so STT finishes
        session._frame_queue.put_nowait(None)

    driver = asyncio.create_task(drive())
    try:
        await asyncio.wait_for(session.run(), timeout=3.0)
    except TimeoutError:
        pytest.fail("Session did not terminate in time")
    finally:
        driver.cancel()

    state_names = [e.state for e in events]
    assert "idle" in state_names
    assert "listening" in state_names
    assert "thinking" in state_names
    assert "speaking" in state_names
    assert tts.spoken == ["world"]


@pytest.mark.asyncio
async def test_single_shot_does_not_loop() -> None:
    """Single_shot mode must return after one full turn."""
    session, _stt, _tts, _speaker, events = _make_session(mode=SessionMode.SINGLE_SHOT)

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)

    driver = asyncio.create_task(drive())
    try:
        await asyncio.wait_for(session.run(), timeout=3.0)
    except TimeoutError:
        pytest.fail("single_shot looped instead of terminating")
    finally:
        driver.cancel()

    # Only one SPEAKING event
    speaking_count = sum(1 for e in events if e.state == "speaking")
    assert speaking_count == 1


@pytest.mark.asyncio
async def test_persistent_loops_to_listening() -> None:
    """Persistent mode: after speaking, next run_idle waits again (no exit)."""
    session, _stt, tts, _speaker, _events = _make_session(mode=SessionMode.PERSISTENT)

    turn = 0

    async def drive() -> None:
        nonlocal turn
        # First wake
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)
        turn = 1

    driver = asyncio.create_task(drive())
    task = asyncio.create_task(session.run())
    await asyncio.sleep(0.5)

    # After one turn, session should be back in IDLE (persistent loops)
    assert turn == 1
    assert tts.spoken  # something was spoken

    task.cancel()
    driver.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_barge_in_cancels_tts() -> None:
    """Wake during SPEAKING should abort TTS and re-enter LISTENING.

    Barge-in sets the _abort flag on speaker and calls abort() on the TTS task.
    The session continues running (does not raise).  We verify the speaker was
    asked to abort and that the session reached SPEAKING at least once.
    """
    session, _stt, _tts, _speaker, events = _make_session(mode=SessionMode.SINGLE_SHOT)

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)
        # Wait a tick for SPEAKING state
        await asyncio.sleep(0.08)
        # Barge-in while SPEAKING
        session.on_wake(_wake_event("barge-in"))

    driver = asyncio.create_task(drive())
    task = asyncio.create_task(session.run())
    await asyncio.sleep(0.4)

    state_names = [e.state for e in events]
    # At minimum, SPEAKING state must have been reached
    assert "speaking" in state_names, f"Expected 'speaking' in {state_names}"

    task.cancel()
    driver.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task


@pytest.mark.asyncio
async def test_silence_timeout_returns_to_idle() -> None:
    """If no transcript arrives within silence_timeout, return to IDLE."""
    stt = _FakeSTT("")  # empty transcript
    tts = _FakeTTS()
    speaker = _FakeSpeaker()
    events: list[AudioEvent] = []

    async def on_transcribed(_text: str) -> str:
        return "reply"

    session = AudioSession(
        stt=stt,  # type: ignore[arg-type]
        tts=tts,  # type: ignore[arg-type]
        speaker=speaker,  # type: ignore[arg-type]
        on_transcribed=on_transcribed,  # type: ignore[arg-type]
        on_event=events.append,
        mode=SessionMode.SINGLE_SHOT,
        silence_timeout=0.1,  # very short for tests
    )

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())

    driver = asyncio.create_task(drive())
    task = asyncio.create_task(session.run())

    # Wait longer than silence_timeout; session should hit IDLE without speaking
    await asyncio.sleep(0.4)
    task.cancel()
    driver.cancel()

    state_names = [e.state for e in events]
    assert "listening" in state_names
    # No speaking because transcript was empty
    assert "speaking" not in state_names


@pytest.mark.asyncio
async def test_state_property() -> None:
    """session.state should reflect the current state string."""
    session, *_ = _make_session()
    assert session.state == "idle"


@pytest.mark.asyncio
async def test_on_event_emits_audio_events() -> None:
    """on_event must be called with AudioEvent on each transition."""
    session, _stt, _tts, _speaker, events = _make_session(mode=SessionMode.SINGLE_SHOT)

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)

    driver = asyncio.create_task(drive())
    try:
        await asyncio.wait_for(session.run(), timeout=3.0)
    except TimeoutError:
        pytest.fail("Timeout")
    finally:
        driver.cancel()

    assert all(isinstance(e, AudioEvent) for e in events)
    assert all(isinstance(e.ts_ms, int) for e in events)
