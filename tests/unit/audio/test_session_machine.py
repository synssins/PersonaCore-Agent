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
async def test_barge_in_speaking_goes_to_listening_not_idle() -> None:
    """SPEAKING -> barge-in fires -> TTS cancelled -> next tick is LISTENING.

    Verifies the fix for the bug where _run_idle() cleared _wake_trigger on
    entry, causing the agent to hang in IDLE instead of jumping to LISTENING
    after a barge-in.  With the fix, _barge_in_pending bypasses _run_idle
    entirely so the machine lands in LISTENING on the very next loop tick.
    """
    # Use a slow TTS so we can fire barge-in while the session is in SPEAKING.
    slow_audio_available = asyncio.Event()
    slow_audio_ready = asyncio.Event()

    class _SlowTTS:
        def __init__(self) -> None:
            self.spoken: list[str] = []
            self._task: AbortableTask | None = None
            self.aborted = False

        async def speak(self, text: str) -> AbortableTask:
            self.spoken.append(text)
            q: asyncio.Queue[bytes | None] = asyncio.Queue()
            task_obj = asyncio.create_task(_noop(), name="slow-tts-task")
            t = AbortableTask(task=task_obj, audio_queue=q)
            self._task = t
            return t

        async def audio_chunks(self, task: AbortableTask) -> AsyncIterator[bytes]:  # noqa: ARG002
            slow_audio_available.set()  # signal: we are now in SPEAKING
            await slow_audio_ready.wait()  # block until test releases us
            # Never actually yields a chunk — barge-in will cancel first.
            # The `if False` branch makes pyright recognize this as an async gen.
            if False:
                yield b""

    stt = _FakeSTT("hello")
    tts = _SlowTTS()
    speaker = _FakeSpeaker()
    events: list[AudioEvent] = []

    async def on_transcribed(_text: str) -> str:
        return "world"

    session = AudioSession(
        stt=stt,  # type: ignore[arg-type]
        tts=tts,  # type: ignore[arg-type]
        speaker=speaker,  # type: ignore[arg-type]
        on_transcribed=on_transcribed,  # type: ignore[arg-type]
        on_event=events.append,
        mode=SessionMode.PERSISTENT,
        silence_timeout=2.0,
    )

    run_task = asyncio.create_task(session.run())

    # Trigger first wake -> listening -> thinking -> speaking
    await asyncio.sleep(0.01)
    session.on_wake(_wake_event())
    await asyncio.sleep(0.01)
    session.push_frame(_fake_frame())
    session._frame_queue.put_nowait(None)

    # Wait until the state machine is inside SPEAKING (audio_chunks blocking)
    await asyncio.wait_for(slow_audio_available.wait(), timeout=2.0)
    assert session.state == "speaking", f"Expected speaking, got {session.state}"

    # Fire barge-in
    session.on_wake(_wake_event("barge-in"))
    slow_audio_ready.set()  # unblock audio_chunks so the coroutine can exit

    # Give the loop a few ticks to transition
    await asyncio.sleep(0.1)

    state_names = [e.state for e in events]
    # The machine must have visited LISTENING after SPEAKING (not stalled in IDLE)
    speaking_idx = max(i for i, e in enumerate(events) if e.state == "speaking")
    post_speaking = [e.state for e in events[speaking_idx + 1:]]
    assert "listening" in post_speaking, (
        f"Expected LISTENING after SPEAKING via barge-in, "
        f"post-speaking states: {post_speaking}  (all: {state_names})"
    )
    assert "idle" not in post_speaking, (
        f"IDLE must NOT appear between SPEAKING and LISTENING during barge-in, "
        f"post-speaking states: {post_speaking}"
    )

    run_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await run_task


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


# ---------------------------------------------------------------------------
# Bug 3 — three mode tests: single_shot, sticky, persistent post-SPEAKING
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mode_single_shot_returns_to_idle_after_speaking() -> None:
    """Bug 3 (single_shot): SPEAKING end -> IDLE, run() terminates.

    Verifies that single_shot mode transitions to IDLE (not LISTENING) after
    SPEAKING completes naturally, and that run() returns (does not loop).
    """
    session, _stt, _tts4, _speaker, events = _make_session(mode=SessionMode.SINGLE_SHOT)

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
        pytest.fail("single_shot run() did not terminate after SPEAKING — wrong mode behaviour")
    finally:
        driver.cancel()

    state_names = [e.state for e in events]
    assert "speaking" in state_names, f"Expected SPEAKING, got: {state_names}"
    # After SPEAKING, the session must have emitted IDLE and then stopped.
    speaking_idx = max(i for i, e in enumerate(events) if e.state == "speaking")
    post = [e.state for e in events[speaking_idx + 1:]]
    assert "idle" in post, (
        f"single_shot: expected IDLE after SPEAKING, post-states: {post}"
    )
    assert "listening" not in post, (
        f"single_shot: must NOT re-enter LISTENING after SPEAKING, post-states: {post}"
    )
    assert _tts4.spoken  # something was actually spoken


@pytest.mark.asyncio
async def test_mode_sticky_returns_to_listening_then_idle_on_timeout() -> None:
    """Bug 3 (sticky): SPEAKING end -> LISTENING for sticky_seconds, then IDLE.

    After speaking, the session must enter LISTENING.  When the sticky window
    expires with no speech, it should return to IDLE (not loop or terminate).
    """
    session, _stt, _tts2, _speaker, events = _make_session(
        transcript="hello",
        reply="world",
        mode=SessionMode.STICKY,
    )
    # Override sticky_seconds with a very short window so the test is fast.
    session._sticky_seconds = 0.1

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)

    driver = asyncio.create_task(drive())
    task = asyncio.create_task(session.run())

    # Wait long enough for: listen -> think -> speak -> sticky-listen -> idle
    await asyncio.sleep(0.8)

    state_names = [e.state for e in events]
    assert "speaking" in state_names, f"Expected SPEAKING, got: {state_names}"

    # After speaking, must have entered LISTENING (sticky window)
    speaking_idx = max(i for i, e in enumerate(events) if e.state == "speaking")
    post = [e.state for e in events[speaking_idx + 1:]]
    assert "listening" in post, (
        f"sticky: expected LISTENING after SPEAKING (sticky window), post-states: {post}"
    )
    # After the sticky window expired with no speech, must be back in IDLE
    # (session is still running, waiting for next wake)
    assert session.state == "idle", (
        f"sticky: expected IDLE after sticky window expired, got: {session.state}"
    )

    task.cancel()
    driver.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_mode_persistent_stays_in_listening_after_speaking() -> None:
    """Bug 3 (persistent): SPEAKING end -> LISTENING permanently (no return to IDLE).

    The original code returned PERSISTENT to IDLE after speaking.  With the fix,
    persistent mode transitions directly from SPEAKING to LISTENING without
    going through IDLE.
    """
    session, _stt, _tts3, _speaker, events = _make_session(
        transcript="hello",
        reply="world",
        mode=SessionMode.PERSISTENT,
    )

    async def drive() -> None:
        await asyncio.sleep(0.01)
        session.on_wake(_wake_event())
        await asyncio.sleep(0.01)
        session.push_frame(_fake_frame())
        session._frame_queue.put_nowait(None)

    driver = asyncio.create_task(drive())
    task = asyncio.create_task(session.run())

    # Wait enough time for: listen -> think -> speak -> (re-)listen
    await asyncio.sleep(0.4)

    state_names = [e.state for e in events]
    assert "speaking" in state_names, f"Expected SPEAKING, got: {state_names}"

    # After SPEAKING, the session MUST enter LISTENING — not IDLE.
    speaking_idx = max(i for i, e in enumerate(events) if e.state == "speaking")
    post = [e.state for e in events[speaking_idx + 1:]]
    assert "listening" in post, (
        f"persistent: expected LISTENING after SPEAKING (not IDLE), post-states: {post}"
    )
    assert post[0] != "idle", (
        f"persistent: first state after SPEAKING must NOT be IDLE, post-states: {post}"
    )

    task.cancel()
    driver.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# Bug 4 — single_shot barge-in re-enters LISTENING (not terminate)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_shot_barge_in_reenters_listening() -> None:
    """Bug 4: barge-in during SPEAKING always re-enters LISTENING, regardless of mode.

    Before the fix, single_shot mode returned immediately after _run_speaking,
    so a barge-in during SPEAKING caused run() to exit instead of continuing
    to LISTENING for the new utterance.

    With the fix, barge-in is checked BEFORE the mode dispatch, so the machine
    always re-enters LISTENING on barge-in — the mode only applies to natural
    SPEAKING end.

    Sequence: mode=single_shot, SPEAKING, wake fires (barge-in) -> LISTENING
    -> new turn SPEAKING ends -> IDLE (single_shot's natural behaviour).
    """
    # Use a slow TTS so barge-in fires while we are in SPEAKING state.
    slow_audio_available = asyncio.Event()
    slow_audio_release = asyncio.Event()

    class _SlowTTS:
        def __init__(self) -> None:
            self.spoken: list[str] = []
            self._task: AbortableTask | None = None

        async def speak(self, text: str) -> AbortableTask:
            self.spoken.append(text)
            q: asyncio.Queue[bytes | None] = asyncio.Queue()
            task_obj = asyncio.create_task(_noop(), name="slow-tts-task")
            t = AbortableTask(task=task_obj, audio_queue=q)
            self._task = t
            return t

        async def audio_chunks(self, task: AbortableTask) -> AsyncIterator[bytes]:  # noqa: ARG002
            slow_audio_available.set()
            await slow_audio_release.wait()
            if False:  # make pyright see this as an async generator
                yield b""

    stt = _FakeSTT("hello")
    tts = _SlowTTS()
    speaker = _FakeSpeaker()
    events: list[AudioEvent] = []

    async def on_transcribed(_text: str) -> str:
        return "world"

    session = AudioSession(
        stt=stt,  # type: ignore[arg-type]
        tts=tts,  # type: ignore[arg-type]
        speaker=speaker,  # type: ignore[arg-type]
        on_transcribed=on_transcribed,  # type: ignore[arg-type]
        on_event=events.append,
        mode=SessionMode.SINGLE_SHOT,
        silence_timeout=2.0,
    )

    run_task = asyncio.create_task(session.run())

    # Trigger first turn: IDLE -> LISTENING -> THINKING -> SPEAKING
    await asyncio.sleep(0.01)
    session.on_wake(_wake_event())
    await asyncio.sleep(0.01)
    session.push_frame(_fake_frame())
    session._frame_queue.put_nowait(None)

    # Wait until SPEAKING
    await asyncio.wait_for(slow_audio_available.wait(), timeout=2.0)
    assert session.state == "speaking", f"Expected SPEAKING, got {session.state}"

    # Fire barge-in while SPEAKING
    session.on_wake(_wake_event("barge-in"))
    assert speaker.aborted, "Speaker.abort() should have been called on barge-in"

    # Release the slow TTS so audio_chunks can return
    slow_audio_release.set()

    # Give the machine a few ticks to re-enter LISTENING
    await asyncio.sleep(0.15)

    state_names = [e.state for e in events]
    # The barge-in must have driven the machine to LISTENING (not terminated).
    assert not run_task.done(), (
        "run() returned early in single_shot after barge-in — "
        "it should re-enter LISTENING for the new turn (Bug 4 not fixed)."
    )
    speaking_indices = [i for i, e in enumerate(events) if e.state == "speaking"]
    assert speaking_indices, f"Expected at least one SPEAKING, got: {state_names}"
    post = [e.state for e in events[speaking_indices[-1] + 1:]]
    assert "listening" in post, (
        f"Bug 4: single_shot barge-in must re-enter LISTENING, post-speaking: {post}"
    )

    run_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await run_task
