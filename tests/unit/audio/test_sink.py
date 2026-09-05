"""Unit tests for Speaker with a fake _SinkBackend."""
from __future__ import annotations

import asyncio
import threading

import pytest

from workstation_agent.audio.sink import Speaker


class _FakeSink:
    """Injectable sink that records written bytes."""

    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_speaker_enqueues_and_plays() -> None:
    """Speaker.enqueue should deliver PCM to the backend."""
    sink = _FakeSink()
    async with Speaker(backend=sink) as speaker:
        chunk = b"\x01\x02" * 160
        speaker.enqueue(chunk)
        # Give the playback thread time to drain
        await asyncio.sleep(0.05)

    assert chunk in sink.written


@pytest.mark.asyncio
async def test_speaker_mute_discards_chunks() -> None:
    """While muted, enqueued chunks should not reach the backend."""
    sink = _FakeSink()
    async with Speaker(backend=sink) as speaker:
        speaker.mute()
        speaker.enqueue(b"\xFF" * 320)
        await asyncio.sleep(0.05)

    assert not sink.written


@pytest.mark.asyncio
async def test_speaker_unmute_resumes_playback() -> None:
    """After unmuting, new chunks should reach the backend."""
    sink = _FakeSink()
    async with Speaker(backend=sink) as speaker:
        speaker.mute()
        speaker.unmute()
        speaker.enqueue(b"\x01" * 320)
        await asyncio.sleep(0.05)

    assert sink.written


@pytest.mark.asyncio
async def test_speaker_abort_drains_queue() -> None:
    """abort() should drain pending audio without playing it."""
    sink = _FakeSink()
    async with Speaker(backend=sink) as speaker:
        # Enqueue many chunks then abort
        for _ in range(20):
            speaker.enqueue(b"\x00" * 320)
        speaker.abort()
        await asyncio.sleep(0.05)

    # Abort may or may not have played some chunks (race), but no exception
    assert not speaker._abort_flag.is_set()


@pytest.mark.asyncio
async def test_speaker_context_manager_closes_backend() -> None:
    """Exiting the context manager should close the backend."""
    sink = _FakeSink()
    async with Speaker(backend=sink):
        pass
    assert sink.closed


@pytest.mark.asyncio
async def test_speaker_multiple_chunks() -> None:
    """Speaker should deliver multiple chunks in order."""
    sink = _FakeSink()
    chunks = [bytes([i]) * 64 for i in range(5)]
    async with Speaker(backend=sink) as speaker:
        for chunk in chunks:
            speaker.enqueue(chunk)
        await asyncio.sleep(0.1)

    assert len(sink.written) == 5


@pytest.mark.asyncio
async def test_speaker_abort_no_busy_wait() -> None:
    """abort() must not cause a CPU busy-loop in the play thread.

    We count how many times the play loop wakes up during a 100 ms abort window.
    A sleep-based wait limits wakeups to at most ~100 (1 ms sleep => 100 ticks).
    We assert < 20 as a safe upper bound — a tight busy-loop would fire thousands
    of iterations in 100 ms and fail this test immediately.
    """

    class _CountingSink:
        def __init__(self) -> None:
            self.write_count = 0

        def write(self, data: bytes) -> None:  # noqa: ARG002
            self.write_count += 1

        def close(self) -> None:
            pass

    iteration_count = 0
    count_lock = threading.Lock()

    sink = _CountingSink()
    speaker = Speaker(backend=sink)
    await speaker.start()

    # Patch the abort flag's is_set to count iterations in the hot path.
    # We monkey-patch on the instance's class proxy instead so we only affect
    # this speaker's flag without touching all Events globally.
    abort_flag = speaker._abort_flag

    real_is_set = abort_flag.is_set

    def counting_is_set() -> bool:
        nonlocal iteration_count
        with count_lock:
            iteration_count += 1
        return real_is_set()

    abort_flag.is_set = counting_is_set  # type: ignore[method-assign]

    # Set abort so the loop stays in the abort-wait branch for 100 ms
    abort_flag.set()
    await asyncio.sleep(0.1)
    abort_flag.clear()

    # Give the thread one tick to re-enter the main path before we read count
    await asyncio.sleep(0.01)
    await speaker.stop()

    with count_lock:
        measured = iteration_count

    # A 1 ms sleep => at most ~100 iterations in 100 ms; allow 20x headroom
    # compared with a tight spin (which would be > 10_000 iterations).
    assert measured < 2_000, (
        f"play-loop woke up {measured} times in 100 ms — looks like a busy-wait. "
        "Expected < 2000 (sane sleep-based polling)."
    )


@pytest.mark.asyncio
async def test_speaker_start_stop_explicit() -> None:
    """Calling start() and stop() directly should work without context manager."""
    sink = _FakeSink()
    speaker = Speaker(backend=sink)
    await speaker.start()
    speaker.enqueue(b"\x00" * 64)
    await asyncio.sleep(0.05)
    await speaker.stop()
    assert sink.closed


@pytest.mark.asyncio
async def test_speaker_abort_then_stop_thread_exits() -> None:
    """Bug 2: abort() followed by stop() must not leave the play thread running.

    Before the fix, abort() drained the queue including the None sentinel that
    stop() enqueued.  The daemon thread never saw the sentinel and spun forever.

    With the fix (dedicated _stop_event instead of sentinel-in-queue), abort()
    only drains audio chunks and the stop event is separate — so the thread
    always sees the stop signal and exits within 200 ms.
    """
    sink = _FakeSink()
    speaker = Speaker(backend=sink)
    await speaker.start()

    assert speaker._thread is not None
    assert speaker._thread.is_alive(), "Play thread should be running after start()"

    # Enqueue some audio so the queue is not empty when we abort
    for _ in range(10):
        speaker.enqueue(b"\x00" * 320)

    # Rapid succession: abort() drains the queue, stop() signals the thread
    speaker.abort()
    await speaker.stop()

    # Thread must have exited
    alive = speaker._thread.is_alive()
    assert not alive, (
        "Play thread is still alive 200 ms after abort()+stop() — "
        "the None sentinel was likely consumed by abort() (Bug 2 not fixed)."
    )
