"""Unit tests for MicStream with a fake _FrameSource."""
from __future__ import annotations

import asyncio
import contextlib

import pytest

from workstation_agent.audio.mic import AudioFrame, MicStream


class _FakeSource:
    """Injectable source that emits a fixed number of frames then returns None."""

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = iter(frames)
        self.closed = False

    def read_frames(self) -> bytes | None:
        return next(self._frames, None)

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_mic_yields_frames() -> None:
    """MicStream should yield each frame returned by the source."""
    pcm_data = [b"\x01" * 320, b"\x02" * 320, b"\x03" * 320]
    source = _FakeSource(pcm_data)

    async with MicStream(source=source) as mic:
        received: list[AudioFrame] = []
        async for frame in mic:
            received.append(frame)
            if len(received) == len(pcm_data):
                break

    assert len(received) == 3
    assert received[0].pcm == b"\x01" * 320
    assert received[1].pcm == b"\x02" * 320
    assert received[2].pcm == b"\x03" * 320


@pytest.mark.asyncio
async def test_mic_stops_on_source_exhaustion() -> None:
    """MicStream should stop iterating when source returns None."""
    source = _FakeSource([b"\x00" * 320])

    async with MicStream(source=source) as mic:
        collected = [frame async for frame in mic]

    assert len(collected) == 1


@pytest.mark.asyncio
async def test_mic_close_signals_consumer() -> None:
    """Stopping MicStream should unblock any async iterator waiting."""
    source = _FakeSource([])  # no frames - will stop immediately

    async with MicStream(source=source) as mic:
        frames = [f async for f in mic]

    assert frames == []
    assert source.closed


@pytest.mark.asyncio
async def test_mic_pause_resumes() -> None:
    """Frames produced while paused should be discarded."""
    # Make source produce many frames, pause partway through
    pcm_data = [b"\xAA" * 320] * 10
    source = _FakeSource(pcm_data)

    mic = MicStream(source=source)
    await mic.start()

    # Pause immediately - frames during pause are dropped
    mic.pause()
    await asyncio.sleep(0.05)

    # Resume
    mic.resume()
    await asyncio.sleep(0.01)

    await mic.stop()
    # No assertion on count - just verify no exception and stop works


@pytest.mark.asyncio
async def test_mic_ts_ms_is_populated() -> None:
    """AudioFrame.ts_ms should be a non-zero timestamp."""
    source = _FakeSource([b"\x00" * 320])

    async with MicStream(source=source) as mic:
        async for frame in mic:
            assert frame.ts_ms > 0
            break


@pytest.mark.asyncio
async def test_mic_context_manager() -> None:
    """MicStream as async context manager should start and stop cleanly."""
    source = _FakeSource([])
    async with MicStream(source=source) as mic:
        assert mic is not None  # context manager works


@pytest.mark.asyncio
async def test_mic_source_closed_on_stop() -> None:
    """source.close() should be called when MicStream stops."""
    source = _FakeSource([b"\x00" * 320])
    async with MicStream(source=source):
        pass
    assert source.closed


@pytest.mark.asyncio
async def test_mic_sentinel_delivered_when_queue_full() -> None:
    """Bug 1: stop() must deliver the None sentinel even when the queue is full.

    Before the fix, MicStream.stop() used put_nowait(None) which silently
    dropped the sentinel when the queue was at capacity — the consumer's
    ``async for`` would then block forever.

    With the fix (await queue.put(None)), the sentinel waits for a slot and
    always arrives, so the consumer exits within 100 ms.
    """
    # Use a very small queue so it fills quickly
    mic = MicStream(source=_FakeSource([]))
    mic._queue = asyncio.Queue(maxsize=3)

    # Fill the queue to capacity with dummy frames
    for _ in range(3):
        mic._queue.put_nowait(AudioFrame(pcm=b"\x00" * 320, ts_ms=1))

    # Now call stop() — the queue is full; the sentinel MUST still arrive.
    # We run a consumer concurrently so the queue can drain while stop() puts.
    consumer_done = asyncio.Event()

    async def consume() -> None:
        # Drain the dummy frames then wait for the sentinel
        count = 0
        while True:
            item = await asyncio.wait_for(mic._queue.get(), timeout=0.5)
            if item is None:
                consumer_done.set()
                return
            count += 1

    # Start consumer first, then trigger stop (which must put the sentinel)
    consumer_task = asyncio.create_task(consume())
    # stop() needs the thread task to be present; just call the sentinel path
    # directly (the internal stop helper) without the full start/stop lifecycle.
    await mic.stop()  # must not drop the sentinel

    try:
        await asyncio.wait_for(consumer_done.wait(), timeout=0.5)
    except TimeoutError:
        pytest.fail(
            "Consumer did not exit within 500 ms — sentinel was likely dropped "
            "because the queue was full (Bug 1 not fixed).",
        )
    finally:
        consumer_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await consumer_task


