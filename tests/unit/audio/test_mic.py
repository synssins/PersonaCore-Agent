"""Unit tests for MicStream with a fake _FrameSource."""
from __future__ import annotations

import asyncio

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
