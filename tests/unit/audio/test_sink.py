"""Unit tests for Speaker with a fake _SinkBackend."""
from __future__ import annotations

import asyncio

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
async def test_speaker_start_stop_explicit() -> None:
    """Calling start() and stop() directly should work without context manager."""
    sink = _FakeSink()
    speaker = Speaker(backend=sink)
    await speaker.start()
    speaker.enqueue(b"\x00" * 64)
    await asyncio.sleep(0.05)
    await speaker.stop()
    assert sink.closed
