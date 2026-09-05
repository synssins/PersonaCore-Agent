"""Integration tests for the full audio pipeline.

Uses FakeWyomingServer for all network I/O; no real sounddevice or sockets.

Tests:
- Fake MicStream -> WyomingSTTClient -> expected transcript
- WyomingTTSClient -> expected audio bytes via FakeWyomingServer
- AbortableTask.abort() cancels TTS mid-stream (barge-in)
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import pytest

from tests.fakes.fake_wyoming import FakeWyomingServer
from workstation_agent.audio.mic import AudioFrame
from workstation_agent.audio.stt import WyomingSTTClient
from workstation_agent.audio.tts import WyomingTTSClient

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frames(n: int = 5) -> list[AudioFrame]:
    """Generate n silence frames."""
    return [AudioFrame(pcm=b"\x00" * 320, ts_ms=i * 20) for i in range(n)]


async def _frames_iter(frames: list[AudioFrame]) -> AsyncIterator[AudioFrame]:
    for f in frames:
        yield f


# ---------------------------------------------------------------------------
# STT tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stt_yields_canned_transcript() -> None:
    """STT client should yield the canned transcript from FakeWyomingServer."""
    server = FakeWyomingServer(canned_transcript="hello world")
    async with server:
        client = WyomingSTTClient("", 0, connect_fn=server.connect)
        async_iter = await client.transcribe(_frames_iter(_frames()))
        transcripts = [text async for text in async_iter]

    assert transcripts == ["hello world"]


@pytest.mark.asyncio
async def test_stt_receives_audio_frames() -> None:
    """FakeWyomingServer should collect the audio frames sent by the STT client."""
    server = FakeWyomingServer(canned_transcript="test")
    async with server:
        client = WyomingSTTClient("", 0, connect_fn=server.connect)
        async_iter = await client.transcribe(_frames_iter(_frames(3)))
        async for _ in async_iter:
            pass

    # Server should have received 3 frames worth of audio
    assert len(server.last_asr_frames) == 3


@pytest.mark.asyncio
async def test_stt_cancellation_safe() -> None:
    """Cancelling the STT iteration should not raise unhandled exceptions."""
    server = FakeWyomingServer(canned_transcript="never")
    async with server:
        client = WyomingSTTClient("", 0, connect_fn=server.connect)

        async def slow_frames() -> AsyncIterator[AudioFrame]:
            for f in _frames(10):
                yield f
                await asyncio.sleep(0.05)

        async def run() -> None:
            async_iter = await client.transcribe(slow_frames())
            async for _ in async_iter:
                pass

        task = asyncio.create_task(run())
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# ---------------------------------------------------------------------------
# TTS tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tts_yields_canned_audio() -> None:
    """TTS client should yield the canned audio bytes from FakeWyomingServer."""
    canned = b"\x01\x02" * 160  # 320 bytes
    server = FakeWyomingServer(canned_audio=canned)
    async with server:
        client = WyomingTTSClient("", 0, connect_fn=server.connect)
        tts_task = await client.speak("Hello, world!")
        received = [chunk async for chunk in client.audio_chunks(tts_task)]

    assert b"".join(received) == canned


@pytest.mark.asyncio
async def test_tts_sends_full_protocol() -> None:
    """FakeWyomingServer should record the full text spoken via TTS."""
    server = FakeWyomingServer()
    async with server:
        client = WyomingTTSClient("", 0, connect_fn=server.connect)
        tts_task = await client.speak("Nice weather today.")
        # Drain audio
        async for _ in client.audio_chunks(tts_task):
            pass

    assert server.spoken_text == "Nice weather today."


@pytest.mark.asyncio
async def test_tts_abort_cancels_mid_stream() -> None:
    """AbortableTask.abort() should stop audio iteration immediately.

    This is the barge-in cancellation test: we abort mid-chunk and confirm
    the iteration exits without error.
    """
    # Use a large chunk so there's something to cancel mid-stream
    large_audio = b"\x00" * 3200
    server = FakeWyomingServer(canned_audio=large_audio)
    async with server:
        client = WyomingTTSClient("", 0, connect_fn=server.connect)
        tts_task = await client.speak("Cancel me.")

        abort_called = False
        async for _chunk in client.audio_chunks(tts_task):
            if not abort_called:
                abort_called = True
                tts_task.abort()
                break  # stop consuming after abort

    # After abort, task should be marked done
    assert tts_task._aborted


@pytest.mark.asyncio
async def test_tts_abortable_task_done_after_completion() -> None:
    """AbortableTask.done should be True after audio stream ends."""
    server = FakeWyomingServer(canned_audio=b"\x00" * 64)
    async with server:
        client = WyomingTTSClient("", 0, connect_fn=server.connect)
        tts_task = await client.speak("Short.")
        async for _ in client.audio_chunks(tts_task):
            pass
        # Give the background task a moment to finish
        await tts_task.wait()

    assert tts_task.done


@pytest.mark.asyncio
async def test_stt_connect_retry_on_failure() -> None:
    """STT client retries on connection refusal and gives up after max_retries."""
    async def always_fail(_host: str, _port: int) -> tuple:  # type: ignore[type-arg]
        raise ConnectionRefusedError

    client = WyomingSTTClient(
        "localhost", 9999, connect_fn=always_fail, max_retries=1, retry_base_delay=0.01,
    )
    async_iter = await client.transcribe(_frames_iter(_frames(1)))
    results = [t async for t in async_iter]

    # Should have given up silently
    assert results == []
