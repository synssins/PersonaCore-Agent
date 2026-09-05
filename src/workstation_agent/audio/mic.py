"""Microphone capture via sounddevice.

Threading contract
------------------
sounddevice.InputStream callbacks fire on a C thread managed by PortAudio.
That thread MUST NOT touch the asyncio event loop.  We avoid the problem
entirely by NOT using the callback form at all: instead we run the blocking
``sounddevice.InputStream.read()`` loop inside ``asyncio.to_thread`` and push
frames into an ``asyncio.Queue`` with ``loop.call_soon_threadsafe``.  The
async iterator on the main thread drains that queue.

This is the "asyncio.to_thread + call_soon_threadsafe" variant documented in
the module docstring of ``workstation_agent.audio``.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_SAMPLE_RATE = 16_000
_CHANNELS = 1
_DTYPE = "int16"
_FRAME_MS = 20  # 20 ms frames, 320 samples


@dataclass(frozen=True, slots=True)
class AudioFrame:
    """One chunk of raw 16-bit mono PCM audio."""

    pcm: bytes
    ts_ms: int  # milliseconds since the Unix epoch


class _FrameSource(Protocol):
    """Injectable frame supplier: real sounddevice in prod, fake in tests."""

    def read_frames(self) -> bytes | None:
        """Return one frame of PCM bytes, or None when done."""
        ...

    def close(self) -> None:
        """Release any held resources."""
        ...


class _SounddeviceSource:
    """Real sounddevice implementation of _FrameSource."""

    def __init__(self, *, samplerate: int, channels: int, dtype: str, frames: int) -> None:
        import sounddevice as sd  # noqa: PLC0415

        self._stream = sd.InputStream(
            samplerate=samplerate,
            channels=channels,
            dtype=dtype,
        )
        self._stream.start()
        self._frames = frames
        self._dtype = dtype

    def read_frames(self) -> bytes | None:
        import numpy as np  # noqa: PLC0415

        data, _overflowed = self._stream.read(self._frames)
        # data is shape (frames, channels), dtype int16
        return data.astype(np.int16).tobytes()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._stream.stop()
            self._stream.close()


class MicStream:
    """Captures 16 kHz mono PCM frames from the OS default input device.

    Usage::

        async with MicStream() as mic:
            async for frame in mic:
                process(frame.pcm)

    Pause/resume is used by the mute integration.  While paused the source
    still runs but frames are discarded so that timing/VAD state is preserved.
    """

    def __init__(
        self,
        *,
        sample_rate: int = _SAMPLE_RATE,
        channels: int = _CHANNELS,
        frame_ms: int = _FRAME_MS,
        source: _FrameSource | None = None,
    ) -> None:
        self._sample_rate = sample_rate
        self._channels = channels
        self._frame_ms = frame_ms
        self._frames_per_chunk = int(sample_rate * frame_ms / 1000)
        self._source = source
        self._queue: asyncio.Queue[AudioFrame | None] = asyncio.Queue(maxsize=50)
        self._paused = False
        self._running = False
        self._thread_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    async def start(self) -> None:
        """Open the input stream and start capturing."""
        if self._source is None:
            self._source = _SounddeviceSource(
                samplerate=self._sample_rate,
                channels=self._channels,
                dtype=_DTYPE,
                frames=self._frames_per_chunk,
            )
        self._running = True
        loop = asyncio.get_running_loop()
        self._thread_task = asyncio.create_task(
            asyncio.to_thread(self._read_loop, loop),
            name="mic-read-loop",
        )

    async def stop(self) -> None:
        """Stop capturing and close the stream."""
        self._running = False
        if self._thread_task is not None:
            self._thread_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._thread_task
        if self._source is not None:
            self._source.close()
        # Signal the consumer — use blocking put() so the sentinel is always
        # delivered even when the queue is at capacity.
        await self._queue.put(None)

    # ------------------------------------------------------------------
    # Async iterator
    # ------------------------------------------------------------------

    def __aiter__(self) -> AsyncIterator[AudioFrame]:
        return self._generate()

    async def _generate(self) -> AsyncIterator[AudioFrame]:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            yield item

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Discard incoming frames until resume()."""
        self._paused = True

    def resume(self) -> None:
        """Resume forwarding frames to the async iterator."""
        self._paused = False

    # ------------------------------------------------------------------
    # Background thread (runs inside asyncio.to_thread)
    # ------------------------------------------------------------------

    def _read_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Blocking read loop - runs in a thread via asyncio.to_thread."""
        if self._source is None:
            return
        temp: queue.SimpleQueue[AudioFrame | None] = queue.SimpleQueue()
        while self._running:
            try:
                pcm = self._source.read_frames()
            except Exception:  # noqa: BLE001
                break
            if pcm is None:
                break
            if self._paused:
                continue
            frame = AudioFrame(pcm=pcm, ts_ms=int(time.time() * 1000))
            temp.put(frame)
            loop.call_soon_threadsafe(self._drain_temp_queue, temp)
        # Use a coroutine-based put so the sentinel is *always* delivered even
        # when the queue is full — put() will wait rather than raise QueueFull.
        asyncio.run_coroutine_threadsafe(self._queue.put(None), loop)

    def _drain_temp_queue(self, temp: queue.SimpleQueue[AudioFrame | None]) -> None:
        """Called on the event loop thread to move frames from temp into async queue."""
        while not temp.empty():
            item = temp.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                self._queue.put_nowait(item)
