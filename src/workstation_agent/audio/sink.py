"""PCM audio output via sounddevice.

Threading pattern
-----------------
Same as :mod:`~workstation_agent.audio.mic`: a blocking write loop runs inside
a daemon thread so the PortAudio C callback thread never touches the asyncio
event loop.  PCM bytes are pushed onto a ``queue.SimpleQueue``; the thread
drains it via blocking ``sounddevice.OutputStream.write``.

Barge-in cancel
---------------
``Speaker.abort()`` sets a flag read by the background thread.  The thread
stops writing immediately and the queue is drained, giving sub-frame latency
for the cancel signal.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import threading
import time
from typing import Protocol, Self

log = logging.getLogger(__name__)

_SAMPLE_RATE = 16_000
_CHANNELS = 1
_DTYPE = "int16"


class _SinkBackend(Protocol):
    """Injectable audio sink for testing without a real sound device."""

    def write(self, data: bytes) -> None:
        """Write raw PCM bytes to the output device."""
        ...

    def close(self) -> None:
        """Release the output device."""
        ...


class _SounddeviceSink:
    """Real sounddevice backend."""

    def __init__(self, *, samplerate: int, channels: int, dtype: str) -> None:
        import sounddevice as sd  # noqa: PLC0415

        self._stream = sd.OutputStream(
            samplerate=samplerate,
            channels=channels,
            dtype=dtype,
        )
        self._stream.start()
        self._channels = channels

    def write(self, data: bytes) -> None:
        import numpy as np  # noqa: PLC0415

        arr = np.frombuffer(data, dtype=np.int16)
        if self._channels > 1:
            arr = arr.reshape(-1, self._channels)
        self._stream.write(arr)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._stream.stop()
            self._stream.close()


class Speaker:
    """Plays PCM audio to the OS default output device.

    Parameters
    ----------
    sample_rate, channels:
        Audio format matching the TTS output.
    backend:
        Injectable sink.  ``None`` uses the real sounddevice backend.
    """

    def __init__(
        self,
        *,
        sample_rate: int = _SAMPLE_RATE,
        channels: int = _CHANNELS,
        backend: _SinkBackend | None = None,
    ) -> None:
        self._sample_rate = sample_rate
        self._channels = channels
        self._backend_arg = backend
        self._backend: _SinkBackend | None = None
        self._queue: queue.SimpleQueue[bytes | None] = queue.SimpleQueue()
        self._abort_flag = threading.Event()
        self._muted = False
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    async def start(self) -> None:
        """Open the output stream and start the playback thread."""
        if self._backend_arg is not None:
            self._backend = self._backend_arg
        else:
            self._backend = _SounddeviceSink(
                samplerate=self._sample_rate,
                channels=self._channels,
                dtype=_DTYPE,
            )
        self._thread = threading.Thread(
            target=self._play_loop, name="speaker-play", daemon=True,
        )
        self._thread.start()

    async def stop(self) -> None:
        """Stop playback and close the stream."""
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._backend is not None:
            self._backend.close()

    # ------------------------------------------------------------------
    # Playback control
    # ------------------------------------------------------------------

    def enqueue(self, pcm: bytes) -> None:
        """Push a PCM chunk onto the playback queue (thread-safe)."""
        if not self._muted:
            self._queue.put(pcm)

    def abort(self) -> None:
        """Immediately stop playback; discard buffered audio (barge-in)."""
        self._abort_flag.set()
        # Drain the queue
        while True:
            try:
                self._queue.get_nowait()
            except Exception:  # noqa: BLE001
                break
        self._abort_flag.clear()

    def mute(self) -> None:
        """Mute speaker output (discard incoming chunks)."""
        self._muted = True
        self.abort()

    def unmute(self) -> None:
        """Unmute speaker output."""
        self._muted = False

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _play_loop(self) -> None:
        """Blocking playback loop - runs in a daemon thread."""
        if self._backend is None:
            return
        while True:
            # If abort is active, sleep briefly instead of spinning so we do
            # not peg a CPU core waiting for the flag to clear.
            if self._abort_flag.is_set():
                time.sleep(0.001)
                continue
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            except Exception:  # noqa: BLE001
                break
            if item is None:
                break
            if self._abort_flag.is_set():
                # Drop this chunk — abort was called between the get and now.
                continue
            with contextlib.suppress(Exception):
                self._backend.write(item)
