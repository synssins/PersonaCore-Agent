"""In-process fake Wyoming server for testing.

Implements the minimal ASR and TTS halves of the Wyoming protocol using the
real wyoming library wire format (``async_read_event`` / ``async_write_event``).
Tests inject this via the ``connect_fn`` parameter of ``WyomingSTTClient`` and
``WyomingTTSClient`` - no real sockets needed.

Usage::

    server = FakeWyomingServer(
        canned_transcript="hello world",
        canned_audio=b"\\x00" * 1024,
    )
    async with server:
        stt = WyomingSTTClient("", 0, connect_fn=server.connect)
        tts = WyomingTTSClient("", 0, connect_fn=server.connect)

The server keeps the last received text and the emitted audio bytes accessible
as ``server.last_asr_frames`` and ``server.spoken_text`` for assertions.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, Self

from wyoming.asr import Transcript
from wyoming.audio import AudioChunk, AudioStart, AudioStop
from wyoming.event import async_read_event, async_write_event
from wyoming.tts import Synthesize, SynthesizeStopped

if TYPE_CHECKING:
    from wyoming.event import Event


# ---------------------------------------------------------------------------
# Memory transport (bidirectional in-process socket pair)
# ---------------------------------------------------------------------------

class _MemoryTransport(asyncio.Transport):
    """Asyncio transport that writes bytes directly into a peer StreamReader."""

    def __init__(self, peer_reader: asyncio.StreamReader) -> None:
        super().__init__()
        self._peer = peer_reader
        self._closing = False

    def write(self, data: bytes | bytearray | memoryview[Any]) -> None:
        if not self._closing:
            self._peer.feed_data(bytes(data))

    def write_eof(self) -> None:
        if not self._closing:
            self._peer.feed_eof()

    def is_closing(self) -> bool:
        return self._closing

    def close(self) -> None:
        if not self._closing:
            self._closing = True
            with contextlib.suppress(Exception):
                self._peer.feed_eof()

    def get_write_buffer_size(self) -> int:
        return 0

    def get_extra_info(self, name: str, default: object = None) -> object:  # noqa: ARG002
        return default


def _make_stream_pair() -> tuple[
    asyncio.StreamReader, asyncio.StreamWriter,
    asyncio.StreamReader, asyncio.StreamWriter,
]:
    """Return (client_reader, client_writer, server_reader, server_writer).

    Data written by client_writer is readable from server_reader and vice versa.
    """
    loop = asyncio.get_running_loop()

    # client writes -> server reads
    server_r = asyncio.StreamReader()
    server_r_proto = asyncio.StreamReaderProtocol(server_r)
    client_w_transport = _MemoryTransport(server_r)
    client_w = asyncio.StreamWriter(
        transport=client_w_transport,  # type: ignore[arg-type]
        protocol=server_r_proto,
        reader=None,  # type: ignore[arg-type]
        loop=loop,
    )

    # server writes -> client reads
    client_r = asyncio.StreamReader()
    client_r_proto = asyncio.StreamReaderProtocol(client_r)
    server_w_transport = _MemoryTransport(client_r)
    server_w = asyncio.StreamWriter(
        transport=server_w_transport,  # type: ignore[arg-type]
        protocol=client_r_proto,
        reader=None,  # type: ignore[arg-type]
        loop=loop,
    )

    return client_r, client_w, server_r, server_w


# ---------------------------------------------------------------------------
# ConnectFn type alias
# ---------------------------------------------------------------------------

ConnectFn = Callable[
    [str, int],
    Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


# ---------------------------------------------------------------------------
# Fake server
# ---------------------------------------------------------------------------

class FakeWyomingServer:
    """Configurable in-process Wyoming server for tests.

    Parameters
    ----------
    canned_transcript:
        Text returned by the ASR half.
    canned_audio:
        Raw PCM bytes returned by the TTS half (single audio-chunk).
    """

    def __init__(
        self,
        canned_transcript: str = "test transcript",
        canned_audio: bytes = b"\x00" * 320,
    ) -> None:
        self.canned_transcript = canned_transcript
        self.canned_audio = canned_audio
        self.last_asr_frames: list[bytes] = []
        self.spoken_text: str = ""
        self._tasks: list[asyncio.Task[None]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # ------------------------------------------------------------------
    # Injectable connect function
    # ------------------------------------------------------------------

    async def connect(
        self,
        host: str,  # noqa: ARG002
        port: int,  # noqa: ARG002
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Return a connected in-memory stream pair and start the server handler."""
        client_r, client_w, server_r, server_w = _make_stream_pair()
        task = asyncio.create_task(
            self._handle_connection(server_r, server_w),
            name="fake-wyoming-handler",
        )
        self._tasks.append(task)
        return client_r, client_w

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Detect protocol and dispatch to ASR or TTS handler."""
        with contextlib.suppress(asyncio.CancelledError, ConnectionResetError, Exception):
            first_event = await async_read_event(reader)
            if first_event is not None:
                if first_event.type in ("transcribe", "audio-start", "audio-chunk", "audio-stop"):
                    await self._handle_asr(reader, writer, first_event)
                else:
                    # synthesize-start, synthesize, synthesize-chunk, synthesize-stop
                    await self._handle_tts(reader, writer, first_event)
        with contextlib.suppress(Exception):
            writer.close()

    async def _handle_asr(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_event: Event,
    ) -> None:
        """ASR: consume audio events, reply with transcript."""
        self.last_asr_frames = []
        event: Event | None = first_event

        while event is not None:
            if event.type == "audio-chunk":
                chunk = AudioChunk.from_event(event)
                if chunk.audio:
                    self.last_asr_frames.append(chunk.audio)
            elif event.type == "audio-stop":
                break
            event = await async_read_event(reader)

        await async_write_event(Transcript(text=self.canned_transcript).event(), writer)

    async def _handle_tts(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_event: Event,
    ) -> None:
        """TTS: consume synthesize events, reply with audio."""
        self.spoken_text = ""
        event: Event | None = first_event

        while event is not None:
            if event.type == "synthesize":
                synth = Synthesize.from_event(event)
                self.spoken_text = synth.text or ""
            elif event.type == "synthesize-stop":
                break
            event = await async_read_event(reader)

        # Reply: audio-start, audio-chunk, audio-stop, synthesize-stopped
        await async_write_event(AudioStart(rate=16000, width=2, channels=1).event(), writer)
        await async_write_event(
            AudioChunk(audio=self.canned_audio, rate=16000, width=2, channels=1).event(),
            writer,
        )
        await async_write_event(AudioStop().event(), writer)
        await async_write_event(SynthesizeStopped().event(), writer)
