"""Wyoming TTS (text-to-speech) client.

Implements the streaming synthesis protocol per the PersonaCore Wyoming client
wire ordering::

    -> synthesize-start   {voice}           no text
    -> synthesize-chunk   {text: "..."}     (xN)
    -> synthesize         {text: "<whole>"} compatibility fallback
    -> synthesize-stop
    <- audio-start / audio-chunk (xN) / audio-stop    per sentence
    <- synthesize-stopped                              terminator

``speak(text)`` returns an :class:`AbortableTask` immediately.  Audio bytes
are pushed into a queue consumed by :class:`~workstation_agent.audio.sink.Speaker`.
Calling ``AbortableTask.abort()`` cancels in-flight audio and sends
``synthesize-stop`` to close the exchange cleanly.

The ``connect_fn`` parameter is injectable: in production it defaults to
``asyncio.open_connection``; in tests the fake Wyoming server is injected.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

from wyoming.audio import AudioChunk
from wyoming.event import async_read_event, async_write_event
from wyoming.tts import (
    Synthesize,
    SynthesizeChunk,
    SynthesizeStart,
    SynthesizeStop,
    SynthesizeStopped,
    SynthesizeVoice,
)

log = logging.getLogger(__name__)

_CHUNK_CHARS = 48

ConnectFn = Callable[
    [str, int],
    Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


async def _default_connect(
    host: str,
    port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(host, port)


def _text_chunks(text: str, size: int = _CHUNK_CHARS) -> list[str]:
    """Split text on whitespace boundaries for streaming synthesis."""
    if not text:
        return []
    chunks: list[str] = []
    start = 0
    length = len(text)
    while start < length:
        end = start + size
        if end >= length:
            chunks.append(text[start:])
            break
        while end < length and not text[end].isspace():
            end += 1
        while end < length and text[end].isspace():
            end += 1
        chunks.append(text[start:end])
        start = end
    return chunks


class AbortableTask:
    """Handle for an in-progress TTS synthesis.

    ``abort()`` cancels the background task, drops queued audio, and sends
    ``synthesize-stop`` to close the server connection.
    """

    def __init__(
        self,
        task: asyncio.Task[None],
        audio_queue: asyncio.Queue[bytes | None],
    ) -> None:
        self._task = task
        self._audio_queue = audio_queue
        self._aborted = False

    def abort(self) -> None:
        """Cancel the synthesis immediately."""
        if self._aborted:
            return
        self._aborted = True
        self._task.cancel()
        # Drain the queue and signal EOF so consumers unblock
        while not self._audio_queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._audio_queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            self._audio_queue.put_nowait(None)

    @property
    def done(self) -> bool:
        """True when the background synthesis task has completed."""
        return self._task.done()

    async def wait(self) -> None:
        """Await completion of the synthesis task, ignoring errors."""
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task


class WyomingTTSClient:
    """Asyncio client for a Wyoming TTS endpoint.

    Parameters
    ----------
    host, port:
        Address of the Wyoming TTS server.
    voice:
        Optional voice name (e.g. ``"vits-onnx/glados"``).
    connect_fn:
        Injectable connection factory for testing.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        voice: str | None = None,
        connect_fn: ConnectFn | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._voice = voice
        self._connect_fn: ConnectFn = connect_fn or _default_connect

    async def speak(self, text: str) -> AbortableTask:
        """Start synthesis in the background.

        Returns immediately.  Audio bytes are pushed into the returned
        task's queue; pass the task to a :class:`~workstation_agent.audio.sink.Speaker`.
        """
        audio_queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=100)
        task = asyncio.create_task(
            self._synthesis_task(text, audio_queue),
            name=f"tts-speak-{id(text)}",
        )
        return AbortableTask(task=task, audio_queue=audio_queue)

    async def audio_chunks(self, task: AbortableTask) -> AsyncIterator[bytes]:
        """Iterate audio bytes from a running AbortableTask."""
        while True:
            chunk = await task._audio_queue.get()  # noqa: SLF001
            if chunk is None:
                return
            yield chunk

    async def _synthesis_task(
        self,
        text: str,
        audio_queue: asyncio.Queue[bytes | None],
    ) -> None:
        """Run the full Wyoming TTS exchange and push audio onto the queue."""
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await self._connect_fn(self._host, self._port)
            await self._send_request(writer, text)
            await self._receive_audio(reader, audio_queue)
        except asyncio.CancelledError:
            # Attempt graceful stop
            if writer is not None and not writer.is_closing():
                with contextlib.suppress(Exception):
                    await async_write_event(SynthesizeStop().event(), writer)
        except Exception as exc:  # noqa: BLE001
            log.warning("tts_session_error error=%s", repr(exc))
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(TimeoutError, Exception):
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            with contextlib.suppress(asyncio.QueueFull):
                audio_queue.put_nowait(None)

    async def _send_request(self, writer: asyncio.StreamWriter, text: str) -> None:
        """Send the full streaming TTS request per the wire ordering.

        After sending all events, we yield to the event loop (sleep(0)) so that
        in-process fake servers get a chance to process the request before we
        start reading the response.
        """
        voice = SynthesizeVoice(name=self._voice) if self._voice else None

        # 1) synthesize-start (no text)
        await async_write_event(SynthesizeStart(voice=voice).event(), writer)

        # 2) synthesize-chunk x N
        for chunk in _text_chunks(text):
            await async_write_event(SynthesizeChunk(text=chunk).event(), writer)

        # 3) synthesize (whole text, compatibility fallback)
        await async_write_event(Synthesize(text=text, voice=voice).event(), writer)

        # 4) synthesize-stop
        await async_write_event(SynthesizeStop().event(), writer)

        # Yield to event loop so in-process fake servers can process the request
        await asyncio.sleep(0)

    async def _receive_audio(
        self,
        reader: asyncio.StreamReader,
        audio_queue: asyncio.Queue[bytes | None],
    ) -> None:
        """Read audio events from server and push bytes onto *audio_queue*."""
        while True:
            event = await async_read_event(reader)
            if event is None:
                break
            if SynthesizeStopped.is_type(event.type):
                # Protocol terminator - we're done
                break
            if AudioChunk.is_type(event.type):
                chunk = AudioChunk.from_event(event)
                if chunk.audio:
                    await audio_queue.put(chunk.audio)
            # AudioStart, AudioStop, unknown events - ignored
