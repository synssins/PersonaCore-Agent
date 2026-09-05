"""Wyoming ASR (STT) client.

Streams ``audio-chunk`` events to the server and yields transcript strings
as they arrive (interim and final).  Reconnects with exponential backoff on
connection failure.

The ``connect_fn`` parameter is injectable: in production it defaults to
``asyncio.open_connection``; in tests the fake Wyoming server is injected.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import TYPE_CHECKING, Any

from wyoming.asr import Transcribe, Transcript
from wyoming.audio import AudioChunk, AudioStart, AudioStop
from wyoming.event import async_read_event, async_write_event

if TYPE_CHECKING:
    from workstation_agent.audio.mic import AudioFrame

log = logging.getLogger(__name__)

_SAMPLE_RATE = 16_000
_SAMPLE_WIDTH = 2  # bytes (int16)
_CHANNELS = 1

ConnectFn = Callable[
    [str, int],
    Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


async def _default_connect(
    host: str,
    port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(host, port)


class WyomingSTTClient:
    """Asyncio client for a Wyoming ASR endpoint.

    Parameters
    ----------
    host, port:
        Address of the Wyoming ASR server.
    connect_fn:
        Injectable connection factory for testing.
    max_retries:
        How many times to retry on connection failure before giving up.
    retry_base_delay:
        Base delay (seconds) for exponential backoff.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_fn: ConnectFn | None = None,
        max_retries: int = 3,
        retry_base_delay: float = 0.5,
    ) -> None:
        self._host = host
        self._port = port
        self._connect_fn: ConnectFn = connect_fn or _default_connect
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay

    async def transcribe(self, frames: AsyncIterator[AudioFrame]) -> AsyncIterator[str]:
        """Stream *frames* to the server and yield transcripts as they arrive.

        Returns an async iterator that yields interim and final transcript
        strings.  The iterator finishes when the frame source is exhausted or
        the connection closes.  Cancellation-safe.
        """
        out_queue: asyncio.Queue[str | None] = asyncio.Queue()
        task = asyncio.create_task(
            self._run(frames, out_queue),
            name="stt-client",
        )

        async def _drain() -> AsyncIterator[str]:
            try:
                while True:
                    item = await out_queue.get()
                    if item is None:
                        break
                    yield item
            except asyncio.CancelledError:
                task.cancel()
                raise
            finally:
                if not task.done():
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        return _drain()

    async def _run(
        self,
        frames: AsyncIterator[AudioFrame],
        out_queue: asyncio.Queue[str | None],
    ) -> None:
        """Background task: connect, stream audio, collect transcripts."""
        for attempt in range(self._max_retries + 1):
            try:
                reader, writer = await self._connect_fn(self._host, self._port)
            except (OSError, ConnectionRefusedError) as exc:
                if attempt >= self._max_retries:
                    log.error(  # noqa: TRY400
                        "stt_connect_failed_giving_up host=%s port=%s error=%s",
                        self._host,
                        self._port,
                        repr(exc),
                    )
                    await out_queue.put(None)
                    return
                delay = self._retry_base_delay * (2**attempt)
                log.warning(
                    "stt_connect_failed_retrying attempt=%s delay=%s error=%s",
                    attempt,
                    delay,
                    repr(exc),
                )
                await asyncio.sleep(delay)
                continue
            else:
                try:
                    await self._session(reader, writer, frames, out_queue)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("stt_session_error error=%s", repr(exc))
                    await out_queue.put(None)
                else:
                    return
                finally:
                    writer.close()
                    with contextlib.suppress(TimeoutError, Exception):
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.1)

        await out_queue.put(None)

    async def _session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        frames: AsyncIterator[AudioFrame],
        out_queue: asyncio.Queue[str | None],
    ) -> None:
        """Run one complete STT session using the real Wyoming wire format.

        After sending all audio (using the Wyoming library's write function),
        we yield to the event loop once (sleep(0)) so that in-process fake
        servers - which write synchronously via _MemoryTransport - get a chance
        to process the data and write their response before we start reading.
        """
        # Send Transcribe + audio-start
        await async_write_event(Transcribe(language="en").event(), writer)
        await async_write_event(
            AudioStart(rate=_SAMPLE_RATE, width=_SAMPLE_WIDTH, channels=_CHANNELS).event(),
            writer,
        )

        # Send all audio frames, then audio-stop
        try:
            async for frame in frames:
                chunk = AudioChunk(
                    audio=frame.pcm,
                    rate=_SAMPLE_RATE,
                    width=_SAMPLE_WIDTH,
                    channels=_CHANNELS,
                )
                await async_write_event(chunk.event(), writer)
            await async_write_event(AudioStop().event(), writer)
            # Yield so in-process fake servers can process the request
            await asyncio.sleep(0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("stt_send_error error=%s", repr(exc))

        # Read transcript events until the server closes
        while True:
            event = await async_read_event(reader)
            if event is None:
                break
            if Transcript.is_type(event.type):
                t = Transcript.from_event(event)
                await out_queue.put(t.text)

        await out_queue.put(None)
