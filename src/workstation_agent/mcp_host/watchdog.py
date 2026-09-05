"""Heartbeat watchdog for MCP plugin subprocesses.

Periodically pings each registered plugin. A plugin that fails to answer
inside the configured timeout window is terminated via the supplied
:class:`PluginSupervisor` and an ``on_plugin_died`` callback fires so
SPEC-03B can decide whether to reload the plugin or mark it quarantined.
"""
# ruff: noqa: S101, ANN401
# S101: internal-invariant asserts for mypy narrowing.
# ANN401: the ``_Pinger`` Protocol's ``ping()`` returns the raw MCP ``{}``
#         payload; typing it as anything narrower would leak MCP wire
#         details into the watchdog.

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Awaitable, Callable

    from .supervisor import PluginSupervisor, SubprocessHandle

log = logging.getLogger(__name__)


class _Pinger(Protocol):
    """Minimum surface the watchdog needs from an MCP client."""

    async def ping(self) -> Any: ...


DiedCallback = "Callable[[SubprocessHandle, str], Awaitable[None] | None]"


@dataclass
class _Entry:
    handle: SubprocessHandle
    client: _Pinger
    last_ok: float = field(default_factory=time.monotonic)


class HeartbeatWatchdog:
    """Ping every registered plugin every ``interval`` seconds."""

    def __init__(  # noqa: PLR0913 - all keyword-only knobs; documented above
        self,
        supervisor: PluginSupervisor,
        *,
        interval: float = 10.0,
        heartbeat_timeout: float = 30.0,
        ping_timeout: float = 5.0,
        on_plugin_died: Callable[[SubprocessHandle, str], Awaitable[None] | None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._supervisor = supervisor
        self._interval = interval
        self._timeout = heartbeat_timeout
        self._ping_timeout = ping_timeout
        self._on_died = on_plugin_died
        self._clock = clock or time.monotonic
        self._entries: dict[int, _Entry] = {}
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self._lock = asyncio.Lock()

    # -- registration ---------------------------------------------------------

    def register(self, handle: SubprocessHandle, client: _Pinger) -> None:
        self._entries[handle.pid] = _Entry(
            handle=handle,
            client=client,
            last_ok=self._clock(),
        )

    def unregister(self, handle: SubprocessHandle) -> None:
        self._entries.pop(handle.pid, None)

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="mcp-watchdog")

    async def stop(self) -> None:
        if self._task is None:
            return
        assert self._stop_event is not None
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=self._interval + 1.0)
        except TimeoutError:
            self._task.cancel()
        self._task = None
        self._stop_event = None

    # -- test hook ------------------------------------------------------------

    async def tick(self) -> None:
        """Single ping sweep — exposed for tests to drive deterministically."""
        await self._sweep_once()

    # -- internals ------------------------------------------------------------

    async def _run(self) -> None:
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            try:
                await self._sweep_once()
            except Exception:
                log.exception("watchdog sweep raised")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._interval)
            except TimeoutError:
                continue

    async def _sweep_once(self) -> None:
        # Snapshot to avoid mutation-during-iteration.
        async with self._lock:
            entries = list(self._entries.values())

        # Purge closed handles up-front (they don't need a ping).
        live: list[_Entry] = []
        for entry in entries:
            if entry.handle.closed:
                self._entries.pop(entry.handle.pid, None)
            else:
                live.append(entry)
        if not live:
            return

        # Concurrent pings: one slow plugin must NOT delay the others by the
        # full ping timeout. Wrap each ping in wait_for so an unresponsive
        # plugin bounds its own latency; gather with return_exceptions so a
        # single failure never crashes the sweep.
        async def _one(entry: _Entry) -> BaseException | None:
            try:
                await asyncio.wait_for(entry.client.ping(), timeout=self._ping_timeout)
            except BaseException as exc:  # noqa: BLE001 - propagate to gather sentinel
                return exc
            return None

        results = await asyncio.gather(*(_one(e) for e in live), return_exceptions=False)

        for entry, exc in zip(live, results, strict=True):
            handle = entry.handle
            if exc is None:
                entry.last_ok = self._clock()
                continue
            elapsed = self._clock() - entry.last_ok
            log.warning(
                "ping failed plugin_id=%s pid=%d elapsed=%.1fs err=%s",
                handle.plugin_id,
                handle.pid,
                elapsed,
                exc,
            )
            if elapsed >= self._timeout:
                await self._kill(handle, reason=f"heartbeat timeout ({elapsed:.1f}s)")

    async def _kill(self, handle: SubprocessHandle, *, reason: str) -> None:
        log.error("terminating plugin_id=%s pid=%d: %s", handle.plugin_id, handle.pid, reason)
        try:
            # No graceful shutdown_fn — the plugin's already unresponsive.
            await self._supervisor.terminate(handle, hard_after=0.5)
        except Exception:
            log.exception("terminate failed for pid=%d", handle.pid)
        self._entries.pop(handle.pid, None)
        if self._on_died is not None:
            try:
                result = self._on_died(handle, reason)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                log.exception("on_plugin_died callback raised")
