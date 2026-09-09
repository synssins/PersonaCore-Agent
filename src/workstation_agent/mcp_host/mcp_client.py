"""Async MCP JSON-RPC client over stdio.

Speaks line-delimited JSON-RPC 2.0 against the ``stdin`` / ``stdout`` streams
returned by :class:`workstation_agent.mcp_host.supervisor.PluginSupervisor`.

The ``mcp`` PyPI package's ``stdio_client`` was evaluated first but rejected
for SPEC-03A: it wants to spawn the subprocess itself (via ``anyio.open_process``)
and inherits ``get_default_environment()``, which bypasses both our Job Object
wrapping and our environment whitelist. Composing the two would require
monkey-patching the mcp package's internals; a ~150 LOC inline implementation
is cleaner, matches the SPEC-03A fallback allowance, and keeps the plumbing
auditable.

Supported wire methods (SPEC-03A subset):

* ``initialize`` — capability handshake.
* ``tools/list`` — enumerate tool descriptors.
* ``tools/call`` — invoke a tool by name.
* ``ping`` — custom heartbeat used by :class:`HeartbeatWatchdog`.
* ``shutdown`` — graceful termination request.
* ``notifications/*`` — async iterator surface for server-initiated events.
"""
# ruff: noqa: S101, ANN401, ASYNC109, TRY003, EM102
# S101: internal-invariant asserts (mypy narrowing) — fine in library code.
# S110: best-effort ``stream.close()`` in cleanup; already-closed pipes are
#       the norm and there is nothing meaningful to log.
# ANN401: Any is deliberate — JSON-RPC payloads are dict[str, Any] by nature.
# ASYNC109: timeout=... on our public API deliberately mirrors the MCP method
#           surface; using ``asyncio.timeout`` blocks would move the parameter
#           to the call site and lose per-request configurability.
# TRY003/EM101/EM102: error messages are short and callsite-local; splitting
#           each into a named local hurts readability without value.

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import threading
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import AsyncIterator

log = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"

# Raised from 10.0 deliberately, for three reasons that all point the same way:
#
# 1. This is the *innermost* leg of a call — host -> plugin over stdio. A tool
#    that is job-capable takes ``wait_s`` up to 25 s (contract §5.4), and the
#    plugin blocks for that long by design. At 10 s a perfectly legal
#    ``shell_run(wait_s=25)`` timed out here before the work could finish.
# 2. A confirmable condition puts a 20 s prompt in front of the call
#    (contract §7). Any path where the wait lands inside this client's budget
#    would have burned three-quarters of it before the plugin was even asked.
# 3. The core's own read timeout for an HTTP plugin is 30 s
#    (PersonaCore ``plugins/mcp_client.py:667``). Matching it means the Agent
#    does not give up before the thing waiting on the Agent does, so a slow
#    call surfaces as one timeout with one explanation rather than two.
#
# 30 s therefore sits above both the 25 s job ceiling and the 20 s confirmation
# window, and level with the core. Individual call sites still pass a shorter
# ``timeout=`` where they have a tighter budget.
_DEFAULT_TIMEOUT = 30.0


class MCPProtocolError(RuntimeError):
    """Raised on transport or JSON-RPC protocol failures."""


class MCPRemoteError(RuntimeError):
    """Raised when the server returns a JSON-RPC ``error`` object."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


class MCPStdioClient:
    """Bidirectional JSON-RPC client bound to a plugin subprocess' stdio."""

    def __init__(self, *, default_timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._stdin: IO[bytes] | None = None
        self._stdout: IO[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._id_gen = itertools.count(1)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._default_timeout = default_timeout
        self._write_lock = asyncio.Lock()

    # -- connection -----------------------------------------------------------

    async def connect(self, stdin: IO[bytes], stdout: IO[bytes]) -> None:
        """Attach to already-open pipe streams and start the reader thread."""
        if self._reader_thread is not None:
            msg = "MCPStdioClient already connected"
            raise MCPProtocolError(msg)
        self._stdin = stdin
        self._stdout = stdout
        self._loop = asyncio.get_running_loop()
        self._reader_thread = threading.Thread(
            target=self._read_forever,
            name="mcp-stdio-reader",
            daemon=True,
        )
        self._reader_thread.start()

    async def close(self) -> None:
        """Stop the reader, fail every outstanding request, close streams."""
        if self._closed:
            return
        self._closed = True
        # Closing stdout is what stops the reader: it is parked in a blocking
        # readline() and there is nothing to cancel.  Streams are closed BEFORE
        # the pending futures are failed so a line already in flight cannot
        # resolve one after it has been failed.
        for stream in (self._stdin, self._stdout):
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()
        self._fail_pending("client closed")

    # -- reader ---------------------------------------------------------------

    def _read_forever(self) -> None:
        """Blocking read loop, on a thread of its own.

        **This must not run on the default executor**, and that is the whole
        point of the method.  It used to be
        ``await loop.run_in_executor(None, self._stdout.readline)`` in a task,
        which parks one shared executor worker *for the entire life of the
        plugin* — a blocking read that never returns until the plugin says
        something is not a unit of work, it is a dedicated thread wearing a
        borrowed one.

        ``ThreadPoolExecutor``'s default size is ``min(32, cpu_count + 4)``, so
        on an 8-core machine the loop's default executor has 12 workers and the
        host could hold **at most 12 plugins open at once**.  The twelfth
        bundled plugin took the last worker; its ``initialize`` then needed a
        worker for ``stdin.write`` and queued behind twelve reads that would
        never finish, so the request never reached the child, the child sat
        waiting on stdin, and the whole start-up deadlocked.  Worse, the
        30-second request timeout did not save it: the write was queued, not
        running, and ``close()``'s ``await self._reader_task`` then waited on a
        task blocked in an uncancellable executor call.  The symptom was a
        suite that stopped dead in an unrelated test with the event loop parked
        in ``GetQueuedCompletionStatus``.

        The ceiling scaled with the machine, which is the nastiest part: a
        4-core CI box has 8 workers and would have failed with the eight
        plugins that shipped long before the twelfth arrived.
        """
        stdout = self._stdout
        loop = self._loop
        if stdout is None or loop is None:  # pragma: no cover - connect() sets both
            return
        try:
            while not self._closed:
                raw = stdout.readline()
                if not raw:
                    break
                loop.call_soon_threadsafe(self._on_line, raw)
        except Exception:
            if not self._closed:
                log.debug("MCP reader stopped on a pipe error", exc_info=True)
        finally:
            # EOF or error: fail every outstanding request, on the loop thread
            # so `_pending` is only ever touched from one thread.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self._fail_pending, "plugin stdout closed")

    def _on_line(self, raw: bytes) -> None:
        """Handle one line, on the event loop thread."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("received non-JSON line from plugin: %r", raw[:120])
            return
        self._dispatch(msg)

    def _fail_pending(self, reason: str) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(MCPProtocolError(reason))
        self._pending.clear()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        # Response
        if "id" in msg and ("result" in msg or "error" in msg):
            fut = self._pending.pop(int(msg["id"]), None)
            if fut is None or fut.done():
                return
            if "error" in msg:
                err = msg["error"]
                fut.set_exception(
                    MCPRemoteError(
                        int(err.get("code", -32000)),
                        str(err.get("message", "")),
                        err.get("data"),
                    ),
                )
            else:
                fut.set_result(msg["result"])
            return
        # Server-initiated notification
        if msg.get("method", "").startswith("notifications/") or (
            "method" in msg and "id" not in msg
        ):
            self._notifications.put_nowait(msg)
            return
        log.debug("unhandled MCP message: %r", msg)

    # -- request/notify -------------------------------------------------------

    async def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        if self._closed:
            msg = "client closed"
            raise MCPProtocolError(msg)
        assert self._stdin is not None
        req_id = next(self._id_gen)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        self._pending[req_id] = fut
        payload: dict[str, Any] = {"jsonrpc": _JSONRPC_VERSION, "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

        async with self._write_lock:
            await loop.run_in_executor(None, self._stdin.write, line)
            await loop.run_in_executor(None, self._stdin.flush)

        try:
            return await asyncio.wait_for(fut, timeout=timeout or self._default_timeout)
        except TimeoutError as exc:
            self._pending.pop(req_id, None)
            raise MCPProtocolError(f"{method} timed out") from exc
        except asyncio.CancelledError:
            self._pending.pop(req_id, None)
            raise

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self._closed:
            return
        assert self._stdin is not None
        payload: dict[str, Any] = {"jsonrpc": _JSONRPC_VERSION, "method": method}
        if params is not None:
            payload["params"] = params
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        loop = asyncio.get_running_loop()
        async with self._write_lock:
            await loop.run_in_executor(None, self._stdin.write, line)
            await loop.run_in_executor(None, self._stdin.flush)

    # -- high-level MCP methods ----------------------------------------------

    async def initialize(
        self,
        *,
        client_name: str = "workstation-agent",
        client_version: str = "0.1.0.dev0",
        protocol_version: str = "2024-11-05",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": client_version},
            },
            timeout=timeout,
        )

    async def tools_list(self, *, timeout: float | None = None) -> list[dict[str, Any]]:
        result = await self._request("tools/list", None, timeout=timeout)
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            msg = f"tools/list returned unexpected shape: {result!r}"
            raise MCPProtocolError(msg)
        return tools

    async def tools_call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "tools/call",
            {"name": tool, "arguments": args or {}},
            timeout=timeout,
        )

    async def ping(self, *, timeout: float | None = None) -> dict[str, Any]:
        return await self._request("ping", None, timeout=timeout or 5.0)

    async def shutdown(self, *, timeout: float | None = None) -> None:
        try:
            await self._request("shutdown", None, timeout=timeout or 3.0)
        except MCPProtocolError:
            # If the plugin closes stdout on shutdown we may get EOF before
            # the response; that's fine.
            log.debug("shutdown response not received cleanly")

    async def notifications(self) -> AsyncIterator[dict[str, Any]]:
        """Yield server-initiated notifications until the client is closed."""
        while not self._closed:
            try:
                msg = await asyncio.wait_for(self._notifications.get(), timeout=0.5)
            except TimeoutError:
                if self._closed:
                    return
                continue
            yield msg
