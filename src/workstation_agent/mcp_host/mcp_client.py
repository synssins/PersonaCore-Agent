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
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import AsyncIterator

log = logging.getLogger(__name__)

_JSONRPC_VERSION = "2.0"
_DEFAULT_TIMEOUT = 10.0


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
        self._reader_task: asyncio.Task[None] | None = None
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._id_gen = itertools.count(1)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._default_timeout = default_timeout
        self._write_lock = asyncio.Lock()

    # -- connection -----------------------------------------------------------

    async def connect(self, stdin: IO[bytes], stdout: IO[bytes]) -> None:
        """Attach to already-open pipe streams and start the reader task."""
        if self._reader_task is not None:
            msg = "MCPStdioClient already connected"
            raise MCPProtocolError(msg)
        self._stdin = stdin
        self._stdout = stdout
        self._loop = asyncio.get_running_loop()
        self._reader_task = asyncio.create_task(self._reader(), name="mcp-stdio-reader")

    async def close(self) -> None:
        """Cancel the reader, fail every outstanding request, close streams."""
        if self._closed:
            return
        self._closed = True
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(MCPProtocolError("client closed"))
        self._pending.clear()
        for stream in (self._stdin, self._stdout):
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()

    # -- reader ---------------------------------------------------------------

    async def _reader(self) -> None:
        assert self._stdout is not None
        loop = asyncio.get_running_loop()
        try:
            while True:
                raw = await loop.run_in_executor(None, self._stdout.readline)
                if not raw:
                    break
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning("received non-JSON line from plugin: %r", raw[:120])
                    continue
                self._dispatch(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("MCP reader crashed")
        finally:
            # EOF or error: fail every outstanding request.
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(MCPProtocolError("plugin stdout closed"))
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
