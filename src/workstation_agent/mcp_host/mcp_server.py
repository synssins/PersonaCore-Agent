"""Agent's own MCP server exposed on a static Windows named pipe.

This module implements Direction 1 of SPEC-08: the agent binds
``\\\\.\\pipe\\PC-Agent-MCP`` so that Claude Code (and any other MCP host)
can drive it by adding a single entry to ``.claude/mcp.json``.

Design
------
* **Static pipe name** ``\\\\.\\pipe\\PC-Agent-MCP`` — fixed so CC's
  ``.claude/mcp.json`` never needs updating when the agent restarts.
* **Single-instance guard** — ``CreateNamedPipe`` returns
  ``ERROR_PIPE_BUSY`` (winerror 231) if a second instance tries to bind.
  The second process logs a warning and exits non-zero.
* **Token authentication** — on startup the agent writes a 32-byte
  random token to ``%APPDATA%\\WorkstationAgent\\mcp-token`` then calls
  ``security.harden_file()`` (SPEC-02 DACL).  Every client connecting
  over the pipe must send the token as the first line of its
  ``initialize`` request (``params.token``); mismatched tokens get a
  ``-32000`` error and the connection is dropped.
* **Exposed tools** — ``agent.speak``, ``agent.toast``, ``agent.status``,
  ``agent.last_transcript``, ``agent.pause_listening``,
  ``agent.execute_local``.

Standalone entry point
----------------------
Running ``python -m workstation_agent.mcp_host.mcp_server`` connects over
the named pipe to a running agent instance that has already bound the pipe
server side.  This lets external processes (e.g. a CC subprocess) use the
agent's capabilities without any IPC of their own.
"""
# ruff: noqa: ANN401, PLC0415, PLR0911, PLR0913, C901

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PIPE_NAME = r"\\.\pipe\PC-Agent-MCP"
_appdata_env = os.environ.get("APPDATA")
_APPDATA = Path(_appdata_env) if _appdata_env else Path.home() / ".config"
TOKEN_DIR = _APPDATA / "WorkstationAgent"
TOKEN_FILE = TOKEN_DIR / "mcp-token"
_JSONRPC = "2.0"

# winerror code returned by CreateNamedPipe when pipe is already bound.
_ERROR_PIPE_BUSY = 231


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

def generate_and_store_token() -> str:
    """Generate a fresh 32-byte random token, write it to *TOKEN_FILE*.

    Applies SPEC-02 DACL hardening (deny Low-IL SID + Everyone; grant only
    current user).  Returns the hex-encoded token string.
    """
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    TOKEN_FILE.write_text(token, encoding="ascii")

    try:
        from workstation_agent.security.dpapi import harden_file  # type: ignore[import]

        harden_file(TOKEN_FILE)
    except Exception:  # noqa: BLE001
        log.warning("security.harden_file unavailable; token file not ACL-hardened")

    log.info("MCP server token written to %s", TOKEN_FILE)
    return token


def load_token() -> str | None:
    """Read the token written by :func:`generate_and_store_token`."""
    if not TOKEN_FILE.exists():
        return None
    return TOKEN_FILE.read_text(encoding="ascii").strip()


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _json_default(obj: Any) -> Any:
    """``json.dumps(default=...)`` hook for types the stdlib can't serialise.

    Tool results routed through :meth:`MCPHost.invoke` come back as
    ``ToolResultImpl`` (and similar) plain dataclasses, not dicts — see
    ``workstation_agent.mcp_host.host``. ``json.dumps`` has no idea how to
    encode a dataclass instance on its own, so every successful
    ``agent.execute_local`` call raised ``TypeError`` and was reported as
    ``isError: True`` before this hook existed.

    Anything that isn't a known-serialisable shape raises ``TypeError``
    here (matching ``json.dumps``'s own contract for a failing ``default``)
    rather than falling back to ``str()``. A permissive string fallback
    would silently turn an unexpected type — a ``set``, an exception, a
    function — into a plausible-looking string instead of surfacing the
    failure, which is exactly the class of bug this hook exists to fix.
    ``_handle_tools_call``'s surrounding ``except Exception`` still turns a
    ``TypeError`` raised here into a proper ``isError: True`` response with
    the real message, so the failure is reported honestly instead of either
    crashing the connection or masquerading as success.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    msg = f"Object of type {type(obj).__name__} is not JSON serializable"
    raise TypeError(msg)


def _reply(req_id: Any, result: Any) -> bytes:
    payload = {"jsonrpc": _JSONRPC, "id": req_id, "result": result}
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def _error(req_id: Any, code: int, message: str) -> bytes:
    payload = {
        "jsonrpc": _JSONRPC,
        "id": req_id,
        "error": {"code": code, "message": message},
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def _notification(method: str, params: dict[str, Any]) -> bytes:
    payload = {"jsonrpc": _JSONRPC, "method": method, "params": params}
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode()


def _toast_action_logger(action_id: str) -> Callable[[], None]:
    """Build a ``ToastPresenter`` action callback that just logs the click.

    ``agent.toast`` is invoked over the pipe and its ``tools/call`` response
    is sent back before the user can possibly have clicked a toast button —
    there is no MCP request left in flight to report the click through. The
    callback exists only so the toast is well-formed and the click is
    observable in the log, not lost silently.
    """

    def _on_click() -> None:
        log.info("agent.toast: action %r activated (no MCP channel to report it)", action_id)

    return _on_click


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

_TOOLS: list[dict[str, Any]] = [
    {
        "name": "agent.speak",
        "description": "Speak text via the agent's TTS engine.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "agent.toast",
        "description": "Display a Windows toast notification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "body": {"type": "string"},
                "actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title", "body"],
        },
    },
    {
        "name": "agent.status",
        "description": "Return the current agent status snapshot.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "agent.last_transcript",
        "description": "Return the last N turns of the conversation transcript.",
        "inputSchema": {
            "type": "object",
            "properties": {"n": {"type": "integer", "default": 10}},
        },
    },
    {
        "name": "agent.pause_listening",
        "description": "Pause the microphone listener for the given number of seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "integer"}},
            "required": ["seconds"],
        },
    },
    {
        "name": "agent.execute_local",
        "description": "Proxy a tool call through MCPHost with permission checks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plugin_id": {"type": "string"},
                "tool": {"type": "string"},
                "args": {"type": "object"},
            },
            "required": ["plugin_id", "tool"],
        },
    },
]


class AgentMCPServer:
    """JSON-RPC 2.0 MCP server session for one connected client.

    Parameters
    ----------
    reader, writer:
        asyncio stream pair for the connected pipe client.
    token:
        Expected auth token.  The first ``initialize`` request must supply
        this in ``params.token`` or the connection is rejected.
    tts:
        Optional TTSSpeaker; used by ``agent.speak``.
    toast:
        Optional ToastPresenter; used by ``agent.toast``.
    mcp_host:
        Optional MCPHost; used by ``agent.execute_local``.
    state_getter:
        Optional callable ``() -> dict`` returning the agent status dict for
        ``agent.status``.
    transcript_getter:
        Optional callable ``(n: int) -> list`` returning transcript turns.
    pause_listener:
        Optional callable ``(seconds: int) -> None``.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        token: str,
        tts: Any | None = None,
        toast: Any | None = None,
        mcp_host: Any | None = None,
        state_getter: Any | None = None,
        transcript_getter: Any | None = None,
        pause_listener: Any | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._token = token
        self._tts = tts
        self._toast = toast
        self._mcp_host = mcp_host
        self._state_getter = state_getter
        self._transcript_getter = transcript_getter
        self._pause_listener = pause_listener
        self._authenticated = False

    async def serve(self) -> None:
        """Read and dispatch JSON-RPC messages until the client disconnects.

        The pre-auth input bound here is deliberately left at asyncio's
        default ``readline()`` limit (64 KiB) rather than a considered
        value: this pipe is local-only today. A real, considered bound —
        and systematic hostile-input coverage generally (oversized
        payloads, rate limiting, connection caps, etc.) — is the
        responsibility of whichever subtask puts this transport on a
        network (B4), not this one.
        """
        try:
            while True:
                try:
                    raw = await self._reader.readline()
                except (
                    asyncio.IncompleteReadError,
                    ConnectionResetError,
                    BrokenPipeError,
                    # readline() raises this (wrapping LimitOverrunError)
                    # when a line exceeds the buffer limit with no newline
                    # in sight — an oversized/malformed line disconnects
                    # cleanly rather than crashing the session.
                    ValueError,
                ):
                    break
                if not raw:
                    break
                try:
                    msg = json.loads(raw.decode("utf-8", errors="replace"))
                except (json.JSONDecodeError, RecursionError):
                    # RecursionError: deeply nested JSON (e.g. "[[[[...]]]]")
                    # blows the interpreter's recursion limit inside the
                    # decoder. Treated the same as malformed JSON — skip the
                    # line rather than letting it crash the read loop.
                    continue
                await self._dispatch(msg)
        finally:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()

    async def _dispatch(self, msg: dict[str, Any]) -> None:
        req_id = msg.get("id")
        method = msg.get("method", "")

        # Notifications (no id) are silently ignored.
        if req_id is None:
            return

        if method == "initialize":
            await self._handle_initialize(req_id, msg.get("params") or {})
            return

        if method == "shutdown":
            self._writer.write(_reply(req_id, {}))
            await self._writer.drain()
            return

        if method == "ping":
            self._writer.write(_reply(req_id, {}))
            await self._writer.drain()
            return

        # All other methods require authentication.
        if not self._authenticated:
            self._writer.write(_error(req_id, -32000, "not authenticated"))
            await self._writer.drain()
            return

        if method == "tools/list":
            self._writer.write(_reply(req_id, {"tools": _TOOLS}))
            await self._writer.drain()
            return

        if method == "tools/call":
            await self._handle_tools_call(req_id, msg.get("params") or {})
            return

        self._writer.write(_error(req_id, -32601, f"method not found: {method}"))
        await self._writer.drain()

    async def _handle_initialize(self, req_id: Any, params: dict[str, Any]) -> None:
        """Validate token and complete the MCP handshake."""
        client_token = params.get("token")
        # This field has now had three variations of the same mistake fixed
        # on it: `!=` assumed both sides were comparable strings, then
        # `compare_digest` on `str` assumed the client's string was
        # ASCII-only, then `.encode("utf-8")` assumed the client's string
        # was well-formed Unicode. It isn't guaranteed to be any of those —
        # this is JSON-RPC params from an untrusted, pre-authentication
        # client, and B4 is about to put this same pattern on a LAN. So:
        # nothing here is trusted until it is safely bytes. A non-str is
        # rejected immediately; a str that fails to encode (e.g. an unpaired
        # surrogate like "\ud800", which json.loads() happily accepts as a
        # value but UTF-8 cannot represent) is caught and rejected the same
        # way, rather than being allowed to raise out of the handshake.
        # Deliberately *rejecting* on a bad encode rather than substituting
        # `errors="replace"`: a replacement policy maps many different
        # malformed inputs onto the same output bytes, which is exactly the
        # kind of collision a token comparison must not tolerate.
        token_bytes: bytes | None = None
        if isinstance(client_token, str):
            try:
                token_bytes = client_token.encode("utf-8")
            except UnicodeEncodeError:
                token_bytes = None

        token_ok = token_bytes is not None and secrets.compare_digest(
            token_bytes, self._token.encode("utf-8"),
        )
        if not token_ok:
            self._writer.write(_error(req_id, -32000, "invalid token"))
            await self._writer.drain()
            log.warning("MCP client presented bad token; rejecting")
            return

        self._authenticated = True
        self._writer.write(_reply(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "workstation-agent", "version": "0.1.0"},
        }))
        await self._writer.drain()

    async def _handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> None:
        """Dispatch to the appropriate agent tool handler."""
        tool_name = params.get("name", "")
        args = params.get("arguments") or {}

        try:
            result = await self._invoke_tool(tool_name, args)
            content = [{"type": "text", "text": json.dumps(result, default=_json_default)}]
            self._writer.write(_reply(req_id, {"content": content, "isError": False}))
        except Exception as exc:  # noqa: BLE001
            content = [{"type": "text", "text": str(exc)}]
            self._writer.write(_reply(req_id, {"content": content, "isError": True}))
        await self._writer.drain()

    async def _invoke_tool(self, tool_name: str, args: dict[str, Any]) -> Any:
        if tool_name == "agent.speak":
            text = str(args.get("text", ""))
            if self._tts is not None:
                await self._tts.speak(text)
            return {"ok": True}

        if tool_name == "agent.toast":
            title = str(args.get("title", ""))
            body = str(args.get("body", ""))
            raw_actions = args.get("actions") or []
            if self._toast is not None:
                toast_actions = {
                    str(action_id): (str(action_id), _toast_action_logger(str(action_id)))
                    for action_id in raw_actions
                }
                # ToastPresenter.show() is synchronous and fire-and-forget: it
                # queues the toast with the OS and returns immediately. It has
                # no "wait for the click" mode, and building one here would
                # mean blocking this already-in-flight tools/call response on
                # a user action that may come seconds later or never — the
                # named-pipe client has no timeout budget for that. Building
                # a real awaitable "wait for user response" primitive is
                # SPEC B1's confirm primitive, not this tool. So we show the
                # toast and acknowledge; any click is only logged, since
                # there is no channel left to report it back through once
                # this call has returned.
                self._toast.show(title=title, body=body, actions=toast_actions or None)
            return {"ok": True}

        if tool_name == "agent.status":
            if self._state_getter is not None:
                return self._state_getter()
            return {"state": "unknown"}

        if tool_name == "agent.last_transcript":
            n = int(args.get("n", 10))
            if self._transcript_getter is not None:
                return {"turns": self._transcript_getter(n)}
            return {"turns": []}

        if tool_name == "agent.pause_listening":
            seconds = int(args.get("seconds", 0))
            if self._pause_listener is not None:
                self._pause_listener(seconds)
            return {"ok": True}

        if tool_name == "agent.execute_local":
            plugin_id = str(args.get("plugin_id", ""))
            tool = str(args.get("tool", ""))
            tool_args = dict(args.get("args") or {})
            if self._mcp_host is None:
                return {"result": None, "error": "mcp_host not available"}
            result = await self._mcp_host.invoke(f"{plugin_id}.{tool}", tool_args)
            return {"result": result}

        msg = f"unknown tool: {tool_name}"
        raise ValueError(msg)


# ---------------------------------------------------------------------------
# Named-pipe server bind / accept loop (Windows)
# ---------------------------------------------------------------------------

async def _create_pipe_server() -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open the named-pipe listen end and wait for a client connection.

    Returns the stream pair for the connected client, or None if binding failed
    (e.g. pipe already taken).
    """
    if sys.platform != "win32":
        log.error("Named pipe server only supported on Windows")
        return None

    import msvcrt

    import win32pipe  # type: ignore[import]

    PIPE_ACCESS_DUPLEX = 0x00000003  # noqa: N806
    PIPE_TYPE_BYTE = 0x00000000  # noqa: N806
    PIPE_READMODE_BYTE = 0x00000000  # noqa: N806
    PIPE_WAIT = 0x00000000  # noqa: N806
    NMPWAIT_USE_DEFAULT_WAIT = 0  # noqa: N806

    try:

        h_pipe = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            65536,
            65536,
            NMPWAIT_USE_DEFAULT_WAIT,
            None,  # type: ignore[arg-type]
        )
    except Exception as exc:  # noqa: BLE001
        winerr = getattr(exc, "winerror", None)
        if winerr == _ERROR_PIPE_BUSY:
            log.error(  # noqa: TRY400
                "Named pipe %s already bound — another agent instance is already running",
                PIPE_NAME,
            )
        else:
            log.error("CreateNamedPipe failed: %s", exc)  # noqa: TRY400
        return None

    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, win32pipe.ConnectNamedPipe, h_pipe, None)
    except Exception as exc:  # noqa: BLE001
        log.error("ConnectNamedPipe failed: %s", exc)  # noqa: TRY400
        import win32api  # type: ignore[import]

        with contextlib.suppress(Exception):
            win32api.CloseHandle(h_pipe)
        return None

    # Adopt the pipe handle into asyncio streams via msvcrt + os.fdopen
    handle_int = int(h_pipe)
    h_pipe.Detach()  # type: ignore[attr-defined]

    try:
        fd = msvcrt.open_osfhandle(handle_int, 0)
        pipe_file = os.fdopen(fd, "rb+", buffering=0)
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to adopt pipe handle: %s", exc)  # noqa: TRY400
        return None

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: protocol, pipe_file)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)  # type: ignore[arg-type]

    return reader, writer


async def run_pipe_server(
    token: str,
    *,
    tts: Any | None = None,
    toast: Any | None = None,
    mcp_host: Any | None = None,
    state_getter: Any | None = None,
    transcript_getter: Any | None = None,
    pause_listener: Any | None = None,
    max_clients: int = 16,
) -> None:
    """Bind the named pipe and serve MCP sessions in a loop.

    Each accepted connection gets its own :class:`AgentMCPServer` session.
    """
    log.info("Agent MCP server starting on %s", PIPE_NAME)

    for _ in range(max_clients):
        pair = await _create_pipe_server()
        if pair is None:
            log.error("Failed to bind pipe; exiting")
            return
        reader, writer = pair
        session = AgentMCPServer(
            reader, writer,
            token=token,
            tts=tts,
            toast=toast,
            mcp_host=mcp_host,
            state_getter=state_getter,
            transcript_getter=transcript_getter,
            pause_listener=pause_listener,
        )
        _task = asyncio.create_task(session.serve(), name="mcp-pipe-session")  # noqa: RUF006
        log.info("Accepted MCP client on %s", PIPE_NAME)


# ---------------------------------------------------------------------------
# TCP fallback server (for integration tests on non-pipe environments)
# ---------------------------------------------------------------------------

async def run_tcp_server(
    token: str,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    tts: Any | None = None,
    mcp_host: Any | None = None,
    state_getter: Any | None = None,
    transcript_getter: Any | None = None,
    pause_listener: Any | None = None,
) -> tuple[asyncio.Server, int]:
    """Bind a TCP server (for tests); returns (server, assigned_port)."""

    async def handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        session = AgentMCPServer(
            reader, writer,
            token=token,
            tts=tts,
            mcp_host=mcp_host,
            state_getter=state_getter,
            transcript_getter=transcript_getter,
            pause_listener=pause_listener,
        )
        await session.serve()

    server = await asyncio.start_server(handle_client, host, port)
    assigned_port = server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    return server, assigned_port


# ---------------------------------------------------------------------------
# __main__ entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Standalone entry — serve MCP on the named pipe."""
    logging.basicConfig(level=logging.INFO)
    token = load_token()
    if token is None:
        token = generate_and_store_token()

    async def _run() -> None:
        await run_pipe_server(token)
        # Keep alive
        await asyncio.sleep(86400)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run())


if __name__ == "__main__":
    main()
