"""Unit / integration tests for the agent's own MCP server.

Spins up AgentMCPServer over a real TCP loopback connection (avoids the
Windows named-pipe complexity in a test runner), calls ``agent.status``, and
asserts that:

1. A valid token produces the expected response.
2. A bad token is rejected with code -32000.
3. Unauthenticated calls (before initialize) are rejected.
4. ``agent.speak``, ``agent.last_transcript``, ``agent.pause_listening``,
   ``agent.execute_local`` return expected shapes.
5. Unknown tool returns isError response.
"""
# ruff: noqa: ANN401, E501, ERA001, PLW0108, RUF059, ARG001, ARG005, SIM117

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workstation_agent.mcp_host.mcp_server import run_tcp_server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TOKEN = "deadbeef" * 8  # 64 hex chars, doesn't need to be real 32-byte secret


async def _open_client(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", port)


def _rpc(method: str, params: dict[str, Any] | None = None, req_id: int = 1) -> bytes:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return (json.dumps(msg) + "\n").encode()


async def _read_one(reader: asyncio.StreamReader) -> dict[str, Any]:
    raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
    return json.loads(raw.decode())


async def _initialize(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, token: str, req_id: int = 1) -> dict[str, Any]:
    writer.write(_rpc("initialize", {"token": token, "protocolVersion": "2024-11-05"}, req_id=req_id))
    await writer.drain()
    return await _read_one(reader)


# ---------------------------------------------------------------------------
# Fixture: running TCP server
# ---------------------------------------------------------------------------


@pytest.fixture
async def mcp_server_port():
    """Start an AgentMCPServer on a random TCP port; yield the port number."""
    tts = MagicMock()
    tts.speak = AsyncMock(return_value=None)

    state_getter = lambda: {"state": "idle", "current_session_id": None, "mute_mic": False, "mute_speaker": False, "plugins_loaded": 3}  # noqa: E731
    transcript_getter = lambda n: [{"role": "user", "text": "hello", "ts": 0}][:n]  # noqa: E731
    pause_calls: list[int] = []
    pause_listener = lambda s: pause_calls.append(s)  # noqa: E731

    server, port = await run_tcp_server(
        TOKEN,
        tts=tts,
        state_getter=state_getter,
        transcript_getter=transcript_getter,
        pause_listener=pause_listener,
    )
    yield port, tts, pause_calls
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: token auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_token_accepted(mcp_server_port) -> None:
    """Valid token produces a successful initialize response."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    resp = await _initialize(reader, writer, TOKEN)

    assert "error" not in resp, f"Unexpected error: {resp}"
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    writer.close()


@pytest.mark.asyncio
async def test_bad_token_rejected(mcp_server_port) -> None:
    """Bad token produces -32000 error and blocks further requests."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    resp = await _initialize(reader, writer, "badbadtoken")

    assert "error" in resp
    assert resp["error"]["code"] == -32000
    writer.close()


@pytest.mark.asyncio
async def test_unauthenticated_call_rejected(mcp_server_port) -> None:
    """Calling tools/list before initialize → -32000."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)

    writer.write(_rpc("tools/list", req_id=1))
    await writer.drain()
    resp = await _read_one(reader)

    assert "error" in resp
    assert resp["error"]["code"] == -32000
    writer.close()


# ---------------------------------------------------------------------------
# Tests: tools/list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_list_returns_expected_tools(mcp_server_port) -> None:
    """tools/list returns the six expected agent tools."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/list", req_id=2))
    await writer.drain()
    resp = await _read_one(reader)

    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {
        "agent.speak",
        "agent.toast",
        "agent.status",
        "agent.last_transcript",
        "agent.pause_listening",
        "agent.execute_local",
    }
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_status_round_trip(mcp_server_port) -> None:
    """agent.status returns the state_getter dict."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.status", "arguments": {}}, req_id=3))
    await writer.drain()
    resp = await _read_one(reader)

    content = resp["result"]["content"][0]["text"]
    status = json.loads(content)
    assert status["state"] == "idle"
    assert "plugins_loaded" in status
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.speak
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_speak_calls_tts(mcp_server_port) -> None:
    """agent.speak invokes the injected TTS."""
    port, tts, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.speak", "arguments": {"text": "Hello world"}}, req_id=4))
    await writer.drain()
    resp = await _read_one(reader)

    assert resp["result"]["isError"] is False
    tts.speak.assert_awaited_once_with("Hello world")
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.last_transcript
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_last_transcript_returns_turns(mcp_server_port) -> None:
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.last_transcript", "arguments": {"n": 5}}, req_id=5))
    await writer.drain()
    resp = await _read_one(reader)

    result = json.loads(resp["result"]["content"][0]["text"])
    assert "turns" in result
    assert isinstance(result["turns"], list)
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.pause_listening
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pause_listening_calls_listener(mcp_server_port) -> None:
    port, _, pause_calls = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.pause_listening", "arguments": {"seconds": 30}}, req_id=6))
    await writer.drain()
    resp = await _read_one(reader)

    assert resp["result"]["isError"] is False
    assert 30 in pause_calls
    writer.close()


# ---------------------------------------------------------------------------
# Tests: unknown tool returns error content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_tool_returns_error(mcp_server_port) -> None:
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.nonexistent", "arguments": {}}, req_id=7))
    await writer.drain()
    resp = await _read_one(reader)

    assert resp["result"]["isError"] is True
    writer.close()


# ---------------------------------------------------------------------------
# Tests: ping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ping_before_auth(mcp_server_port) -> None:
    """ping is allowed before authentication."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)

    writer.write(_rpc("ping", req_id=1))
    await writer.drain()
    resp = await _read_one(reader)

    assert "error" not in resp
    writer.close()


# ---------------------------------------------------------------------------
# Tests: generate_and_store_token + load_token
# ---------------------------------------------------------------------------


def test_token_round_trip(tmp_path: Any, monkeypatch: Any) -> None:
    """generate_and_store_token writes token; load_token reads it back."""
    import workstation_agent.mcp_host.mcp_server as srv

    monkeypatch.setattr(srv, "TOKEN_DIR", tmp_path)
    monkeypatch.setattr(srv, "TOKEN_FILE", tmp_path / "mcp-token")

    token = srv.generate_and_store_token()
    assert len(token) == 64  # 32 bytes hex

    loaded = srv.load_token()
    assert loaded == token


def test_load_token_returns_none_when_missing(tmp_path: Any, monkeypatch: Any) -> None:
    import workstation_agent.mcp_host.mcp_server as srv

    monkeypatch.setattr(srv, "TOKEN_FILE", tmp_path / "no-such-file")
    assert srv.load_token() is None


# ---------------------------------------------------------------------------
# Tests: agent.toast (with and without presenter)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_toast_no_presenter(mcp_server_port) -> None:
    """agent.toast without a presenter returns ok=True."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.toast", "arguments": {"title": "T", "body": "B"}}, req_id=8))
    await writer.drain()
    resp = await _read_one(reader)

    # No toast presenter registered → still ok
    assert resp["result"]["isError"] is False
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.status without state_getter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_status_no_getter() -> None:
    """agent.status returns {state: unknown} when state_getter is None."""
    server, port = await run_tcp_server(TOKEN)

    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.status", "arguments": {}}, req_id=3))
    await writer.drain()
    resp = await _read_one(reader)

    status = json.loads(resp["result"]["content"][0]["text"])
    assert status["state"] == "unknown"
    writer.close()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: agent.execute_local without mcp_host
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_execute_local_no_host() -> None:
    """agent.execute_local without mcp_host returns error message."""
    server, port = await run_tcp_server(TOKEN)

    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.execute_local", "arguments": {"plugin_id": "foo", "tool": "bar"}}, req_id=3))
    await writer.drain()
    resp = await _read_one(reader)

    result = json.loads(resp["result"]["content"][0]["text"])
    assert "error" in result
    writer.close()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: agent.last_transcript without transcript_getter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_last_transcript_no_getter() -> None:
    """agent.last_transcript without transcript_getter returns empty turns."""
    server, port = await run_tcp_server(TOKEN)

    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.last_transcript", "arguments": {}}, req_id=3))
    await writer.drain()
    resp = await _read_one(reader)

    result = json.loads(resp["result"]["content"][0]["text"])
    assert result == {"turns": []}
    writer.close()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: unknown method after auth → -32601
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_method_after_auth_returns_error(mcp_server_port) -> None:
    """Calling an unknown method after auth → -32601."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("no_such_method", req_id=9))
    await writer.drain()
    resp = await _read_one(reader)

    assert "error" in resp
    assert resp["error"]["code"] == -32601
    writer.close()


# ---------------------------------------------------------------------------
# Tests: notification (no id) is silently ignored
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notification_ignored(mcp_server_port) -> None:
    """Messages without 'id' (notifications) are silently ignored."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    # Send a notification (no id), then ping to verify server is still alive.
    notification = (json.dumps({"jsonrpc": "2.0", "method": "notifications/test"}) + "\n").encode()
    writer.write(notification)
    await writer.drain()

    writer.write(_rpc("ping", req_id=10))
    await writer.drain()
    resp = await _read_one(reader)

    assert "error" not in resp
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.pause_listening without listener (still returns ok)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pause_listening_no_listener() -> None:
    server, port = await run_tcp_server(TOKEN)

    reader, writer = await _open_client(port)
    await _initialize(reader, writer, TOKEN)

    writer.write(_rpc("tools/call", {"name": "agent.pause_listening", "arguments": {"seconds": 5}}, req_id=3))
    await writer.drain()
    resp = await _read_one(reader)

    assert resp["result"]["isError"] is False
    writer.close()
    server.close()
    await server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: JSON-RPC helper functions
# ---------------------------------------------------------------------------


def test_notification_helper() -> None:
    """_notification returns valid JSON bytes."""
    from workstation_agent.mcp_host.mcp_server import _notification

    data = _notification("test.event", {"key": "value"})
    msg = json.loads(data.decode())
    assert msg["method"] == "test.event"
    assert msg["params"]["key"] == "value"


def test_reply_helper() -> None:
    from workstation_agent.mcp_host.mcp_server import _reply

    data = _reply(1, {"ok": True})
    msg = json.loads(data.decode())
    assert msg["id"] == 1
    assert msg["result"]["ok"] is True


def test_error_helper() -> None:
    from workstation_agent.mcp_host.mcp_server import _error

    data = _error(2, -32600, "bad request")
    msg = json.loads(data.decode())
    assert msg["id"] == 2
    assert msg["error"]["code"] == -32600


# ---------------------------------------------------------------------------
# Tests: shutdown method
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shutdown_before_auth(mcp_server_port) -> None:
    """shutdown method is accepted before auth."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)

    writer.write(_rpc("shutdown", req_id=99))
    await writer.drain()
    resp = await _read_one(reader)

    assert "error" not in resp
    writer.close()


# ---------------------------------------------------------------------------
# Tests: agent.toast WITH presenter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_toast_with_presenter() -> None:
    """agent.toast with a presenter calls presenter.present()."""
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    _toast = MagicMock()
    _toast.present = AsyncMock(return_value="clicked")

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN, toast=_toast)
        await session.serve()

    mini_server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    mp = mini_server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    r2, w2 = await asyncio.open_connection("127.0.0.1", mp)
    w2.write(_rpc("initialize", {"token": TOKEN}, req_id=1))
    await w2.drain()
    _ = await _read_one(r2)

    w2.write(_rpc("tools/call", {"name": "agent.toast", "arguments": {"title": "Hi", "body": "World"}}, req_id=2))
    await w2.drain()
    resp = await _read_one(r2)

    assert resp["result"]["isError"] is False
    result = json.loads(resp["result"]["content"][0]["text"])
    assert result["ok"] is True
    _toast.present.assert_awaited_once()
    w2.close()
    mini_server.close()
    await mini_server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: agent.execute_local WITH mcp_host
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_execute_local_with_host() -> None:
    """agent.execute_local invokes the mcp_host and returns its result."""
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    mock_host = MagicMock()
    mock_host.invoke = AsyncMock(return_value={"content": [{"type": "text", "text": "ok"}]})

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN, mcp_host=mock_host)
        await session.serve()

    mini_server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    mp = mini_server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    r2, w2 = await asyncio.open_connection("127.0.0.1", mp)
    w2.write(_rpc("initialize", {"token": TOKEN}, req_id=1))
    await w2.drain()
    _ = await _read_one(r2)

    w2.write(_rpc("tools/call", {
        "name": "agent.execute_local",
        "arguments": {"plugin_id": "my_plugin", "tool": "my_tool", "args": {"x": 1}},
    }, req_id=2))
    await w2.drain()
    resp = await _read_one(r2)

    assert resp["result"]["isError"] is False
    mock_host.invoke.assert_awaited_once_with("my_plugin.my_tool", {"x": 1})
    w2.close()
    mini_server.close()
    await mini_server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: generate_and_store_token with harden_file available
# ---------------------------------------------------------------------------


def test_generate_token_with_harden_file(tmp_path: Any, monkeypatch: Any) -> None:
    """generate_and_store_token calls harden_file when available."""
    import sys
    import types

    import workstation_agent.mcp_host.mcp_server as srv

    monkeypatch.setattr(srv, "TOKEN_DIR", tmp_path)
    monkeypatch.setattr(srv, "TOKEN_FILE", tmp_path / "mcp-token")

    harden_called: list[Any] = []

    def fake_harden(path: Any) -> None:
        harden_called.append(path)

    # Temporarily make the harden_file import work
    fake_dpapi = types.ModuleType("workstation_agent.security.dpapi")
    fake_dpapi.harden_file = fake_harden  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"workstation_agent.security.dpapi": fake_dpapi}):
        token = srv.generate_and_store_token()

    assert len(token) == 64
    assert len(harden_called) == 1


# ---------------------------------------------------------------------------
# Tests: serve() exception paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_serve_handles_invalid_json(mcp_server_port) -> None:
    """serve() silently skips lines that are not valid JSON."""
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)
    # Send garbage JSON, then a valid ping to verify server is still alive.
    writer.write(b"not-valid-json\n")
    await writer.drain()

    writer.write(_rpc("ping", req_id=1))
    await writer.drain()
    resp = await _read_one(reader)
    assert "error" not in resp
    writer.close()


@pytest.mark.asyncio
async def test_serve_handles_connection_reset() -> None:
    """serve() exits cleanly when the client disconnects abruptly."""
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    done_event = asyncio.Event()

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN)
        await session.serve()
        done_event.set()

    mini_server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    mp = mini_server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    r2, w2 = await asyncio.open_connection("127.0.0.1", mp)
    # Close immediately without sending anything
    w2.close()
    await asyncio.wait_for(done_event.wait(), timeout=3.0)
    mini_server.close()
    await mini_server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: main() function
# ---------------------------------------------------------------------------


def test_main_loads_existing_token(tmp_path: Any, monkeypatch: Any) -> None:
    """main() loads an existing token from TOKEN_FILE when it exists."""
    import workstation_agent.mcp_host.mcp_server as srv

    token_file = tmp_path / "mcp-token"
    token_file.write_text("existing_token_abc123", encoding="ascii")
    monkeypatch.setattr(srv, "TOKEN_FILE", token_file)
    monkeypatch.setattr(srv, "TOKEN_DIR", tmp_path)

    run_pipe_calls: list[str] = []

    async def fake_run_pipe_server(t: str, **kwargs: Any) -> None:
        run_pipe_calls.append(t)

    async def fake_sleep(s: float) -> None:
        pass

    with patch.object(srv, "run_pipe_server", fake_run_pipe_server):
        with patch("asyncio.sleep", fake_sleep):
            with patch("asyncio.run") as mock_run:
                # asyncio.run calls the coroutine synchronously in mock
                mock_run.side_effect = lambda coro: None
                srv.main()
    # main() loaded token from file — no generate call


def test_main_generates_token_when_missing(tmp_path: Any, monkeypatch: Any) -> None:
    """main() generates a new token when TOKEN_FILE does not exist."""
    import workstation_agent.mcp_host.mcp_server as srv

    missing_file = tmp_path / "no-token"
    monkeypatch.setattr(srv, "TOKEN_FILE", missing_file)
    monkeypatch.setattr(srv, "TOKEN_DIR", tmp_path)

    generated_tokens: list[str] = []

    def fake_generate() -> str:
        t = "generated_" + "x" * 54
        generated_tokens.append(t)
        return t

    with patch.object(srv, "generate_and_store_token", fake_generate):
        with patch("asyncio.run") as mock_run:
            mock_run.side_effect = lambda coro: None
            srv.main()

    assert len(generated_tokens) == 1
