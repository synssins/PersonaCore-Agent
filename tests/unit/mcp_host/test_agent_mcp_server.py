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
import contextlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from workstation_agent.mcp_host.host import ToolResultImpl
from workstation_agent.mcp_host.mcp_server import run_tcp_server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TOKEN = "deadbeef" * 8  # 64 hex chars, doesn't need to be real 32-byte secret


class FakeToastPresenter:
    """A fake matching :class:`ToastPresenter`'s ACTUAL public signature.

    Deliberately NOT a ``MagicMock``: a ``MagicMock`` accepts any method
    name (``.present(...)``, ``.pop(...)``, anything) and any signature, so
    it would happily "succeed" against code calling a method that does not
    exist on the real ``ToastPresenter``. This fake only has ``show()``,
    keyword-only, matching ``toast.py``'s real signature exactly — calling
    ``.present(...)`` on it raises ``AttributeError`` just like it would on
    the real presenter, which is the whole point.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def show(
        self,
        *,
        title: str,
        body: str,
        actions: dict[str, tuple[str, Any]] | None = None,
    ) -> None:
        self.calls.append({"title": title, "body": body, "actions": actions})


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


# ---------------------------------------------------------------------------
# Tests: the "token" field is hostile input — sweep the space, not one case
#
# This one field has had three variations of the same mistake fixed on it in
# successive review rounds: `!=` assumed both sides were comparable strings,
# then `compare_digest` on plain `str` assumed the client's string was
# ASCII-only, then `.encode("utf-8")` assumed the client's string was
# well-formed Unicode (an unpaired surrogate like "\ud800" is valid JSON but
# not valid UTF-8). Each fix was locally correct and moved the crash
# somewhere new. So rather than one regression test per bug found, this
# parametrizes the whole space of things a hostile, pre-authentication
# client can put in this field, and asserts none of them can raise: each
# must come back as a clean "invalid token" JSON-RPC error *and* leave the
# connection usable afterward (checked with a follow-up ping), never an
# exception that kills the session.
# ---------------------------------------------------------------------------

_MISSING_TOKEN = object()  # sentinel: omit the "token" key entirely

_HOSTILE_TOKEN_CASES = [
    pytest.param(_MISSING_TOKEN, id="missing-key"),
    pytest.param(None, id="null"),
    pytest.param(123, id="non-string-int"),
    pytest.param(["a", "b"], id="non-string-list"),
    pytest.param({"x": 1}, id="non-string-dict"),
    pytest.param("", id="empty-string"),
    pytest.param("\ud800", id="unpaired-surrogate-high"),
    pytest.param("\udfff", id="unpaired-surrogate-low"),
    pytest.param("café-你好-token", id="non-ascii-valid-utf8"),
    # NOTE: a "very long token" case (e.g. 10 MB) deliberately is NOT here.
    # With B0 rescoped to leave the pre-auth input bound at asyncio's
    # default 64 KiB readline() limit (a considered bound is B4's job, once
    # this transport is on a network), an oversized single-line request
    # overruns that limit before _handle_initialize ever runs, so it can't
    # get a polite "invalid token" JSON-RPC reply the way every case below
    # can — see test_very_long_token_disconnects_cleanly for what it *is*
    # expected to do instead.
]


@pytest.mark.asyncio
@pytest.mark.parametrize("token_value", _HOSTILE_TOKEN_CASES)
async def test_hostile_token_values_rejected_without_crashing(mcp_server_port, token_value) -> None:
    """No value a client can put in the "token" field may raise.

    Covers: a missing key, JSON null, wrong JSON types, an empty string, a
    lone UTF-16 surrogate in each half of the pair, and a genuinely
    non-ASCII (but well-formed) token. Every case must be rejected the
    normal way, with the connection still usable — proving the handler
    itself never raised.
    """
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)

    params: dict[str, Any] = {"protocolVersion": "2024-11-05"}
    if token_value is not _MISSING_TOKEN:
        params["token"] = token_value

    writer.write(_rpc("initialize", params, req_id=1))
    await writer.drain()
    resp = await asyncio.wait_for(_read_one(reader), timeout=10.0)

    assert "error" in resp, f"Expected a clean rejection, got: {resp}"
    assert resp["error"]["code"] == -32000

    # The connection must still be alive: a follow-up ping gets a normal
    # reply, proving the handler returned instead of raising out of the
    # session and tearing the connection down.
    writer.write(_rpc("ping", req_id=2))
    await writer.drain()
    ping_resp = await asyncio.wait_for(_read_one(reader), timeout=5.0)
    assert "error" not in ping_resp

    writer.close()


@pytest.mark.asyncio
async def test_very_long_token_disconnects_cleanly(mcp_server_port) -> None:
    """A 10 MB token overruns the read buffer — dropped, not politely refused.

    This case is deliberately split out from the parametrized sweep above:
    with the pre-auth input bound left at asyncio's default 64 KiB (B0 does
    not harden the framing layer — that is B4's job for the networked
    endpoint), a request this large blows ``readline()``'s buffer before a
    separator is ever found, well before ``_handle_initialize`` runs. So it
    cannot get a clean "invalid token" JSON-RPC reply the way the other
    hostile values can. What must still hold: no unhandled exception
    anywhere in the event loop (the read loop's ``ValueError`` catch turns
    the overrun into a plain disconnect), the connection actually ends
    rather than hanging, and — the "server process is unharmed" part — a
    second, unrelated connection to the same server still completes a
    normal handshake afterward.
    """
    port, _, _ = mcp_server_port

    loop = asyncio.get_running_loop()
    loop_exceptions: list[BaseException] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda _loop, context: loop_exceptions.append(context["exception"])
        if context.get("exception") is not None
        else None,
    )

    try:
        reader, writer = await _open_client(port)
        big_token = "A" * (10 * 1024 * 1024)
        payload = _rpc(
            "initialize",
            {"token": big_token, "protocolVersion": "2024-11-05"},
            req_id=1,
        )

        # The server may drop the connection before the client finishes
        # writing 10 MB; a reset while writing is an acceptable outcome
        # here, not a test failure.
        with contextlib.suppress(ConnectionResetError, BrokenPipeError, OSError):
            writer.write(payload)
            await writer.drain()

        # No polite JSON-RPC reply is expected: the connection should just
        # end (EOF) rather than yield a response or hang.
        with contextlib.suppress(ConnectionResetError, BrokenPipeError, OSError):
            raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
            assert raw == b"", f"Expected EOF/disconnect, got a reply: {raw!r}"

        with contextlib.suppress(Exception):
            writer.close()

        # Give the event loop a beat so any unhandled exception from the
        # server-side connection handler surfaces before we check for one.
        await asyncio.sleep(0.05)
        assert not loop_exceptions, f"Unhandled exception(s) in event loop: {loop_exceptions}"
    finally:
        loop.set_exception_handler(previous_handler)

    # The server itself is unharmed: an unrelated, fresh connection still
    # completes a normal handshake.
    reader2, writer2 = await _open_client(port)
    resp2 = await _initialize(reader2, writer2, TOKEN)
    assert "error" not in resp2, f"Unexpected error on unrelated connection: {resp2}"
    writer2.close()


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
# Tests: _json_default
# ---------------------------------------------------------------------------


def test_json_default_serialises_dataclass() -> None:
    """_json_default still converts dataclasses (e.g. ToolResultImpl)."""
    from workstation_agent.mcp_host.mcp_server import _json_default

    result = ToolResultImpl(content=[{"type": "text", "text": "hi"}], is_error=False, raw={})
    assert _json_default(result) == {
        "content": [{"type": "text", "text": "hi"}],
        "is_error": False,
        "raw": {},
        # B2: the §5.2 envelope keys travel with the dataclass.
        "ok": True,
        "code": None,
        "reason": None,
    }


@pytest.mark.parametrize("value", [{1, 2, 3}, object(), ValueError("boom"), lambda: None])
def test_json_default_raises_for_unexpected_types(value: Any) -> None:
    """_json_default raises TypeError instead of silently stringifying.

    Pre-fix, the fallback was ``return str(obj)``: a ``set``, an exception
    instance, or a function would silently become a plausible-looking
    string (``"{1, 2, 3}"``, ``"<function ... at 0x...>"``) instead of
    surfacing a serialisation failure — exactly how the ``ToolResultImpl``
    defect (defect 2) hid undetected. This asserts the permissive fallback
    is gone.
    """
    from workstation_agent.mcp_host.mcp_server import _json_default

    with pytest.raises(TypeError):
        _json_default(value)


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
    """agent.toast with a presenter calls the real ToastPresenter.show() API.

    Uses ``FakeToastPresenter``, which only implements ``show(*, title, body,
    actions)`` — the real ``ToastPresenter`` signature. Pre-fix, the call
    site invoked ``self._toast.present(...)``, which does not exist on this
    fake (nor on the real presenter): this test would have raised
    ``AttributeError`` inside ``_invoke_tool``, caught by the broad
    ``except Exception`` in ``_handle_tools_call``, and come back as
    ``isError: True`` with the error text mentioning ``present`` — failing
    the ``isError is False`` assertion below. That is the regression this
    test guards against.
    """
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    _toast = FakeToastPresenter()

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN, toast=_toast)
        await session.serve()

    mini_server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    mp = mini_server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    r2, w2 = await asyncio.open_connection("127.0.0.1", mp)
    w2.write(_rpc("initialize", {"token": TOKEN}, req_id=1))
    await w2.drain()
    _ = await _read_one(r2)

    w2.write(_rpc("tools/call", {
        "name": "agent.toast",
        "arguments": {"title": "Hi", "body": "World", "actions": ["update_now", "later"]},
    }, req_id=2))
    await w2.drain()
    resp = await _read_one(r2)

    assert resp["result"]["isError"] is False
    result = json.loads(resp["result"]["content"][0]["text"])
    assert result == {"ok": True}

    # show() was actually called, with the real keyword-only signature.
    assert len(_toast.calls) == 1
    call = _toast.calls[0]
    assert call["title"] == "Hi"
    assert call["body"] == "World"

    # The list-of-strings "actions" arg from the tool call was adapted into
    # the dict-of-(label, callback) shape show() actually takes.
    assert set(call["actions"]) == {"update_now", "later"}
    for action_id, (label, callback) in call["actions"].items():
        assert label == action_id
        assert callable(callback)
        callback()  # must not raise

    w2.close()
    mini_server.close()
    await mini_server.wait_closed()


@pytest.mark.asyncio
async def test_agent_toast_with_presenter_no_actions() -> None:
    """agent.toast with no actions passes actions=None, not an empty dict."""
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    _toast = FakeToastPresenter()

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
    assert len(_toast.calls) == 1
    assert _toast.calls[0]["actions"] is None

    w2.close()
    mini_server.close()
    await mini_server.wait_closed()


# ---------------------------------------------------------------------------
# Tests: agent.execute_local WITH mcp_host
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_execute_local_with_host() -> None:
    """agent.execute_local invokes the mcp_host and returns its ToolResultImpl.

    ``MCPHost.invoke`` returns a real ``ToolResultImpl`` dataclass (see
    ``host.py``), never a plain dict — a mock returning a bare dict here
    would hide the ``json.dumps`` defect entirely, since dicts are already
    JSON-serialisable. Pre-fix, ``json.dumps({"result": ToolResultImpl(...)})``
    with no ``default=`` raised ``TypeError: Object of type ToolResultImpl is
    not JSON serializable`` inside ``_handle_tools_call``'s try block, which
    was swallowed by ``except Exception`` and reported as ``isError: True``.
    This test asserts ``isError is False`` and the full payload, which fails
    against the pre-fix code.
    """
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    tool_result = ToolResultImpl(
        content=[{"type": "text", "text": "ok"}],
        is_error=False,
        raw={"exit_code": 0},
    )
    mock_host = MagicMock()
    mock_host.invoke = AsyncMock(return_value=tool_result)

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

    # This is the regression assertion: a successful call must report
    # isError: False, not True from a swallowed serialisation TypeError.
    assert resp["result"]["isError"] is False

    # B2: the call site now carries a session identity and the MCP request id
    # down to the gate.  Asserted rather than dropped, so a regression that
    # stops plumbing the session — silently breaking B3's "remember for this
    # session", which has nothing else to key on — fails here.
    mock_host.invoke.assert_awaited_once()
    call = mock_host.invoke.await_args
    assert call.args == ("my_plugin.my_tool", {"x": 1})
    session = call.kwargs["session"]
    assert session.session_id
    assert session.transport == "named_pipe"
    assert session.request_id == "2"

    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["ok"] is True
    assert payload["session_id"] == session.session_id
    assert payload["result"] == {
        "content": [{"type": "text", "text": "ok"}],
        "is_error": False,
        "raw": {"exit_code": 0},
        "ok": True,
        "code": None,
        "reason": None,
    }
    w2.close()
    mini_server.close()
    await mini_server.wait_closed()


@pytest.mark.asyncio
async def test_agent_execute_local_unserialisable_result_is_error() -> None:
    """A genuinely unserialisable result reports isError: True, not success.

    If ``mcp_host.invoke`` ever returns something ``_json_default`` can't
    handle (here, a plain ``set``), the tool call must surface that as a
    real error — not silently succeed with a stringified value, which is
    exactly the failure mode a permissive ``str()`` fallback would produce.
    """
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    mock_host = MagicMock()
    mock_host.invoke = AsyncMock(return_value={1, 2, 3})

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
        "arguments": {"plugin_id": "my_plugin", "tool": "my_tool"},
    }, req_id=2))
    await w2.drain()
    resp = await _read_one(r2)

    assert resp["result"]["isError"] is True
    assert "not JSON serializable" in resp["result"]["content"][0]["text"]
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
async def test_serve_handles_deeply_nested_json(mcp_server_port) -> None:
    """serve() skips a line that blows the JSON decoder's recursion limit.

    Deeply nested JSON such as ``[[[[...]]]]`` makes ``json.loads`` raise
    ``RecursionError``, which ``json.JSONDecodeError`` alone does not catch.
    Pre-fix, that propagated straight out of the read loop's inner
    try/except and crashed the session instead of just skipping the line —
    the same "assume the input is well-formed" mistake found on the token
    field, just here in the general JSON-RPC framing. This sends such a
    line, then a valid ping to prove the connection survived.
    """
    port, _, _ = mcp_server_port
    reader, writer = await _open_client(port)

    # Deep enough to blow the JSON decoder's recursion/C-stack guard
    # (empirically ~20_000 levels), but the resulting line (~50 KB) must
    # stay under the read loop's separate 64 KiB readline() buffer limit —
    # this test is about the decoder's own recursion handling, not that
    # buffer limit (see test_very_long_token_disconnects_cleanly for that).
    depth = 25_000
    nested = ("[" * depth) + ("]" * depth)
    writer.write(nested.encode() + b"\n")
    await writer.drain()

    writer.write(_rpc("ping", req_id=1))
    await writer.drain()
    resp = await asyncio.wait_for(_read_one(reader), timeout=10.0)
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


# ---------------------------------------------------------------------------
# Tests: APPDATA path resolution
# ---------------------------------------------------------------------------


def test_token_path_uses_appdata_when_set(tmp_path: Any, monkeypatch: Any) -> None:
    """TOKEN_DIR/TOKEN_FILE are rooted under APPDATA when APPDATA is set."""
    import importlib
    import sys

    monkeypatch.setenv("APPDATA", str(tmp_path))
    # Remove cached module so constants are re-evaluated with new env
    monkeypatch.delitem(sys.modules, "workstation_agent.mcp_host.mcp_server", raising=False)
    import workstation_agent.mcp_host.mcp_server as srv_fresh

    try:
        assert srv_fresh.TOKEN_DIR.is_relative_to(tmp_path), (
            f"TOKEN_DIR {srv_fresh.TOKEN_DIR!r} should be under APPDATA={tmp_path!r}"
        )
        assert srv_fresh.TOKEN_FILE.is_relative_to(tmp_path), (
            f"TOKEN_FILE {srv_fresh.TOKEN_FILE!r} should be under APPDATA={tmp_path!r}"
        )
    finally:
        # Re-import the original module so other tests are not affected
        importlib.reload(srv_fresh)


def test_token_path_falls_back_when_appdata_unset(tmp_path: Any, monkeypatch: Any) -> None:
    """When APPDATA is absent, TOKEN_DIR falls back to home/.config/… not cwd."""
    import importlib
    import sys

    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delitem(sys.modules, "workstation_agent.mcp_host.mcp_server", raising=False)
    import workstation_agent.mcp_host.mcp_server as srv_fresh

    try:
        cwd = Path()
        # Must not be rooted in the current working directory
        try:
            rel = srv_fresh.TOKEN_DIR.relative_to(cwd.resolve())
        except ValueError:
            rel = None

        assert rel is None or str(srv_fresh.TOKEN_DIR.resolve()) != str(cwd.resolve()), (
            "TOKEN_DIR must not be the current working directory"
        )
        # Must not start with '.' (i.e. Path('.') / ...)
        assert str(srv_fresh.TOKEN_DIR)[0] != ".", (
            f"TOKEN_DIR {srv_fresh.TOKEN_DIR!r} must not be relative/cwd-rooted"
        )
        # Must be rooted under home directory
        assert srv_fresh.TOKEN_DIR.is_relative_to(Path.home()), (
            f"TOKEN_DIR {srv_fresh.TOKEN_DIR!r} should be under home={Path.home()!r}"
        )
    finally:
        importlib.reload(srv_fresh)


def test_token_file_hardened_after_save(tmp_path: Any, monkeypatch: Any) -> None:
    """generate_and_store_token() calls harden_file with the token path."""
    import sys
    import types

    import workstation_agent.mcp_host.mcp_server as srv

    monkeypatch.setattr(srv, "TOKEN_DIR", tmp_path)
    monkeypatch.setattr(srv, "TOKEN_FILE", tmp_path / "mcp-token")

    harden_calls: list[Any] = []

    def fake_harden(path: Any) -> None:
        harden_calls.append(path)

    fake_dpapi = types.ModuleType("workstation_agent.security.dpapi")
    fake_dpapi.harden_file = fake_harden  # type: ignore[attr-defined]

    with patch.dict(sys.modules, {"workstation_agent.security.dpapi": fake_dpapi}):
        srv.generate_and_store_token()

    assert len(harden_calls) == 1, "harden_file must be called exactly once"
    assert harden_calls[0] == tmp_path / "mcp-token", (
        f"harden_file called with {harden_calls[0]!r}, expected {tmp_path / 'mcp-token'!r}"
    )


# ---------------------------------------------------------------------------
# Tests: run_pipe_server when _create_pipe_server returns None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_pipe_server_exits_on_bind_failure() -> None:
    """run_pipe_server returns immediately when _create_pipe_server fails."""
    from workstation_agent.mcp_host import mcp_server as srv

    async def _return_none() -> None:
        return None

    with patch.object(srv, "_create_pipe_server", side_effect=_return_none) as mock_create:
        # Should return immediately without raising
        await srv.run_pipe_server("test-token", max_clients=3)
    mock_create.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: serve() IncompleteReadError path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_serve_handles_incomplete_read() -> None:
    """serve() exits cleanly when readline raises IncompleteReadError."""
    from workstation_agent.mcp_host.mcp_server import AgentMCPServer

    done_event = asyncio.Event()

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN)
        # Patch the reader so readline raises IncompleteReadError
        async def _bad_readline() -> bytes:
            _partial: bytes = b""
            raise asyncio.IncompleteReadError(_partial, None)

        r.readline = _bad_readline  # type: ignore[method-assign]
        await session.serve()
        done_event.set()

    mini_server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    mp = mini_server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    _r, _w = await asyncio.open_connection("127.0.0.1", mp)
    await asyncio.wait_for(done_event.wait(), timeout=3.0)
    _w.close()
    mini_server.close()
    await mini_server.wait_closed()
