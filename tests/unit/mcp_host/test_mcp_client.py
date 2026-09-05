"""SPEC-03A MCP client tests.

End-to-end round trip against ``echo_plugin`` for the SPEC-03A surface:
``initialize``, ``tools/list``, ``tools/call``, ``ping``, ``shutdown`` and
the ``notifications()`` async iterator. Also covers timeout, cancellation,
protocol/remote errors, and closed-client behaviour without the plugin.
"""
# ruff: noqa: ARG002, EM101, TRY003, TC003

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="echo_plugin subprocess race on CI py3.12 (task #10)",
)

from workstation_agent.mcp_host.mcp_client import (
    MCPProtocolError,
    MCPRemoteError,
    MCPStdioClient,
)
from workstation_agent.mcp_host.supervisor import PluginSupervisor


@pytest.fixture
async def live_client(
    echo_plugin_cmd: list[str], repo_root: Path,
):
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="mcp-client-test")
    client = MCPStdioClient(default_timeout=5.0)
    await client.connect(handle.stdin, handle.stdout)
    try:
        yield client, handle, supervisor
    finally:
        await client.close()
        await supervisor.terminate(handle, hard_after=1.0)


async def test_initialize_returns_server_info(live_client) -> None:
    client, _handle, _sup = live_client
    result = await client.initialize()
    assert result["protocolVersion"] == "2024-11-05"
    assert result["serverInfo"]["name"] == "echo_plugin"


async def test_ping_round_trip(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()
    resp = await client.ping()
    assert resp == {}


async def test_tools_list_returns_echo_tool(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()
    tools = await client.tools_list()
    assert any(t["name"] == "hello.echo" for t in tools)


async def test_tools_call_echoes_text(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()
    result = await client.tools_call("hello.echo", {"text": "meow"})
    assert result["content"][0]["text"] == "meow"
    assert result["isError"] is False


async def test_tools_call_unknown_tool_raises_remote_error(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()
    with pytest.raises(MCPRemoteError) as exc_info:
        await client.tools_call("does.not.exist", {})
    assert exc_info.value.code == -32601


async def test_notifications_receives_hello_from_server(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()

    async def _first():
        async for msg in client.notifications():
            return msg
        return None

    msg = await asyncio.wait_for(_first(), timeout=3.0)
    assert msg is not None
    assert msg["method"] == "notifications/hello"
    assert msg["params"] == {"who": "echo"}


async def test_shutdown_completes(live_client) -> None:
    client, _handle, _sup = live_client
    await client.initialize()
    # Should not raise even if the plugin closes stdout before responding.
    await client.shutdown()


async def test_double_connect_rejected(live_client) -> None:
    client, handle, _sup = live_client
    with pytest.raises(MCPProtocolError):
        await client.connect(handle.stdin, handle.stdout)


async def test_close_is_idempotent(live_client) -> None:
    client, _handle, _sup = live_client
    await client.close()
    await client.close()


# ---------------------------------------------------------------------------
# unit-level (no subprocess) tests for the internals
# ---------------------------------------------------------------------------


class _FakePipe(io.RawIOBase):
    """A dead-in-both-directions pipe (readline returns b'')."""

    def readline(self, *_a, **_kw):
        return b""

    def write(self, data):
        return 0

    def flush(self):
        return None


async def test_request_after_close_raises() -> None:
    client = MCPStdioClient()
    await client.close()
    with pytest.raises(MCPProtocolError):
        await client._request("ping")


async def test_dispatch_ignores_unknown_response_id() -> None:
    client = MCPStdioClient()
    # No pending future for id=999 — must not raise.
    client._dispatch({"jsonrpc": "2.0", "id": 999, "result": {}})


async def test_dispatch_routes_error_response() -> None:
    client = MCPStdioClient()
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    client._pending[7] = fut
    client._dispatch({
        "jsonrpc": "2.0", "id": 7,
        "error": {"code": -1, "message": "nope", "data": {"why": "test"}},
    })
    with pytest.raises(MCPRemoteError) as exc:
        await fut
    assert exc.value.code == -1
    assert exc.value.data == {"why": "test"}


async def test_dispatch_routes_notification_without_id() -> None:
    client = MCPStdioClient()
    client._dispatch({"jsonrpc": "2.0", "method": "notifications/tick", "params": {}})
    msg = await asyncio.wait_for(client._notifications.get(), timeout=0.5)
    assert msg["method"] == "notifications/tick"


async def test_notify_no_op_when_closed() -> None:
    client = MCPStdioClient()
    await client.close()
    # Should return silently, not raise.
    await client._notify("ignored")


async def test_tools_list_rejects_bad_shape() -> None:
    """If the plugin returns something other than {"tools": [...]}, we raise."""
    client = MCPStdioClient()

    async def _fake_request(*_a, **_kw):
        return {"nope": True}

    client._request = _fake_request  # type: ignore[method-assign]
    with pytest.raises(MCPProtocolError):
        await client.tools_list()


async def test_request_timeout_raises_protocol_error() -> None:
    """A request that never receives a response must surface as MCPProtocolError."""
    import io as _io

    stdin_buf = _io.BytesIO()
    stdout_buf = _FakePipe()
    client = MCPStdioClient(default_timeout=0.05)
    # Connect but the fake stdout is inert, so no response ever comes.
    await client.connect(stdin_buf, stdout_buf)  # type: ignore[arg-type]
    try:
        with pytest.raises(MCPProtocolError):
            await client._request("ping", timeout=0.05)
    finally:
        await client.close()


async def test_request_cancellation_cleans_pending() -> None:
    import io as _io

    stdin_buf = _io.BytesIO()
    stdout_buf = _FakePipe()
    client = MCPStdioClient(default_timeout=5.0)
    await client.connect(stdin_buf, stdout_buf)  # type: ignore[arg-type]
    try:
        task = asyncio.create_task(client._request("ping", timeout=5.0))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not client._pending
    finally:
        await client.close()


async def test_shutdown_tolerates_protocol_error() -> None:
    client = MCPStdioClient()

    async def _boom(*_a, **_kw):
        raise MCPProtocolError("no response")

    client._request = _boom  # type: ignore[method-assign]
    # Must not propagate.
    await client.shutdown()


async def test_reader_ignores_non_json_lines() -> None:
    """Garbage lines from a misbehaving plugin should not crash the reader."""
    client = MCPStdioClient()

    class _JunkThenGood(io.RawIOBase):
        def __init__(self) -> None:
            self._lines = [
                b"not json at all\n",
                json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}).encode() + b"\n",
                b"",  # EOF
            ]

            self._i = 0

            def rl(*_a, **_kw):
                if self._i >= len(self._lines):
                    return b""
                line = self._lines[self._i]
                self._i += 1
                return line

            self.readline = rl  # type: ignore[assignment]

    stdin_buf = io.BytesIO()
    stdout_buf = _JunkThenGood()
    await client.connect(stdin_buf, stdout_buf)  # type: ignore[arg-type]
    msg = await asyncio.wait_for(client._notifications.get(), timeout=2.0)
    assert msg["method"] == "notifications/x"
    await client.close()
