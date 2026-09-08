"""The named-pipe transport still round-trips after the §5.2 envelope landed.

B2 changed what ``MCPHost.invoke`` returns.  ``agent.execute_local`` is the
only existing call site of it on the transport, so it is the thing that
breaks silently if the two drift apart.  These tests drive a **real**
``MCPHost`` (with a real permissions evaluation and a real audit database)
through the JSON-RPC wire the pipe speaks, rather than a mock of the host —
a mock of ``invoke`` would happily return the old shape forever.

The wire is TCP rather than a Windows named pipe: ``AgentMCPServer`` takes an
``asyncio`` stream pair and is identical on both, and ``run_tcp_server``
exists precisely so this path is testable.
"""

# ruff: noqa: ANN401, PLR0913, PLR0917

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

import workstation_agent.mcp_host.audit as audit_mod
from workstation_agent.mcp_host import host as host_mod
from workstation_agent.mcp_host.host import MCPHost
from workstation_agent.mcp_host.loader import PluginManifest, VerifyResult
from workstation_agent.mcp_host.mcp_server import AgentMCPServer

TOKEN = "cafebabe" * 8


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    audit_mod.set_db_path(tmp_path / "audit.db")
    yield tmp_path / "audit.db"
    audit_mod.reset_connection()


def _runtime(plugin_id: str, client: Any) -> Any:
    manifest = PluginManifest(
        id=plugin_id,
        name="Files",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            f"tool:{plugin_id}.read",
            f"tool:{plugin_id}.write",
            "path:/roots/documents",
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    return host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": f"{plugin_id}.read"}, {"name": f"{plugin_id}.write"}],
        granted_permissions={f"tool:{plugin_id}.read", f"tool:{plugin_id}.write"},
        client=client,
    )


async def _serve(host: MCPHost):
    """Start a one-connection AgentMCPServer wired to *host*; return (port, server)."""
    sessions: list[AgentMCPServer] = []

    async def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        session = AgentMCPServer(r, w, token=TOKEN, mcp_host=host)
        sessions.append(session)
        await session.serve()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return port, server, sessions


def _rpc(method: str, params: dict[str, Any], req_id: int) -> bytes:
    return (json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
            + "\n").encode()


async def _call(reader, writer, plugin_id: str, tool: str, args: dict, req_id: int) -> dict:
    writer.write(_rpc("tools/call", {
        "name": "agent.execute_local",
        "arguments": {"plugin_id": plugin_id, "tool": tool, "args": args},
    }, req_id))
    await writer.drain()
    raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
    return json.loads(raw.decode())


@pytest.mark.asyncio
async def test_pipe_execute_local_round_trips_a_successful_call() -> None:
    """A permitted call still comes back over the wire with its payload intact."""
    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": '{"content": "hello"}'}],
                      "isError": False},
    )
    host = MCPHost()
    host._runtimes["files"] = _runtime("files", client)

    port, server, _ = await _serve(host)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_rpc("initialize", {"token": TOKEN}, 1))
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5.0)

        resp = await _call(reader, writer, "files", "read",
                           {"path": "/roots/documents/a.txt"}, 2)
    finally:
        writer.close()
        server.close()
        await server.wait_closed()

    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["ok"] is True
    assert payload["session_id"]
    # The tool's own text survived the trip unmangled, with §5.2's `ok` added.
    inner = json.loads(payload["result"]["content"][0]["text"])
    assert inner == {"ok": True, "content": "hello"}
    client.tools_call.assert_awaited_once()


@pytest.mark.asyncio
async def test_pipe_execute_local_reports_a_denial_as_a_result_not_a_crash() -> None:
    """An out-of-roots read comes back over the pipe as §5.2 `denied`.

    Before B2 this raised ``PermissionError`` inside ``_handle_tools_call``,
    which reported ``isError: True`` with a Python exception message —
    indistinguishable, to a caller, from the server having fallen over.
    """
    client = AsyncMock()
    host = MCPHost()
    host._runtimes["files"] = _runtime("files", client)

    port, server, _ = await _serve(host)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_rpc("initialize", {"token": TOKEN}, 1))
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5.0)

        resp = await _call(reader, writer, "files", "read", {"path": "/elsewhere/x"}, 2)
    finally:
        writer.close()
        server.close()
        await server.wait_closed()

    # §7: a refusal is a normal result, not an error.
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["code"] == "denied"
    assert payload["reason"]
    client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_pipe_session_id_is_stable_within_a_connection(isolated_audit_db) -> None:
    """Two calls on one connection share a session id; §5.7's row records it.

    This is the identifier B3's "remember for this session" keys on — if it
    changed per call, "remember" would have nothing to remember against.
    """
    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    host = MCPHost()
    host._runtimes["files"] = _runtime("files", client)

    port, server, sessions = await _serve(host)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_rpc("initialize", {"token": TOKEN}, 1))
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5.0)

        first = await _call(reader, writer, "files", "read",
                            {"path": "/roots/documents/a"}, 2)
        second = await _call(reader, writer, "files", "read",
                             {"path": "/roots/documents/b"}, 3)
    finally:
        writer.close()
        server.close()
        await server.wait_closed()

    sid = json.loads(first["result"]["content"][0]["text"])["session_id"]
    assert json.loads(second["result"]["content"][0]["text"])["session_id"] == sid
    assert sessions[0].session_id == sid

    rows = audit_mod.query(audit_mod.AuditQuery(session_id=sid), db_path=isolated_audit_db)
    assert len(rows) == 2
    # §5.7's MCP request id, distinct per call within the one session.
    assert {r.request_id for r in rows} == {"2", "3"}
    assert all(r.duration_ms is not None for r in rows)


@pytest.mark.asyncio
async def test_pipe_session_ids_differ_between_connections() -> None:
    """Two connections are two sessions; one cannot inherit the other's approvals."""
    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    host = MCPHost()
    host._runtimes["files"] = _runtime("files", client)

    port, server, sessions = await _serve(host)
    try:
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(_rpc("initialize", {"token": TOKEN}, 1))
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5.0)
            await _call(reader, writer, "files", "read", {"path": "/roots/documents/a"}, 2)
            writer.close()
    finally:
        server.close()
        await server.wait_closed()

    assert len({s.session_id for s in sessions}) == 2


@pytest.mark.asyncio
async def test_pipe_tolerates_a_host_that_does_not_accept_a_session() -> None:
    """A host implementing only ``protocols.MCPHost`` still works over the pipe.

    The keyword is offered by introspection, not by calling and retrying on
    ``TypeError`` — a retry would re-run a side-effecting tool if the
    ``TypeError`` had come from inside it.
    """
    calls: list[tuple] = []

    class LegacyHost:
        async def invoke(self, tool_id: str, args: dict) -> Any:
            calls.append((tool_id, args))
            return {"content": [{"type": "text", "text": "legacy"}], "isError": False}

    port, server, _ = await _serve(LegacyHost())  # type: ignore[arg-type]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_rpc("initialize", {"token": TOKEN}, 1))
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5.0)
        resp = await _call(reader, writer, "files", "read", {"path": "/x"}, 2)
    finally:
        writer.close()
        server.close()
        await server.wait_closed()

    assert resp["result"]["isError"] is False
    assert calls == [("files.read", {"path": "/x"})]
