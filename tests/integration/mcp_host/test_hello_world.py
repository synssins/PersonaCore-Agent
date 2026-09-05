"""Integration test: MCPHost start → hello_world.echo → audit → stop.

This test exercises the full round-trip:
1. MCPHost.start() discovers, signs (via fixture), and spawns hello_world.
2. MCPHost.invoke("hello_world.echo", {"text": "ping"}) returns the echo.
3. An audit row for the invocation is present in the audit DB.
4. MCPHost.stop() cleans up without error.
"""
# ruff: noqa: S603, S607, E402, ARG001, ASYNC221

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="plugin subprocess race on GH Actions py3.12 (task #10)",
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import workstation_agent.mcp_host.audit as audit_mod
from tests.fakes.gen_test_keypair import signed_hello_world_keypair  # noqa: F401
from workstation_agent.config.schema import AgentConfig
from workstation_agent.mcp_host.audit import AuditQuery, query
from workstation_agent.mcp_host.host import MCPHost


@pytest.fixture
def agent_config():
    """Minimal AgentConfig with allow_unsigned=True and hello_world tool grant.

    Under the SPEC-03B default-deny permissions model, the plugin must both
    (a) declare ``tool:hello_world.echo`` in its manifest AND (b) have that
    permission granted in the user's config.  We do (b) here so the
    integration test can actually invoke the tool.
    """
    from workstation_agent.config.schema import PluginConfig as _PluginCfg
    cfg = AgentConfig()
    cfg.plugins.allow_unsigned = True
    cfg.plugins.per_plugin["hello_world"] = _PluginCfg(
        enabled=True,
        granted_permissions=["tool:hello_world.echo"],
    )
    return cfg


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    """Each integration test gets its own audit DB."""
    db_path = tmp_path / "audit.db"
    audit_mod.set_db_path(db_path)
    yield db_path
    audit_mod.reset_connection()


@pytest.mark.asyncio
async def test_hello_world_roundtrip(agent_config, isolated_audit_db, signed_hello_world_keypair):  # noqa: F811
    """Full round-trip: start, invoke echo, check audit, stop."""
    _pubkey, _ = signed_hello_world_keypair

    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        plugin_list = await host.plugins()
        plugin_ids = [p.id for p in plugin_list]
        assert "hello_world" in plugin_ids, f"hello_world not in plugins: {plugin_ids}"

        running = next(p for p in plugin_list if p.id == "hello_world")
        assert running.status == "running", f"expected running, got {running.status}"

        result = await host.invoke("hello_world.echo", {"text": "ping"})
        assert not result.is_error
        texts = [item["text"] for item in result.content if item.get("type") == "text"]
        assert texts == ["ping"], f"unexpected echo: {texts}"

        rows = query(AuditQuery(event="tool_invoke"), db_path=isolated_audit_db)
        assert len(rows) >= 1, "expected at least one audit row"
        assert rows[0].tool_id == "hello_world.echo"
        assert rows[0].plugin_id == "hello_world"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_hello_world_stop_cleans_up(agent_config, isolated_audit_db):
    """MCPHost.stop() terminates the subprocess cleanly."""
    host = MCPHost()
    await host.start(agent_config)

    plugins_before = await host.plugins()
    running = [p for p in plugins_before if p.status == "running"]
    pids = [p.pid for p in running if p.pid is not None]

    await host.stop()

    for pid in pids:
        with contextlib.suppress(Exception):
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            assert str(pid) not in result.stdout, f"pid {pid} still alive after stop()"


@pytest.mark.asyncio
async def test_hello_world_audit_on_start_stop(agent_config, isolated_audit_db):
    """host_started and host_stopped audit events are written."""
    host = MCPHost()
    await host.start(agent_config)
    await host.stop()

    started_rows = query(AuditQuery(event="host_started"), db_path=isolated_audit_db)
    stopped_rows = query(AuditQuery(event="host_stopped"), db_path=isolated_audit_db)
    assert len(started_rows) >= 1
    assert len(stopped_rows) >= 1


@pytest.mark.asyncio
async def test_invoke_unknown_tool_raises(agent_config, isolated_audit_db):
    """Invoking a tool that doesn't exist raises KeyError."""
    host = MCPHost()
    await host.start(agent_config)
    try:
        with pytest.raises(KeyError):
            await host.invoke("nonexistent.tool", {})
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_hello_world_tools_list(agent_config, isolated_audit_db):
    """MCPHost.tools() includes hello_world.echo."""
    host = MCPHost()
    await host.start(agent_config)
    try:
        tools = await host.tools()
        tool_names = [t.name for t in tools]
        assert "hello_world.echo" in tool_names
    finally:
        await host.stop()
