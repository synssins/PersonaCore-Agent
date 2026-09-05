"""Unit tests for workstation_agent.mcp_host.host (non-integration paths)."""
# ruff: noqa: ANN201, S101, SLF001, ARG001

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import workstation_agent.mcp_host.audit as audit_mod
from workstation_agent.config.schema import AgentConfig
from workstation_agent.mcp_host import host as host_mod
from workstation_agent.mcp_host.host import (
    ConfirmationRequestImpl,
    MCPHost,
    PluginInfoImpl,
    ToolDescriptorImpl,
    ToolResultImpl,
    _resolve_entry,
)
from workstation_agent.mcp_host.loader import PluginManifest, VerifyResult
from workstation_agent.mcp_host.supervisor import ResourceLimits, SubprocessHandle


def _make_manifest(plugin_id: str = "fake", declared_permissions=None) -> PluginManifest:
    return PluginManifest(
        id=plugin_id,
        name="Fake Plugin",
        version="0.0.1",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=declared_permissions or [],
        confirmable_conditions=[],
    )


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    db_path = tmp_path / "audit.db"
    audit_mod.set_db_path(db_path)
    yield db_path
    audit_mod.reset_connection()


# ---------------------------------------------------------------------------
# _resolve_entry
# ---------------------------------------------------------------------------


def test_resolve_entry_empty_entry():
    """Empty entry → defaults to `python -u -m workstation_agent.plugins.<id>`."""
    m = _make_manifest("my_plugin")
    m.entry.clear()
    result = _resolve_entry(m)
    assert result[-1] == "workstation_agent.plugins.my_plugin"
    assert result[-2] == "-m"


def test_resolve_entry_relative_starts_with_dash():
    """Entry starting with '-m' → prepend python -u."""
    import sys
    m = _make_manifest()
    m.entry[:] = ["-m", "workstation_agent.plugins.hello_world"]
    result = _resolve_entry(m)
    assert result[0] == sys.executable
    assert result[2] == "-m"


def test_resolve_entry_absolute_path(tmp_path):
    """Entry starting with absolute path → used as-is."""
    exe = tmp_path / "plugin.exe"
    exe.write_bytes(b"")
    m = _make_manifest()
    m.entry[:] = [str(exe), "--flag"]
    result = _resolve_entry(m)
    assert result[0] == str(exe)
    assert result[1] == "--flag"


# ---------------------------------------------------------------------------
# Dataclass checks
# ---------------------------------------------------------------------------


def test_plugin_info_impl_fields():
    info = PluginInfoImpl(
        id="p",
        name="P",
        version="1.0",
        status="running",
        signature_status="valid",
        granted_permissions=["*"],
        resource_limits={"max_memory_mb": 512},
        integrity="low",
        pid=1234,
    )
    assert info.id == "p"
    assert info.pid == 1234


def test_tool_descriptor_impl_fields():
    td = ToolDescriptorImpl(
        name="foo.bar",
        description="Does foo",
        input_schema={"type": "object"},
        plugin_id="foo",
    )
    assert td.name == "foo.bar"


def test_tool_result_impl_defaults():
    tr = ToolResultImpl(content=[])
    assert not tr.is_error
    assert tr.raw == {}


def test_confirmation_request_impl():
    req = ConfirmationRequestImpl(plugin_id="p", tool_id="p.t", args={"x": 1})
    assert req.condition == ""


# ---------------------------------------------------------------------------
# MCPHost with mocked discover
# ---------------------------------------------------------------------------


@pytest.fixture
def cfg_allow_unsigned():
    cfg = AgentConfig()
    cfg.plugins.allow_unsigned = True
    return cfg


@pytest.fixture
def cfg_disallow_unsigned():
    cfg = AgentConfig()
    cfg.plugins.allow_unsigned = False
    return cfg


@pytest.mark.asyncio
async def test_start_quarantines_invalid_sig(cfg_disallow_unsigned, isolated_audit_db):
    """Plugin with invalid signature is quarantined, not spawned."""
    manifest = _make_manifest("bad_plugin")
    manifest.signature_file = Path("nonexistent.sig")

    with patch("workstation_agent.mcp_host.host.discover", return_value=[manifest]):
        host = MCPHost()
        await host.start(cfg_disallow_unsigned)
        plugins = await host.plugins()
        await host.stop()

    bad = next(p for p in plugins if p.id == "bad_plugin")
    assert bad.status == "quarantined"


@pytest.mark.asyncio
async def test_start_skips_disabled_plugin(cfg_allow_unsigned, isolated_audit_db):
    """Plugin with enabled=False in per_plugin config is skipped."""
    from workstation_agent.config.schema import PluginConfig as PluginCfg
    cfg_allow_unsigned.plugins.per_plugin["disabled_plugin"] = PluginCfg(enabled=False)

    manifest = _make_manifest("disabled_plugin")
    manifest.signature_file = Path("nonexistent.sig")

    with patch("workstation_agent.mcp_host.host.discover", return_value=[manifest]):
        host = MCPHost()
        await host.start(cfg_allow_unsigned)
        plugins = await host.plugins()
        await host.stop()

    assert not any(p.id == "disabled_plugin" for p in plugins)


@pytest.mark.asyncio
async def test_invoke_deny_raises_permission_error(isolated_audit_db):
    """invoke() raises PermissionError when permissions evaluate to deny."""
    manifest = _make_manifest("perm_plugin", declared_permissions=["tool:other.tool"])
    vresult = VerifyResult(status="unsigned")

    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "perm_plugin.restricted"}],
        granted_permissions=set(),
    )
    fake_runtime.client = AsyncMock()

    h = MCPHost()
    h._runtimes["perm_plugin"] = fake_runtime

    with pytest.raises(PermissionError):
        await h.invoke("perm_plugin.restricted", {"x": 1})


@pytest.mark.asyncio
async def test_invoke_confirm_rejected(isolated_audit_db):
    """invoke() raises PermissionError when user rejects confirm prompt."""
    manifest = _make_manifest("confirm_plugin")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = ["tool:confirm_plugin.write", "path:/safe/"]

    vresult = VerifyResult(status="unsigned")
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "confirm_plugin.write"}],
        granted_permissions={"tool:confirm_plugin.write"},
    )
    fake_runtime.client = AsyncMock()

    async def _deny_cb(req: ConfirmationRequestImpl) -> bool:
        return False

    h = MCPHost()
    h._confirm_cb = _deny_cb
    h._runtimes["confirm_plugin"] = fake_runtime

    with pytest.raises(PermissionError):
        await h.invoke("confirm_plugin.write", {"path": "/unsafe/x.txt"})


@pytest.mark.asyncio
async def test_invoke_confirm_accepted(isolated_audit_db):
    """invoke() proceeds when confirm_cb returns True."""
    manifest = _make_manifest("confirm_plugin2")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = ["tool:confirm_plugin2.write", "path:/safe/"]

    vresult = VerifyResult(status="unsigned")
    fake_client = AsyncMock()
    fake_client.tools_call = AsyncMock(return_value={
        "content": [{"type": "text", "text": "done"}],
        "isError": False,
    })

    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "confirm_plugin2.write"}],
        granted_permissions={"tool:confirm_plugin2.write"},
        client=fake_client,
    )

    async def _accept_cb(req: ConfirmationRequestImpl) -> bool:
        return True

    h = MCPHost()
    h._confirm_cb = _accept_cb
    h._runtimes["confirm_plugin2"] = fake_runtime

    result = await h.invoke("confirm_plugin2.write", {"path": "/unsafe/x.txt"})
    assert not result.is_error
    assert result.content[0]["text"] == "done"


@pytest.mark.asyncio
async def test_plugins_returns_quarantined(isolated_audit_db):
    """plugins() returns all runtimes including quarantined."""
    h = MCPHost()
    m = _make_manifest("q_plugin")
    h._runtimes["q_plugin"] = host_mod._PluginRuntime(
        manifest=m,
        verify_result=VerifyResult(status="quarantined"),
        status="quarantined",
    )
    infos = await h.plugins()
    assert any(p.id == "q_plugin" and p.status == "quarantined" for p in infos)


@pytest.mark.asyncio
async def test_tools_skips_non_running(isolated_audit_db):
    """tools() only includes tools from running plugins."""
    h = MCPHost()
    m = _make_manifest("stopped_plugin")
    h._runtimes["stopped_plugin"] = host_mod._PluginRuntime(
        manifest=m,
        verify_result=VerifyResult(status="unsigned"),
        status="stopped",
        tools=[{"name": "stopped.tool"}],
    )
    tools = await h.tools()
    assert not any(t.name == "stopped.tool" for t in tools)


@pytest.mark.asyncio
async def test_reload_unknown_plugin_raises(isolated_audit_db):
    """reload() raises KeyError for unknown plugin ID."""
    h = MCPHost()
    with pytest.raises(KeyError):
        await h.reload("nonexistent")


@pytest.mark.asyncio
async def test_stop_with_no_plugins(isolated_audit_db):
    """stop() with no plugins does not raise."""
    h = MCPHost()
    await h.stop()
    rows = audit_mod.query(audit_mod.AuditQuery(event="host_stopped"), db_path=isolated_audit_db)
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_on_plugin_died_updates_status(isolated_audit_db):
    """_on_plugin_died marks the runtime as stopped."""
    h = MCPHost()
    m = _make_manifest("dying_plugin")

    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.pid = 9999
    mock_proc.stdin = MagicMock()
    mock_proc.stdout = MagicMock()

    mock_handle = SubprocessHandle(
        pid=9999,
        process=mock_proc,
        job_handle=MagicMock(),
        integrity="low",
        stdin=MagicMock(),
        stdout=MagicMock(),
        plugin_id="dying_plugin",
        resource_limits=ResourceLimits(),
    )

    runtime = host_mod._PluginRuntime(
        manifest=m,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        handle=mock_handle,
    )
    h._runtimes["dying_plugin"] = runtime

    await h._on_plugin_died(mock_handle, "test timeout")

    assert runtime.status == "stopped"
    assert runtime.handle is None


@pytest.mark.asyncio
async def test_tts_speak_called_on_confirm(isolated_audit_db):
    """_do_confirm calls tts_speak.speak when tts_speak is set."""
    manifest = _make_manifest("tts_test")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = ["tool:tts_test.write", "path:/safe/"]

    vresult = VerifyResult(status="unsigned")
    fake_client = AsyncMock()
    fake_client.tools_call = AsyncMock(return_value={
        "content": [{"type": "text", "text": "ok"}],
        "isError": False,
    })
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "tts_test.write"}],
        granted_permissions={"tool:tts_test.write"},
        client=fake_client,
    )

    mock_tts = AsyncMock()
    mock_tts.speak = AsyncMock()

    async def _accept(req: ConfirmationRequestImpl) -> bool:
        return True

    h = MCPHost()
    h._tts_speak = mock_tts
    h._confirm_cb = _accept
    h._runtimes["tts_test"] = fake_runtime

    result = await h.invoke("tts_test.write", {"path": "/unsafe/x.txt"})
    assert not result.is_error
    mock_tts.speak.assert_called_once()


@pytest.mark.asyncio
async def test_on_plugin_died_unknown_plugin(isolated_audit_db):
    """_on_plugin_died with unknown plugin_id is a no-op."""
    h = MCPHost()
    # create a handle for a plugin not in _runtimes
    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.pid = 8888
    mock_handle = SubprocessHandle(
        pid=8888,
        process=mock_proc,
        job_handle=MagicMock(),
        integrity="low",
        stdin=MagicMock(),
        stdout=MagicMock(),
        plugin_id="ghost_plugin",
        resource_limits=ResourceLimits(),
    )
    # should not raise
    await h._on_plugin_died(mock_handle, "timeout")


@pytest.mark.asyncio
async def test_reload_stopped_plugin(isolated_audit_db):
    """reload() of a stopped plugin (no handle) re-verifies and marks quarantined if invalid."""
    h = MCPHost()
    cfg = AgentConfig()
    cfg.plugins.allow_unsigned = False
    h._config = cfg
    m = _make_manifest("stoprld")
    m.signature_file = Path("missing.sig")

    h._runtimes["stoprld"] = host_mod._PluginRuntime(
        manifest=m,
        verify_result=VerifyResult(status="quarantined"),
        status="stopped",
    )

    await h.reload("stoprld")
    assert h._runtimes["stoprld"].status == "quarantined"


@pytest.mark.asyncio
async def test_stop_skips_already_closed(isolated_audit_db):
    """stop() skips runtimes whose handle is already closed."""
    h = MCPHost()
    m = _make_manifest("closed_plugin")

    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.pid = 7777
    mock_handle = SubprocessHandle(
        pid=7777,
        process=mock_proc,
        job_handle=MagicMock(),
        integrity="low",
        stdin=MagicMock(),
        stdout=MagicMock(),
        plugin_id="closed_plugin",
        resource_limits=ResourceLimits(),
        closed=True,  # already closed
    )
    h._runtimes["closed_plugin"] = host_mod._PluginRuntime(
        manifest=m,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        handle=mock_handle,
    )
    # Should not raise even with a closed handle
    await h.stop()


@pytest.mark.asyncio
async def test_invoke_tool_error_logged(isolated_audit_db):
    """When tools_call raises, a tool_error audit event is written."""
    manifest = _make_manifest(
        "err_plugin", declared_permissions=["tool:err_plugin.fail"],
    )
    vresult = VerifyResult(status="unsigned")
    fake_client = AsyncMock()
    fake_client.tools_call = AsyncMock(side_effect=RuntimeError("oops"))

    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "err_plugin.fail"}],
        granted_permissions={"tool:err_plugin.fail"},
        client=fake_client,
    )
    h = MCPHost()
    h._runtimes["err_plugin"] = fake_runtime

    with pytest.raises(RuntimeError, match="oops"):
        await h.invoke("err_plugin.fail", {})

    rows = audit_mod.query(audit_mod.AuditQuery(event="tool_error"), db_path=isolated_audit_db)
    assert len(rows) == 1
