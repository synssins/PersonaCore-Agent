"""Unit tests for workstation_agent.mcp_host.host (non-integration paths)."""
# ruff: noqa: ARG001

from __future__ import annotations

import json
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
from workstation_agent.mcp_host.permissions import SessionContext
from workstation_agent.mcp_host.supervisor import ResourceLimits, SubprocessHandle


def _write_args(plugin_id: str) -> str:
    """The argument declaration a ``<plugin>.write`` fixture needs.

    Under default-deny-on-absence a manifest has to say what its tool's
    arguments are before anything downstream (the path guard, the confirm
    branch) can be reached at all.  These fixtures are testing the *confirm*
    machinery, so they declare the minimum that gets them there.
    """
    return f"args:{plugin_id}.write:action:!path=ws_path"


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
async def test_invoke_deny_returns_denied_envelope(isolated_audit_db):
    """invoke() returns a §5.2 `denied` envelope when permissions deny.

    Replaces the former ``pytest.raises(PermissionError)``: §7 says a refusal
    is a normal result, not an error, and §11 item 6 needs the refusal to
    reach the operator in plain English.  Strictly stronger than the raise it
    replaces — it also pins the code, checks the tool never ran, and checks
    the audit row.
    """
    manifest = _make_manifest("perm_plugin", declared_permissions=["tool:other.tool"])
    vresult = VerifyResult(status="unsigned")

    fake_client = AsyncMock()
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=vresult,
        status="running",
        tools=[{"name": "perm_plugin.restricted"}],
        granted_permissions=set(),
        client=fake_client,
    )

    h = MCPHost()
    h._runtimes["perm_plugin"] = fake_runtime

    result = await h.invoke("perm_plugin.restricted", {"x": 1})

    assert result.ok is False
    assert result.code == "denied"
    assert result.reason
    fake_client.tools_call.assert_not_called()

    payload = json.loads(result.content[0]["text"])
    assert payload["ok"] is False
    assert payload["code"] == "denied"

    rows = audit_mod.query(audit_mod.AuditQuery(event="tool_denied"), db_path=isolated_audit_db)
    assert len(rows) == 1
    assert rows[0].code == "denied"


@pytest.mark.asyncio
async def test_invoke_confirm_rejected(isolated_audit_db):
    """invoke() returns `unconfirmed` when the user rejects the confirm prompt."""
    manifest = _make_manifest("confirm_plugin")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:confirm_plugin.write", "path:/safe/", _write_args("confirm_plugin"),
    ]

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

    result = await h.invoke("confirm_plugin.write", {"path": "/unsafe/x.txt"})
    assert result.ok is False
    assert result.code == "unconfirmed"
    assert result.is_error is False, "§7: a refusal is a normal result, not an error"
    fake_runtime.client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_invoke_confirm_accepted(isolated_audit_db):
    """invoke() proceeds when confirm_cb returns True."""
    manifest = _make_manifest("confirm_plugin2")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:confirm_plugin2.write", "path:/safe/", _write_args("confirm_plugin2"),
    ]

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
async def test_start_hands_tts_speak_to_confirm_callback(cfg_allow_unsigned):
    """start() attaches tts_speak to a confirm callback that accepts a voice.

    Presentation (toast + spoken line) lives in the confirm adapter so the two
    share one timeout and one answer; the host's job is to hand the adapter the
    voice the application configured.
    """
    class _Cb:
        def __init__(self) -> None:
            self.voice = None

        def attach_voice(self, voice) -> None:
            self.voice = voice

        async def __call__(self, req) -> bool:  # noqa: ARG002
            return True

    cb = _Cb()
    mock_tts = AsyncMock()

    h = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await h.start(cfg_allow_unsigned, confirm_cb=cb, tts_speak=mock_tts)
    await h.stop()

    assert cb.voice is mock_tts


@pytest.mark.asyncio
async def test_start_tolerates_callback_without_attach_voice(cfg_allow_unsigned):
    """A plain-function confirm callback simply gets no voice — not an error."""
    async def _accept(req: ConfirmationRequestImpl) -> bool:
        return True

    h = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await h.start(cfg_allow_unsigned, confirm_cb=_accept, tts_speak=AsyncMock())
    await h.stop()

    assert h._confirm_cb is _accept


@pytest.mark.asyncio
async def test_start_tolerates_attach_voice_raising(cfg_allow_unsigned):
    """An attach_voice that raises must not take the host down."""
    class _Cb:
        def attach_voice(self, voice) -> None:  # noqa: ARG002
            msg = "nope"
            raise RuntimeError(msg)

        async def __call__(self, req) -> bool:  # noqa: ARG002
            return True

    h = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await h.start(cfg_allow_unsigned, confirm_cb=_Cb(), tts_speak=AsyncMock())
    await h.stop()


@pytest.mark.asyncio
async def test_do_confirm_denies_when_no_callback(isolated_audit_db):
    """No confirm callback wired => deny.  The 'silently denied' bug, asserted."""
    manifest = _make_manifest("nocb")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:nocb.write", "path:/safe/", _write_args("nocb"),
    ]

    fake_client = AsyncMock()
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "nocb.write"}],
        granted_permissions={"tool:nocb.write"},
        client=fake_client,
    )

    h = MCPHost()
    h._runtimes["nocb"] = fake_runtime

    result = await h.invoke("nocb.write", {"path": "/unsafe/x.txt"})
    assert result.ok is False
    assert result.code == "unconfirmed"
    fake_client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_do_confirm_denies_when_callback_raises(isolated_audit_db):
    """An exception inside the confirm callback denies; it never allows."""
    manifest = _make_manifest("boomcb")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:boomcb.write", "path:/safe/", _write_args("boomcb"),
    ]

    fake_client = AsyncMock()
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "boomcb.write"}],
        granted_permissions={"tool:boomcb.write"},
        client=fake_client,
    )

    async def _boom(req: ConfirmationRequestImpl) -> bool:
        msg = "presenter exploded"
        raise RuntimeError(msg)

    h = MCPHost()
    h._confirm_cb = _boom
    h._runtimes["boomcb"] = fake_runtime

    result = await h.invoke("boomcb.write", {"path": "/unsafe/x.txt"})
    assert result.ok is False
    assert result.code == "unconfirmed"
    fake_client.tools_call.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [None, 0, "", "yes", 1, object()])
async def test_do_confirm_requires_literal_true(isolated_audit_db, answer):
    """Only ``True`` allows — a truthy or odd return value still denies."""
    manifest = _make_manifest("truthy")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:truthy.write", "path:/safe/", _write_args("truthy"),
    ]

    fake_client = AsyncMock()
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "truthy.write"}],
        granted_permissions={"tool:truthy.write"},
        client=fake_client,
    )

    async def _weird(req: ConfirmationRequestImpl):
        return answer

    h = MCPHost()
    h._confirm_cb = _weird
    h._runtimes["truthy"] = fake_runtime

    result = await h.invoke("truthy.write", {"path": "/unsafe/x.txt"})
    assert result.ok is False
    assert result.code == "unconfirmed"
    fake_client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_do_confirm_passes_correlation_id(isolated_audit_db):
    """Every prompt carries a correlation id, and it reaches the audit row."""
    manifest = _make_manifest("corr")
    manifest.confirmable_conditions = ["outside_declared_paths"]
    manifest.declared_permissions = [
        "tool:corr.write", "path:/safe/", _write_args("corr"),
    ]

    fake_client = AsyncMock()
    fake_client.tools_call = AsyncMock(return_value={
        "content": [{"type": "text", "text": "ok"}],
        "isError": False,
    })
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "corr.write"}],
        granted_permissions={"tool:corr.write"},
        client=fake_client,
    )

    seen: list[str] = []

    async def _accept(req: ConfirmationRequestImpl) -> bool:
        seen.append(req.correlation_id)
        return True

    h = MCPHost()
    h._confirm_cb = _accept
    h._runtimes["corr"] = fake_runtime

    result = await h.invoke("corr.write", {"path": "/unsafe/x.txt"})
    assert not result.is_error
    assert len(seen) == 1
    assert seen[0]

    # B2 folds the correlation id into its own column instead of leaving it
    # in the free-text `detail` blob, so it is queryable rather than
    # grep-able.  Asserted on the column AND via the filter.
    rows = audit_mod.query(audit_mod.AuditQuery(plugin_id="corr"))
    assert [r.correlation_id for r in rows] == [seen[0], seen[0]]
    assert all("correlation_id=" not in (r.detail or "") for r in rows)

    by_corr = audit_mod.query(audit_mod.AuditQuery(correlation_id=seen[0]))
    assert {r.event for r in by_corr} == {"tool_confirmed", "tool_invoke"}


@pytest.mark.asyncio
async def test_legacy_correlation_id_in_detail_is_recovered_on_read(isolated_audit_db):
    """A pre-migration row keeps its id in `detail`; query() recovers it.

    Those rows cannot be rewritten — that is what append-only means — so the
    backfill has to happen on the read side.
    """
    audit_mod.log(
        audit_mod.AuditEvent(
            event="tool_confirmed",
            plugin_id="legacy",
            detail="correlation_id=abc123def",
        ),
        db_path=isolated_audit_db,
    )
    rows = audit_mod.query(audit_mod.AuditQuery(plugin_id="legacy"), db_path=isolated_audit_db)
    assert rows[0].correlation_id == "abc123def"


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
        "err_plugin",
        declared_permissions=["tool:err_plugin.fail", "args:err_plugin.fail:action"],
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

    result = await h.invoke("err_plugin.fail", {})

    # §5.2: `error` is "anything else, with the underlying message" — a
    # result, not an exception thrown at whatever caller happens to be there.
    assert result.ok is False
    assert result.code == "error"
    assert result.is_error is True
    assert "oops" in (result.reason or "")

    rows = audit_mod.query(audit_mod.AuditQuery(event="tool_error"), db_path=isolated_audit_db)
    assert len(rows) == 1
    assert rows[0].code == "error"


# ---------------------------------------------------------------------------
# §7 confirmation policy (B3) — never/always-prompt, remember, mapping
# ---------------------------------------------------------------------------


def _ok_client() -> AsyncMock:
    client = AsyncMock()
    client.tools_call = AsyncMock(return_value={
        "content": [{"type": "text", "text": "done"}],
        "isError": False,
    })
    return client


def _policy_cfg(*, never=(), always=(), remember=()) -> AgentConfig:
    cfg = AgentConfig()
    cfg.confirmation.never_prompt = list(never)
    cfg.confirmation.always_prompt = list(always)
    cfg.confirmation.remember_for_session = list(remember)
    return cfg


def _serial_write_runtime() -> host_mod._PluginRuntime:
    """A `serial.write` tool whose gate decision is "confirm" for this path."""
    manifest = _make_manifest(
        "serial",
        declared_permissions=[
            "tool:serial.write",
            "path:/safe/",
            "args:serial.write:action:!path=ws_path",
        ],
    )
    manifest.confirmable_conditions = ["outside_declared_paths"]
    return host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "serial.write"}],
        granted_permissions={"tool:serial.write"},
        client=_ok_client(),
    )


def _shell_run_runtime(client: AsyncMock | None = None) -> host_mod._PluginRuntime:
    """A `shell.run` tool whose `cmd:*` allowlist makes the gate say "allow"."""
    manifest = _make_manifest(
        "shell",
        declared_permissions=[
            "tool:shell.run",
            "cmd:*",
            "args:shell.run:action:!command=ws_command",
        ],
    )
    manifest.confirmable_conditions = ["command_outside_allowlist"]
    return host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "shell.run"}],
        granted_permissions={"tool:shell.run"},
        client=client or _ok_client(),
    )


@pytest.mark.asyncio
async def test_never_prompt_suppresses_a_gate_confirm(isolated_audit_db):
    """A never-prompt tool that the gate would confirm does not prompt at all."""
    h = MCPHost()
    h._runtimes["serial"] = _serial_write_runtime()
    h._config = _policy_cfg(never=["serial_write"])

    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb

    result = await h.invoke("serial.write", {"path": "/unsafe/x.txt"})

    assert result.ok is True
    confirm_cb.assert_not_called()

    rows = audit_mod.query(
        audit_mod.AuditQuery(event="tool_confirmed"), db_path=isolated_audit_db,
    )
    assert any(r.decision == "confirm_preapproved" for r in rows)


@pytest.mark.asyncio
async def test_always_prompt_forces_a_prompt_on_a_gate_allow(isolated_audit_db):
    """An always-prompt tool the gate would silently allow still prompts."""
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["shell_run"])

    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb

    result = await h.invoke("shell.run", {"command": "dir"})

    assert result.ok is True
    confirm_cb.assert_awaited_once()


@pytest.mark.asyncio
async def test_capitalised_always_prompt_entry_still_prompts(isolated_audit_db):
    """Rework cycle 1, finding #1 -- the unsafe direction, end to end.

    `Shell_Run` (hand-typed with a capital) must still force a prompt for
    `shell.run`. Before case-folding, `underscore_to_dotted("Shell_Run")`
    stayed `"Shell.Run"` and never matched the gate's lower-case
    `shell.run`, so the tool would have silently fallen through to the
    gate's own "allow" -- no prompt at all for a tool the operator meant to
    always confirm.
    """
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["Shell_Run"])
    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb

    result = await h.invoke("shell.run", {"command": "dir"})

    assert result.ok is True
    confirm_cb.assert_awaited_once()


@pytest.mark.asyncio
async def test_always_prompt_rejection_is_unconfirmed(isolated_audit_db):
    """A forced always-prompt that the operator denies is `unconfirmed`, not a silent allow."""
    h = MCPHost()
    client = _ok_client()
    h._runtimes["shell"] = _shell_run_runtime(client=client)
    h._config = _policy_cfg(always=["shell_run"])
    h._confirm_cb = AsyncMock(return_value=False)

    result = await h.invoke("shell.run", {"command": "dir"})

    assert result.ok is False
    assert result.code == "unconfirmed"
    client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_moving_a_tool_between_lists_takes_effect(isolated_audit_db):
    """set_config (the UI's live push) changes behaviour on the very next call."""
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg()  # shell_run on neither list -> gate's own "allow" stands
    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb

    await h.invoke("shell.run", {"command": "dir"})
    confirm_cb.assert_not_called()

    h.set_config(_policy_cfg(always=["shell_run"]))
    await h.invoke("shell.run", {"command": "dir"})
    confirm_cb.assert_awaited_once()


@pytest.mark.asyncio
async def test_remember_suppresses_second_prompt_same_session(isolated_audit_db):
    """§7: "a burst of serial writes asks once" — same tool, same session."""
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["shell_run"], remember=["shell_run"])
    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb
    session = SessionContext(session_id="s1")

    r1 = await h.invoke("shell.run", {"command": "dir"}, session=session)
    r2 = await h.invoke("shell.run", {"command": "dir /w"}, session=session)

    assert r1.ok is True
    assert r2.ok is True
    confirm_cb.assert_awaited_once()  # only the first call actually prompted


@pytest.mark.asyncio
async def test_remember_does_not_leak_to_a_different_session(isolated_audit_db):
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["shell_run"], remember=["shell_run"])
    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb

    await h.invoke("shell.run", {"command": "dir"}, session=SessionContext(session_id="s1"))
    await h.invoke("shell.run", {"command": "dir"}, session=SessionContext(session_id="s2"))

    assert confirm_cb.await_count == 2  # a different session prompts again


@pytest.mark.asyncio
async def test_remember_does_not_survive_a_restart(cfg_allow_unsigned, isolated_audit_db):
    """§5.5: sessions die with the Agent — MCPHost.start must drop remembered approvals."""
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["shell_run"], remember=["shell_run"])
    h._confirm_cb = AsyncMock(return_value=True)
    session = SessionContext(session_id="s1")

    await h.invoke("shell.run", {"command": "dir"}, session=session)
    assert h._prompt_policy.is_remembered(session.session_id, "shell.run")

    with patch("workstation_agent.mcp_host.host.discover", return_value=[]):
        await h.start(cfg_allow_unsigned)
        await h.stop()

    assert not h._prompt_policy.is_remembered(session.session_id, "shell.run")


@pytest.mark.asyncio
async def test_remember_without_opt_in_prompts_every_time(isolated_audit_db):
    """always-prompt without the remember flag never suppresses -- burst still asks each time."""
    h = MCPHost()
    h._runtimes["shell"] = _shell_run_runtime()
    h._config = _policy_cfg(always=["shell_run"])  # no remember_for_session entry
    confirm_cb = AsyncMock(return_value=True)
    h._confirm_cb = confirm_cb
    session = SessionContext(session_id="s1")

    await h.invoke("shell.run", {"command": "dir"}, session=session)
    await h.invoke("shell.run", {"command": "dir /w"}, session=session)

    assert confirm_cb.await_count == 2


@pytest.mark.asyncio
async def test_never_prompt_cannot_widen_a_gate_denial(isolated_audit_db):
    """Mutation-tested claim: pre-approval must never turn a `deny` into an `allow`.

    `files.read` outside its declared root is a hard `deny` from the gate's
    read/action split (contract §11 item 6) -- never a `confirm`.  Putting it
    on the never-prompt list, and even wiring a confirm callback that would
    happily say yes, must not change the outcome: the policy layer is never
    consulted for a `deny` at all.
    """
    manifest = _make_manifest(
        "files",
        declared_permissions=[
            "tool:files.read",
            "path:/safe/",
            "args:files.read:read:!path=ws_path",
        ],
    )
    client = _ok_client()
    fake_runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "files.read"}],
        granted_permissions={"tool:files.read"},
        client=client,
    )

    h = MCPHost()
    h._runtimes["files"] = fake_runtime
    h._config = _policy_cfg(never=["files_read"])
    confirm_cb = AsyncMock(return_value=True)  # would allow anything, if ever asked
    h._confirm_cb = confirm_cb

    result = await h.invoke("files.read", {"path": "/unsafe/x.txt"})

    assert result.ok is False
    assert result.code == "denied"
    confirm_cb.assert_not_called()
    client.tools_call.assert_not_called()

    rows = audit_mod.query(audit_mod.AuditQuery(event="tool_denied"), db_path=isolated_audit_db)
    assert any(r.code == "denied" for r in rows)
