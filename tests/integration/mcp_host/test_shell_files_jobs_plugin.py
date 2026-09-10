"""End-to-end: the shell/files/jobs plugin through the real host and supervisor.

The unit tests exercise the families in-process.  This one spawns the plugin
the way the product does — signature-verified, low-integrity token, Job Object,
16-variable environment — and calls it through ``MCPHost.invoke``, so it covers
the parts that only exist once there is a subprocess: the dotted tool ids the
gate actually receives, the §5.2 envelope surviving the transport, the
watchdog's ping getting an answer while a tool blocks, and the process limit
being high enough for the job model to work at all.
"""
# ruff: noqa: E402, ANN401, PTH118, ASYNC240
# E402:    the pubkey and sys.path setup must run before the package imports.
# ANN401:  ToolResult payloads are arbitrary JSON documents.
# PTH118/ASYNC240: os.path.join and two tiny file touches; the test is about
#          the plugin, and the blocking cost is microseconds.

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKTREE_SRC = _REPO_ROOT / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))

import workstation_agent.mcp_host.audit as audit_mod
import workstation_agent.mcp_host.host as host_mod
import workstation_agent.mcp_host.loader as loader_mod
import workstation_agent.mcp_host.supervisor as sup_mod
from workstation_agent.config.schema import AgentConfig, PluginConfig
from workstation_agent.mcp_host.host import MCPHost

_PUB = (_REPO_ROOT / "working" / "signing" / "first_party.pub.hex").read_text().strip()
loader_mod.TRUSTED_PUBKEYS.insert(0, bytes.fromhex(_PUB))

_PLUGIN_ID = "shell_files_jobs"


def _bare_interpreter_can_import() -> bool:
    """Can a fresh ``sys.executable`` import this plugin's package?

    In an installed tree, yes — which is what ``host._resolve_entry``'s
    ``-m workstation_agent.plugins.<id>`` relies on.  In a git worktree it is
    no, because the venv's editable install points at the *main* checkout and
    the parent process only sees this one through ``pytest.ini``'s
    ``pythonpath = src``.  That is an artefact of where the tests are run from,
    not a property of the product, so the fixture below shims it out rather
    than letting it masquerade as a plugin defect.
    """
    import subprocess

    probe = subprocess.run(  # noqa: S603
        [sys.executable, "-c", f"import workstation_agent.plugins.{_PLUGIN_ID}"],
        check=False,
        capture_output=True,
    )
    return probe.returncode == 0


@pytest.fixture(autouse=True)
def _entry_resolves_to_this_worktree(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the spawned interpreter at the source tree under test.

    ``runpy.run_module(..., run_name="__main__")`` is what ``-m`` does, so the
    child is the same program by the same path; only how it finds the package
    changes.  Everything the test is actually about — the signature check, the
    low-integrity token, the Job Object, the environment allow-list, the
    JSON-RPC transport, the gate — is untouched.  No-ops once the package is
    installed, so the real ``-m`` spawn is what runs post-merge.
    """
    if _bare_interpreter_can_import():
        return
    real = host_mod._resolve_entry

    def _resolve(manifest: loader_mod.PluginManifest) -> list[str]:
        if manifest.id != _PLUGIN_ID:
            return real(manifest)
        boot = (
            f"import sys; sys.path.insert(0, {str(_WORKTREE_SRC)!r}); "
            f"import runpy; runpy.run_module("
            f"'workstation_agent.plugins.{_PLUGIN_ID}', run_name='__main__')"
        )
        return [sys.executable, "-u", "-c", boot]

    monkeypatch.setattr(host_mod, "_resolve_entry", _resolve)


_TOOLS = {
    "shell.run",
    "files.list",
    "files.read",
    "files.write",
    "jobs.wait",
    "jobs.output",
    "jobs.list",
    "jobs.kill",
}


@pytest.fixture
def agent_config() -> AgentConfig:
    cfg = AgentConfig()
    # Only this plugin; the others are other subtasks' business and spawning
    # eight subprocesses to test one is a slow way to find someone else's bug.
    for manifest in loader_mod.discover():
        cfg.plugins.per_plugin[manifest.id] = PluginConfig(
            enabled=manifest.id == _PLUGIN_ID,
            granted_permissions=sorted(f"tool:{t}" for t in _TOOLS)
            if manifest.id == _PLUGIN_ID
            else [],
        )
    return cfg


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path: Path):
    audit_mod.set_db_path(tmp_path / "audit.db")
    yield
    audit_mod.reset_connection()


async def _confirm_yes(_req: Any) -> bool:
    return True


def _envelope(result: Any) -> dict[str, Any]:
    return json.loads(result.content[0]["text"])


@pytest.fixture
async def host(agent_config: AgentConfig):
    h = MCPHost()
    await h.start(agent_config, confirm_cb=_confirm_yes)
    try:
        yield h
    finally:
        await h.stop()


@pytest.mark.asyncio
async def test_the_plugin_loads_signed_and_advertises_its_eight_tools(host: MCPHost) -> None:
    plugins = {p.id: p for p in await host.plugins()}
    assert _PLUGIN_ID in plugins, f"not loaded: {sorted(plugins)}"
    assert plugins[_PLUGIN_ID].status == "running"
    names = {t.name for t in await host.tools() if t.plugin_id == _PLUGIN_ID}
    assert names == _TOOLS


@pytest.mark.asyncio
async def test_a_pre_approved_call_round_trips_as_a_5_2_envelope(host: MCPHost) -> None:
    result = await host.invoke("jobs.list", {})
    assert result.ok is True
    payload = _envelope(result)
    assert payload["ok"] is True
    assert payload["jobs"] == []


@pytest.mark.asyncio
async def test_a_path_outside_the_declared_roots_is_denied_by_the_gate(host: MCPHost) -> None:
    result = await host.invoke("files.read", {"path": r"C:\Windows\win.ini"})
    assert result.ok is False
    assert result.code == "denied"
    assert result.is_error is False


@pytest.mark.asyncio
async def test_files_write_then_read_inside_the_writable_root(host: MCPHost) -> None:
    target = os.path.join(
        os.path.expandvars(r"%USERPROFILE%\AppData\LocalLow\WorkstationAgent"),
        "integration-b6.txt",
    )
    written = _envelope(await host.invoke("files.write", {"path": target, "content": "b6 ok"}))
    assert written["ok"] is True, written

    read = _envelope(await host.invoke("files.read", {"path": target}))
    assert read["content"] == "b6 ok"
    assert read["total_bytes"] == 5
    Path(target).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_shell_run_always_reaches_the_prompt_and_runs_when_confirmed(
    host: MCPHost,
) -> None:
    """§7 puts shell_run on the always-prompt list; the manifest's empty
    ``cmd:`` allowlist plus a confirmable ``command_outside_allowlist`` is how
    it gets there."""
    result = await host.invoke("shell.run", {"command": "echo integration", "shell": "cmd"})
    payload = _envelope(result)
    assert payload["ok"] is True, payload
    assert payload["job_id"] is None
    assert payload["stdout"].strip() == "integration"


@pytest.mark.asyncio
async def test_shell_run_is_refused_when_nobody_can_confirm(
    agent_config: AgentConfig,
) -> None:
    """Fail-closed: no confirmation callback means the §7 prompt cannot be
    shown, and a call that cannot be confirmed is not run."""
    h = MCPHost()
    await h.start(agent_config, confirm_cb=None)
    try:
        result = await h.invoke("shell.run", {"command": "echo nope", "shell": "cmd"})
        assert result.ok is False
        assert result.code == "unconfirmed"
    finally:
        await h.stop()


@pytest.mark.asyncio
async def test_binary_output_is_refused_across_the_transport(host: MCPHost) -> None:
    """§5.3 at the far end of a real pipe, not just at a function boundary."""
    blob = Path(
        os.path.expandvars(r"%USERPROFILE%\AppData\LocalLow\WorkstationAgent"),
    ) / "integration-b6.bin"
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(bytes(range(256)) * 4)
    try:
        payload = _envelope(await host.invoke("files.read", {"path": str(blob)}))
        assert payload["ok"] is False
        assert payload["code"] == "error"
        assert "binary transfer is not available yet" in payload["reason"]
        assert "content" not in payload
    finally:
        blob.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_a_job_survives_a_watchdog_ping_while_it_blocks(host: MCPHost) -> None:
    """The reason the plugin's loop is threaded.

    ``jobs_wait`` blocks by design.  If the plugin answered ``ping`` only after
    it returned, the watchdog's 5 s window would elapse and the plugin would be
    killed for obeying §5.4.
    """
    runtime = host._runtimes[_PLUGIN_ID]
    started = _envelope(
        await host.invoke(
            "shell.run",
            {"command": "ping -n 30 127.0.0.1 >nul", "shell": "cmd", "wait_s": 25},
        ),
    )
    assert started["state"] == "running", started
    job_id = started["job_id"]

    import asyncio

    waiter = asyncio.create_task(host.invoke("jobs.wait", {"job_id": job_id, "wait_s": 5}))
    await asyncio.sleep(0.5)
    client = runtime.client
    assert client is not None
    assert await client.ping() == {}, "ping was queued behind the blocking call"
    await waiter

    killed = _envelope(await host.invoke("jobs.kill", {"job_id": job_id}))
    assert killed["state"] == "killed"


def test_the_spawned_job_object_can_hold_the_contracts_eight_jobs() -> None:
    """§5.4 needs eight concurrent jobs; each is a process in the same Job
    Object as the plugin.  ``host._spawn`` builds a bare ``ResourceLimits()``,
    so both the default and the plugin's floor have to be big enough."""
    default = sup_mod.ResourceLimits()
    assert default.max_active_processes >= 9
    effective = sup_mod.apply_limit_floor(_PLUGIN_ID, default)
    assert effective.max_active_processes >= 17
    assert effective.max_job_memory_mb >= 2048
