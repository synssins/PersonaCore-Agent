"""SPEC-03A supervisor tests.

Covers:
* env whitelist round-trip (spawn, ask child to dump env, assert names).
* Job Object + PID exist after spawn and are cleared after terminate.
* Low-integrity fallback path when SetTokenInformation raises.
"""
# ruff: noqa: ARG001, EM101, TRY003, TC003, E402

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="echo_plugin subprocess race on CI py3.12 (task #10)",
)

from workstation_agent.mcp_host import supervisor as sup_mod
from workstation_agent.mcp_host.supervisor import (
    ENV_WHITELIST,
    PluginSupervisor,
    ResourceLimits,
    build_child_env,
)

# ---------------------------------------------------------------------------
# pure-python helpers
# ---------------------------------------------------------------------------


def test_env_whitelist_names_exact() -> None:
    """The whitelist must be the exact SPEC-03A list, no more, no less."""
    expected = {
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
        "USERPROFILE", "USERNAME", "USERDOMAIN",
        "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        "PATHEXT", "PATH", "COMSPEC",
        "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    }
    assert set(ENV_WHITELIST) == expected


def test_build_child_env_adds_plugin_id_and_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("PATH", "C:\\bin")
    monkeypatch.setenv("SECRET_TOKEN", "leak-me")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAsomething")
    env = build_child_env("plug-1")
    assert env["WSA_PLUGIN_ID"] == "plug-1"
    assert env["SYSTEMROOT"] == r"C:\Windows"
    assert env["PATH"] == "C:\\bin"
    assert "SECRET_TOKEN" not in env
    assert "AWS_ACCESS_KEY_ID" not in env


def test_build_child_env_skips_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_WHITELIST:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "C:\\bin")
    env = build_child_env("plug-2")
    assert set(env.keys()) == {"PATH", "WSA_PLUGIN_ID"}


# ---------------------------------------------------------------------------
# spawn / terminate against a REAL subprocess
# ---------------------------------------------------------------------------


def _send_line(handle, obj: dict) -> None:
    handle.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
    handle.stdin.flush()


def _read_line(handle) -> dict:
    line = handle.stdout.readline()
    assert line, "plugin closed stdout without responding"
    return json.loads(line)


def test_spawn_pid_and_job_present_then_terminated(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="echo-1")
    try:
        assert handle.pid > 0
        assert handle.job_handle is not None
        assert handle.integrity in {"low", "medium"}
        assert handle.process.poll() is None, "child exited immediately"

        # Sanity: it actually speaks MCP.
        _send_line(handle, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        resp = _read_line(handle)
        assert resp["id"] == 1
    finally:
        asyncio.run(supervisor.terminate(handle, hard_after=1.0))

    assert handle.closed
    # Job Object closed + subprocess exited.
    assert handle.process.poll() is not None
    for _ in range(20):
        if handle.pid not in supervisor._handles:
            break
        time.sleep(0.05)
    assert handle.pid not in supervisor._handles


def test_env_whitelist_is_enforced_in_child(
    echo_plugin_cmd: list[str],
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL: the audit-found bug guard.

    Set a bogus secret in the parent env, spawn the child, ask it to dump
    its environment, and assert the secret did NOT leak through.
    """
    monkeypatch.setenv("SECRET_LEAK_CANARY_XYZZY", "should-not-appear")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "nope")
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="env-check")
    try:
        _send_line(handle, {"jsonrpc": "2.0", "id": 42, "method": "env/dump"})
        resp = _read_line(handle)
        env_seen = resp["result"]["env"]
        # Every seen key must be either whitelisted or WSA_PLUGIN_ID.
        allowed = set(ENV_WHITELIST) | {"WSA_PLUGIN_ID"}
        stray = set(env_seen.keys()) - allowed
        assert not stray, f"leaked env vars: {sorted(stray)}"
        # And our specific canary is absent:
        assert "SECRET_LEAK_CANARY_XYZZY" not in env_seen
        assert "AWS_SECRET_ACCESS_KEY" not in env_seen
        # WSA_PLUGIN_ID is set correctly.
        assert env_seen["WSA_PLUGIN_ID"] == "env-check"
    finally:
        asyncio.run(supervisor.terminate(handle, hard_after=1.0))


def test_terminate_uses_shutdown_fn_when_provided(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="graceful")
    called = {"count": 0}

    def graceful() -> None:
        called["count"] += 1
        # Tell the child to shut down cleanly.
        _send_line(handle, {"jsonrpc": "2.0", "id": 99, "method": "shutdown"})

    asyncio.run(supervisor.terminate(handle, hard_after=1.5, shutdown_fn=graceful))
    assert called["count"] == 1
    assert handle.closed


def test_terminate_swallows_shutdown_exceptions(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="shutdown-boom")

    def boom() -> None:
        raise RuntimeError("boom")

    # Must not raise: exception is logged, then the hard kill takes over.
    asyncio.run(supervisor.terminate(handle, hard_after=0.2, shutdown_fn=boom))
    assert handle.closed


def test_terminate_idempotent(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="dup-term")
    asyncio.run(supervisor.terminate(handle, hard_after=0.5))
    # Second call is a no-op.
    asyncio.run(supervisor.terminate(handle, hard_after=0.5))
    assert handle.closed


def test_terminate_sync_skips_shutdown_fn(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    """terminate_sync closes the Job Object without needing an event loop."""
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="sync-term")
    supervisor.terminate_sync(handle)
    assert handle.closed
    # Second call is a no-op.
    supervisor.terminate_sync(handle)
    assert handle.closed


# ---------------------------------------------------------------------------
# integrity-level fallback
# ---------------------------------------------------------------------------


def test_low_integrity_fallback_when_token_call_raises(
    echo_plugin_cmd: list[str],
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If SetTokenInformation blows up we must fall back with a WARN log."""

    def _boom() -> None:
        raise OSError("simulated: SetTokenInformation failed on this SKU")

    monkeypatch.setattr(sup_mod, "_make_low_integrity_token", _boom)
    supervisor = PluginSupervisor()
    with caplog.at_level("WARNING", logger="workstation_agent.mcp_host.supervisor"):
        handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="il-fallback")
    try:
        assert handle.integrity == "medium"
        assert any("low-integrity token unavailable" in r.getMessage() for r in caplog.records)
    finally:
        asyncio.run(supervisor.terminate(handle, hard_after=1.0))


def test_low_integrity_fallback_when_spawn_call_raises(
    echo_plugin_cmd: list[str],
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the low-IL spawn itself raises, we still fall back cleanly."""

    def _fake_low_spawn(*a, **kw):
        raise OSError("simulated: CreateProcessAsUser failed")

    monkeypatch.setattr(
        PluginSupervisor, "_spawn_low_integrity", staticmethod(_fake_low_spawn),
    )
    supervisor = PluginSupervisor()
    with caplog.at_level("WARNING", logger="workstation_agent.mcp_host.supervisor"):
        handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="il-spawn-fallback")
    try:
        assert handle.integrity == "medium"
        assert any("low-integrity spawn failed" in r.getMessage() for r in caplog.records)
    finally:
        asyncio.run(supervisor.terminate(handle, hard_after=1.0))


# ---------------------------------------------------------------------------
# Job Object limits actually take effect
# ---------------------------------------------------------------------------


def test_job_object_carries_expected_limits() -> None:
    """Round-trip our limits through win32job.QueryInformationJobObject."""
    import win32job

    limits = ResourceLimits(
        max_memory_mb=64,
        max_job_memory_mb=128,
        max_active_processes=2,
    )
    job = sup_mod._create_job_object(limits)
    info = win32job.QueryInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation,
    )
    flags = info["BasicLimitInformation"]["LimitFlags"]
    assert flags & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert flags & win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
    assert flags & win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
    assert flags & win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    assert info["BasicLimitInformation"]["ActiveProcessLimit"] == 2
    assert info["ProcessMemoryLimit"] == 64 * 1024 * 1024
    assert info["JobMemoryLimit"] == 128 * 1024 * 1024
    sup_mod._close_job(job)


def test_job_object_time_limit_flag_optional() -> None:
    import win32job

    limits = ResourceLimits(job_user_time_100ns=10_000_000)
    job = sup_mod._create_job_object(limits)
    info = win32job.QueryInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation,
    )
    assert info["BasicLimitInformation"]["LimitFlags"] & win32job.JOB_OBJECT_LIMIT_JOB_TIME
    sup_mod._close_job(job)


def test_pump_stderr_survives_broken_stream() -> None:
    """Stderr pump must never crash the host even on a broken stream."""
    import io

    class _Broken(io.RawIOBase):
        def readline(self, *_a, **_kw):
            raise OSError("broken")

    # Should return without raising.
    sup_mod._pump_stderr(_Broken(), "test")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Bug-1 regression: terminate() must not deadlock the event loop
# ---------------------------------------------------------------------------


async def test_terminate_does_not_deadlock_async_shutdown_task(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    """shutdown_fn schedules an async task; that task MUST run before terminate returns.

    Prior implementation called ``handle.process.wait`` synchronously on the
    event-loop thread, so any task scheduled from ``shutdown_fn`` could not
    execute until ``wait`` returned — which itself waited for a plugin whose
    exit signal came from that never-scheduled task. Deadlock.

    The fix off-loads ``wait`` to the default executor and awaits it so the
    loop stays live; this test asserts the scheduled coroutine ran BEFORE
    ``terminate`` returned.
    """
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="deadlock-guard")

    task_ran = asyncio.Event()

    async def scheduled_shutdown() -> None:
        # Simulate an async MCP ``shutdown`` handshake: sleep briefly, mark
        # ran, then push the shutdown message so the child exits.
        await asyncio.sleep(0.05)
        task_ran.set()
        _send_line(handle, {"jsonrpc": "2.0", "id": 77, "method": "shutdown"})

    def shutdown_fn() -> asyncio.Task[None]:
        # Schedule an async task on the running loop, exactly the way an
        # async MCP client's ``shutdown()`` would.
        return asyncio.create_task(scheduled_shutdown())

    await supervisor.terminate(handle, hard_after=2.0, shutdown_fn=shutdown_fn)
    assert task_ran.is_set(), "scheduled shutdown task never ran — event loop was deadlocked"
    assert handle.closed


async def test_terminate_awaits_async_shutdown_fn(
    echo_plugin_cmd: list[str], repo_root: Path,
) -> None:
    """A shutdown_fn that IS itself a coroutine must be awaited."""
    supervisor = PluginSupervisor()
    handle = supervisor.spawn(echo_plugin_cmd, cwd=repo_root, plugin_id="async-shutdown-fn")

    ran = {"count": 0}

    async def coro_shutdown() -> None:
        await asyncio.sleep(0)
        ran["count"] += 1
        _send_line(handle, {"jsonrpc": "2.0", "id": 88, "method": "shutdown"})

    await supervisor.terminate(handle, hard_after=2.0, shutdown_fn=coro_shutdown)
    assert ran["count"] == 1
    assert handle.closed
