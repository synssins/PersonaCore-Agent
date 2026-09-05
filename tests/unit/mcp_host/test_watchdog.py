"""SPEC-03A heartbeat watchdog tests."""
# ruff: noqa: ANN401, ARG001, ARG002, EM101, TRY003, TC002

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import pytest

from workstation_agent.mcp_host.supervisor import ResourceLimits, SubprocessHandle
from workstation_agent.mcp_host.watchdog import HeartbeatWatchdog


class _FakeClient:
    def __init__(self, *, will_fail: bool = False) -> None:
        self.will_fail = will_fail
        self.pings = 0

    async def ping(self) -> Any:
        self.pings += 1
        if self.will_fail:
            raise TimeoutError("fake plugin refuses to pong")
        return {}


class _FakeSupervisor:
    def __init__(self) -> None:
        self.terminated: list[int] = []

    async def terminate(self, handle: SubprocessHandle, *, hard_after: float = 5.0) -> None:
        handle.closed = True
        self.terminated.append(handle.pid)


@dataclass
class _StubHandle:
    pid: int
    plugin_id: str = "stub"
    closed: bool = False
    integrity: str = "low"
    job_handle: Any = None
    process: Any = None
    stdin: Any = None
    stdout: Any = None
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)


def _handle(pid: int) -> SubprocessHandle:
    # SubprocessHandle uses dataclass; instantiate with stubs.
    return _StubHandle(pid=pid)  # type: ignore[return-value]


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_ping_success_resets_timer_and_no_termination() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=5.0,
        clock=clock,
    )
    handle = _handle(pid=1234)
    client = _FakeClient(will_fail=False)
    watchdog.register(handle, client)

    clock.advance(2.0)
    await watchdog.tick()
    assert client.pings == 1
    assert supervisor.terminated == []
    # last_ok must have been refreshed to the new "now".
    entry = watchdog._entries[handle.pid]
    assert entry.last_ok == clock.now


async def test_ping_failure_within_timeout_does_not_kill() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=10.0,
        clock=clock,
    )
    handle = _handle(pid=1)
    client = _FakeClient(will_fail=True)
    watchdog.register(handle, client)

    clock.advance(1.0)
    await watchdog.tick()  # ping fails, elapsed = 1.0s < 10s
    assert supervisor.terminated == []
    assert not handle.closed


async def test_ping_timeout_terminates_and_fires_callback() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    died_events: list[tuple[int, str]] = []

    async def on_died(handle: SubprocessHandle, reason: str) -> None:
        died_events.append((handle.pid, reason))

    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=5.0,
        clock=clock,
        on_plugin_died=on_died,
    )
    handle = _handle(pid=42)
    client = _FakeClient(will_fail=True)
    watchdog.register(handle, client)

    clock.advance(6.0)  # elapsed >= timeout
    await watchdog.tick()

    assert supervisor.terminated == [42]
    assert died_events
    assert died_events[0][0] == 42
    assert "heartbeat timeout" in died_events[0][1]
    assert handle.pid not in watchdog._entries


async def test_sync_on_died_callback_is_awaited_correctly() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    called: list[int] = []

    def sync_died(handle: SubprocessHandle, reason: str) -> None:
        called.append(handle.pid)

    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=1.0,
        clock=clock,
        on_plugin_died=sync_died,
    )
    handle = _handle(pid=7)
    watchdog.register(handle, _FakeClient(will_fail=True))
    clock.advance(2.0)
    await watchdog.tick()
    assert called == [7]


async def test_start_stop_lifecycle_runs_a_sweep() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=0.05,
        heartbeat_timeout=10.0,
        clock=clock,
    )
    client = _FakeClient(will_fail=False)
    handle = _handle(pid=100)
    watchdog.register(handle, client)
    await watchdog.start()
    # Second start is a no-op.
    await watchdog.start()
    try:
        for _ in range(50):
            if client.pings >= 1:
                break
            await asyncio.sleep(0.02)
        assert client.pings >= 1
    finally:
        await watchdog.stop()
        await watchdog.stop()  # idempotent


async def test_unregister_removes_entry() -> None:
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(supervisor=supervisor)  # type: ignore[arg-type]
    handle = _handle(pid=11)
    watchdog.register(handle, _FakeClient())
    watchdog.unregister(handle)
    assert handle.pid not in watchdog._entries


async def test_closed_handle_is_purged_by_sweep() -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=0.1,
        heartbeat_timeout=1.0,
        clock=clock,
    )
    handle = _handle(pid=55)
    handle.closed = True
    watchdog.register(handle, _FakeClient())
    await watchdog.tick()
    assert handle.pid not in watchdog._entries


async def test_callback_exceptions_are_logged_not_propagated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()
    supervisor = _FakeSupervisor()

    def raising(handle: SubprocessHandle, reason: str) -> None:
        raise RuntimeError("callback boom")

    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=1.0,
        clock=clock,
        on_plugin_died=raising,
    )
    handle = _handle(pid=88)
    watchdog.register(handle, _FakeClient(will_fail=True))
    clock.advance(5.0)
    with caplog.at_level("ERROR", logger="workstation_agent.mcp_host.watchdog"):
        await watchdog.tick()
    assert any("on_plugin_died" in r.getMessage() for r in caplog.records)


async def test_supervisor_terminate_failure_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()

    class _AngrySupervisor:
        async def terminate(self, *_a, **_kw) -> None:
            raise RuntimeError("cannot terminate")

    watchdog = HeartbeatWatchdog(
        supervisor=_AngrySupervisor(),  # type: ignore[arg-type]
        interval=1.0,
        heartbeat_timeout=1.0,
        clock=clock,
    )
    handle = _handle(pid=91)
    watchdog.register(handle, _FakeClient(will_fail=True))
    clock.advance(5.0)
    with caplog.at_level("ERROR", logger="workstation_agent.mcp_host.watchdog"):
        await watchdog.tick()
    assert any("terminate failed" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Bug-3 regression: pings must run concurrently across plugins
# ---------------------------------------------------------------------------


class _SlowClient:
    """Ping that sleeps ``delay`` seconds — simulates a slow / hung plugin."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.pings = 0

    async def ping(self) -> Any:
        self.pings += 1
        await asyncio.sleep(self.delay)
        return {}


async def test_pings_run_concurrently_not_sequentially() -> None:
    """Total sweep time must be ~= slowest ping, NOT sum of all pings.

    Prior implementation awaited each ping in a for loop; three 300ms pings
    would take ~900ms. With ``asyncio.gather`` all three run concurrently so
    the sweep is bounded by the slowest one (~300ms) plus small overhead.
    """
    supervisor = _FakeSupervisor()
    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=10.0,
        heartbeat_timeout=60.0,
        ping_timeout=5.0,
    )
    # Three plugins with different ping latencies. If sequential the sweep
    # would take ~0.9s (0.3+0.3+0.3); concurrent should be ~0.3s.
    clients = [_SlowClient(0.3), _SlowClient(0.3), _SlowClient(0.3)]
    for i, client in enumerate(clients, start=1):
        watchdog.register(_handle(pid=i), client)

    t0 = time.monotonic()
    await watchdog.tick()
    elapsed = time.monotonic() - t0

    # Every plugin got pinged.
    assert all(c.pings == 1 for c in clients)
    # Concurrency bound: slowest ping + small overhead (< 2x slowest).
    # Sequential would be ~0.9s, so anything < 0.6s proves concurrency.
    assert elapsed < 0.6, f"sweep took {elapsed:.3f}s — pings appear to be sequential"


async def test_ping_timeout_bounds_slow_plugin() -> None:
    """A hung plugin (ping never returns) must be bounded by ``ping_timeout``.

    Without a per-ping timeout, gather() would wait forever for the slow
    plugin, hanging the whole sweep. With wait_for(..., timeout=ping_timeout)
    the hung plugin is cut off and treated as a failure.
    """
    clock = _Clock()
    supervisor = _FakeSupervisor()

    class _Hanger:
        async def ping(self) -> Any:
            await asyncio.sleep(10.0)  # would hang the sweep if not bounded
            return {}

    watchdog = HeartbeatWatchdog(
        supervisor=supervisor,  # type: ignore[arg-type]
        interval=10.0,
        heartbeat_timeout=60.0,
        ping_timeout=0.2,
        clock=clock,
    )
    watchdog.register(_handle(pid=501), _Hanger())
    watchdog.register(_handle(pid=502), _FakeClient(will_fail=False))

    t0 = time.monotonic()
    await watchdog.tick()
    elapsed = time.monotonic() - t0

    # Bounded by ping_timeout (0.2s) — the healthy plugin is fast.
    assert elapsed < 1.0, f"sweep took {elapsed:.3f}s despite per-ping timeout"
