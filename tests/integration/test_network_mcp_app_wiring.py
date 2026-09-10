"""Subtask B5 -- the app.py wiring B4 deliberately left for B5.

B4's own handover (network_mcp/server.py's module docstring):

    if cfg.network_mcp.enabled:
        subs.network_mcp = NetworkMCPServer(cfg.network_mcp, mcp_host=subs.mcp_host)
        info = await subs.network_mcp.start()
    # shutdown, beside the uvicorn teardown:
        await subs.network_mcp.stop()

These tests pin that wiring in ``Application._start_network_mcp`` /
``Application._shutdown_async`` without touching real APPDATA state (a stub
``NetworkMCPServer`` is substituted at the module the app imports it from,
the same pattern ``tests/integration/test_confirm_wiring.py`` uses for
``MCPHost``), plus one true end-to-end test that binds a real ephemeral
loopback socket and tears it down cleanly.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import tempfile
from typing import ClassVar

import pytest

from workstation_agent.app import Application
from workstation_agent.config.schema import AgentConfig
from workstation_agent.network_mcp import server as network_mcp_server_mod

# Imported at module (collection) time, deliberately -- not inside the test
# body. The autouse `_stub_server` fixture below monkeypatches
# `network_mcp_server_mod.NetworkMCPServer` to the stub before any test body
# runs; a `from ... import NetworkMCPServer as RealNetworkMCPServer` done
# *inside* a test would resolve to the already-patched stub, not the real
# class, silently defeating the one test that exists to prove the real class
# works.
from workstation_agent.network_mcp.server import (
    NetworkMCPServer as RealNetworkMCPServer,
)

# `test_a_real_endpoint_binds_and_stops_cleanly` stands up a real uvicorn server
# on pytest's main-thread loop and stops it again, so this file is both a
# possible source and a possible victim of sse_starlette's process-global
# shutdown latch. Which tests that latch actually breaks is decided by collection
# order and by scheduling luck, so the file opts in rather than waiting to be
# reordered into failing. See the fixture's docstring in
# tests/integration/conftest.py.
pytestmark = pytest.mark.usefixtures("sse_shutdown_latch_cleared")


def _fake_info(*, running: bool) -> network_mcp_server_mod.NetworkEndpointInfo:
    return network_mcp_server_mod.NetworkEndpointInfo(
        url="https://192.168.1.50:8765/mcp",
        bind_host="192.168.1.50",
        port=8765,
        fingerprint="sha256:" + "ab" * 32,
        token="x" * 64,
        certificate_sans=("192.168.1.50",),
        certificate_expires=dt.datetime.now(dt.UTC) + dt.timedelta(days=3650),
        tool_names=("workstation_status",),
        running=running,
    )


class StubNetworkMCPServer:
    """Records lifecycle calls without binding a real socket."""

    instances: ClassVar[list[StubNetworkMCPServer]] = []

    def __init__(self, config, *, mcp_host=None, state_dir=None) -> None:
        self.config = config
        self.mcp_host = mcp_host
        self.state_dir = state_dir
        self.started = False
        self.stopped = False
        StubNetworkMCPServer.instances.append(self)

    async def start(self):
        self.started = True
        return _fake_info(running=True)

    async def stop(self):
        self.stopped = True

    def info(self):
        return _fake_info(running=self.started and not self.stopped)


@pytest.fixture(autouse=True)
def _reset_instances():
    StubNetworkMCPServer.instances.clear()
    yield
    StubNetworkMCPServer.instances.clear()


@pytest.fixture(autouse=True)
def _stub_server(monkeypatch):
    """Every test but the real-endpoint one gets the stub; each overrides
    freely by re-patching within its own body if it needs something else."""
    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", StubNetworkMCPServer)


# ---------------------------------------------------------------------------
# Disabled: the endpoint is never constructed
# ---------------------------------------------------------------------------


async def test_disabled_by_default_starts_nothing():
    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    assert cfg.network_mcp.enabled is False
    app._subs.config = cfg

    await app._start_network_mcp(cfg)

    assert app._subs.network_mcp is None
    assert StubNetworkMCPServer.instances == []
    health = app._subs.started["network_mcp"]
    assert health.ok is True
    assert health.detail == "disabled"


async def test_stopping_is_a_noop_when_the_endpoint_was_never_enabled():
    app = Application(fake_backends=True, headless=True)
    app._subs.config = AgentConfig()
    await app._start_network_mcp(app._subs.config)

    # Must not raise even though subs.network_mcp is None.
    await app._shutdown_async()
    assert StubNetworkMCPServer.instances == []


# ---------------------------------------------------------------------------
# Enabled: constructed, started, wired into BackendContext, stopped on shutdown
# ---------------------------------------------------------------------------


async def test_enabled_constructs_starts_and_records_health():
    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    cfg.network_mcp.enabled = True
    cfg.network_mcp.bind_host = "192.168.1.50"
    app._subs.config = cfg
    app._subs.mcp_host = object()

    await app._start_network_mcp(cfg)

    assert isinstance(app._subs.network_mcp, StubNetworkMCPServer)
    assert app._subs.network_mcp.started is True
    assert app._subs.network_mcp.mcp_host is app._subs.mcp_host
    health = app._subs.started["network_mcp"]
    assert health.ok is True
    assert "https://192.168.1.50:8765/mcp" in health.detail


async def test_enabled_is_stopped_on_shutdown():
    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    cfg.network_mcp.enabled = True
    app._subs.config = cfg

    await app._start_network_mcp(cfg)
    server = app._subs.network_mcp
    assert server.stopped is False

    await app._shutdown_async()
    assert server.stopped is True


async def test_a_start_failure_is_recorded_not_raised(monkeypatch):
    """One subsystem failing to start must not take the app down with it --
    the same treatment _start_mcp_host and _start_update_poller already get."""

    class ExplodingServer(StubNetworkMCPServer):
        async def start(self):
            msg = "port already in use"
            raise RuntimeError(msg)

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", ExplodingServer)

    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    cfg.network_mcp.enabled = True
    app._subs.config = cfg

    await app._start_network_mcp(cfg)  # must not raise

    health = app._subs.started["network_mcp"]
    assert health.ok is False
    assert "port already in use" in health.detail
    # Shutdown must still tolerate a server object that never finished start().
    await app._shutdown_async()


async def test_backend_context_receives_the_live_network_mcp_server(monkeypatch):
    """The UI's credential surface (ctx.network_mcp) gets a real reference."""
    import workstation_agent.ui.backend.app as backend_app_mod

    captured: dict = {}
    real_create_app = backend_app_mod.create_app

    def _capturing_create_app(ctx=None):
        captured["ctx"] = ctx
        return real_create_app(ctx)

    monkeypatch.setattr(backend_app_mod, "create_app", _capturing_create_app)
    monkeypatch.setenv("PC_AGENT_APPDATA", tempfile.mkdtemp())

    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    cfg.network_mcp.enabled = True
    app._subs.config = cfg
    app._subs.session_store = object()

    await app._start_network_mcp(cfg)
    await app._start_fastapi_backend()
    try:
        assert captured["ctx"].network_mcp is app._subs.network_mcp
        assert isinstance(captured["ctx"].network_mcp, StubNetworkMCPServer)
    finally:
        if app._subs.uvicorn_server is not None:
            app._subs.uvicorn_server.should_exit = True
        if app._subs.uvicorn_task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(app._subs.uvicorn_task, timeout=5.0)


# ---------------------------------------------------------------------------
# End-to-end: a real endpoint binds an ephemeral loopback port and stops cleanly
# ---------------------------------------------------------------------------


async def test_a_real_endpoint_binds_and_stops_cleanly(tmp_path, monkeypatch):
    """No stub here: proves the wiring works against the real NetworkMCPServer.

    ``network_mcp/credentials.py`` resolves its default state directory from
    ``APPDATA`` at *import* time, so setting the env var here would not
    retarget an already-imported module. Instead this pins ``state_dir`` to
    ``tmp_path`` the same way B4's own tests do (``network_mcp/test_server.py``),
    via a factory substituted at the name ``Application._start_network_mcp``
    imports -- everything else about the call is the real class, a real
    bind, real TLS.
    """
    def _factory(config, *, mcp_host=None, state_dir=None):  # noqa: ARG001
        return RealNetworkMCPServer(config, mcp_host=mcp_host, state_dir=tmp_path)

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _factory)

    app = Application(fake_backends=True, headless=True)
    cfg = AgentConfig()
    cfg.network_mcp.enabled = True
    cfg.network_mcp.bind_host = "127.0.0.1"
    cfg.network_mcp.port = 0  # OS picks an ephemeral port
    app._subs.config = cfg

    await app._start_network_mcp(cfg)
    try:
        server = app._subs.network_mcp
        assert server is not None
        assert server.running is True
        assert app._subs.started["network_mcp"].ok is True
    finally:
        await app._shutdown_async()

    assert app._subs.network_mcp.running is False
