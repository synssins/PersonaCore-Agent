"""Shared fixtures for UI backend unit tests."""

# ruff: noqa: ANN401

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from starlette.testclient import TestClient

from workstation_agent.config.schema import AgentConfig
from workstation_agent.ui.backend.app import BackendContext, create_app

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

# ---------------------------------------------------------------------------
# Loopback-spoofing ASGI wrapper for tests
# ---------------------------------------------------------------------------


class _LoopbackASGI:
    """ASGI middleware that overrides scope['client'] to (127.0.0.1, 12345)."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in {"http", "websocket"}:
            scope = {**scope, "client": ("127.0.0.1", 12345)}
        await self._app(scope, receive, send)


# ---------------------------------------------------------------------------
# Fake config store
# ---------------------------------------------------------------------------

class FakeConfigStore:
    """In-memory config store for testing."""

    def __init__(self, cfg: AgentConfig | None = None) -> None:
        self._cfg = cfg or AgentConfig()

    def load(self) -> AgentConfig:
        return self._cfg

    def save(self, cfg: AgentConfig) -> None:
        self._cfg = cfg


# ---------------------------------------------------------------------------
# Fake MCP host
# ---------------------------------------------------------------------------

@dataclass
class FakePluginInfo:
    id: str = "test_plugin"
    name: str = "Test Plugin"
    version: str = "1.0.0"
    status: str = "running"
    signature_status: str = "trusted"
    granted_permissions: list[str] = field(default_factory=list)
    resource_limits: dict[str, Any] = field(default_factory=dict)
    integrity: str = "high"
    pid: int | None = None


class FakeMCPHost:
    def __init__(self, plugins_list: list[FakePluginInfo] | None = None) -> None:
        self._plugins = plugins_list or []
        self.reloaded: list[str] = []

    async def plugins(self) -> list[FakePluginInfo]:
        return self._plugins

    async def tools(self) -> list[Any]:
        return []

    async def invoke(self, tool_id: str, args: dict[str, Any]) -> object:
        raise NotImplementedError

    async def reload(self, plugin_id: str) -> None:
        self.reloaded.append(plugin_id)


# ---------------------------------------------------------------------------
# Fake audit reader
# ---------------------------------------------------------------------------

class FakeAuditReader:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def __call__(self, _query: object) -> list[Any]:
        return self._rows


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def make_client(
    config_store: Any = None,
    mcp_host: Any = None,
    audit_reader: Any = None,
    log_dir: Path | None = None,
    tmp_path: Path | None = None,
) -> TestClient:
    """Build a TestClient with a fully-injected BackendContext."""
    ctx = BackendContext(
        config_store=config_store or FakeConfigStore(),
        mcp_host=mcp_host or FakeMCPHost(),
        audit_reader=audit_reader or FakeAuditReader(),
        log_dir=log_dir or (tmp_path / "logs" if tmp_path else Path.cwd() / ".logs_test"),
    )
    app = create_app(ctx)
    # Wrap with loopback spoof so the middleware passes in tests
    wrapped = _LoopbackASGI(app)
    return TestClient(wrapped, raise_server_exceptions=True)


@pytest.fixture
def fake_store() -> FakeConfigStore:
    return FakeConfigStore()


@pytest.fixture
def client(tmp_path: Path, fake_store: FakeConfigStore) -> TestClient:
    return make_client(config_store=fake_store, tmp_path=tmp_path)
