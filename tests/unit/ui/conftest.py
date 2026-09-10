"""Shared fixtures for UI backend unit tests."""

# ruff: noqa: ANN401

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, overload

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
# Same-origin test client
# ---------------------------------------------------------------------------

#: The origin every UI test client speaks from. It has to be a loopback name --
#: ``ui/backend/csrf.py`` refuses a state-changing request arriving under any
#: other ``Host``, because for such a request there is no honest way to say what
#: the app's own origin is.
TEST_ORIGIN = "http://127.0.0.1:12345"


def ui_test_client(app: ASGIApp, **kwargs: Any) -> TestClient:
    """A :class:`TestClient` that looks like the Agent's own Settings window.

    ``base_url`` fixes the ``Host``; the headers are the two a browser would
    have set. They are sent on every request rather than injected into the ASGI
    scope on purpose: the CSRF check stays in the path of all 170-odd existing
    POST tests, so those tests keep proving that a legitimate same-origin POST
    still reaches its route, instead of quietly bypassing the check they now
    share the app with.
    """
    return TestClient(
        app,
        base_url=TEST_ORIGIN,
        headers={"Origin": TEST_ORIGIN, "Sec-Fetch-Site": "same-origin"},
        **kwargs,
    )


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
        #: Every config pushed via set_config(), most recent last -- lets a
        #: test assert a UI save reached the running host without a restart.
        self.configs_set: list[Any] = []

    async def plugins(self) -> list[FakePluginInfo]:
        return self._plugins

    async def tools(self) -> list[Any]:
        return []

    async def invoke(self, tool_id: str, args: dict[str, Any]) -> object:
        raise NotImplementedError

    async def reload(self, plugin_id: str) -> None:
        self.reloaded.append(plugin_id)

    def set_config(self, config: Any) -> None:
        """Mirror ``MCPHost.set_config`` (B3, §7 policy live-push)."""
        self.configs_set.append(config)


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

@overload
def make_client(
    config_store: Any = ...,
    mcp_host: Any = ...,
    audit_reader: Any = ...,
    log_dir: Path | None = ...,
    tmp_path: Path | None = ...,
    network_mcp: Any = ...,
    network_mcp_factory: Any = ...,
    on_network_mcp_change: Any = ...,
    *,
    return_ctx: Literal[False] = ...,
) -> TestClient: ...


@overload
def make_client(
    config_store: Any = ...,
    mcp_host: Any = ...,
    audit_reader: Any = ...,
    log_dir: Path | None = ...,
    tmp_path: Path | None = ...,
    network_mcp: Any = ...,
    network_mcp_factory: Any = ...,
    on_network_mcp_change: Any = ...,
    *,
    return_ctx: Literal[True],
) -> tuple[TestClient, BackendContext]: ...


def make_client(  # noqa: PLR0913, PLR0917 -- one param per injected BackendContext field
    config_store: Any = None,
    mcp_host: Any = None,
    audit_reader: Any = None,
    log_dir: Path | None = None,
    tmp_path: Path | None = None,
    network_mcp: Any = None,
    network_mcp_factory: Any = None,
    on_network_mcp_change: Any = None,
    *,
    return_ctx: bool = False,
) -> TestClient | tuple[TestClient, BackendContext]:
    """Build a TestClient with a fully-injected BackendContext.

    Overloaded on ``return_ctx`` rather than returning a bare union: dozens of
    existing call sites do ``make_client(...).get(...)``, and a union return
    would make every one of them a type error for the sake of the handful that
    want the context too.

    ``return_ctx`` hands back the context as well, for the tests that need to
    inspect what a request did to it -- ``POST /network-mcp/settings`` replaces
    ``ctx.network_mcp`` with the endpoint it started, and asserting on that is
    the difference between "the page said it started it" and "it started it".
    """
    ctx = BackendContext(
        config_store=config_store or FakeConfigStore(),
        mcp_host=mcp_host if mcp_host is not None else FakeMCPHost(),
        audit_reader=audit_reader or FakeAuditReader(),
        log_dir=log_dir or (tmp_path / "logs" if tmp_path else Path.cwd() / ".logs_test"),
        network_mcp=network_mcp,
        network_mcp_factory=network_mcp_factory,
        on_network_mcp_change=on_network_mcp_change,
    )
    app = create_app(ctx)
    # Wrap with loopback spoof so the middleware passes in tests
    wrapped = _LoopbackASGI(app)
    client = ui_test_client(wrapped, raise_server_exceptions=True)
    return (client, ctx) if return_ctx else client


@pytest.fixture
def fake_store() -> FakeConfigStore:
    return FakeConfigStore()


@pytest.fixture
def client(tmp_path: Path, fake_store: FakeConfigStore) -> TestClient:
    return make_client(config_store=fake_store, tmp_path=tmp_path)
