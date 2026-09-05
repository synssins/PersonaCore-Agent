"""Tests: loopback-only middleware rejects non-127.0.0.1 clients."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.testclient import TestClient

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.ui.backend.app import BackendContext, create_app

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


def test_loopback_allowed(tmp_path):
    """Requests with client=127.0.0.1 are passed through (not 403)."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code != 403


def test_non_loopback_rejected(tmp_path):
    """Requests from a non-loopback IP must be rejected with 403."""
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)

    class _NonLoopbackWrapper:
        """ASGI wrapper that injects a non-loopback client address."""

        def __init__(self, inner: ASGIApp) -> None:
            self._inner = inner

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] in {"http", "websocket"}:
                scope = {**scope, "client": ("10.0.0.1", 9999)}
            await self._inner(scope, receive, send)

    wrapped = _NonLoopbackWrapper(app)
    client = TestClient(wrapped, raise_server_exceptions=True)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 403


def test_loopback_middleware_passes_body(tmp_path):
    """Loopback requests reach routes and return content (not empty 403)."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/first-run")
    assert resp.status_code == 200
    assert len(resp.content) > 0


def test_no_client_header_rejected(tmp_path):
    """Requests with no client info (None) must be rejected with 403."""
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)

    class _NullClientWrapper:
        """ASGI wrapper that sets client=None."""

        def __init__(self, inner: ASGIApp) -> None:
            self._inner = inner

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] in {"http", "websocket"}:
                scope = {**scope, "client": None}
            await self._inner(scope, receive, send)

    wrapped = _NullClientWrapper(app)
    client = TestClient(wrapped, raise_server_exceptions=True)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 403
