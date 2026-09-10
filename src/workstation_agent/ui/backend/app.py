"""FastAPI application: loopback-only, ephemeral port, dependency-injected context.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Bind address: 127.0.0.1:0 (OS picks ephemeral port at runtime).
Port is written atomically to %APPDATA%\\WorkstationAgent\\ui-port so SPEC-07B
(WebView2) can discover it.

BackendContext carries all subsystem references.  SPEC-10 wiring instantiates
the real objects; tests inject fakes.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request, Response

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from workstation_agent.ui.backend.csrf import SameOriginGuard

log = logging.getLogger(__name__)

_HERE = Path(__file__).parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# First-run flag helpers
# ---------------------------------------------------------------------------

_FIRST_RUN_FLAG_NAME = "first_run_completed"


def _appdata_root() -> Path:
    override = os.environ.get("PC_AGENT_APPDATA")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA") or Path.home()
    return Path(str(base)) / "WorkstationAgent"


def first_run_completed() -> bool:
    """Return True if the first-run wizard has been completed."""
    return (_appdata_root() / _FIRST_RUN_FLAG_NAME).exists()


def mark_first_run_completed() -> None:
    """Write the first-run completion flag file."""
    root = _appdata_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / _FIRST_RUN_FLAG_NAME).touch()


# ---------------------------------------------------------------------------
# BackendContext — dependency-injected surfaces
# ---------------------------------------------------------------------------


@dataclass
class BackendContext:
    """Holds references to all subsystems consumed by UI routes.

    SPEC-10 wiring populates real objects at startup.  Tests inject fakes.
    """

    config_store: Any = field(default=None)
    """Object with ``load() -> AgentConfig`` and ``save(cfg)`` methods."""

    session_store: Any = field(default=None)
    """workstation_agent.llm.session_store.SessionStore (or fake)."""

    mcp_host: Any = field(default=None)
    """workstation_agent.mcp_host.host.MCPHost (or fake)."""

    update_poller: Any = field(default=None)
    """workstation_agent.updater_client.poller.UpdatePoller (or fake)."""

    audit_reader: Any = field(default=None)
    """Callable(AuditQuery) -> list[AuditEvent] (or fake)."""

    network_mcp: Any = field(default=None)
    """workstation_agent.network_mcp.server.NetworkMCPServer (or fake), or
    None when no endpoint object exists yet. Backs the /network-mcp
    identity surface (contract §3: URL and fingerprint, shown once). The
    bearer token is no longer displayed here -- enrolment pushes it to
    PersonaCore directly -- so this object's ``token`` is read only to feed
    the endpoint's own auth, never rendered.

    **Mutable at runtime.** ``POST /network-mcp/settings`` replaces this with a
    server built from the newly-saved config, so enabling the endpoint from
    the UI brings it up without an Agent restart. It is therefore *not* a
    reliable proxy for "the endpoint is enabled" — a stopped server is kept
    here after the operator switches the endpoint off, so the page can still
    show its identity. Ask ``.running`` (or the config) for that.
    """

    network_mcp_factory: Any = field(default=None)
    """Optional ``Callable[[NetworkMcpConfig], NetworkMCPServer]``.

    ``None`` (production) means the router builds a real
    :class:`~workstation_agent.network_mcp.server.NetworkMCPServer` wired to
    :attr:`mcp_host`. Tests inject a factory returning a fake so the endpoint
    lifecycle can be exercised without binding a socket."""

    on_network_mcp_change: Any = field(default=None)
    """Optional ``Callable[[NetworkMCPServer | None], None]``.

    Called whenever the router replaces :attr:`network_mcp`, so the
    composition root's own handle stays in step and a UI-started endpoint is
    stopped at shutdown like an autostarted one. Absent (tests, or a backend
    running standalone) the router simply skips the notification."""

    log_dir: Path = field(default_factory=lambda: _appdata_root() / "logs")
    """Directory containing rotated JSONL log files."""

    current_version: str = field(default="0.1.0.dev0")


# Module-level singleton, replaced by SPEC-10 wiring or test fixtures.
_ctx: BackendContext = BackendContext()


def get_context() -> BackendContext:
    """FastAPI dependency: return the active BackendContext."""
    return _ctx


def set_context(ctx: BackendContext) -> None:
    """Replace the active context (called by SPEC-10 wiring and tests)."""
    global _ctx  # noqa: PLW0603
    _ctx = ctx


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(ctx: BackendContext | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        ctx: Optional BackendContext; if given, replaces the module-level one.

    Returns:
        Configured :class:`fastapi.FastAPI` instance.
    """
    if ctx is not None:
        set_context(ctx)

    app = FastAPI(title="PersonaCore-Agent UI", docs_url=None, redoc_url=None)

    # ------------------------------------------------------------------
    # Same-origin (CSRF) middleware
    #
    # Registered *before* the loopback guard on purpose. Starlette runs the
    # most recently added middleware outermost, so this ordering leaves the
    # loopback guard on the outside exactly where it already was: an HTTP
    # request from off-machine still gets "Forbidden: loopback only" and never
    # reaches this check.
    #
    # This is middleware and not a per-form token so that a route added later
    # is covered without anyone having to remember it -- which is why it is
    # raw ASGI rather than ``app.middleware("http")``. HTTP middleware is only
    # ever handed an ``http`` scope, so a WebSocket route added later would
    # have slipped past both this check and the loopback guard above; this
    # surface has no WebSocket routes, so :class:`SameOriginGuard` refuses the
    # upgrade outright. See ``ui/backend/csrf.py`` for that, for the mechanism,
    # and for the reasoning on requests that carry no ``Origin`` at all.
    # ------------------------------------------------------------------
    app.add_middleware(SameOriginGuard)

    # ------------------------------------------------------------------
    # Loopback-only middleware
    # ------------------------------------------------------------------

    @app.middleware("http")
    async def _loopback_guard(
        request: Request,
        call_next: Callable[[Request], Coroutine[Any, Any, Response]],
    ) -> Response:
        client = request.client
        if client is None or client.host != "127.0.0.1":
            return Response(status_code=403, content="Forbidden: loopback only")
        return await call_next(request)

    # ------------------------------------------------------------------
    # Static files
    # ------------------------------------------------------------------
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    from workstation_agent.ui.backend.routers import (  # noqa: PLC0415
        about_routes,
        audit_routes,
        config_routes,
        dashboard,
        first_run,
        logs_routes,
        network_mcp_routes,
        plugins_routes,
    )

    app.include_router(first_run.router)
    app.include_router(dashboard.router)
    app.include_router(config_routes.router)
    app.include_router(plugins_routes.router)
    app.include_router(network_mcp_routes.router)
    app.include_router(audit_routes.router)
    app.include_router(logs_routes.router)
    app.include_router(about_routes.router)

    # ------------------------------------------------------------------
    # Root redirect
    # ------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def _root() -> RedirectResponse:
        if first_run_completed():
            return RedirectResponse(url="/dashboard")
        return RedirectResponse(url="/first-run")

    return app


# ---------------------------------------------------------------------------
# Port-file helper (called by SPEC-10 after binding)
# ---------------------------------------------------------------------------


def write_port_file(port: int) -> None:
    """Write *port* atomically to %APPDATA%\\WorkstationAgent\\ui-port.

    Args:
        port: The ephemeral port number assigned by the OS.
    """
    root = _appdata_root()
    root.mkdir(parents=True, exist_ok=True)
    dest = root / "ui-port"
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(str(port), encoding="utf-8")
    tmp.replace(dest)
    log.info("UI port file written: port=%d path=%s", port, dest)
