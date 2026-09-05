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
        plugins_routes,
    )

    app.include_router(first_run.router)
    app.include_router(dashboard.router)
    app.include_router(config_routes.router)
    app.include_router(plugins_routes.router)
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
