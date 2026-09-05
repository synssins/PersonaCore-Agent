"""Dashboard route: GET /dashboard.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

_LAST_EXCHANGES = 5


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the main dashboard page."""
    cfg = None
    if ctx.config_store is not None:
        try:
            cfg = ctx.config_store.load()
        except Exception:
            log.exception("dashboard: failed to load config")

    plugin_statuses: list[dict[str, str]] = []
    if ctx.mcp_host is not None:
        try:
            import asyncio  # noqa: PLC0415
            plugins = await asyncio.wait_for(ctx.mcp_host.plugins(), timeout=2.0)
            plugin_statuses = [
                {"id": p.id, "name": p.name, "status": p.status}
                for p in plugins
            ]
        except Exception:  # noqa: BLE001
            log.debug("dashboard: mcp_host.plugins() unavailable")

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "cfg": cfg,
            "plugin_statuses": plugin_statuses,
            "version": ctx.current_version,
        },
    )
