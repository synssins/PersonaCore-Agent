"""Audit log routes: GET /audit.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates

log = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["audit"])


@dataclass
class _AuditFilters:
    plugin_id: str | None
    tool_id: str | None
    event: str | None
    since: str | None
    until: str | None
    limit: int


@router.get("", response_class=HTMLResponse)
async def audit_page(  # noqa: PLR0913, PLR0917
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    plugin_id: Annotated[str | None, Query()] = None,
    tool_id: Annotated[str | None, Query()] = None,
    event: Annotated[str | None, Query()] = None,
    since: Annotated[str | None, Query()] = None,
    until: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> HTMLResponse:
    """Render the audit log page with optional filters."""
    rows: list[object] = []
    errors: dict[str, str] = {}
    filters = _AuditFilters(
        plugin_id=plugin_id,
        tool_id=tool_id,
        event=event,
        since=since,
        until=until,
        limit=limit,
    )

    if ctx.audit_reader is not None:
        try:
            from workstation_agent.mcp_host.audit import AuditQuery  # noqa: PLC0415
            q = AuditQuery(
                plugin_id=filters.plugin_id,
                tool_id=filters.tool_id,
                event=filters.event,
                since=filters.since,
                until=filters.until,
                limit=filters.limit,
            )
            rows = ctx.audit_reader(q)
        except Exception as exc:
            log.exception("audit GET: query failed")
            errors["_global"] = str(exc)

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "rows": rows,
            "filters": {
                "plugin_id": filters.plugin_id,
                "tool_id": filters.tool_id,
                "event": filters.event,
                "since": filters.since,
                "until": filters.until,
                "limit": filters.limit,
            },
            "errors": errors,
        },
    )
