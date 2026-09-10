"""Audit log routes: GET /audit.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from workstation_agent.network_mcp.tools import internal_name_for_wire, wire_name
from workstation_agent.ui.backend.app import BackendContext, get_context, templates

log = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["audit"])

#: Shown when the operator's filter was translated from the wire spelling.
#: Silently searching for something other than what he typed would be its own
#: small lie, even when the translation is right.
TOOL_FILTER_TRANSLATED_NOTE = (
    "Showing {wire}, which the Agent records internally as {internal}. "
    "Either spelling works in this box."
)


def _resolve_tool_filter(typed: str | None) -> tuple[str | None, str]:
    """The tool id to query for, plus a note if it is not what he typed.

    Audit rows carry the **internal** dotted id, because that is what
    ``MCPHost.invoke`` is called with. The owner types the **wire** name,
    because that is the one PersonaCore shows him and the one this page now
    displays. A filter box that only understood the stored spelling would send
    him away believing there were no records for a tool he had just watched run.

    The translation is a table lookup
    (:func:`~workstation_agent.network_mcp.tools.internal_name_for_wire`), never
    a string substitution: ``_`` → ``.`` cannot be inverted reliably, and a
    guess here would quietly filter for a tool that does not exist. Anything the
    table does not know is passed through exactly as typed.
    """
    if not typed:
        return typed, ""
    wanted = typed.strip()
    if not wanted or "." in wanted:
        return typed, ""
    internal = internal_name_for_wire(wanted)
    if internal is None or internal == wanted:
        return typed, ""
    return internal, TOOL_FILTER_TRANSLATED_NOTE.format(wire=wanted, internal=internal)


def _audit_view_rows(rows: list[object]) -> list[dict[str, object]]:
    """Audit records with the tool named the way the operator knows it.

    The wire name leads and the dotted one follows it, the same order as the
    permissions page: one tool, two spellings, and he should never have to know
    the second one to recognise the first.
    """
    view: list[dict[str, object]] = []
    for row in rows:
        tool_id = str(getattr(row, "tool_id", "") or "")
        view.append({
            "ts": getattr(row, "ts", ""),
            "event": getattr(row, "event", ""),
            "plugin_id": getattr(row, "plugin_id", "") or "",
            "tool_wire": wire_name(tool_id),
            "tool_internal": tool_id,
            "decision": getattr(row, "decision", "") or "",
            "result": getattr(row, "result", "") or "",
            "detail": getattr(row, "detail", "") or "",
        })
    return view


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

    queried_tool, tool_note = _resolve_tool_filter(filters.tool_id)

    if ctx.audit_reader is not None:
        try:
            from workstation_agent.mcp_host.audit import AuditQuery  # noqa: PLC0415
            q = AuditQuery(
                plugin_id=filters.plugin_id,
                tool_id=queried_tool,
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
            "rows": _audit_view_rows(rows),
            "tool_note": tool_note,
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
