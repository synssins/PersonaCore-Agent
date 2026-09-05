"""About/update routes: GET /about, POST /about/check-updates, POST /about/rollback.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates

log = logging.getLogger(__name__)

router = APIRouter(prefix="/about", tags=["about"])


@router.get("", response_class=HTMLResponse)
async def about_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the About page."""
    return templates.TemplateResponse(
        request,
        "about.html",
        {
            "version": ctx.current_version,
            "message": None,
        },
    )


@router.post("/check-updates")
async def check_updates(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Trigger an immediate update check."""
    if ctx.update_poller is not None:
        try:
            ctx.update_poller.check_now()
            log.info("about: triggered update check")
        except Exception:
            log.exception("about: check_now failed")
    return RedirectResponse(url="/about", status_code=303)


@router.post("/rollback")
async def rollback(
    ctx: Annotated[BackendContext, Depends(get_context)],  # noqa: ARG001
    target_version: Annotated[str, Form()] = "",
) -> RedirectResponse:
    """Initiate a rollback to a previous version."""
    log.info("about: rollback requested to version=%r", target_version)
    # Actual rollback wired by SPEC-10; here we log the intent.
    return RedirectResponse(url="/about", status_code=303)
