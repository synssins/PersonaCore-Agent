"""First-run wizard routes: GET /first-run, POST /first-run/*.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.ui.backend.app import (
    BackendContext,
    get_context,
    mark_first_run_completed,
    templates,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/first-run", tags=["first-run"])

_WYOMING_PORT_MAX = 65535


@router.get("", response_class=HTMLResponse)
async def first_run_page(request: Request) -> HTMLResponse:
    """Render first-run wizard step 1."""
    return templates.TemplateResponse(
        request, "first_run.html", {"step": 1, "errors": {}},
    )


@router.post("/llm", response_class=HTMLResponse, response_model=None)
async def first_run_llm(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    base_url: Annotated[str, Form()] = "http://192.168.1.150:8053/v1",
    model: Annotated[str, Form()] = "gpt-4o",
    api_key_ref: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Process LLM step of the wizard."""
    errors: dict[str, str] = {}
    if not base_url.startswith("http"):
        errors["base_url"] = "Must be a valid HTTP URL"

    if errors:
        return templates.TemplateResponse(
            request, "first_run.html",
            {"step": 1, "errors": errors, "base_url": base_url, "model": model},
        )

    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        cfg.llm.base_url = base_url  # type: ignore[assignment]
        cfg.llm.model = model
        cfg.llm.api_key_ref = api_key_ref
        ctx.config_store.save(cfg)

    return templates.TemplateResponse(
        request, "first_run.html", {"step": 2, "errors": {}},
    )


@router.post("/wyoming", response_class=HTMLResponse, response_model=None)
async def first_run_wyoming(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    wyoming_host: Annotated[str, Form()] = "192.168.1.150",
    wyoming_port: Annotated[int, Form()] = 10300,
) -> HTMLResponse | RedirectResponse:
    """Process Wyoming step of the wizard."""
    errors: dict[str, str] = {}
    if not (1 <= wyoming_port <= _WYOMING_PORT_MAX):
        errors["wyoming_port"] = "Port must be 1-65535"

    if errors:
        return templates.TemplateResponse(
            request, "first_run.html",
            {"step": 2, "errors": errors,
             "wyoming_host": wyoming_host, "wyoming_port": wyoming_port},
        )

    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        cfg.wyoming.host = wyoming_host
        cfg.wyoming.port = wyoming_port
        ctx.config_store.save(cfg)

    return templates.TemplateResponse(
        request, "first_run.html", {"step": 3, "errors": {}},
    )


@router.post("/complete")
async def first_run_complete(
    ctx: Annotated[BackendContext, Depends(get_context)],  # noqa: ARG001
) -> RedirectResponse:
    """Mark first-run completed and redirect to dashboard."""
    mark_first_run_completed()
    log.info("first-run wizard completed")
    return RedirectResponse(url="/dashboard", status_code=303)
