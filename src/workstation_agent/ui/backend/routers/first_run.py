"""First-run wizard routes: GET /first-run, POST /first-run/*.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from workstation_agent.ui.backend.app import (
    BackendContext,
    get_context,
    mark_first_run_completed,
    templates,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/first-run", tags=["first-run"])

_WYOMING_PORT_MAX = 65535


def _split_url(url: str, default_port: int = 8053) -> tuple[str, int]:
    """Split a URL (or bare host) into ``(host, port)`` — best-effort.

    Accepts ``http://192.168.1.150:8053/v1``, ``192.168.1.150:8053``,
    ``192.168.1.150`` — anything reasonable a user might paste. Extra path
    segments (``/v1``) are discarded; the caller reappends them.
    """
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or "192.168.1.150"
    port = parsed.port or default_port
    return host, port


def _build_base_url(host: str, port: int) -> str:
    """Assemble ``http://<host>:<port>/v1`` — auto-adds the ``/v1`` suffix."""
    return f"http://{host}:{port}/v1"


@router.get("", response_class=HTMLResponse)
async def first_run_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render first-run wizard step 1 with pre-populated values from config."""
    host, port, model = "192.168.1.150", 8053, "gpt-4o"
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        host, port = _split_url(str(cfg.llm.base_url))
        model = cfg.llm.model
    return templates.TemplateResponse(
        request, "first_run.html",
        {"step": 1, "errors": {}, "llm_host": host, "llm_port": port, "model": model},
    )


@router.get("/detect-models", response_model=None)
async def detect_models(
    host: Annotated[str, Query()] = "",
    port: Annotated[int, Query()] = 0,
    api_key: Annotated[str, Query()] = "",
) -> JSONResponse:
    """Probe ``http://host:port/v1/models`` and return the model IDs.

    Works with or without an API key. Any transport / auth error returns
    ``{"models": [], "error": "..."}`` so the UI can fall back to manual entry.
    """
    if not host or not port:
        return JSONResponse({"models": [], "error": "host and port are required"})
    url = _build_base_url(host, port) + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code >= 400:
            return JSONResponse({
                "models": [], "error": f"HTTP {resp.status_code}",
            })
        payload = resp.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return JSONResponse({"models": [], "error": "unexpected response shape"})
        ids = [item.get("id") for item in data if isinstance(item, dict) and item.get("id")]
        return JSONResponse({"models": ids, "error": ""})
    except (httpx.HTTPError, ValueError) as exc:
        return JSONResponse({"models": [], "error": str(exc)})


@router.post("/llm", response_class=HTMLResponse, response_model=None)
async def first_run_llm(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    llm_host: Annotated[str, Form()] = "192.168.1.150",
    llm_port: Annotated[int, Form()] = 8053,
    model: Annotated[str, Form()] = "gpt-4o",
    api_key_ref: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Process LLM step of the wizard."""
    errors: dict[str, str] = {}
    llm_host = llm_host.strip()
    # Accept the whole URL pasted into the host field — reparse.
    if "://" in llm_host or "/" in llm_host:
        llm_host, port_guess = _split_url(llm_host, default_port=llm_port)
        llm_port = port_guess
    if not llm_host:
        errors["llm_host"] = "Host is required"
    if not (1 <= llm_port <= _WYOMING_PORT_MAX):
        errors["llm_port"] = f"Port must be 1-{_WYOMING_PORT_MAX}"
    if not model.strip():
        errors["model"] = "Model name is required"

    if errors:
        return templates.TemplateResponse(
            request, "first_run.html",
            {"step": 1, "errors": errors, "llm_host": llm_host,
             "llm_port": llm_port, "model": model, "api_key_ref": api_key_ref},
        )

    base_url = _build_base_url(llm_host, llm_port)

    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        cfg.llm.base_url = base_url  # type: ignore[assignment]
        cfg.llm.model = model.strip()
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

    input_devices, output_devices = _enumerate_audio_devices()
    selected_in = selected_out = ""
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        selected_in = cfg.audio.input_device or ""
        selected_out = cfg.audio.output_device or ""
    return templates.TemplateResponse(
        request, "first_run.html",
        {"step": 3, "errors": {}, "input_devices": input_devices,
         "output_devices": output_devices,
         "selected_input": selected_in, "selected_output": selected_out},
    )


@router.post("/audio", response_class=HTMLResponse, response_model=None)
async def first_run_audio(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    input_device: Annotated[str, Form()] = "",
    output_device: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Save the selected audio devices (empty string = OS default)."""
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        cfg.audio.input_device = input_device.strip() or None
        cfg.audio.output_device = output_device.strip() or None
        ctx.config_store.save(cfg)
    return templates.TemplateResponse(
        request, "first_run.html", {"step": 4, "errors": {}},
    )


@router.post("/complete")
async def first_run_complete(
    ctx: Annotated[BackendContext, Depends(get_context)],  # noqa: ARG001
) -> RedirectResponse:
    """Mark first-run completed and redirect to dashboard."""
    mark_first_run_completed()
    log.info("first-run wizard completed")
    return RedirectResponse(url="/dashboard", status_code=303)


def _enumerate_audio_devices() -> tuple[list[str], list[str]]:
    """Return ``(input_device_names, output_device_names)``.

    Uses ``sounddevice.query_devices()``; falls back to empty lists if the
    library or the driver is unavailable (headless CI, etc.).
    """
    try:
        import sounddevice as sd  # noqa: PLC0415
        devs = sd.query_devices()
    except Exception:  # noqa: BLE001
        return [], []
    inputs: list[str] = []
    outputs: list[str] = []
    for dev in devs:
        if not isinstance(dev, dict):
            continue
        name = dev.get("name")
        if not name:
            continue
        if dev.get("max_input_channels", 0) > 0:
            inputs.append(str(name))
        if dev.get("max_output_channels", 0) > 0:
            outputs.append(str(name))
    return inputs, outputs
