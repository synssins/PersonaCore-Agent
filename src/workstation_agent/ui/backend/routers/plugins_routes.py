"""Plugin management routes: GET /plugins, POST /plugins/*.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.mcp_host.loader import TRUSTED_PUBKEYS, discover, verify
from workstation_agent.ui.backend.app import BackendContext, get_context, templates

if TYPE_CHECKING:
    from workstation_agent.config.schema import AgentConfig

log = logging.getLogger(__name__)

router = APIRouter(prefix="/plugins", tags=["plugins"])

_TRUTHY = {"true", "1", "yes", "on"}


def _signature_overview(cfg: AgentConfig | None) -> dict[str, Any]:
    """Compute the real, current signature-verification picture.

    Calls :func:`loader.discover` and :func:`loader.verify` directly against
    whatever plugins are actually installed, verified under *cfg*'s current
    ``allow_unsigned``. Deliberately independent of whether an ``MCPHost`` is
    running: the toggle's banner and confirmation text describe what would
    really happen, not a static description of the setting, and this stays
    accurate even before any host has started.
    """
    allow_unsigned = cfg.plugins.allow_unsigned if cfg is not None else False
    affected: list[dict[str, str]] = []
    try:
        manifests = discover()
    except Exception:
        log.exception("plugin discovery failed while building signature overview")
        manifests = []
    for manifest in manifests:
        try:
            result = verify(manifest, TRUSTED_PUBKEYS, allow_unsigned=allow_unsigned)
        except Exception:
            log.exception("verify failed for plugin=%s", manifest.id)
            continue
        if result.status in {"unsigned", "quarantined"}:
            affected.append({
                "id": manifest.id,
                "name": manifest.name,
                "status": result.status,
            })
    return {"allow_unsigned": allow_unsigned, "affected": affected}


def _update_plugin_config(ctx: BackendContext, plugin_id: str, **kwargs: object) -> None:
    """Helper: update per-plugin config entry."""
    if ctx.config_store is None:
        return
    cfg = ctx.config_store.load()
    from workstation_agent.config.schema import PluginConfig  # noqa: PLC0415
    entry = cfg.plugins.per_plugin.get(plugin_id, PluginConfig())
    for k, v in kwargs.items():
        setattr(entry, k, v)
    cfg.plugins.per_plugin[plugin_id] = entry
    ctx.config_store.save(cfg)


@router.get("", response_class=HTMLResponse)
async def plugins_list(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render plugin list page."""
    plugins: list[Any] = []
    if ctx.mcp_host is not None:
        with contextlib.suppress(Exception):
            plugins = await ctx.mcp_host.plugins()

    cfg = None
    if ctx.config_store is not None:
        with contextlib.suppress(Exception):
            cfg = ctx.config_store.load()

    return templates.TemplateResponse(
        request,
        "plugins.html",
        {"plugins": plugins, "cfg": cfg, "errors": {}, "sig": _signature_overview(cfg)},
    )


@router.post("/signature-verification/enable")
async def signature_verification_enable(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Turn signature verification back on (the safe direction).

    Returning to the safe state is frictionless by design: no confirmation,
    one click. Only *disabling* verification (allowing unsigned plugins)
    requires the deliberate confirmation step below.
    """
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        cfg.plugins.allow_unsigned = False
        ctx.config_store.save(cfg)
    log.info("signature verification re-enabled (allow_unsigned=False)")
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/signature-verification/disable", response_model=None)
async def signature_verification_disable(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    confirm: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Allow unsigned plugins to run — the dangerous direction.

    The gate is server-side, not a client-side ``confirm()``: a request that
    omits ``confirm=true`` (the first click, or a script posting straight to
    this endpoint) never touches the config. It instead re-renders the page
    with the real, current list of plugins this would newly let run
    unverified, and a second form carrying ``confirm=true`` that the operator
    must submit deliberately.
    """
    cfg = None
    if ctx.config_store is not None:
        with contextlib.suppress(Exception):
            cfg = ctx.config_store.load()

    if confirm.strip().lower() not in _TRUTHY:
        plugins: list[Any] = []
        if ctx.mcp_host is not None:
            with contextlib.suppress(Exception):
                plugins = await ctx.mcp_host.plugins()
        return templates.TemplateResponse(
            request,
            "plugins.html",
            {
                "plugins": plugins,
                "cfg": cfg,
                "errors": {},
                "sig": _signature_overview(cfg),
                "signature_confirm_pending": True,
            },
        )

    if ctx.config_store is not None and cfg is not None:
        cfg.plugins.allow_unsigned = True
        ctx.config_store.save(cfg)
    log.warning("signature verification disabled (allow_unsigned=True) — unsigned plugins allowed")
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/{plugin_id}/enable")
async def plugin_enable(
    plugin_id: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Enable a plugin."""
    _update_plugin_config(ctx, plugin_id, enabled=True)
    log.info("plugin enabled: id=%s", plugin_id)
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/{plugin_id}/disable")
async def plugin_disable(
    plugin_id: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Disable a plugin."""
    _update_plugin_config(ctx, plugin_id, enabled=False)
    log.info("plugin disabled: id=%s", plugin_id)
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/{plugin_id}/grant/{perm}")
async def plugin_grant(
    plugin_id: str,
    perm: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Grant a permission to a plugin."""
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        from workstation_agent.config.schema import PluginConfig  # noqa: PLC0415
        entry = cfg.plugins.per_plugin.get(plugin_id, PluginConfig())
        if perm not in entry.granted_permissions:
            entry.granted_permissions = [*entry.granted_permissions, perm]
        cfg.plugins.per_plugin[plugin_id] = entry
        ctx.config_store.save(cfg)
    log.info("permission granted: id=%s perm=%s", plugin_id, perm)
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/install-file", response_model=None)
async def plugin_install_file(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    plugin_file: Annotated[UploadFile, File()],
    acknowledged: Annotated[str, Form()] = "",
) -> HTMLResponse | RedirectResponse:
    """Install a plugin from an uploaded file (multipart).

    Unsigned installs require ``acknowledged=true`` in the form.
    """
    cfg = None
    if ctx.config_store is not None:
        with contextlib.suppress(Exception):
            cfg = ctx.config_store.load()

    allow_unsigned = cfg.plugins.allow_unsigned if cfg is not None else False
    ack_bool = acknowledged.lower() in {"true", "1", "yes", "on"}

    if not allow_unsigned and not ack_bool:
        return templates.TemplateResponse(
            request,
            "plugins.html",
            {
                "plugins": [],
                "cfg": cfg,
                "errors": {
                    "install": "Unsigned plugin installation requires explicit acknowledgment. "
                    "Set acknowledged=true to proceed.",
                },
                "sig": _signature_overview(cfg),
            },
            status_code=400,
        )

    filename = plugin_file.filename or "unknown"
    content = await plugin_file.read()
    log.info(
        "plugin install-file: filename=%s size=%d acknowledged=%s",
        filename, len(content), ack_bool,
    )
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/install-registry")
async def plugin_install_registry(
    registry_url: Annotated[str, Form()],
    ctx: Annotated[BackendContext, Depends(get_context)],  # noqa: ARG001
) -> RedirectResponse:
    """Install a plugin from the registry."""
    log.info("plugin install-registry: url=%s", registry_url)
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/{plugin_id}/reload")
async def plugin_reload(
    plugin_id: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Reload a plugin."""
    if ctx.mcp_host is not None:
        with contextlib.suppress(Exception):
            await ctx.mcp_host.reload(plugin_id)
    log.info("plugin reload: id=%s", plugin_id)
    return RedirectResponse(url="/plugins", status_code=303)
