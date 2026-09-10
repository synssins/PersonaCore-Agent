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
from workstation_agent.mcp_host.permissions import (
    WILDCARD,
    always_denied_guards,
    grantable_permissions,
    parse_declared_permissions,
)
from workstation_agent.ui.backend.app import BackendContext, get_context, templates

if TYPE_CHECKING:
    from workstation_agent.config.schema import AgentConfig

log = logging.getLogger(__name__)

router = APIRouter(prefix="/plugins", tags=["plugins"])

_TRUTHY = {"true", "1", "yes", "on"}

#: Prefix of a tool-identity grant, as the gate spells it.
_TOOL_PREFIX = "tool:"

#: Shown against a granted permission the plugin's manifest no longer declares.
#: Such a grant is inert -- the identity gate requires *both* halves -- and the
#: page has to say so rather than listing it as though it were doing something.
STALE_GRANT_NOTE = "granted, but the plugin no longer declares it, so it has no effect"

#: Shown against a tool that is granted but whose manifest carries no ``args:``
#: entry.  The identity gate passes and the declaration gate then refuses every
#: call.  Saying "Allowed" and stopping there would be a lie of omission.
NO_ARG_DECLARATION_NOTE = (
    "the plugin's signed manifest does not declare this tool's arguments, "
    "so calls to it are refused even when it is allowed here"
)

#: What ``*`` actually buys.  Spelled out because a control that reads as
#: "allow everything" and is not would be worse than no control at all.
WILDCARD_NOTE = (
    "tool identity only — it lets the plugin be allowed to call any tool it "
    "ships, and every one of those calls is still refused unless the signed "
    "manifest declares that tool's arguments, and is still checked against the "
    "folders, commands and sites the manifest declares"
)

GRANT_NOT_DECLARED_ERROR = (
    "The {plugin!r} plugin does not declare {perm!r} in its signed manifest, so "
    "this workstation cannot allow it. Nothing was changed. A permission has to "
    "be declared by the plugin before it can be allowed here — granting one "
    "the plugin never declared would have no effect anyway, because every call "
    "using it would still be refused."
)

GRANT_UNKNOWN_PLUGIN_ERROR = (
    "There is no plugin called {plugin!r} loaded on this workstation, so there "
    "is no signed manifest to say what it may be allowed to do. Nothing was "
    "changed."
)


def _plugin_rows(plugins: list[Any], cfg: AgentConfig | None) -> list[dict[str, Any]]:
    """One permissions view per plugin: declared, granted, and what is refused.

    Three questions, answered from two sources and nothing else. What the
    plugin *can* ask for comes from :func:`grantable_permissions` over the
    **signed** ``declared_permissions`` -- the same function the gate's
    identity check uses, so the page cannot offer a control the gate would
    never honour. What it is *currently allowed* comes from the operator's
    config. What happens when it asks for anything else is read off
    ``_HARD_GUARDS`` minus whatever the manifest declares confirmable.
    """
    per_plugin = cfg.plugins.per_plugin if cfg is not None else {}
    rows: list[dict[str, Any]] = []
    for plugin in plugins:
        plugin_id = str(getattr(plugin, "id", ""))
        declared_raw = list(getattr(plugin, "declared_permissions", []) or [])
        confirmable = [
            str(c) for c in (getattr(plugin, "confirmable_conditions", []) or [])
        ]
        entry = per_plugin.get(plugin_id)
        granted = set(entry.granted_permissions) if entry is not None else set()
        declarations = parse_declared_permissions(plugin_id, declared_raw)

        permissions: list[dict[str, Any]] = []
        for perm in grantable_permissions(declared_raw):
            is_wildcard = perm == WILDCARD
            tool = "" if is_wildcard else perm[len(_TOOL_PREFIX):]
            note = ""
            if is_wildcard:
                note = WILDCARD_NOTE
            elif tool.strip().lower() not in declarations:
                note = NO_ARG_DECLARATION_NOTE
            permissions.append({
                "perm": perm,
                "label": "Any tool this plugin ships" if is_wildcard else tool,
                "wildcard": is_wildcard,
                "granted": perm in granted,
                "note": note,
            })

        declared_set = set(grantable_permissions(declared_raw))
        stale = sorted(g for g in granted if g not in declared_set)

        rows.append({
            "id": plugin_id,
            "name": getattr(plugin, "name", plugin_id),
            "permissions": permissions,
            "stale": stale,
            "guards": [
                {"name": name, "reason": reason}
                for name, reason in always_denied_guards(confirmable)
            ],
            "confirmable": sorted(
                {c for c, _ in always_denied_guards([])} & set(confirmable),
            ),
        })
    return rows


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
        {
            "plugins": plugins,
            "cfg": cfg,
            "errors": {},
            "sig": _signature_overview(cfg),
            "perm_rows": _plugin_rows(plugins, cfg),
        },
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
                "perm_rows": _plugin_rows(plugins, cfg),
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


async def _loaded_plugins(ctx: BackendContext) -> list[Any]:
    """Every plugin the host knows about, or an empty list if it cannot say."""
    if ctx.mcp_host is None:
        return []
    try:
        return list(await ctx.mcp_host.plugins())
    except Exception:
        log.exception("could not list plugins")
        return []


def _push_to_running_host(ctx: BackendContext, cfg: AgentConfig) -> None:
    """Best-effort live-push of *cfg* so the next tool call sees the change.

    ``MCPHost.start`` snapshots each plugin's grants into its runtime record and
    the gate reads that snapshot, so a saved grant that is not pushed does not
    take effect until the Agent restarts. The page would then say "Allowed"
    while the gate went on denying -- the same disagreement between screen and
    behaviour that this whole subtask exists to end.
    """
    if ctx.mcp_host is None:
        return
    push = getattr(ctx.mcp_host, "set_config", None)
    if not callable(push):
        return
    try:
        push(cfg)
    except Exception:
        log.exception("permissions: failed to push config to mcp_host")


def _refused_permission_page(
    request: Request,
    plugins: list[Any],
    cfg: AgentConfig | None,
    message: str,
) -> HTMLResponse:
    """Redraw Plugins from what is *stored*, with *message*, and a 400.

    Redrawn from storage on purpose: the point of a refusal is that nothing
    moved, so the page the operator is left looking at has to be the page he
    would have got by not clicking at all.
    """
    return templates.TemplateResponse(
        request,
        "plugins.html",
        {
            "plugins": plugins,
            "cfg": cfg,
            "errors": {"permissions": message},
            "sig": _signature_overview(cfg),
            "perm_rows": _plugin_rows(plugins, cfg),
        },
        status_code=400,
    )


@router.post("/{plugin_id}/grant/{perm}", response_model=None)
async def plugin_grant(
    request: Request,
    plugin_id: str,
    perm: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse | RedirectResponse:
    """Allow *plugin_id* to use *perm*, if its signed manifest declares it.

    **Granting is bounded by the declaration.** The identity gate
    (``permissions._check_tool_permission``) allows a call only when the
    permission is in the plugin's signed ``declared_permissions`` *and* in the
    operator's granted set, so a grant for something never declared could never
    permit anything -- it would sit in the config looking like an authority the
    owner had handed out, and deny every call. This route therefore refuses it
    outright rather than storing it, and the page never offers it.

    The bound is read from the same
    :func:`~workstation_agent.mcp_host.permissions.grantable_permissions` the
    gate uses, so the two cannot drift apart.

    Idempotent: granting what is already granted changes nothing and is not an
    error. The owner clicking twice is not a mistake he should be told off for.
    """
    plugins = await _loaded_plugins(ctx)
    cfg = None
    if ctx.config_store is not None:
        with contextlib.suppress(Exception):
            cfg = ctx.config_store.load()

    match = next((p for p in plugins if str(getattr(p, "id", "")) == plugin_id), None)
    if match is None:
        log.warning("permission grant refused: unknown plugin id=%s", plugin_id)
        return _refused_permission_page(
            request, plugins, cfg,
            GRANT_UNKNOWN_PLUGIN_ERROR.format(plugin=plugin_id),
        )

    declared = grantable_permissions(getattr(match, "declared_permissions", []) or [])
    if perm not in declared:
        log.warning(
            "permission grant refused: id=%s perm=%s is not declared",
            plugin_id, perm,
        )
        return _refused_permission_page(
            request, plugins, cfg,
            GRANT_NOT_DECLARED_ERROR.format(plugin=plugin_id, perm=perm),
        )

    if ctx.config_store is not None and cfg is not None:
        from workstation_agent.config.schema import PluginConfig  # noqa: PLC0415
        entry = cfg.plugins.per_plugin.get(plugin_id, PluginConfig())
        if perm not in entry.granted_permissions:
            entry.granted_permissions = [*entry.granted_permissions, perm]
        cfg.plugins.per_plugin[plugin_id] = entry
        ctx.config_store.save(cfg)
        _push_to_running_host(ctx, cfg)
    log.info("permission granted: id=%s perm=%s", plugin_id, perm)
    return RedirectResponse(url="/plugins", status_code=303)


@router.post("/{plugin_id}/revoke/{perm}")
async def plugin_revoke(
    plugin_id: str,
    perm: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Take *perm* back from *plugin_id*.

    A grant that cannot be taken back is not a control, so this is the other
    half of :func:`plugin_grant` and not an afterthought.

    Deliberately **not** bounded by the declaration, where granting is. The
    grants most worth removing are exactly the ones a manifest no longer
    declares -- a plugin updated to drop a tool leaves the owner's grant behind
    it -- and a revoke that refused those would strand them in the config with
    no way to clear them but the config file, which is the thing this product
    does not ask of him. Removing an authority can only ever narrow what is
    permitted, so there is nothing here for the bound to protect.

    Idempotent: revoking what is not granted changes nothing and is not an
    error.
    """
    if ctx.config_store is not None:
        cfg = ctx.config_store.load()
        entry = cfg.plugins.per_plugin.get(plugin_id)
        if entry is not None and perm in entry.granted_permissions:
            entry.granted_permissions = [p for p in entry.granted_permissions if p != perm]
            cfg.plugins.per_plugin[plugin_id] = entry
            ctx.config_store.save(cfg)
            _push_to_running_host(ctx, cfg)
    log.info("permission revoked: id=%s perm=%s", plugin_id, perm)
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
                "perm_rows": [],
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


@router.post("/reload")
async def plugin_reload_all(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Reload every loaded plugin.

    The tray's "Reload plugins" item has been posting here since it shipped and
    getting a 404: the only reload route was ``/plugins/{plugin_id}/reload``,
    which cannot express "all of them", and the tray has no plugin list to
    iterate. The menu item is a real feature -- it carries the pending-plugin
    badge, and it is how the operator applies a plugin change without opening
    the UI -- so the missing route is the thing that was wrong, not the caller.

    Each plugin is reloaded independently: one plugin that refuses to come back
    must not stop the rest, and the operator's other tools should still be
    there afterwards.
    """
    reloaded = 0
    if ctx.mcp_host is not None:
        try:
            plugins = await ctx.mcp_host.plugins()
        except Exception:
            log.exception("plugin reload-all: could not list plugins")
            plugins = []
        for plugin in plugins:
            try:
                await ctx.mcp_host.reload(plugin.id)
            except Exception:
                log.exception("plugin reload-all: reload failed for id=%s", plugin.id)
            else:
                reloaded += 1
    log.info("plugin reload-all: reloaded %d plugin(s)", reloaded)
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
