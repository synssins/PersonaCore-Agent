"""Plugin management routes: GET /plugins, POST /plugins/*.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from typing import TYPE_CHECKING, Annotated, Any
from weakref import WeakKeyDictionary

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.mcp_host.loader import (
    TRUSTED_PUBKEYS,
    PluginDeclaration,
    discover,
    plugin_declaration,
    verify,
)
from workstation_agent.mcp_host.permissions import (
    WILDCARD,
    always_denied_guards,
    grantable_permissions,
    parse_declared_permissions,
)
from workstation_agent.network_mcp.tools import tool_family, wire_name
from workstation_agent.ui.backend.app import BackendContext, get_context, templates

if TYPE_CHECKING:
    from workstation_agent.config.schema import AgentConfig
    from workstation_agent.mcp_host.loader import PluginManifest

log = logging.getLogger(__name__)

router = APIRouter(prefix="/plugins", tags=["plugins"])

_TRUTHY = {"true", "1", "yes", "on"}


def _is_truthy(value: str) -> bool:
    """Whether a form or query value means yes."""
    return value.strip().lower() in _TRUTHY


#: Everything a fragment identifier should not carry. A plugin id is
#: operator-visible text from a signed manifest, not a slug, so it is scrubbed
#: rather than trusted -- and scrubbed by one function used by both the anchor
#: the page emits and the anchor a redirect points at, so the two agree.
_ANCHOR_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _anchor(plugin_id: str) -> str:
    """A fragment identifier for *plugin_id*'s section on the page."""
    return _ANCHOR_UNSAFE.sub("-", plugin_id)[:64]

#: Serialises this router's read-modify-write cycles against each other.
#:
#: Every mutation here is load-the-config, change one field, save it back.
#: ``config.store.save`` writes to a temporary file and ``Path.replace``\ s it
#: in, so a *save* is atomic -- a reader never sees half a file. That is the
#: only atomicity the store has: it has no lock, no revision and no
#: compare-and-swap, so it cannot notice that the config it is being handed was
#: derived from a version that has since been replaced. Two overlapping
#: requests therefore both read the same starting state and the second one
#: writes its copy over the first, and the update the first made is simply
#: gone. Revoke ``tool:a``, then immediately allow ``tool:b``, and the config
#: can end up holding *both* -- the gate allowing something the owner has just
#: explicitly stopped. With twenty-one tools to turn on he will click several
#: in a row, so this is an ordinary Tuesday, not a race that needs contriving.
#:
#: A lock rather than a retry loop, deliberately: the second click waits its
#: turn and is then applied to what the first one actually wrote. Compare-and-
#: retry would have to decide what to do with the loser, and the only honest
#: answers are "do it again" (this, with extra steps) or "drop it" (the bug).
#:
#: Held across the whole decision, not just the write. The host listing and the
#: declaration check are *inputs* to what gets stored, so reading them outside
#: the lock would leave the same window one step further back.
#:
#: Module-level because the store is a process-wide file and the router is a
#: singleton. It does not reach ``config_routes``, which has the same shape
#: over the same file; that is a real remaining gap and is noted rather than
#: silently widened here.
#:
#: Keyed by running loop, and created on first use rather than at import.
#: ``asyncio.Lock`` binds itself to the loop that first acquires it and raises
#: on every later loop, so one lock built at import time would work for the
#: Agent's single long-lived loop and then wedge every state-changing click the
#: moment the app was served from a second one -- which is what the tests do
#: constantly, and it is not a property worth betting the page on. Per-loop is
#: also the honest scope: two coroutines can only interleave if they share a
#: loop, so that is exactly the boundary the serialisation has to cover.
_CONFIG_WRITE_LOCKS: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    WeakKeyDictionary()
)


def _config_write_lock() -> asyncio.Lock:
    """The write lock for the loop this request is running on.

    Synchronous, and therefore not itself a race: it runs to completion between
    two of the loop's own steps, so two callers cannot both find it absent.
    """
    loop = asyncio.get_running_loop()
    lock = _CONFIG_WRITE_LOCKS.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _CONFIG_WRITE_LOCKS[loop] = lock
    return lock

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

#: Said once, at the top of the section, because the owner meets a tool under
#: two spellings and has to know they are one tool.  The wire name leads
#: everywhere on this page: it is the name PersonaCore lists, logs and refuses
#: under, so it is the only one he has ever been shown.  Searching this page for
#: it has to find the row -- he went looking for ``shell_run``, found nothing,
#: and concluded the tool was missing.
NAME_SPELLING_NOTE = (
    "Each tool is named the way you see it everywhere else — shell_run, "
    "serial_open — with the Agent's internal spelling (shell.run) beside it. "
    "They are the same tool. The dotted spelling is what the audit log and a "
    "refusal message show, which is why it is here too."
)

#: A family grant is N explicit ``tool:`` entries, so a tool the plugin declares
#: in a later version is not covered by a click made today.  Said on the page
#: rather than left to be discovered, because the alternative is finding out
#: when a call is refused -- or, in the other direction, believing an update
#: silently widened what he had allowed.
FAMILY_SCOPE_NOTE = (
    "Allowing a whole family allows exactly the tools it declares today. If a "
    "later version of the plugin adds a tool to the family, that new tool is "
    "not allowed until you allow it here — a new capability asks again."
)

#: Shown for a plugin the host is not running because the owner switched it off.
#: It must still appear: a page that silently omits a plugin whose tools he can
#: see being called elsewhere is broken whatever the reason, and "the row is
#: missing" is indistinguishable from "the tool does not exist".
DISABLED_PLUGIN_NOTE = (
    "This plugin is switched off, so the Agent is not running it and nothing "
    "it declares can be allowed yet. Enable it first, then allow what you want "
    "it to do. What it declares is listed below so you can see what enabling it "
    "would put on the table."
)

#: Shown for a plugin that is installed and enabled but is not in the running
#: host's list -- the Agent has not started, or the plugin failed to start.
NOT_RUNNING_PLUGIN_NOTE = (
    "This plugin is installed and switched on, but the Agent is not currently "
    "running it — either the Agent has not started it yet, or it failed to "
    "start. What it declares is listed below; the permissions become "
    "changeable once it is running."
)

#: What ``*`` actually buys.  Spelled out because a control that reads as
#: "allow everything" and is not would be worse than no control at all.
WILDCARD_NOTE = (
    "tool identity only — it lets the plugin be allowed to call any tool it "
    "ships, and every one of those calls is still refused unless the signed "
    "manifest declares that tool's arguments, and is still checked against the "
    "folders, commands and sites the manifest declares"
)

#: How much of a caller-supplied permission string is echoed back in a refusal.
#: ``{perm:path}`` accepts a long, arbitrary tail, and the refusal is a page --
#: long enough for any real permission to be recognisable, short enough that
#: the page stays a page. Jinja escapes it on the way out, so this is about
#: length, not markup.
_PERM_ECHO_LIMIT = 80


def _shown_perm(perm: str) -> str:
    """*perm*, bounded, for a message a person reads."""
    return perm if len(perm) <= _PERM_ECHO_LIMIT else perm[:_PERM_ECHO_LIMIT] + "…"


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

FAMILY_NOT_DECLARED_ERROR = (
    "The {plugin!r} plugin does not declare any {family!r} tools in its signed "
    "manifest, so there is nothing here to allow. Nothing was changed."
)


def _page_notes() -> dict[str, str]:
    """The two things the section has to say once, rather than per row.

    Kept as module constants and handed to the template so a test can assert on
    the same string the page renders, instead of on a paraphrase of it that can
    drift out of the template without anything failing.
    """
    return {"names": NAME_SPELLING_NOTE, "family_scope": FAMILY_SCOPE_NOTE}


def _declaration_of(plugin: object) -> PluginDeclaration:
    """The host's ``PluginInfo`` row, carried into the shared declaration type.

    An adapter, **not** a second parsing of the manifest: the fields it copies
    were themselves filled in by
    :func:`~workstation_agent.mcp_host.loader.plugin_declaration` inside
    :meth:`~workstation_agent.mcp_host.host.MCPHost.plugins`. It exists so that
    the row builder below sees one type whether the plugin is running (host
    listing) or not (``discover`` + ``plugin_declaration``), rather than
    branching on where its input came from -- which is how the two would drift.

    Attribute access is defensive because the host is injected and the tests
    supply their own stand-ins.
    """
    plugin_id = str(getattr(plugin, "id", ""))
    return PluginDeclaration(
        id=plugin_id,
        name=str(getattr(plugin, "name", "") or plugin_id),
        version=str(getattr(plugin, "version", "")),
        declared_permissions=tuple(
            str(p) for p in (getattr(plugin, "declared_permissions", []) or [])
        ),
        confirmable_conditions=tuple(
            str(c) for c in (getattr(plugin, "confirmable_conditions", []) or [])
        ),
    )


def _tool_of(perm: str) -> str:
    """The dotted tool id inside a ``tool:`` grant, or ``""`` for anything else."""
    return perm[len(_TOOL_PREFIX):] if perm.startswith(_TOOL_PREFIX) else ""


def _family_of_perm(perm: str) -> str:
    """The family a ``tool:`` grant belongs to, or ``""`` if it belongs to none.

    ``""`` covers the wildcard (which is not a tool and so is not in any
    family) and a malformed ``tool:`` entry with no tool name after it. Both are
    shown on their own rather than swept into a family control: a family button
    whose URL carried an empty family would be a control that cannot work.
    """
    tool = _tool_of(perm)
    return tool_family(tool) if tool else ""


def _permission_views(
    decl: PluginDeclaration,
    granted: set[str],
) -> list[dict[str, Any]]:
    """One view per grantable permission: both spellings, state, and caveat.

    What the plugin *can* ask for comes from :func:`grantable_permissions` over
    the **signed** ``declared_permissions`` -- the same function the gate's
    identity check uses, so the page cannot offer a control the gate would never
    honour.

    Both names are carried. ``wire`` leads in the UI because it is the spelling
    the owner is shown by PersonaCore, by its logs and by the confirmation
    policy on the Settings page; ``internal`` is the dotted id the gate, the
    audit log and refusal messages use. The grant itself is keyed by the dotted
    id, because that is what ``_check_tool_permission`` compares against -- the
    translation is presentation, and it stops at the template.
    """
    declarations = parse_declared_permissions(
        decl.id, list(decl.declared_permissions),
    )
    views: list[dict[str, Any]] = []
    for perm in grantable_permissions(decl.declared_permissions):
        is_wildcard = perm == WILDCARD
        tool = _tool_of(perm)
        args_declared = bool(tool) and tool.strip().lower() in declarations
        note = ""
        if is_wildcard:
            note = WILDCARD_NOTE
        elif not args_declared:
            note = NO_ARG_DECLARATION_NOTE
        views.append({
            "perm": perm,
            "wire": wire_name(tool) if tool else "",
            "internal": tool,
            "family": _family_of_perm(perm),
            "label": "Any tool this plugin ships" if is_wildcard else wire_name(tool),
            "wildcard": is_wildcard,
            "granted": perm in granted,
            "args_declared": args_declared,
            "note": note,
        })
    return views


def _family_views(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The default interface: one control per declared family.

    The family is not invented here. Tool ids are already ``family.verb``, the
    wire names are already ``family_verb``, and contract §7's confirmation
    policy already speaks in ``jobs_*``. This surfaces the grouping that exists
    rather than adding one.

    **Interface granularity, not enforcement granularity.** A family control
    stands for the N ``tool:`` entries it lists and nothing else; granting one
    writes those N entries and the gate is not told about families at all. That
    is why ``state`` has three values and not two: three of five serial tools
    allowed is *partly* allowed, and a control that rounded it to on or off
    would be lying about what the gate would do -- the same rule the network
    endpoint's own block applies.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for perm in permissions:
        family = perm["family"]
        if not family:
            continue
        groups.setdefault(family, []).append(perm)

    rows: list[dict[str, Any]] = []
    for key in sorted(groups):
        tools = groups[key]
        allowed = [t for t in tools if t["granted"]]
        missing = [t for t in tools if not t["granted"]]
        if not missing:
            state = "all"
        elif not allowed:
            state = "none"
        else:
            state = "partly"
        rows.append({
            "key": key,
            "title": key.replace("_", " ").capitalize(),
            "wire_label": f"{key}_*",
            "tools": tools,
            "total": len(tools),
            "granted_count": len(allowed),
            "state": state,
            "allowed_names": [t["wire"] for t in allowed],
            "missing_names": [t["wire"] for t in missing],
            "undeclared_args": [t["wire"] for t in tools if not t["args_declared"]],
        })
    return rows


def _plugin_rows(
    plugins: list[Any],
    cfg: AgentConfig | None,
    manifests: list[PluginManifest] | None = None,
) -> list[dict[str, Any]]:
    """One permissions view per plugin -- **including** the ones not running.

    Three questions per plugin, answered from two sources and nothing else.
    What the plugin *can* ask for comes from the signed manifest. What it is
    *currently allowed* comes from the operator's config. What happens when it
    asks for anything else is read off ``_HARD_GUARDS`` minus whatever the
    manifest declares confirmable.

    A plugin the host is not running (switched off, or failed to start) never
    enters ``MCPHost._runtimes`` and so is absent from ``plugins``. Listing only
    the running ones made the page silently omit a tool the owner could watch
    being refused elsewhere -- indistinguishable, from where he sits, from the
    tool not existing. So *manifests* (from ``loader.discover``, the same signed
    files the host reads) fills in the rest, through the same
    :func:`~workstation_agent.mcp_host.loader.plugin_declaration` the host uses.
    One function answers "what does this plugin declare", running or not; the
    row simply says which it is, and a non-running plugin offers no grant
    controls because there is nothing to grant to until it is enabled.
    """
    per_plugin = cfg.plugins.per_plugin if cfg is not None else {}
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _row(decl: PluginDeclaration, *, running: bool, absent_note: str) -> dict[str, Any]:
        entry = per_plugin.get(decl.id)
        granted = set(entry.granted_permissions) if entry is not None else set()
        permissions = _permission_views(decl, granted)
        declared_set = set(grantable_permissions(decl.declared_permissions))
        confirmable = list(decl.confirmable_conditions)
        # A stale grant carries both spellings too. It is the one entry the
        # owner is most likely to have to recognise from somewhere else -- it is
        # left over from a version of the plugin he used to run -- so showing it
        # only under the dotted name would repeat this defect where it hurts
        # most.
        stale = [
            {
                "perm": g,
                "label": wire_name(_tool_of(g)) if _tool_of(g) else g,
            }
            for g in sorted(g for g in granted if g not in declared_set)
        ]
        return {
            "id": decl.id,
            "anchor": _anchor(decl.id),
            "name": decl.name or decl.id,
            "running": running,
            "absent_note": absent_note,
            "permissions": permissions,
            "families": _family_views(permissions),
            "ungrouped": [p for p in permissions if not p["family"]],
            "stale": stale,
            "guards": [
                {"name": name, "reason": reason}
                for name, reason in always_denied_guards(confirmable)
            ],
            "confirmable": sorted(
                {c for c, _ in always_denied_guards([])} & set(confirmable),
            ),
        }

    for plugin in plugins:
        decl = _declaration_of(plugin)
        seen.add(decl.id)
        rows.append(_row(decl, running=True, absent_note=""))

    for manifest in manifests or []:
        decl = plugin_declaration(manifest)
        if decl.id in seen:
            continue
        seen.add(decl.id)
        entry = per_plugin.get(decl.id)
        enabled = entry.enabled if entry is not None else True
        rows.append(_row(
            decl,
            running=False,
            absent_note=NOT_RUNNING_PLUGIN_NOTE if enabled else DISABLED_PLUGIN_NOTE,
        ))
    return rows


def _discovered() -> list[PluginManifest]:
    """Every installed plugin's signed manifest, or ``[]`` if discovery fails.

    Discovery is a filesystem walk over three sources and it must never be able
    to take the page down: a page that 500s tells the owner even less than a
    page missing a row. Read once per render and handed to both readers -- the
    signature overview and the permissions list -- so the two cannot disagree
    about which plugins are installed within a single page.
    """
    try:
        return discover()
    except Exception:
        log.exception("plugin discovery failed")
        return []


def _signature_overview(
    cfg: AgentConfig | None,
    manifests: list[PluginManifest] | None = None,
) -> dict[str, Any]:
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
    if manifests is None:
        manifests = _discovered()
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
    advanced: Annotated[str, Query()] = "",
) -> HTMLResponse:
    """Render plugin list page.

    ``advanced`` opens the per-tool view. It is a query parameter rather than
    browser state so that the per-tool grant and revoke buttons can send the
    owner back to the view he was in: without it, every click inside Advanced
    would drop him back to the family view and he would have to reopen it --
    which is the same "make him click again" complaint in a smaller font.
    """
    plugins: list[Any] = []
    if ctx.mcp_host is not None:
        with contextlib.suppress(Exception):
            plugins = await ctx.mcp_host.plugins()

    cfg = None
    if ctx.config_store is not None:
        with contextlib.suppress(Exception):
            cfg = ctx.config_store.load()

    manifests = _discovered()
    return templates.TemplateResponse(
        request,
        "plugins.html",
        {
            "plugins": plugins,
            "cfg": cfg,
            "errors": {},
            "sig": _signature_overview(cfg, manifests),
            "perm_rows": _plugin_rows(plugins, cfg, manifests),
            "notes": _page_notes(),
            "advanced": _is_truthy(advanced),
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

    if not _is_truthy(confirm):
        plugins: list[Any] = []
        if ctx.mcp_host is not None:
            with contextlib.suppress(Exception):
                plugins = await ctx.mcp_host.plugins()
        manifests = _discovered()
        return templates.TemplateResponse(
            request,
            "plugins.html",
            {
                "plugins": plugins,
                "cfg": cfg,
                "errors": {},
                "sig": _signature_overview(cfg, manifests),
                "signature_confirm_pending": True,
                "perm_rows": _plugin_rows(plugins, cfg, manifests),
                "notes": _page_notes(),
                "advanced": False,
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
    *,
    advanced: bool = False,
) -> HTMLResponse:
    """Redraw Plugins from what is *stored*, with *message*, and a 400.

    Redrawn from storage on purpose: the point of a refusal is that nothing
    moved, so the page the operator is left looking at has to be the page he
    would have got by not clicking at all -- including which view he was in
    when he clicked.
    """
    manifests = _discovered()
    return templates.TemplateResponse(
        request,
        "plugins.html",
        {
            "plugins": plugins,
            "cfg": cfg,
            "errors": {"permissions": message},
            "sig": _signature_overview(cfg, manifests),
            "perm_rows": _plugin_rows(plugins, cfg, manifests),
            "notes": _page_notes(),
            "advanced": advanced,
        },
        status_code=400,
    )


def _back_to_plugins(*, advanced: bool, plugin_id: str = "") -> RedirectResponse:
    """Redirect to the Plugins page, in the view the click was made from.

    A per-tool click comes from the Advanced view, and sending him back to the
    family view would collapse what he opened and lose his place on a long
    page. The anchor puts him back at the plugin he was working on.
    """
    url = "/plugins?advanced=1" if advanced else "/plugins"
    if advanced and plugin_id:
        url = f"{url}#plugin-{_anchor(plugin_id)}"
    return RedirectResponse(url=url, status_code=303)


@router.post("/{plugin_id}/grant/{perm:path}", response_model=None)
async def plugin_grant(
    request: Request,
    plugin_id: str,
    perm: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
    advanced: Annotated[str, Form()] = "",
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

    ``{perm:path}`` rather than ``{perm}``: a path parameter stops at the first
    ``/``, so a declared permission carrying one (a ``path:`` scope, say) would
    render an Allow button whose POST 404s -- a control that cannot work, which
    is the failure this page exists to remove. Widening the *matcher* cannot
    widen what is grantable: the declaration check below is what bounds this
    route, and it is unchanged. Do not "tighten" this back.
    """
    show_advanced = _is_truthy(advanced)
    async with _config_write_lock():
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
                advanced=show_advanced,
            )

        declared = grantable_permissions(getattr(match, "declared_permissions", []) or [])
        if perm not in declared:
            log.warning(
                "permission grant refused: id=%s perm=%s is not declared",
                plugin_id, perm,
            )
            return _refused_permission_page(
                request, plugins, cfg,
                GRANT_NOT_DECLARED_ERROR.format(
                    plugin=plugin_id, perm=_shown_perm(perm),
                ),
                advanced=show_advanced,
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
    return _back_to_plugins(advanced=show_advanced, plugin_id=plugin_id)


@router.post("/{plugin_id}/grant-family/{family:path}", response_model=None)
async def plugin_grant_family(
    request: Request,
    plugin_id: str,
    family: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse | RedirectResponse:
    """Allow every tool *plugin_id*'s signed manifest declares in *family*.

    **This is a UI route, not a change to the gate.** The owner's objection was
    never to default-deny; it was to being made to express one intention
    twenty-one times. So this expands one click into exactly the ``tool:``
    entries the manifest declares in that family and stores them individually,
    which is precisely what he would have got by clicking each row in the
    Advanced view. ``_check_tool_permission`` matches ``tool:<exact>`` or
    ``*`` and has no prefix form; adding one would have been the tidier
    implementation and the wrong change -- it would silently extend the grant to
    whatever a future version of the plugin adds to the family, turning a
    presentation fix into a real widening of enforcement.

    Bounded by the declaration exactly as :func:`plugin_grant` is, and by the
    same :func:`grantable_permissions`: a family expands only to what this
    manifest declares today. A family it declares nothing in is refused rather
    than silently writing nothing, because a button that reports success while
    doing nothing is the class of lie this page exists to end.

    No confirmation step, deliberately. Turning on a family is the ordinary
    operation this page is for, and an "are you sure?" on each one would be the
    twenty-one clicks again wearing a different hat.
    """
    async with _config_write_lock():
        plugins = await _loaded_plugins(ctx)
        cfg = None
        if ctx.config_store is not None:
            with contextlib.suppress(Exception):
                cfg = ctx.config_store.load()

        match = next((p for p in plugins if str(getattr(p, "id", "")) == plugin_id), None)
        if match is None:
            log.warning("family grant refused: unknown plugin id=%s", plugin_id)
            return _refused_permission_page(
                request, plugins, cfg,
                GRANT_UNKNOWN_PLUGIN_ERROR.format(plugin=plugin_id),
            )

        declared = grantable_permissions(
            getattr(match, "declared_permissions", []) or [],
        )
        perms = [p for p in declared if p != WILDCARD and _family_of_perm(p) == family]
        if not perms:
            log.warning(
                "family grant refused: id=%s family=%s declares no tools",
                plugin_id, family,
            )
            return _refused_permission_page(
                request, plugins, cfg,
                FAMILY_NOT_DECLARED_ERROR.format(
                    plugin=plugin_id, family=_shown_perm(family),
                ),
            )

        added: list[str] = []
        if ctx.config_store is not None and cfg is not None:
            from workstation_agent.config.schema import PluginConfig  # noqa: PLC0415
            entry = cfg.plugins.per_plugin.get(plugin_id, PluginConfig())
            added = [p for p in perms if p not in entry.granted_permissions]
            entry.granted_permissions = [*entry.granted_permissions, *added]
            cfg.plugins.per_plugin[plugin_id] = entry
            ctx.config_store.save(cfg)
            _push_to_running_host(ctx, cfg)
    log.info(
        "family granted: id=%s family=%s tools=%d newly_allowed=%d",
        plugin_id, family, len(perms), len(added),
    )
    return _back_to_plugins(advanced=False)


@router.post("/{plugin_id}/revoke-family/{family:path}")
async def plugin_revoke_family(
    plugin_id: str,
    family: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Stop allowing every tool granted to *plugin_id* in *family*.

    The other half of :func:`plugin_grant_family`: a family control that could
    only be switched on would not be a control.

    Unbounded by the declaration, for the same reason :func:`plugin_revoke` is:
    it removes every *granted* ``tool:`` entry in the family, including one the
    manifest has since stopped declaring. Removing authority can only narrow
    what is permitted, so there is nothing here for a bound to protect, and the
    grants most worth clearing are exactly the ones the manifest no longer
    mentions.
    """
    removed = 0
    async with _config_write_lock():
        if ctx.config_store is not None:
            cfg = ctx.config_store.load()
            entry = cfg.plugins.per_plugin.get(plugin_id)
            if entry is not None:
                keep = [
                    p for p in entry.granted_permissions
                    if not (p.startswith(_TOOL_PREFIX) and _family_of_perm(p) == family)
                ]
                removed = len(entry.granted_permissions) - len(keep)
                if removed:
                    entry.granted_permissions = keep
                    cfg.plugins.per_plugin[plugin_id] = entry
                    ctx.config_store.save(cfg)
                    _push_to_running_host(ctx, cfg)
    log.info("family revoked: id=%s family=%s removed=%d", plugin_id, family, removed)
    return _back_to_plugins(advanced=False)


@router.post("/{plugin_id}/revoke/{perm:path}")
async def plugin_revoke(
    plugin_id: str,
    perm: str,
    ctx: Annotated[BackendContext, Depends(get_context)],
    advanced: Annotated[str, Form()] = "",
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

    ``{perm:path}`` matters more here than on the grant side. A stale grant is
    arbitrary stored text -- whatever some past manifest declared, a ``path:``
    scope with a drive letter in it -- and one containing a ``/`` would simply
    404, leaving the owner unable to remove it by clicking. That is the config
    file as the only way out, which is the thing this product does not ask of
    him, and it would have undone the whole reason revoke is unbounded.
    """
    async with _config_write_lock():
        if ctx.config_store is not None:
            cfg = ctx.config_store.load()
            entry = cfg.plugins.per_plugin.get(plugin_id)
            if entry is not None and perm in entry.granted_permissions:
                entry.granted_permissions = [
                    p for p in entry.granted_permissions if p != perm
                ]
                cfg.plugins.per_plugin[plugin_id] = entry
                ctx.config_store.save(cfg)
                _push_to_running_host(ctx, cfg)
    log.info("permission revoked: id=%s perm=%s", plugin_id, perm)
    return _back_to_plugins(advanced=_is_truthy(advanced), plugin_id=plugin_id)


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
                "notes": _page_notes(),
                "advanced": False,
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
