"""Config routes: GET/POST /config.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from workstation_agent.config.schema import (
    DEFAULT_ALWAYS_PROMPT_TOOLS,
    DEFAULT_NEVER_PROMPT_TOOLS,
    AdbConfig,
    AgentConfig,
)
from workstation_agent.ui.backend.app import BackendContext, get_context, templates

if TYPE_CHECKING:
    from starlette.datastructures import FormData

log = logging.getLogger(__name__)

router = APIRouter(prefix="/config", tags=["config"])

_PORT_MAX = 65535
_PORT_MIN = 1


def _confirmation_tool_names(cfg: AgentConfig | None) -> list[str]:
    """Every §7 tool the settings UI offers a never/always choice for.

    The fixed contract defaults, plus anything already present in the
    loaded config's lists — so a tool an operator (or a future family) added
    outside the defaults still shows up rather than silently vanishing from
    the form on the next save.
    """
    names = set(DEFAULT_NEVER_PROMPT_TOOLS) | set(DEFAULT_ALWAYS_PROMPT_TOOLS)
    if cfg is not None:
        confirmation = getattr(cfg, "confirmation", None)
        if confirmation is not None:
            names |= set(getattr(confirmation, "never_prompt", None) or ())
            names |= set(getattr(confirmation, "always_prompt", None) or ())
    return sorted(names)


def _settings_page(
    request: Request,
    cfg: AgentConfig | None,
    *,
    errors: dict[str, str] | None = None,
    warnings: dict[str, str] | None = None,
    saved: bool = False,
) -> HTMLResponse:
    """Shared ``config.html`` render for every ``GET``/``POST /config`` outcome.

    Every branch of this router used to build the same eight-key context dict
    by hand. Adding one key meant editing six copies, and missing one produced
    a template that renders a blank field instead of failing -- so the copies
    are gone.

    ``warnings`` is distinct from ``errors`` on purpose: an error means nothing
    was saved, a warning means the save went through and there is still
    something the operator should know (an ``adb.exe`` path that is not there
    yet, for instance). Conflating them would either block a legitimate save or
    hide a real problem.
    """
    return templates.TemplateResponse(
        request,
        "config.html",
        {
            "cfg": cfg,
            "errors": errors or {},
            "warnings": warnings or {},
            "saved": saved,
            "confirmation_tools": _confirmation_tool_names(cfg),
            "policy_errors": {},
            "policy_saved": False,
        },
    )


def _adb_path_warning(binary_path: str) -> str | None:
    """Why the operator should look again at the ``adb.exe`` path they just saved.

    Not an error, and deliberately not a refusal: an operator may well point
    the Agent at an ADB they are about to install, and the value is still
    correct then. But a configured path that is not there is *not* silently
    replaced by one found on ``PATH`` -- the adb family raises
    ``AdbNotFoundError`` instead (see ``plugins/adb``) -- so saying nothing
    would leave the adb tools broken with the reason buried in a plugin's
    error message.

    ``OSError`` is caught because ``is_file`` reaches the filesystem: a path on
    a disconnected network share, or one the Agent cannot traverse, raises
    rather than returning ``False``, and a settings page must not 500 over a
    field it was only trying to be helpful about.
    """
    if not binary_path:
        return None
    try:
        exists = Path(binary_path).is_file()
    except OSError as exc:
        return (
            f"Saved, but the adb path could not be checked ({exc}). The adb tools "
            "will report a clearer error if it turns out to be unreachable."
        )
    if exists:
        return None
    return (
        "Saved, but there is no file at that adb path. The adb tools will refuse "
        "to run rather than quietly using a different adb — clear the field to "
        "search PATH and the usual SDK locations instead."
    )


@router.get("", response_class=HTMLResponse)
async def config_get(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the configuration form."""
    cfg = None
    errors: dict[str, str] = {}
    if ctx.config_store is not None:
        try:
            cfg = ctx.config_store.load()
        except Exception as exc:
            log.exception("config GET: failed to load config")
            errors["_global"] = str(exc)

    return _settings_page(request, cfg, errors=errors)


@router.post("", response_class=HTMLResponse, response_model=None)
async def config_post(  # noqa: PLR0913, PLR0917
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    # LLM
    llm_base_url: Annotated[str, Form(alias="llm_base_url")] = "http://192.168.1.150:8053/v1",
    llm_model: Annotated[str, Form(alias="llm_model")] = "gpt-4o",
    llm_timeout_seconds: Annotated[int, Form(alias="llm_timeout_seconds")] = 60,
    llm_streaming: Annotated[str, Form(alias="llm_streaming")] = "",
    # Wyoming
    wyoming_host: Annotated[str, Form(alias="wyoming_host")] = "192.168.1.150",
    wyoming_port: Annotated[int, Form(alias="wyoming_port")] = 10300,
    # Wake
    wake_enabled: Annotated[str, Form(alias="wake_enabled")] = "",
    wake_threshold: Annotated[float, Form(alias="wake_threshold")] = 0.5,
    # Session
    session_mode: Annotated[str, Form(alias="session_mode")] = "sticky",
    session_sticky_seconds: Annotated[int, Form(alias="session_sticky_seconds")] = 30,
    # Update
    update_enabled: Annotated[str, Form(alias="update_enabled")] = "",
    update_channel: Annotated[str, Form(alias="update_channel")] = "stable",
    # ADB
    adb_binary_path: Annotated[str, Form(alias="adb_binary_path")] = "",
) -> HTMLResponse:
    """Process configuration form submission with Pydantic validation."""
    errors: dict[str, str] = {}
    cfg = None

    # HTML checkboxes send "true" or are absent; coerce to bool
    streaming = bool(llm_streaming)
    wake_on = bool(wake_enabled)
    update_on = bool(update_enabled)

    if ctx.config_store is None:
        return _settings_page(request, cfg, errors={"_global": "Config store not available"})

    try:
        cfg = ctx.config_store.load()
    except Exception as exc:  # noqa: BLE001
        return _settings_page(
            request, cfg, errors={"_global": f"Failed to load current config: {exc}"},
        )

    # Validate
    if not (_PORT_MIN <= wyoming_port <= _PORT_MAX):
        errors["wyoming_port"] = f"Port must be {_PORT_MIN}-{_PORT_MAX}"
    if llm_timeout_seconds <= 0:
        errors["llm_timeout_seconds"] = "Timeout must be positive"
    if not (0.0 <= wake_threshold <= 1.0):
        errors["wake_threshold"] = "Threshold must be 0.0-1.0"
    if session_mode not in {"single_shot", "sticky", "persistent"}:
        errors["session_mode"] = "Invalid session mode"
    if session_sticky_seconds <= 0:
        errors["session_sticky_seconds"] = "Must be positive"

    if errors:
        return _settings_page(request, cfg, errors=errors)

    # Apply changes
    cfg.llm.base_url = llm_base_url  # type: ignore[assignment]
    cfg.llm.model = llm_model
    cfg.llm.timeout_seconds = llm_timeout_seconds
    cfg.llm.streaming = streaming
    cfg.wyoming.host = wyoming_host
    cfg.wyoming.port = wyoming_port
    cfg.wake.enabled = wake_on
    cfg.wake.threshold = wake_threshold
    cfg.session.mode = session_mode  # type: ignore[assignment]
    cfg.session.sticky_seconds = session_sticky_seconds
    cfg.update.enabled = update_on
    cfg.update.channel = update_channel
    # Re-validated rather than assigned: AdbConfig strips whitespace and the
    # quotes an Explorer "Copy as path" adds, and plain attribute assignment
    # does not run field validators (AgentConfig does not set
    # validate_assignment). Assigning the raw string would write `"C:\...\adb.exe"`
    # -- quotes included -- into config.toml, and the adb plugin would then look
    # for a file whose name really does start with a quote.
    cfg.adb = AdbConfig(binary_path=adb_binary_path)

    try:
        ctx.config_store.save(cfg)
    except Exception as exc:  # noqa: BLE001
        return _settings_page(request, cfg, errors={"_global": f"Failed to save config: {exc}"})

    warning = _adb_path_warning(cfg.adb.binary_path)
    return _settings_page(
        request,
        cfg,
        saved=True,
        warnings={"adb_binary_path": warning} if warning else None,
    )


def _policy_page(
    request: Request,
    cfg: AgentConfig | None,
    *,
    policy_errors: dict[str, str],
    policy_saved: bool,
) -> HTMLResponse:
    """Shared ``config.html`` render for every ``POST /config/confirmation`` outcome."""
    return templates.TemplateResponse(
        request,
        "config.html",
        {
            "cfg": cfg,
            "errors": {},
            "warnings": {},
            "saved": False,
            "confirmation_tools": _confirmation_tool_names(cfg),
            "policy_errors": policy_errors,
            "policy_saved": policy_saved,
        },
    )


def _apply_confirmation_form(cfg: AgentConfig, tools: list[str], form: FormData) -> None:
    """Parse the dynamic per-tool radios/checkboxes and write them onto *cfg*."""
    never: list[str] = []
    always: list[str] = []
    remember: list[str] = []
    for tool in tools:
        choice = form.get(f"policy_{tool}")
        if choice == "never":
            never.append(tool)
        elif choice == "always":
            always.append(tool)
        if form.get(f"remember_{tool}"):
            remember.append(tool)

    cfg.confirmation.never_prompt = never
    cfg.confirmation.always_prompt = always
    cfg.confirmation.remember_for_session = remember


def _push_to_running_host(ctx: BackendContext, cfg: AgentConfig) -> None:
    """Best-effort live-push of *cfg* to ``ctx.mcp_host`` (§7: no restart needed)."""
    if ctx.mcp_host is None:
        return
    push = getattr(ctx.mcp_host, "set_config", None)
    if not callable(push):
        return
    try:
        push(cfg)
    except Exception:
        log.exception("confirmation policy: failed to push config to mcp_host")


@router.post("/confirmation", response_class=HTMLResponse, response_model=None)
async def confirmation_policy_post(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Save §7's per-tool never/always-prompt assignment and remember flags.

    A separate endpoint from ``POST /config`` on purpose: the tool list is
    dynamic (driven by :func:`_confirmation_tool_names`, not a fixed set of
    named fields), so it is read from the raw form body rather than typed
    ``Form(...)`` parameters. Saving pushes the new policy into the running
    :class:`~workstation_agent.mcp_host.host.MCPHost` (when one is wired) via
    ``set_config`` so a moved tool, or a newly-enabled "remember", takes
    effect on the very next tool call -- not just after a restart.
    """
    if ctx.config_store is None:
        return _policy_page(
            request, None, policy_errors={"_global": "Config store not available"},
            policy_saved=False,
        )

    try:
        cfg = ctx.config_store.load()
    except Exception as exc:  # noqa: BLE001
        return _policy_page(
            request, None,
            policy_errors={"_global": f"Failed to load current config: {exc}"},
            policy_saved=False,
        )

    tools = _confirmation_tool_names(cfg)
    form = await request.form()
    _apply_confirmation_form(cfg, tools, form)

    try:
        ctx.config_store.save(cfg)
    except Exception as exc:  # noqa: BLE001
        return _policy_page(
            request, cfg,
            policy_errors={"_global": f"Failed to save config: {exc}"},
            policy_saved=False,
        )

    _push_to_running_host(ctx, cfg)

    return _policy_page(request, cfg, policy_errors={}, policy_saved=True)
