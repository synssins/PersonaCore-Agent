"""Config routes: GET/POST /config.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict

from workstation_agent.config.schema import (
    DEFAULT_ALWAYS_PROMPT_TOOLS,
    DEFAULT_NEVER_PROMPT_TOOLS,
    AdbConfig,
    AgentConfig,
)
from workstation_agent.ui.backend.app import BackendContext, get_context, templates
from workstation_agent.ui.backend.form_guard import not_a_form_body

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


# ---------------------------------------------------------------------------
# What a POST /config body has to be before it is allowed to save anything
#
# The shipped bug this guards (alpha.12/13): every ``Form(...)`` parameter
# below has a default, and Starlette parses a *non-form* body -- a JSON body,
# say -- as an empty ``FormData`` rather than raising. So a caller that posted
# JSON got all thirteen defaults written over the operator's configuration,
# with a 200 and no error. The tray did exactly that on every mute click and
# every session-mode click.
#
# The fix is not "the tray should have sent a form". It is that this route
# could not tell "the caller sent no fields" from "the caller sent the
# defaults", on a route whose entire job is to replace the whole
# configuration. Any future caller -- a new menu item, a script, a retry with
# a truncated body -- walked into the same hole. So the body has to prove it
# is a settings-form submission before a single field is written.
# ---------------------------------------------------------------------------

#: Every field name ``POST /config`` knows how to read. A body carrying none of
#: them is not a settings submission, whatever it claims to be.
_SETTINGS_FIELDS = frozenset({
    "llm_base_url",
    "llm_model",
    "llm_timeout_seconds",
    "llm_streaming",
    "wyoming_host",
    "wyoming_port",
    "wake_enabled",
    "wake_threshold",
    "session_mode",
    "session_sticky_seconds",
    "update_enabled",
    "update_channel",
    "adb_binary_path",
})

#: Hidden field in ``config.html`` naming the checkboxes that submission speaks
#: for. See :func:`_checkbox`.
_CHECKBOX_DECLARATION = "checkbox_fields"


def _unreadable_body(request: Request, form: FormData) -> tuple[int, str] | None:
    """``(status, message)`` when this body must not be allowed to save.

    Two distinct refusals, because they are two distinct caller mistakes:

    * a body that is not form-encoded at all (415) -- a JSON body arriving at
      a form route is a caller error, and answering 200 for it is how the
      configuration got erased;
    * a form-encoded body that mentions none of this route's fields (400) --
      an empty or truncated submission. "Save the whole configuration" and
      "I sent you no fields" cannot both be honoured, and it is the request
      that has to lose.
    """
    wrong_encoding = not_a_form_body(
        request,
        saves="saves the whole configuration",
        instead="To change a single setting, use its own route "
                "(POST /config/session-mode).",
    )
    if wrong_encoding is not None:
        return (status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, wrong_encoding)
    if not (_SETTINGS_FIELDS & set(form)):
        return (
            status.HTTP_400_BAD_REQUEST,
            (
                "The form carried none of the settings fields, so there was nothing "
                "to save and saving would have replaced every setting with a "
                "default. Nothing was saved."
            ),
        )
    return None


def _kept[T](form: FormData, name: str, submitted: T, current: T) -> T:
    """*submitted* if the caller actually sent *name*, otherwise *current*.

    This is the half of the fix that makes absent distinguishable from
    default. A field nobody mentioned keeps the value already in the config
    instead of being overwritten with the ``Form(...)`` fallback -- so a
    partial submission changes what it named and leaves the rest alone.
    """
    return submitted if name in form else current


def _checkbox(form: FormData, name: str, submitted: str, *, current: bool) -> bool:
    """Resolve one checkbox, which HTML omits entirely when it is unticked.

    Absence is genuinely ambiguous for a checkbox, so ``config.html`` submits a
    hidden ``checkbox_fields`` listing the boxes it speaks for. Named there and
    absent means the operator unticked it; not named at all means this caller
    never had an opinion, and the stored value stands.
    """
    if name in form:
        return bool(submitted)
    declared = str(form.get(_CHECKBOX_DECLARATION) or "").split()
    return False if name in declared else current


def _field_errors(
    wyoming_port: int,
    llm_timeout_seconds: int,
    wake_threshold: float,
    session_mode: str,
    session_sticky_seconds: int,
) -> dict[str, str]:
    """Per-field validation for a settings submission; empty means it may save."""
    errors: dict[str, str] = {}
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
    return errors


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
    """Replace the whole configuration from a settings-form submission.

    Refuses any body it cannot read as a settings form rather than treating it
    as an empty one, and leaves alone every field the submission did not carry.
    See :func:`_unreadable_body` and :func:`_kept` for why both are here.
    """
    cfg = None

    # Already parsed by the Form(...) dependencies above; Starlette caches it,
    # so this is the same FormData, not a second read of the body.
    form = await request.form()
    refusal = _unreadable_body(request, form)

    if ctx.config_store is None:
        return _settings_page(request, cfg, errors={"_global": "Config store not available"})

    try:
        cfg = ctx.config_store.load()
    except Exception as exc:  # noqa: BLE001
        return _settings_page(
            request, cfg, errors={"_global": f"Failed to load current config: {exc}"},
        )

    if refusal is not None:
        refusal_status, message = refusal
        log.warning("config POST refused (%s): %s", refusal_status, message)
        # The page still renders the *stored* config, so the operator sees what
        # is actually in force -- the point of the refusal is that nothing moved.
        refused = _settings_page(request, cfg, errors={"_global": message})
        refused.status_code = refusal_status
        return refused

    # A field the caller did not send keeps the value it already has. The three
    # checkboxes go through _checkbox instead, because for them "absent" can
    # legitimately mean "unticked" -- but only when the form says so.
    llm_base_url = _kept(form, "llm_base_url", llm_base_url, str(cfg.llm.base_url))
    llm_model = _kept(form, "llm_model", llm_model, cfg.llm.model)
    llm_timeout_seconds = _kept(
        form, "llm_timeout_seconds", llm_timeout_seconds, cfg.llm.timeout_seconds,
    )
    wyoming_host = _kept(form, "wyoming_host", wyoming_host, cfg.wyoming.host)
    wyoming_port = _kept(form, "wyoming_port", wyoming_port, cfg.wyoming.port)
    wake_threshold = _kept(form, "wake_threshold", wake_threshold, cfg.wake.threshold)
    session_mode = _kept(form, "session_mode", session_mode, cfg.session.mode)
    session_sticky_seconds = _kept(
        form, "session_sticky_seconds", session_sticky_seconds, cfg.session.sticky_seconds,
    )
    update_channel = _kept(form, "update_channel", update_channel, cfg.update.channel)
    adb_binary_path = _kept(form, "adb_binary_path", adb_binary_path, cfg.adb.binary_path)

    streaming = _checkbox(form, "llm_streaming", llm_streaming, current=cfg.llm.streaming)
    wake_on = _checkbox(form, "wake_enabled", wake_enabled, current=cfg.wake.enabled)
    update_on = _checkbox(form, "update_enabled", update_enabled, current=cfg.update.enabled)

    errors = _field_errors(
        wyoming_port, llm_timeout_seconds, wake_threshold,
        session_mode, session_sticky_seconds,
    )
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


class _SessionModeRequest(BaseModel):
    """Body of ``POST /config/session-mode``.

    ``extra="forbid"`` on purpose: a caller that misspells the key, or that
    hopes this route will also set something else, gets a 422 naming the
    problem rather than a silent no-op.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["single_shot", "sticky", "persistent"]


@router.post("/session-mode")
async def session_mode_post(
    body: _SessionModeRequest,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> JSONResponse:
    """Change the session mode, and nothing else.

    The tray's three session-mode menu items want to change exactly one
    setting. They used to say so by posting ``{"session_mode": ...}`` at
    ``POST /config`` -- a route whose contract is "replace the entire
    configuration with this form" -- and the mismatch is what erased the
    operator's LLM base URL, model, Wyoming host, wake settings and update
    channel on every click.

    A single-setting operation and a save-everything form are different
    operations, so they no longer share a handler. This route is deliberately
    narrow rather than a general "patch any field" endpoint: a typed body with
    one ``Literal`` field cannot be talked into writing something the caller
    did not name, which is the whole property that was missing.
    """
    if ctx.config_store is None:
        return JSONResponse(
            {"error": "Config store not available"},
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    try:
        cfg = ctx.config_store.load()
    except Exception as exc:
        log.exception("session-mode: failed to load config")
        return JSONResponse(
            {"error": f"Failed to load current config: {exc}"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    cfg.session.mode = body.mode
    try:
        ctx.config_store.save(cfg)
    except Exception as exc:
        log.exception("session-mode: failed to save config")
        return JSONResponse(
            {"error": f"Failed to save config: {exc}"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    log.info("session mode set to %s", body.mode)
    return JSONResponse({"session_mode": body.mode})


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

    # Same hole as POST /config had, in the same file: this route replaces the
    # whole §7 policy from the raw form, and a non-form body parses as an empty
    # one -- which reads as "no tool is never-prompt, no tool is always-prompt,
    # nothing is remembered". That silently drops a tool the operator had
    # pinned to always-prompt down to ask, which is a weaker policy than they
    # chose. An *empty* form is left alone: with only never/always radios and
    # no "ask" radio, "the operator chose ask for everything" really does
    # submit nothing.
    wrong_encoding = not_a_form_body(request, saves="saves the whole confirmation policy")
    if wrong_encoding is not None:
        log.warning("confirmation policy POST refused (415): %s", wrong_encoding)
        refused = _policy_page(
            request, cfg, policy_errors={"_global": wrong_encoding}, policy_saved=False,
        )
        refused.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        return refused

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
