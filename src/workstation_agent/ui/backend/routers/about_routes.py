"""About/update routes: the version, the update channel, and what the last check found.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Three things live here, and all three are answers to the same complaint: the
updater did things the owner could not see.

**What the last check actually found.** ``POST /about/check-updates`` used to
nudge the poller and redirect, and the poller logged one line and returned
``None`` whatever had happened — so "there is nothing newer", "I could not
reach GitHub" and "GitHub answered 404 because the client asked the wrong
question" all looked identical from the page, and the last of those was what
happened every single time for the life of the project. The page now renders
:class:`~workstation_agent.updater_client.poller.UpdateCheckResult`: when the
check ran, what it concluded, and for a failure what failed, in a sentence that
says in as many words that it is not the same as being up to date. Same rule as
the endpoint block: report what is true, not what was configured.

**Choosing the channel.** ``POST /about/channel`` writes ``update.channel``
and, when a poller is running in this process, pushes it into that poller so
the change applies to the very next check — including the one the owner's next
click triggers. When no poller is running there is nothing to push to, and the
page says so rather than implying the change took effect. The control is a
``<select>`` of the three channels the manifest validator accepts, so the value
written can only be one of them.

*Why About and not Config.* A channel is only meaningful next to its
consequence — the version you are on, the version the channel found, and the
button that goes and looks. All three are here. On the Config page it would be
a fourteenth field in a column of transport settings, and the owner would have
to change it in one place and go somewhere else to see whether it did anything.
The Config page keeps its ``update_channel`` field so an existing save is not
a surprise, but it is now the same three-value select and ``POST /config``
refuses anything else.

**Taking the update.** ``POST /about/install`` stages the verified manifest and
spawns ``Updater.exe``. It exists because the decision was notify-then-click,
not auto-install: an agent that upgraded itself mid-diagnosis would have hidden
several of this project's real defects. ``update.auto_install`` is offered on
this page for owners who want the other behaviour, and it is off by default.

Nothing here weakens the update trust boundary. The bytes installed are the
exact bytes whose Ed25519 signature the poller verified (they are handed over
from :attr:`~workstation_agent.updater_client.poller.UpdatePoller.pending`, not
re-downloaded), and every URL involved was checked against the source pin
before it was ever fetched.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates
from workstation_agent.ui.backend.form_guard import not_a_form_body, speaks_for
from workstation_agent.updater_client import handoff
from workstation_agent.updater_client.channels import (
    CHANNEL_DESCRIPTIONS,
    CHANNELS,
    normalise_channel,
)

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from workstation_agent.updater_client.poller import UpdateCheckResult

log = logging.getLogger(__name__)

router = APIRouter(prefix="/about", tags=["about"])

#: How long a "Check for updates now" click may block the page. The check is
#: an outbound HTTPS request; the injected client has its own timeout, and this
#: is only the backstop that keeps a wedged socket from wedging the page. A
#: check cut off here is recorded by the poller as unreachable, which is what
#: it is from the owner's point of view.
_CHECK_TIMEOUT_SECONDS = 45.0

#: What ``about.html``'s channel form declares in ``speaks_for``. Without it the
#: unticked ``auto_install`` checkbox is indistinguishable from a body that
#: never mentioned it -- the same ambiguity that erased the configuration from
#: the tray. See :mod:`workstation_agent.ui.backend.form_guard`.
_UPDATE_PREFS_SCOPE = "update_prefs"


def _last_check(poller: Any) -> UpdateCheckResult | None:  # noqa: ANN401
    """``poller.last_check`` when the wired object has one.

    ``BackendContext.update_poller`` is deliberately untyped -- tests inject
    fakes, and a fake predating this change has ``check_now`` and nothing else.
    Such a fake means "no check has been recorded", not a 500.
    """
    if poller is None:
        return None
    return getattr(poller, "last_check", None)


def _about_context(ctx: BackendContext, message: str | None = None) -> dict[str, Any]:
    """Everything ``about.html`` renders, read from live objects where possible.

    The channel shown is the one the *running poller* will use when there is
    one, falling back to the stored config otherwise -- if those two ever
    disagree, the page must show the one that is actually in force.
    """
    cfg = None
    if ctx.config_store is not None:
        try:
            cfg = ctx.config_store.load()
        except Exception:
            log.exception("about: failed to load config")

    poller = ctx.update_poller
    stored_channel = getattr(getattr(cfg, "update", None), "channel", "stable")
    live_channel = getattr(poller, "channel", None)
    channel = live_channel if isinstance(live_channel, str) else stored_channel

    pending = getattr(poller, "pending", None)
    pending_version = pending[0].version if pending else None

    return {
        "version": ctx.current_version,
        "message": message,
        "channel": channel,
        "channel_known": normalise_channel(channel) is not None,
        "channels": [(name, CHANNEL_DESCRIPTIONS[name]) for name in CHANNELS],
        "speaks_for_scope": _UPDATE_PREFS_SCOPE,
        "last_check": _last_check(poller),
        "checks_run_here": poller is not None,
        "auto_install": bool(getattr(getattr(cfg, "update", None), "auto_install", False)),
        "updates_enabled": bool(getattr(getattr(cfg, "update", None), "enabled", True)),
        "repo": getattr(getattr(cfg, "update", None), "github_repo", ""),
        "pending_version": pending_version,
    }


def _page(request: Request, ctx: BackendContext, message: str | None = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "about.html", _about_context(ctx, message))


@router.get("", response_class=HTMLResponse)
async def about_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the About page, including the outcome of the last update check."""
    return _page(request, ctx)


@router.post("/check-updates")
async def check_updates(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Run an update check now, and redirect to the page that reports it.

    Awaits the check rather than nudging the background loop and returning, so
    that the page the owner lands on shows the outcome of *this* click. The
    poller serialises checks internally, so this cannot race the scheduled one.

    ``check_now()`` remains the fallback for anything wired in that cannot be
    awaited (the tray's own fake, older test doubles); it starts a check whose
    result the next page load will show.
    """
    poller = ctx.update_poller
    if poller is None:
        return RedirectResponse(url="/about", status_code=303)

    poll_once: Any = getattr(poller, "poll_once", None)
    if callable(poll_once):
        try:
            await asyncio.wait_for(
                cast("Coroutine[Any, Any, Any]", poll_once()),
                timeout=_CHECK_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            log.warning("about: update check timed out after %ss", _CHECK_TIMEOUT_SECONDS)
        except Exception:
            log.exception("about: update check raised")
    else:
        try:
            poller.check_now()
            log.info("about: triggered update check")
        except Exception:
            log.exception("about: check_now failed")
    return RedirectResponse(url="/about", status_code=303)


def _apply_channel_to_poller(ctx: BackendContext, channel: str) -> bool:
    """Push *channel* into the running poller. True if it took effect now."""
    poller = ctx.update_poller
    setter = getattr(poller, "set_channel", None)
    if not callable(setter):
        return False
    try:
        setter(channel)
    except Exception:
        log.exception("about: failed to push channel to the running poller")
        return False
    return True


@router.post("/channel", response_class=HTMLResponse, response_model=None)
async def set_update_channel(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    update_channel: Annotated[str, Form()] = "",
    auto_install: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Save the update channel and the auto-install preference.

    Refuses a body it cannot read as this form rather than treating it as an
    empty one, and refuses a channel outside ``stable|beta|dev`` rather than
    writing a value the poller would then have to report as unusable.
    """
    wrong_encoding = not_a_form_body(
        request, saves="saves your update channel and auto-install preference",
    )
    if wrong_encoding is not None:
        log.warning("about: channel POST refused (415): %s", wrong_encoding)
        refused = _page(request, ctx, wrong_encoding)
        refused.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        return refused

    form = await request.form()
    if _UPDATE_PREFS_SCOPE not in speaks_for(form):
        message = (
            "This form-encoded body did not come from the update settings form, so "
            "nothing was saved. An unticked checkbox is submitted as no field at "
            "all, so without that declaration a body that simply arrived empty "
            "would read as 'turn auto-install off'."
        )
        log.warning("about: channel POST refused (400): %s", message)
        refused = _page(request, ctx, message)
        refused.status_code = status.HTTP_400_BAD_REQUEST
        return refused

    channel = normalise_channel(update_channel)
    if channel is None:
        message = (
            f"{update_channel!r} is not an update channel. Choose one of "
            f"{', '.join(CHANNELS)}. Nothing was saved."
        )
        refused = _page(request, ctx, message)
        refused.status_code = status.HTTP_400_BAD_REQUEST
        return refused

    if ctx.config_store is None:
        return _page(request, ctx, "Config store not available; nothing was saved.")

    try:
        cfg = ctx.config_store.load()
        cfg.update.channel = channel
        cfg.update.auto_install = bool(auto_install)
        ctx.config_store.save(cfg)
    except Exception as exc:
        log.exception("about: failed to save update settings")
        return _page(request, ctx, f"Failed to save update settings: {exc}")

    live = _apply_channel_to_poller(ctx, channel)
    install_note = (
        "Updates found will be installed automatically."
        if cfg.update.auto_install
        else "Updates found will be offered here, not installed."
    )
    if live:
        message = (
f"Update channel: {channel}. In force now — the next check uses it, "
            f"including the one you start with the button above. {install_note}"
        )
    else:
        message = (
            f"Update channel: {channel}, saved. No update checker is running in "
            "this Agent right now, so nothing has changed yet: the new channel "
            f"takes effect the next time the Agent starts. {install_note}"
        )
    log.info("about: update channel set to %s (live=%s)", channel, live)
    return _page(request, ctx, message)


@router.post("/install", response_class=HTMLResponse, response_model=None)
async def install_update(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Install the update the last check verified.

    Stages the *exact* manifest bytes and signature the poller verified and
    hands off to ``Updater.exe``; nothing is re-downloaded here, so what gets
    installed is what passed the signature check and not a second fetch that
    might differ.
    """
    pending = getattr(ctx.update_poller, "pending", None)
    if not pending:
        return _page(
            request, ctx,
            "There is no verified update staged to install. Press Check for "
            "updates now first; if it finds one, this button will take it.",
        )

    manifest, raw, sig = pending
    try:
        # Reached through the module rather than by a bound name so the
        # hand-off can be substituted in a test without spawning a real process.
        handoff.stage_pending(manifest, manifest_bytes=raw, signature_bytes=sig)
        pid = handoff.spawn_updater()
    except Exception as exc:
        log.exception("about: handing off to the updater failed")
        return _page(
            request, ctx,
            f"Could not start the updater for {manifest.version}: {exc}. Nothing "
            "has been changed on disk; the update is still available to retry.",
        )

    log.info("about: updater spawned pid=%s for version=%s", pid, manifest.version)
    return _page(
        request, ctx,
        f"Installing {manifest.version}. The updater is running and the Agent "
        "will restart itself when it is done.",
    )


@router.post("/rollback")
async def rollback(
    ctx: Annotated[BackendContext, Depends(get_context)],  # noqa: ARG001
    target_version: Annotated[str, Form()] = "",
) -> RedirectResponse:
    """Initiate a rollback to a previous version."""
    log.info("about: rollback requested to version=%r", target_version)
    # Actual rollback wired by SPEC-10; here we log the intent.
    return RedirectResponse(url="/about", status_code=303)
