"""Network MCP: the whole endpoint, configured and operated from the browser.

Contract §3: the URL, the certificate fingerprint and the bearer token are
shown **once**, each with a copy button, so the operator can paste them into
PersonaCore's Plugins page and secret store. :func:`NetworkMCPServer.info`
(``network_mcp/server.py``) is the read-only source for all of it; this
router never mutates anything under ``network_mcp/`` -- it calls that
package's public interface and nothing else.

Beyond that surface this router owns three things the operator previously had
to leave the UI for, and the product requirement is that they never have to
again -- no config file, no command line:

* **Switching the endpoint on, and choosing its interfaces and port.**
  ``POST /network-mcp/settings`` writes ``[network_mcp]`` through the config
  store and then starts, stops or rebinds the live endpoint on the Agent's own
  event loop, so the change takes effect without a restart. See
  :func:`_apply_endpoint`. The interface control is a **multi-select**: a
  machine that bridges two networks has to answer on both, and which addresses
  is the operator's decision, made from a list of the addresses this machine
  actually has. Selecting three is not selecting "all" — the wildcard the
  schema refuses is refused just as hard per entry.
* **Never letting the operator choose an address the certificate cannot
  cover.** An address outside the SAN is one where PersonaCore's pin succeeds
  and any hostname-verifying client is rejected. Such an address is rendered
  unselectable, and — because a disabled attribute is decoration, not a rule —
  :func:`settings_post` refuses to save a selection containing one. The only
  way through is the explicit "regenerate the certificate to cover these
  addresses" action, which states the fingerprint consequence first. See
  :func:`_gate_uncovered`.
* **Exporting the registration.** ``POST /network-mcp/export-registration``
  writes ``workstation-registration.zip`` and
  ``GET /network-mcp/registration.zip`` hands it to the browser; the
  ``Agent.exe export-registration`` subcommand is untouched and still works for
  scripted use.
* **Refusing to hand over a registration that cannot work.** The export
  pre-flight (:func:`registration_problems`) reads the *live* endpoint, so a
  registration for a stopped endpoint, or one pointing at loopback, is
  reported before it is written rather than discovered on the core.
* **Joining a PersonaCore.** ``POST /network-mcp/join`` takes three things the
  owner supplies — the core's address, the pairing code its console is showing,
  and which of this machine's bound addresses the core should reach it on — and
  hands them to :func:`~workstation_agent.network_mcp.join.join_core`. That call
  owns the whole handshake: it opens the enrolment window, sends the Join, and
  closes the window again on every failure. See ``network_mcp/join.py`` for the
  order and why it is that order.

  **This router does not call ``begin_join`` itself, and must not start.**
  ``join_core`` opens the window *inside its own* ``try``/``finally``, which is
  what guarantees the window closes when the outbound leg fails. A window opened
  out here would be opened outside the block that closes it, and this endpoint's
  one unauthenticated route would be left standing open for the rest of its TTL.
  ``can_join`` still asks whether ``begin_join`` exists, because that is the
  member ``join_core`` needs on the endpoint — asking is not calling.

  **The code is never echoed back into the page and never logged**, here or
  anywhere below. The field is rendered empty on every outcome, including the
  failures — a re-rendered form that helpfully preserves what the owner typed is
  a pairing code sitting in a page, in a webview, in a screenshot. Nor does any
  of this reach the audit database, whose ``args_json`` is *truncated* to 200
  characters, which is not the same thing as redacted. The core's *address* is
  not a secret and is echoed back on a failure so the owner does not retype it,
  but it is still kept out of the log: nothing is gained by writing down which
  household machine talks to which, and a log line is the easiest place for that
  to end up by accident.

* **Listing what this workstation is enrolled with, and removing it.**
  ``POST /network-mcp/enrolled/remove`` calls
  :func:`~workstation_agent.network_mcp.join.remove_enrolled_core`, which drops
  the row **and rotates the bearer token** so the removed core cannot reconnect.
  This endpoint holds exactly one token, so that rotation locks out *every*
  enrolled core, not only the one removed. The page says so before the button is
  pressed, not after — see the Enrolled section of ``network_mcp.html``.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import ValidationError

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp.enrolment import EnrolmentError
from workstation_agent.network_mcp.join import (
    join_and_report,
    list_enrolled_cores,
    remove_enrolled_core,
)
from workstation_agent.registration_export import (
    REGISTRATION_ZIP_NAME,
    export_registration_from_endpoint,
    is_loopback_host,
    registration_problems,
    san_covers,
)
from workstation_agent.ui.backend.app import (
    BackendContext,
    _appdata_root,
    get_context,
    templates,
)
from workstation_agent.ui.backend.credential_reveal import (
    RevealPersistenceError,
    consume_reveal,
)

if TYPE_CHECKING:  # pragma: no cover
    from workstation_agent.config.schema import AgentConfig

log = logging.getLogger(__name__)

router = APIRouter(prefix="/network-mcp", tags=["network-mcp"])

_PORT_MIN = 0
_PORT_MAX = 65535

#: Ceiling on an operator-facing message before it is rendered.
#:
#: The reason is the Join: a core's refusal is passed through **verbatim**,
#: which is right — it is the diagnosis, and rewording it would throw the
#: diagnosis away — but it is also a string chosen by a remote machine at an
#: address someone typed, arriving through ``join._refusal_of``, which reads a
#: ``detail`` out of a body capped at 64 KiB and does not bound the sentence.
#: 64 KiB of unbroken characters in a ``<p>`` is a page the owner cannot use.
#: Generous enough that no real refusal is ever cut — the core's are one line —
#: and the cut says so when it happens, because a truncated message that looks
#: whole is worse than one that admits it.
_MAX_MESSAGE_CHARS: Final = 400


def _bounded(message: str | None) -> str | None:
    """Cap a message at :data:`_MAX_MESSAGE_CHARS`, visibly.

    Applied in :func:`_render` rather than at each call site, so a path that
    forgets cannot exist. Local messages are far below the cap and pass through
    untouched; this is here for the ones written by the core.
    """
    if message is None or len(message) <= _MAX_MESSAGE_CHARS:
        return message
    return message[:_MAX_MESSAGE_CHARS].rstrip() + " … (message truncated)"

#: Sentinel value for the "type an address the list did not offer" option.
_OTHER = "__other__"


def _token_identity(token: str) -> str:
    """A stand-in for the token that is safe to keep in the reveal-state file.

    Never the token itself: :func:`consume_reveal` persists whatever it is
    given to disk, and the whole point of this surface is that the token
    only ever lives in memory and in what the operator pasted elsewhere.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def export_dir() -> Path:
    """Where ``workstation-registration.zip`` is written.

    Under ``%APPDATA%\\WorkstationAgent`` rather than the working directory
    (which for a windowed Agent is wherever the shortcut happened to point) or
    the Downloads folder (which the browser download owns). It honours
    ``PC_AGENT_APPDATA`` through :func:`_appdata_root`, so tests never write to
    the real profile.
    """
    return _appdata_root() / "registration"


# ---------------------------------------------------------------------------
# Interface discovery for the bind_host control
# ---------------------------------------------------------------------------


def _interface_choices(
    selected: Sequence[str],
    sans: object = None,
    *,
    check_coverage: bool = False,
) -> list[dict[str, Any]]:
    """The addresses this machine actually has, classified for the UI.

    ``NetworkMcpConfig`` refuses a wildcard bind outright, so offering a bare
    text box means the operator's first attempt at "listen everywhere" is a
    validation error. Offering the machine's real addresses instead turns the
    decision the schema is asking for -- *which* interfaces -- into a choice
    from a list, with loopback visibly marked as the answer that cannot work
    for PersonaCore.

    The addresses come from
    :func:`~workstation_agent.network_mcp.certs.local_identities`, which is
    also what the certificate's SAN is built from. Using the same source for
    both is deliberate: an address offered here is, on a freshly generated
    certificate, an address the certificate already covers.

    Args:
        selected: The addresses currently chosen. Every one of them appears in
            the list even if this machine no longer has it, marked selected --
            a control that silently dropped a configured address would look
            like the operator had deselected it.
        sans: The live certificate's SAN entries, for the ``covered`` flag.
        check_coverage: Whether ``sans`` is trustworthy. False when there is no
            endpoint to ask *or* when what it returned is not a readable list of
            entries, in which case every choice is reported covered: marking
            everything unselectable because a certificate could not be read
            would be a page with no working options on it, and the endpoint's
            own refusal to bind an uncovered address still stands either way.

    Returns:
        Dicts of ``value``/``label``/``kind``/``selected``/``covered``, LAN
        addresses first, then hostnames, then loopback.
    """
    dns_names: list[str] = []
    ips: list[str] = []
    try:
        from workstation_agent.network_mcp.certs import local_identities  # noqa: PLC0415

        dns_names, ips = local_identities()
    except Exception:
        log.warning("network-mcp: could not enumerate this machine's addresses", exc_info=True)

    chosen = {h.strip().lower() for h in selected if h and h.strip()}
    lan: list[dict[str, Any]] = []
    loopback: list[dict[str, Any]] = []
    names: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(value: str, kind: str, label: str) -> None:
        key = value.strip().lower()
        if not key or key in seen:
            return
        seen.add(key)
        covered = san_covers(value, sans) if check_coverage else True
        {"lan": lan, "loopback": loopback, "hostname": names}[kind].append({
            "value": value,
            "label": label if covered else f"{label} — NOT in the certificate",
            "kind": kind,
            "selected": key in chosen,
            "covered": covered,
        })

    for ip in ips:
        if is_loopback_host(ip):
            _add(ip, "loopback", f"{ip} — loopback, this machine only")
        else:
            _add(ip, "lan", f"{ip} — LAN address, reachable from PersonaCore")
    for name in dns_names:
        if is_loopback_host(name):
            _add(name, "loopback", f"{name} — loopback, this machine only")
        else:
            _add(name, "hostname", f"{name} — this machine's name (needs working DNS)")

    choices = lan + names + loopback
    for current in selected:
        if not current or current.strip().lower() in seen:
            continue
        seen.add(current.strip().lower())
        kind = "loopback" if is_loopback_host(current) else "lan"
        suffix = " — loopback, this machine only" if kind == "loopback" else " — currently set"
        covered = san_covers(current, sans) if check_coverage else True
        choices.append({
            "value": current,
            "label": f"{current}{suffix}" + ("" if covered else " — NOT in the certificate"),
            "kind": kind,
            "selected": True,
            "covered": covered,
        })
    return choices


def _readable_sans(info: Any) -> Sequence[object] | None:  # noqa: ANN401
    """The endpoint's SAN entries, or ``None`` if they cannot be read as a list.

    ``info`` is whatever ``ctx.network_mcp`` returned: a stub, a build with a
    renamed field, an ``info()`` that degraded. :func:`san_covers` answers "not
    covered" for anything that is not a real sequence, which is the right answer
    for one address and the wrong one for a *rule* -- it would call every
    address uncovered.
    """
    sans = getattr(info, "certificate_sans", None) if info is not None else None
    if isinstance(sans, (str, bytes)) or not isinstance(sans, Sequence) or not sans:
        return None
    return sans


def _uncovered_hosts(hosts: Sequence[str], info: Any) -> tuple[str, ...]:  # noqa: ANN401
    """Which of *hosts* the endpoint's certificate does not cover, for display.

    Compares literally, including against a SAN that could not be read -- which
    reports everything uncovered, and is right *here*, because the page's job is
    to say "we cannot confirm the certificate covers this". Refusing a save on
    that basis is a different question; see :func:`_gate_uncovered`.
    """
    if info is None:
        return ()
    sans = getattr(info, "certificate_sans", None)
    return tuple(h for h in hosts if h and not san_covers(h, sans))


def _gate_uncovered(hosts: Sequence[str], info: Any) -> tuple[str, ...]:  # noqa: ANN401
    """Which of *hosts* to **refuse the save for**.

    **This is the gate, not the disabled attribute in the template.** An
    ``<option disabled>`` stops a click; it stops nothing else -- not a crafted
    POST, not a browser with scripting off, not a stale page rendered before
    the certificate was rotated narrower. The selection is therefore checked
    here, on the server, on the way to the config store, and the same
    comparison (:func:`san_covers`) is what the endpoint itself uses to decide
    whether to bind an address at all. Two gates, one rule, and the second one
    holds even if this router is bypassed entirely.

    Empty when there is no endpoint to ask, and when its SAN cannot be read:
    refusing every address on the strength of a value nobody could read would
    lock the operator out of the one screen that can fix it. That leniency is
    safe *precisely because this is not the invariant* --
    :func:`~workstation_agent.network_mcp.listeners.open_listeners` compares
    against the parsed certificate, which is always a real tuple, and refuses to
    bind regardless of what this function decided. The page still says it could
    not confirm coverage, via :func:`_uncovered_hosts`.
    """
    if _readable_sans(info) is None:
        if info is not None:
            log.warning(
                "network-mcp: the endpoint's certificate SAN could not be read, so the "
                "address selection was not refused here; the endpoint itself still "
                "refuses to bind an address it cannot present a certificate for",
            )
        return ()
    return _uncovered_hosts(hosts, info)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _load_config(ctx: BackendContext) -> tuple[AgentConfig | None, str | None]:
    """Load the config, returning ``(cfg, error)`` rather than raising."""
    if ctx.config_store is None:
        return None, (
            "The configuration store is not available, so the endpoint's settings "
            "cannot be read or changed from here."
        )
    try:
        return ctx.config_store.load(), None
    except Exception as exc:
        log.exception("network-mcp: failed to load config")
        return None, f"Failed to load the current configuration: {exc}"


def _read_info(server: Any) -> tuple[Any, str | None]:  # noqa: ANN401
    """``server.info()``, or ``(None, message)`` if it cannot be read."""
    if server is None:
        return None, None
    try:
        return server.info(), None
    except Exception as exc:  # noqa: BLE001 — surfaced to the page, not raised
        log.warning("network-mcp: info() failed: %s", exc)
        return None, "Could not read the network MCP endpoint's current state."


def _consume_reveals(info: Any) -> tuple[bool, bool, str | None]:  # noqa: ANN401
    """Show-once bookkeeping for the token and fingerprint.

    Fail-closed on a persistence failure: when we cannot durably record that a
    value was shown, it is *not* shown. Revealing anyway would turn one write
    failure into a standing leak of the token on every page load.
    """
    if info is None:
        return False, False, None
    try:
        return (
            consume_reveal("token", _token_identity(info.token)),
            consume_reveal("fingerprint", info.fingerprint),
            None,
        )
    except RevealPersistenceError:
        log.exception("network-mcp: reveal state persistence failed")
        return False, False, (
            "Could not record that the token/fingerprint were shown, so they "
            "are being kept hidden for safety. Check that this workstation's "
            "%APPDATA%\\WorkstationAgent directory is writable, then reload "
            "this page."
        )


def _join_status(server: Any) -> Any:  # noqa: ANN401
    """The pending enrolment window, or ``None``.

    ``getattr`` rather than attribute access for the same reason ``_read_info``
    uses it: ``ctx.network_mcp`` is whatever was injected, and a stub without
    this method must render a page without a Join section rather than 500 the
    whole settings screen.
    """
    status = getattr(server, "join_status", None)
    if not callable(status):
        return None
    try:
        return status()
    except Exception:
        log.warning("network-mcp: join_status() failed", exc_info=True)
        return None


def _enrolled_state_dir(server: Any) -> Path:  # noqa: ANN401 — whatever was injected
    """Where *this page's* enrolled-core rows live.

    Asked of the endpoint the page is rendering, not of
    :data:`~workstation_agent.network_mcp.join._endpoint`, so a listing and the
    removal that follows it are always about the same directory — the failure
    mode ``join._state_dir_for`` calls "a bug with no symptom".

    The fallback matters only for a stub or an endpoint object old enough not to
    expose ``state_dir``. It is spelled through :func:`_appdata_root` rather than
    imported from ``credentials.DEFAULT_STATE_DIR`` because that constant is
    computed at import time from ``%APPDATA%`` and cannot see a later override,
    so a test with ``PC_AGENT_APPDATA`` set would read — and a removal would
    rotate a token in — the real user's profile.
    """
    directory = getattr(server, "state_dir", None)
    if isinstance(directory, Path):
        return directory
    return _appdata_root() / "network-mcp"


def _enrolled_cores(server: Any) -> tuple[Any, ...]:  # noqa: ANN401 — see _read_info
    """Every core this workstation has joined, for the listing.

    ``list_enrolled_cores`` already answers an unreadable file with an empty
    tuple for the reason this wrapper exists as well: the Remove button on that
    page is what an operator fixes a bad state *with*, and a listing that raised
    would take it away. What is caught here is the layer below it — an
    ``%APPDATA%`` that cannot be resolved at all.
    """
    try:
        return tuple(list_enrolled_cores(state_dir=_enrolled_state_dir(server)))
    except Exception:
        log.warning("network-mcp: the enrolled-core listing could not be read", exc_info=True)
        return ()


def _listen_choices(info: Any) -> list[dict[str, str]]:  # noqa: ANN401 — see _read_info
    """The addresses the owner may tell PersonaCore to reach this machine at.

    Built from the endpoint's own :attr:`~...server.NetworkEndpointInfo.urls`
    and ``bind_hosts`` — which while running are the addresses that actually
    *bound*, so an address the operator chose and that failed to bind is not
    offered as somewhere the core can connect.

    **Loopback is filtered out, and the filter is not the rule.** Telling the
    core to connect to ``127.0.0.1`` tells it to connect to *itself*. Both
    :meth:`~...server.NetworkMCPServer.begin_join` and the core refuse such an
    address already; dropping it here only spares the owner choosing something
    that was always going to be refused. When the filter leaves nothing, the
    page says so rather than showing an empty dropdown — see
    :func:`_no_listen_address_message`.
    """
    hosts = [str(h) for h in (getattr(info, "bind_hosts", ()) or ()) if str(h)]
    urls = [str(u) for u in (getattr(info, "urls", ()) or ()) if str(u)]
    if not hosts:
        # A stub, or a build predating the multi-bind fields. The preferred
        # address is the whole of what such an endpoint can tell us.
        one = str(getattr(info, "bind_host", "") or "")
        hosts = [one] if one else []
        urls = urls or ([str(getattr(info, "url", "") or "")] if one else [])

    choices: list[dict[str, str]] = []
    for index, host in enumerate(hosts):
        if is_loopback_host(host):
            continue
        url = urls[index] if index < len(urls) else ""
        # The URL is the label's payload, not decoration: it is literally what
        # gets written into the core's plugin manifest, so the owner is picking
        # a connection string and should be able to read the one they picked.
        label = f"{host} — PersonaCore will connect to {url}" if url else host
        choices.append({"value": host, "label": label, "url": url})
    return choices


def _no_listen_address_message(info: Any) -> str:  # noqa: ANN401 — see _read_info
    """Why there is nothing to pick, when :func:`_listen_choices` came back empty.

    The first two sentences are **deliberately the same sentences**
    :meth:`~...server.NetworkMCPServer.begin_join` refuses a loopback-only
    endpoint with. The owner meets this condition by two routes — pre-empted
    here, or refused there if they get as far as pressing Join — and being told
    it twice in two different voices reads as two different problems. Where the
    two differ is the ending: ``begin_join`` says "bind a LAN address first",
    which is advice; this one can point at the control that does it, which is a
    click.
    """
    hosts = [str(h) for h in (getattr(info, "bind_hosts", ()) or ()) if str(h)]
    if not hosts:
        one = str(getattr(info, "bind_host", "") or "")
        hosts = [one] if one else []
    listed = ", ".join(hosts)
    if not listed:
        return (
            "The endpoint is not answering on any address, so there is nothing to "
            "tell PersonaCore to connect to. Switch it on in Endpoint settings above, "
            "wait for it to report that it is listening, then join."
        )
    return (
        f"The endpoint is bound to {listed}, which is this machine only. "
        f"PersonaCore runs elsewhere and cannot reach it to push the token. "
        f"Bind a LAN address first, then join."
    )


def _refuse_listen_address(typed: str, choices: Sequence[dict[str, str]]) -> str | None:
    """Refuse a listen address this endpoint is not actually answering on.

    **This is the gate; the ``<select>`` is not.** It is the same relationship
    :func:`_gate_uncovered` has with its ``<option disabled>``: a dropdown
    constrains a browser being operated normally and constrains nothing else,
    and every field on a form is attacker-supplied whatever the page offered.
    Without this check a hand-made POST carrying ``listen_address=127.0.0.1``
    walks straight past the loopback-only screen the template renders so
    carefully — ``begin_join`` would not catch it either, because what *it*
    asks is whether the endpoint is loopback-*bound*, which is a different
    question from what address the core is being told to dial.

    It has to live here rather than in ``join.py`` for the reason ``listen_url``
    gives for not checking loopback itself: only the router can see the live
    bind set, and :func:`_listen_choices` is built from it, so comparing against
    that list is comparing against the endpoint.

    An empty value is passed through untouched. ``join.listen_url`` already
    refuses it with a sentence written for the operator, and answering the same
    condition here would be a second wording of it.

    Returns:
        The refusal, or ``None`` if *typed* is one this endpoint is serving.
    """
    wanted = typed.strip().lower()
    if not wanted:
        return None
    if any(c["value"].strip().lower() == wanted for c in choices):
        return None

    if is_loopback_host(typed.strip()):
        # The core's own sentence for this exact condition, quoted in
        # ``join.listen_url``'s docstring. It is the authority on what it will
        # accept, and a refusal of ours in different words for the same reason
        # would read as a different problem when the owner met both.
        return (
            f"{typed.strip()} is not an address another machine can be reached at. "
            f"Give the workstation's address on the network the core is on."
        )
    offered = ", ".join(c["value"] for c in choices)
    if not offered:
        return _no_listen_address_message(None)
    return (
        f"This endpoint is not answering on the address that was submitted, so "
        f"PersonaCore would be sent somewhere it cannot reach this workstation. "
        f"It is answering on {offered}. Choose one of those and join again."
    )


def _render(  # noqa: PLR0913 — one parameter per independent page outcome
    request: Request,
    ctx: BackendContext,
    *,
    saved: bool = False,
    notice: str | None = None,
    field_errors: dict[str, str] | None = None,
    form_values: dict[str, Any] | None = None,
    export_result: Any = None,  # noqa: ANN401
    export_problems: tuple[str, ...] = (),
    export_error: str | None = None,
    join_error: str | None = None,
    join_notice: str | None = None,
    join_values: dict[str, str] | None = None,
    remove_error: str | None = None,
    remove_notice: str | None = None,
    uncovered: tuple[str, ...] = (),
) -> HTMLResponse:
    """Render ``network_mcp.html`` for every outcome this router produces.

    One renderer for GET and for each POST, so a validation failure shows the
    same page with the message attached rather than a bare error screen, and
    so no outcome can quietly forget the show-once bookkeeping.
    """
    cfg, cfg_error = _load_config(ctx)
    info, info_error = _read_info(ctx.network_mcp)
    reveal_token, reveal_fingerprint, reveal_error = _consume_reveals(info)

    nm = cfg.network_mcp if cfg is not None else NetworkMcpConfig()
    values = {
        "enabled": nm.enabled,
        "bind_host": nm.bind_host,
        "bind_hosts": list(nm.bind_hosts),
        "port": nm.port,
        **(form_values or {}),
    }
    bind_hosts = [str(h) for h in values["bind_hosts"]]

    running = bool(getattr(info, "running", False))
    cert_warning: str | None = None
    # ``getattr``, not attribute access: ``info`` is whatever ``ctx.network_mcp``
    # returned, and a stub or a future field rename must degrade to "we cannot
    # confirm the certificate covers this" rather than 500 the settings page.
    sans = getattr(info, "certificate_sans", None)
    # Reported for the whole selection, not only the preferred address: with a
    # set, a SAN gap on the third entry is exactly as fatal to a
    # hostname-verifying client as one on the first, and naming only the first
    # would send the operator to regenerate for an address that was already fine.
    missing = uncovered or _uncovered_hosts(bind_hosts, info)
    if missing:
        listed = ", ".join(str(s) for s in sans) if isinstance(sans, (tuple, list)) else "empty"
        subject = ", ".join(missing)
        cert_warning = (
            f"The stored certificate does not cover {subject}. Its SAN is {listed}. "
            "PersonaCore pins the fingerprint rather than checking the name, so it "
            "will most likely still connect; any client that does verify hostnames "
            "will not, and this endpoint will not bind an address it cannot present "
            "a matching certificate for. Regenerating fixes the SAN but changes the "
            "fingerprint, which breaks the core's pin until the registration below "
            "is re-exported and reinstalled on the Plugins page."
        )

    # Same leniency as ``_gate_uncovered``: a SAN we could not read must not
    # grey out every option on the page. The warning above still says so.
    choices = _interface_choices(
        bind_hosts, sans, check_coverage=_readable_sans(info) is not None,
    )
    listen_choices = _listen_choices(info) if info is not None else []
    last_export = export_dir() / REGISTRATION_ZIP_NAME
    try:
        have_export = last_export.is_file()
    except OSError:  # a roaming/redirected APPDATA that is currently unreachable
        log.warning("network-mcp: could not stat %s", last_export, exc_info=True)
        have_export = False
    return templates.TemplateResponse(
        request,
        "network_mcp.html",
        {
            # identity / credentials
            "enabled": ctx.network_mcp is not None,
            "info": info,
            "running": running,
            "error": info_error or cfg_error,
            "reveal_error": reveal_error,
            "reveal_token": reveal_token,
            "reveal_fingerprint": reveal_fingerprint,
            # endpoint settings form
            "can_configure": cfg is not None,
            "values": values,
            "host_choices": choices,
            # True only when *every* chosen address is loopback: a set that
            # includes a LAN address is reachable, and warning about it would be
            # a red message the operator cannot act on.
            "bind_is_loopback": bool(bind_hosts) and all(
                is_loopback_host(h) for h in bind_hosts
            ),
            "field_errors": field_errors or {},
            "saved": saved,
            "notice": notice,
            "other_sentinel": _OTHER,
            "host_is_listed": all(
                any(c["value"].strip().lower() == h.strip().lower() for c in choices)
                for h in bind_hosts
            ),
            "cert_warning": cert_warning,
            "uncovered": tuple(missing),
            # A partial bind: serving, but not everywhere the operator chose.
            # Rendered as a failure, never folded into the "running" light.
            "bind_failures": tuple(getattr(info, "bind_failures", ()) or ()),
            "degraded": bool(getattr(info, "degraded", False)),
            # export
            "export_result": export_result,
            "export_problems": export_problems,
            "export_error": export_error,
            "export_path": str(last_export),
            "have_previous_export": have_export,
            # enrolment. ``join`` never carries the pairing code, and no
            # template variable holds it: see this module's docstring.
            # ``join_values`` deliberately has no ``code`` key at all -- an
            # absent key cannot be re-rendered by a template that forgets.
            "join": _join_status(ctx.network_mcp),
            # Bounded here rather than at each call site: both of these can
            # carry a sentence the *core* wrote, and a path that forgot to cap
            # one would be a page a remote machine could stretch. See
            # :func:`_bounded`.
            "join_error": _bounded(join_error),
            "join_notice": _bounded(join_notice),
            "join_values": {
                "core_address": (join_values or {}).get("core_address", ""),
                "listen_address": (join_values or {}).get("listen_address", ""),
            },
            "can_join": callable(getattr(ctx.network_mcp, "begin_join", None)),
            "listen_choices": listen_choices,
            # Rendered only when there is nothing to choose, so the owner never
            # meets an empty dropdown with no explanation beside it.
            "listen_empty": (
                _no_listen_address_message(info) if info is not None and not listen_choices
                else None
            ),
            # enrolled cores. Both messages quote display names the core
            # normalised, so they are remote text too and capped alike.
            "enrolled": _enrolled_cores(ctx.network_mcp),
            "remove_error": _bounded(remove_error),
            "remove_notice": _bounded(remove_notice),
        },
    )


@router.get("", response_class=HTMLResponse)
async def network_mcp_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the endpoint's settings, its identity, and any unseen credentials."""
    return _render(request, ctx)


# ---------------------------------------------------------------------------
# Endpoint settings: enable / bind_host / port, applied to the running server
# ---------------------------------------------------------------------------


def _parse_settings_form(
    enabled: str,
    bind_hosts: Sequence[str],
    bind_host_choice: str,
    bind_host_other: str,
    port: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Turn the raw form strings into values, collecting per-field errors.

    Every field arrives as ``str`` on purpose. Declaring ``port: int`` would
    hand a typo to FastAPI's own validation, which answers 422 with a JSON
    error body -- a dead end in a webview with no way back to the form. Parsed
    here, a typo comes back as a message next to the field.

    *bind_hosts* is the multi-select. *bind_host_choice* is the single-select
    that preceded it, still accepted and folded into the same set: the page is
    not the only thing that posts here (the export flow re-posts the settings,
    and a bookmarked or scripted POST is a real shape), and silently ignoring a
    field that used to work would look like a save that did nothing.

    The first selected address is the **preferred** one -- the address the
    registration names -- so the order of the selection is meaningful and is
    preserved. De-duplication is by :func:`_host_key`, so choosing both ``::1``
    and ``[::1]`` is one address rather than a bind failure on the second.
    """
    from workstation_agent.config.schema import _host_key  # noqa: PLC0415

    errors: dict[str, str] = {}

    hosts: list[str] = []
    seen: set[str] = set()
    for raw in [*bind_hosts, bind_host_choice]:
        entry = (bind_host_other if raw.strip() == _OTHER else raw).strip()
        if not entry:
            continue
        key = _host_key(entry)
        if key in seen:
            continue
        seen.add(key)
        hosts.append(entry)

    host = hosts[0] if hosts else ""
    if not host:
        errors["bind_host"] = (
            "Choose the interface to bind, or type one. It must name a single "
            "interface on this machine."
        )

    # The *raw* string when parsing fails, never a substituted 0. Echoing 0
    # back would both lose what the operator typed and trip the page's genuine
    # "port 0 lets the OS pick a different port every start" warning, which has
    # nothing to do with the typo they actually made.
    parsed_port: Any = port.strip()
    stripped_port = port.strip()
    if not stripped_port:
        # Not defaulted silently. FastAPI substitutes a parameter default for an
        # empty form value, so declaring `port: str = "8765"` would turn a
        # cleared field into a save that quietly bound 8765 -- a port the
        # operator never chose, on an endpoint they were in the middle of
        # configuring.
        errors["port"] = "Enter a port number."
    else:
        try:
            parsed_port = int(stripped_port)
        except (TypeError, ValueError):
            errors["port"] = f"{stripped_port!r} is not a whole number."
        else:
            if not (_PORT_MIN <= parsed_port <= _PORT_MAX):
                errors["port"] = f"Port must be between {_PORT_MIN} and {_PORT_MAX}."

    return (
        {
            "enabled": bool(enabled),
            "bind_host": host,
            "additional_bind_hosts": hosts[1:],
            # Not a schema field -- the resolved set, for re-rendering the
            # control and for the SAN gate. :func:`_validated_network_config`
            # drops it rather than handing pydantic something it does not know.
            "bind_hosts": hosts,
            "port": parsed_port,
        },
        errors,
    )


def _validated_network_config(
    nm: NetworkMcpConfig,
    values: dict[str, Any],
) -> tuple[NetworkMcpConfig | None, str | None]:
    """Apply *values* onto a copy of *nm*, running the schema's validators.

    Assignment is not enough: ``NetworkMcpConfig`` does not set
    ``validate_assignment``, so ``nm.bind_host = "0.0.0.0"`` would sail past
    the wildcard validator and be written to disk. Re-validating the whole
    model is what actually runs :meth:`NetworkMcpConfig._reject_wildcard_bind`.

    The message handed back is the schema's own -- pydantic prefixes a
    validator's ``ValueError`` with ``"Value error, "``, which is stripped so
    the operator reads the sentence the schema wrote and not pydantic's
    framing. Keeping one copy of that sentence means the UI cannot drift out
    of step with what the schema actually refuses.
    """
    data = nm.model_dump()
    # Only real fields: ``values`` also carries the resolved ``bind_hosts`` set,
    # which is a *property* of the model. Pydantic ignores unknown keys by
    # default, so passing it would be silently harmless today and a silently
    # ignored setting the day someone adds ``extra="forbid"``.
    data.update({k: v for k, v in values.items() if k in NetworkMcpConfig.model_fields})
    try:
        return NetworkMcpConfig.model_validate(data), None
    except ValidationError as exc:
        first = exc.errors()[0]
        message = str(first.get("msg", "")).removeprefix("Value error, ")
        field = ".".join(str(p) for p in first.get("loc", ())) or "setting"
        return None, message or f"{field} is not valid."


async def _stop_quietly(server: Any) -> None:  # noqa: ANN401
    """``await server.stop()``, tolerating a server that cannot be stopped."""
    stop = getattr(server, "stop", None)
    if stop is None:
        return
    try:
        result = stop()
        if inspect.isawaitable(result):
            await result
    except Exception:
        log.exception("network-mcp: stopping the previous endpoint failed")


def _build_server(ctx: BackendContext, nm: NetworkMcpConfig) -> Any:  # noqa: ANN401
    """Construct an endpoint for *nm*, via the injected factory if there is one."""
    factory = ctx.network_mcp_factory
    if callable(factory):
        return factory(nm)
    from workstation_agent.network_mcp.server import NetworkMCPServer  # noqa: PLC0415

    return NetworkMCPServer(nm, mcp_host=ctx.mcp_host)


def _publish(ctx: BackendContext, server: Any) -> None:  # noqa: ANN401
    """Install *server* as the live endpoint and tell the composition root.

    Without the callback the Agent's own handle would still point at the
    server it started (or at nothing), and a UI-started endpoint would keep
    listening after shutdown because nobody knew to stop it.
    """
    ctx.network_mcp = server
    notify = ctx.on_network_mcp_change
    if callable(notify):
        try:
            notify(server)
        except Exception:
            log.exception("network-mcp: on_network_mcp_change callback failed")


def _partial_bind_message(server: Any) -> str | None:  # noqa: ANN401
    """The operator-facing sentence for a partial bind, or ``None`` if there is none.

    Names every address that did not bind **and** its reason, and says what the
    endpoint *is* answering on, because both halves are needed to act: which one
    to go and free, and whether the core can reach the machine meanwhile.
    """
    info, _ = _read_info(server)
    failures: tuple[Any, ...] = tuple(getattr(info, "bind_failures", ()) or ())
    if not failures:
        return None
    answering = ", ".join(str(u) for u in getattr(info, "urls", ()) or ()) or "nothing"
    listed = "; ".join(f"{getattr(f, 'host', f)} — {getattr(f, 'reason', '')}" for f in failures)
    return (
        f"Saved, and the endpoint is answering on {answering} — but it is NOT "
        f"answering on every address you chose. Not bound: {listed}. "
        "Free that address (or deselect it) and save again."
    )


def _coverage_probe(ctx: BackendContext, new: NetworkMcpConfig) -> tuple[Any, Any]:
    """Return ``(prepared, info)`` for the SAN gate to compare against.

    The certificate is the endpoint's, so the endpoint is what gets asked. The
    awkward case is the *common* one: with the endpoint switched off the Agent
    never built one, so ``ctx.network_mcp`` is ``None`` and there is nothing to
    ask — which is exactly the first time the operator ever picks an address.
    A gate that quietly passed there would be a gate that never fired when it
    mattered.

    So one is built, published (the page then shows a real identity and can
    grey out what the certificate does not cover) and handed back as
    *prepared*, so :func:`_bring_up` starts **that** object rather than
    building a second: the endpoint the coverage was checked against and the
    endpoint that binds must be the same one, or the check was about a
    certificate other than the one presented.

    Returns ``(None, None)`` if it cannot be built; :func:`_bring_up` then
    reports the construction failure with its own message.
    """
    server = ctx.network_mcp
    if server is None:
        try:
            server = _build_server(ctx, new)
        except Exception:
            log.exception("network-mcp: could not build an endpoint to check the certificate")
            return None, None
        _publish(ctx, server)
        info, _ = _read_info(server)
        return server, info
    info, _ = _read_info(server)
    return None, info


async def _bring_up(
    ctx: BackendContext, new: NetworkMcpConfig, *, prepared: Any = None,  # noqa: ANN401
) -> tuple[str, str | None]:
    """Build a fresh endpoint for *new* and start it. Returns ``(notice, error)``.

    *prepared* is an endpoint already built from *new* by :func:`_coverage_probe`
    in this same request. Reusing it rather than building a second is not an
    optimisation: the certificate whose SAN was checked has to be the
    certificate the listener presents.

    Every failure here is reported rather than raised, and each message says
    what state the operator is actually in. "Saved" is true in all of them --
    the configuration is already on disk by the time this runs -- so the
    distinction that matters is whether the endpoint is up now or only will be
    after a restart, and the messages say which.
    """
    server = prepared
    if server is None:
        try:
            server = _build_server(ctx, new)
        except Exception as exc:
            log.exception("network-mcp: could not build the endpoint")
            return "", (
                f"Saved, but this build could not create the endpoint from the UI ({exc}). "
                "Restart the Agent to apply the change."
            )

    # Already published if it came from `_coverage_probe`; publishing twice
    # would fire the composition root's adoption callback twice for one save.
    if ctx.network_mcp is not server:
        _publish(ctx, server)

    start = getattr(server, "start", None)
    if not callable(start):
        return "", (
            "Saved. This endpoint cannot be started from the UI — restart the "
            "Agent to apply the change."
        )

    try:
        result = start()
        if inspect.isawaitable(result):
            await result
    except Exception as exc:  # noqa: BLE001 — a bind failure is the operator's news
        log.warning("network-mcp: endpoint failed to start: %s", exc)
        return "", (
            f"Saved, but the endpoint could not start: {exc}. The most common cause "
            "is another process already listening on that port. Fix that and save "
            "again, or restart the Agent."
        )

    # A partial bind is reported as a failure, never as a notice. The operator
    # chose three addresses and got two: telling them "the endpoint is
    # listening" would be true and useless, and the missing address is the only
    # part of it they can act on.
    partial = _partial_bind_message(server)
    if partial is not None:
        return "", partial

    if ctx.mcp_host is None:
        # Serving, but every tools/call returns the §5.2 error envelope until a
        # host is attached. Silence here would look like a healthy endpoint.
        return (
            "The endpoint is listening. It is serving its tool list, but no plugin "
            "host is attached, so every tool call will return an error until the "
            "Agent's plugin host is running."
        ), None
    return "The endpoint is listening.", None


async def _apply_endpoint(
    ctx: BackendContext,
    old: NetworkMcpConfig,
    new: NetworkMcpConfig,
    *,
    prepared: Any = None,  # noqa: ANN401
) -> tuple[str, str | None]:
    """Bring the live endpoint into line with *new*. Returns ``(notice, error)``.

    This runs on the Agent's own asyncio loop -- the FastAPI backend and the
    network endpoint are both tasks on the loop owned by
    ``app.Application._loop_thread`` -- so starting and stopping the endpoint
    from a request is a plain ``await``, and enabling it from the UI genuinely
    brings it up rather than promising to at the next restart.

    The endpoint is only touched when something that defines it actually
    changed, or when it is meant to be up and is not. Rebinding drops whatever
    connection the core is holding, so doing it on every save -- including
    saves that changed only an unrelated field -- would be a self-inflicted
    outage.

    A server object is kept even while the endpoint is switched off, built from
    the saved config, so the page can still show the identity and fingerprint
    the operator has to paste into PersonaCore. That is why ``ctx.network_mcp``
    is not a proxy for "enabled".
    """
    # The whole set, not just the preferred address: adding a second address to
    # a running endpoint is a change that has to be applied, and comparing only
    # ``bind_host`` would report "already running with these settings" while one
    # of the chosen addresses had nothing listening on it.
    rebind = (old.bind_hosts, old.port) != (new.bind_hosts, new.port)
    current = ctx.network_mcp
    running = bool(getattr(current, "running", False))

    if not new.enabled:
        if current is not None and running:
            await _stop_quietly(current)
        if current is None or rebind:
            with contextlib.suppress(Exception):
                _publish(ctx, _build_server(ctx, new))
        return ("The endpoint is switched off and no longer listening.", None)

    if current is not None and not rebind and running:
        # Still not a green light if it never bound everything it was asked to.
        partial = _partial_bind_message(current)
        if partial is not None:
            return "", partial
        return "The endpoint is already running with these settings.", None

    # ``current is not prepared``: the endpoint built moments ago for the
    # certificate check is the one about to be started, and stopping it first
    # would report a stop the operator never asked for.
    if current is not None and current is not prepared:
        await _stop_quietly(current)
    return await _bring_up(ctx, new, prepared=prepared)


def _regenerate_for(server: Any, hosts: Sequence[str]) -> None:  # noqa: ANN401
    """Rotate the certificate so it covers *hosts*, tolerating an older shape.

    ``for_hosts`` is checked by introspection rather than assumed: the injected
    endpoint is whatever ``ctx.network_mcp`` holds, and a build whose
    ``regenerate_certificate`` predates the pending-selection argument must
    still rotate rather than raise a ``TypeError`` into the settings page.
    """
    fn = getattr(server, "regenerate_certificate", None)
    if not callable(fn):
        return
    try:
        accepts = "for_hosts" in inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover — a C-level callable
        accepts = False
    if accepts:
        fn(for_hosts=tuple(hosts))
    else:
        fn()


@router.post("/settings", response_class=HTMLResponse, response_model=None)
async def settings_post(  # noqa: PLR0913, PLR0917 — one per form field/outcome
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    enabled: Annotated[str, Form(alias="enabled")] = "",
    bind_hosts: Annotated[list[str], Form(alias="bind_hosts")] = [],  # noqa: B006
    bind_host_choice: Annotated[str, Form(alias="bind_host_choice")] = "",
    bind_host_other: Annotated[str, Form(alias="bind_host_other")] = "",
    port: Annotated[str, Form(alias="port")] = "",
    regenerate: Annotated[str, Form(alias="regenerate")] = "",
) -> HTMLResponse:
    """Save ``[network_mcp]`` and start/stop/rebind the live endpoint.

    ``regenerate`` is the operator's explicit second click on the offer made
    when their selection includes an address the certificate does not cover. It
    rotates the fingerprint -- which breaks PersonaCore's pin until the
    registration is re-exported -- so it is never inferred, only obeyed.

    The mutable default on *bind_hosts* is FastAPI's own convention for a
    repeated form field and is never mutated here; ruff's B006 is about
    functions that mutate theirs.
    """
    cfg, _cfg_error = _load_config(ctx)
    values, errors = _parse_settings_form(
        enabled, bind_hosts, bind_host_choice, bind_host_other, port,
    )

    # ``cfg is None`` means the store is unavailable or unreadable; ``_render``
    # already surfaces that message. Either way the operator's typing is echoed
    # back so nothing they entered is lost.
    if cfg is None or errors:
        return _render(request, ctx, field_errors=errors, form_values=values)

    old = cfg.network_mcp.model_copy(deep=True)
    new, message = _validated_network_config(cfg.network_mcp, values)
    if new is None:
        return _render(
            request, ctx, field_errors={"bind_host": message or ""}, form_values=values,
        )

    # The SAN gate, before anything is written or bound. Only when the endpoint
    # is meant to be up: a selection saved with the endpoint switched off binds
    # nothing, and the endpoint's own refusal still stands at start time.
    prepared: Any = None
    chosen: list[str] = list(values["bind_hosts"])
    if new.enabled:
        prepared, info = _coverage_probe(ctx, new)
        missing = _gate_uncovered(chosen, info)
        if missing and not regenerate:
            return _render(
                request, ctx, form_values=values, uncovered=missing,
                field_errors={"bind_host": (
                    "The endpoint's certificate does not cover "
                    + ", ".join(missing)
                    + ", so the endpoint will not bind that address and nothing has "
                    "been saved. Regenerate the certificate below to cover it, or "
                    "choose a different address."
                )},
            )
        if missing:
            _regenerate_for(ctx.network_mcp, chosen)
            info, _ = _read_info(ctx.network_mcp)
            still = _gate_uncovered(chosen, info)
            if still:
                # Reached when the address is not one this machine has, so
                # ``local_identities`` cannot put it in a SAN. Refused rather
                # than bound: a fingerprint was rotated for nothing already,
                # and binding anyway is the state this gate exists to prevent.
                return _render(
                    request, ctx, form_values=values, uncovered=still,
                    field_errors={"bind_host": (
                        "The certificate was regenerated and still does not cover "
                        + ", ".join(still)
                        + ". That address is not one this machine has, so nothing "
                        "can present a certificate for it. Choose an address from "
                        "the list."
                    )},
                )

    cfg.network_mcp = new
    try:
        ctx.config_store.save(cfg)
    except Exception as exc:
        log.exception("network-mcp: failed to save config")
        return _render(
            request,
            ctx,
            field_errors={"_global": f"Failed to save the configuration: {exc}"},
            form_values=values,
        )

    notice, apply_error = await _apply_endpoint(ctx, old, new, prepared=prepared)
    # No ``form_values``: the save succeeded, so the config store is now the
    # truth and the form redraws from it. Echoing the submitted values back
    # would hide a store that silently normalised something.
    return _render(
        request,
        ctx,
        saved=True,
        notice=notice or None,
        field_errors={"_global": apply_error} if apply_error else None,
    )


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


@router.post("/rotate-token")
async def rotate_token(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Generate a fresh bearer token; it is shown once on the next page load."""
    if ctx.network_mcp is not None:
        with contextlib.suppress(Exception):
            ctx.network_mcp.rotate_token()
        log.info("network-mcp: token rotated")
    return RedirectResponse(url="/network-mcp", status_code=303)


@router.post("/regenerate-certificate")
async def regenerate_certificate(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Generate a fresh certificate; changes the pinned fingerprint.

    The exported registration must be regenerated and reinstalled on
    PersonaCore's Plugins page afterwards, or the core's pin fails.
    """
    if ctx.network_mcp is not None:
        with contextlib.suppress(Exception):
            ctx.network_mcp.regenerate_certificate()
        log.info("network-mcp: certificate regenerated")
    return RedirectResponse(url="/network-mcp", status_code=303)


# ---------------------------------------------------------------------------
# Enrolment: opening the window PersonaCore pushes a token into
# ---------------------------------------------------------------------------


@router.post("/join", response_class=HTMLResponse, response_model=None)
async def join_post(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    code: Annotated[str, Form(alias="code")] = "",
    core_address: Annotated[str, Form(alias="core_address")] = "",
    listen_address: Annotated[str, Form(alias="listen_address")] = "",
) -> HTMLResponse:
    """Run the whole Join: address in, pairing code in, enrolled row out.

    Every field is declared as ``str`` with a default for the same reason every
    other field on this page is: FastAPI answers a missing form field with a 422
    JSON body, which is a dead end in a webview with no way back to the form.

    **This calls ``join_core`` and never ``begin_join``, and calling both would
    be a defect.** ``join_core`` opens the enrolment window itself, inside the
    ``try``/``finally`` that closes it again on every failure. Opening one out
    here as well would put the open outside the block that closes it and leave
    this endpoint's one unauthenticated route standing open for the rest of its
    TTL. It is called through this module's global so a test can substitute it;
    the substitution is a stand-in for the same function, never a second path.

    The endpoint is passed explicitly rather than left to ``join_core``'s
    registered default. The page is rendered from ``ctx.network_mcp``, so that is
    the endpoint the owner is looking at and the one their click has to be about;
    resolving a different object would enrol something the page never described.

    Nothing here logs, echoes or stores *code*. It goes into
    :func:`~workstation_agent.network_mcp.join.join_core`, which keeps it out of
    every log line, exception and stored row, and scrubs the request body once
    the call is over.

    Every refusal reaches the owner as its own author wrote it.
    :class:`~workstation_agent.network_mcp.join.JoinError` subclasses
    ``EnrolmentError``, so the core's verbatim refusal, the receiver's "the
    endpoint is not running", and the "a Join is already in progress" that makes
    a second Join a refusal rather than a queue all arrive through one
    ``except`` and are rendered unwrapped.
    """
    server = ctx.network_mcp
    if server is None or not callable(getattr(server, "begin_join", None)):
        return _render(
            request,
            ctx,
            join_error=(
                "There is no endpoint to enrol yet. Switch it on above, then join."
            ),
        )

    # The core's address and the chosen listen address go back into the form on
    # every failure so a refusal costs one correction rather than three. The
    # pairing code is not among them and there is no key for it to occupy.
    typed = {"core_address": core_address, "listen_address": listen_address}

    # Checked **before the window opens**, and it is the only check there is:
    # see :func:`_refuse_listen_address` for why neither the dropdown nor
    # ``begin_join`` covers this. *core_address* deliberately gets no gate of
    # its own here -- ``join.core_enrol_url`` runs first thing inside the call,
    # ahead of the window, and already refuses an empty address, an unparseable
    # authority, a scheme that is not http(s), an address naming no host, and
    # one carrying userinfo, each with its own operator-facing sentence. A
    # second set of rules out here could only agree with those or contradict
    # them, and the second is the likelier outcome over time.
    refusal = _refuse_listen_address(listen_address, _listen_choices(_read_info(server)[0]))
    if refusal is not None:
        log.warning("network-mcp: a Join named an address this endpoint is not serving")
        return _render(request, ctx, join_error=refusal, join_values=typed)

    try:
        result = await join_and_report(
            core_address, code, listen_address, endpoint=server,
        )
    except EnrolmentError as exc:
        # Written by whoever refused — the core, the receiver, or the address
        # parser — to be read by the owner, so it is passed through as-is rather
        # than wrapped in framing of our own.
        return _render(request, ctx, join_error=str(exc), join_values=typed)
    except Exception as exc:  # noqa: BLE001 — reported on the page, never raised
        # ``type(exc).__name__``, not ``exc``: an unexpected exception from
        # inside the Join can be an httpx error, and an httpx error holds the
        # request, and the request holds the body the pairing code was in. This
        # is the same refusal ``join._post_join`` makes for the same reason.
        log.warning(
            "network-mcp: the Join failed unexpectedly (%s)", type(exc).__name__,
        )
        return _render(
            request,
            ctx,
            join_error=(
                f"The Join failed unexpectedly ({type(exc).__name__}). Check the "
                f"Agent's log, then try again with a fresh pairing code."
            ),
            join_values=typed,
        )

    # No code, no length, no prefix, and no address either: see this module's
    # docstring. ``join.py`` logs the plugin name and health it was told.
    log.info("network-mcp: joined a PersonaCore from the UI")
    return _render(
        request,
        ctx,
        # The core writes this sentence to be shown to the operator, and when
        # the core never answered, ``join.py`` writes the one that says exactly
        # that. Either way it is the truest available account of what happened.
        join_notice=result.message,
    )


@router.post("/join/cancel")
async def join_cancel(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Close the enrolment window without waiting for it to expire."""
    cancel = getattr(ctx.network_mcp, "cancel_join", None)
    if callable(cancel):
        with contextlib.suppress(Exception):
            cancel()
        log.info("network-mcp: enrolment window closed from the UI")
    return RedirectResponse(url="/network-mcp", status_code=303)


@router.post("/enrolled/remove", response_class=HTMLResponse, response_model=None)
async def enrolled_remove(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    slug: Annotated[str, Form(alias="slug")] = "",
) -> HTMLResponse:
    """Remove an enrolled core, and stop it being able to come back.

    :func:`~workstation_agent.network_mcp.join.remove_enrolled_core` drops the
    row **and rotates this endpoint's bearer token**, because the owner asked
    that removing a core actually prevent it reconnecting rather than hide a
    listing. This endpoint holds one token, so that rotation locks out every
    core enrolled here, not only the one removed.

    That consequence is stated three times before it can happen — in the
    button's own label, in the paragraph above the table, and in the browser
    confirmation — so this handler does not have to guess whether the owner
    understood it. What it does add is the *specific* aftermath — which cores
    were, in fact, just locked out — because "every enrolled core" is an
    abstraction until it is a list of names.

    A slug naming no listed core is refused here and never reaches the
    removal; see the guard below for why that is this function's job and not
    ``remove_enrolled_core``'s.

    Renders rather than redirects, unlike :func:`join_cancel`, so that
    aftermath survives to be read; a 303 back to the page would drop it.
    """
    server = ctx.network_mcp
    wanted = slug.strip().lower()
    if not wanted:
        return _render(
            request,
            ctx,
            remove_error=(
                "No core was named to remove. Use the Remove button beside the one "
                "you want gone."
            ),
        )

    # Read before the removal, because after it the row is gone and the count of
    # collateral is unrecoverable from the listing.
    before = _enrolled_cores(server)
    target = next((core for core in before if getattr(core, "slug", "") == wanted), None)

    # **Refused before ``remove_enrolled_core`` is reached, and this guard is
    # not redundant with it.** That function rotates the token for a slug it
    # cannot find, deliberately and by a documented rule: it is written for a
    # caller that has already decided a core must lose access, and a row that is
    # missing (hand-edited file, half-finished Join) is not evidence that it
    # has. That is right for the lever and wrong for the button. Here the slug
    # arrives from a form, so a typo or a crafted POST would otherwise perform
    # the most destructive act in the product — locking out every enrolled core
    # — and delete nothing, with no row gone to connect the effect back to. The
    # guard belongs on the caller that cannot vouch for its input, which is this
    # one; putting it in ``join.py`` instead would take away the only means of
    # revoking a credential whose row is already gone.
    if target is None:
        return _render(
            request,
            ctx,
            remove_error=(
                "That core is not in this workstation's list, so nothing was removed "
                "and the bearer token was NOT rotated — everything listed below still "
                "works. Reload this page and use the Remove button beside the core you "
                "want gone."
            ),
        )

    named = str(getattr(target, "display_name", "") or wanted)
    others = [
        str(getattr(core, "display_name", "") or getattr(core, "slug", ""))
        for core in before
        if getattr(core, "slug", "") != wanted
    ]

    try:
        remove_enrolled_core(wanted, state_dir=_enrolled_state_dir(server))
    except EnrolmentError as exc:
        # Written for the operator by the function that failed, and the state it
        # describes is specific: the token is already rotated by the time this
        # can be raised, so the core is out and the listing is merely stale.
        return _render(request, ctx, remove_error=str(exc))
    except Exception as exc:  # noqa: BLE001 — reported on the page, never raised
        # **The type name and nothing else, exactly as :func:`join_post` does
        # it, and deliberately alike so the two do not drift apart.** The reason
        # is the same one: an arbitrary exception escaping this call can be an
        # httpx error from the revocation path, an httpx error holds the
        # request, and a request on this page's Join is the one that carried the
        # pairing code. ``str(exc)`` would put that in the log and on the page.
        log.warning(
            "network-mcp: could not remove an enrolled core (%s)", type(exc).__name__,
        )
        return _render(
            request,
            ctx,
            remove_error=(
                f"Could not remove that core ({type(exc).__name__}). Check the Agent's "
                f"log. The bearer token may or may not have been rotated, so treat "
                f"every enrolled core as needing to join again."
            ),
        )

    log.info("network-mcp: an enrolled core was removed from the UI")
    if others:
        listed = ", ".join(others)
        notice = (
            f"Removed {named}, and rotated this workstation's bearer token so it "
            f"cannot reconnect. This endpoint has one token, so rotating it also "
            f"locked out everything else that was enrolled here: {listed}. "
            f"Each of those has to join again."
        )
    else:
        notice = (
            f"Removed {named}, and rotated this workstation's bearer token so it "
            f"cannot reconnect. Nothing else was enrolled here, so nothing else "
            f"was affected."
        )
    return _render(request, ctx, remove_notice=notice)


# ---------------------------------------------------------------------------
# Registration export
# ---------------------------------------------------------------------------


def _multi_address_problems(info: Any) -> tuple[str, ...]:  # noqa: ANN401
    """Pre-flight items that only exist once the endpoint binds a *set*.

    Added here rather than in
    :func:`~workstation_agent.registration_export.registration_problems`
    because the manifest's own shape is the thing in question and that module
    is held pending a core-side decision: today ``manifest.toml`` carries a
    single ``url`` and ``[permissions] network = ["<one address>"]``, so a
    registration exported from a multi-address endpoint is *correct but
    partial* -- it describes the preferred address and says nothing about the
    rest. That is a fact the operator should read before installing it on the
    core, not a defect to be silently papered over here.
    """
    problems: list[str] = []

    failures: tuple[Any, ...] = tuple(getattr(info, "bind_failures", ()) or ())
    if failures:
        listed = "; ".join(
            f"{getattr(f, 'host', f)} — {getattr(f, 'reason', '')}" for f in failures
        )
        problems.append(
            "The endpoint is not answering on every address you chose. Not bound: "
            f"{listed}. If the registration names one of those, PersonaCore will "
            "install the plugin and then fail to connect.",
        )

    urls = tuple(str(u) for u in (getattr(info, "urls", ()) or ()))
    if len(urls) > 1:
        others = ", ".join(u for u in urls if u != getattr(info, "url", None))
        problems.append(
            f"This endpoint is bound to {len(urls)} addresses, and a registration "
            f"carries one URL. It will name {getattr(info, 'url', '')} and its "
            f"[permissions] network entry will list only that address; the others "
            f"({others}) stay reachable but undescribed. That is fine if "
            "PersonaCore reaches this workstation on the address named.",
        )

    return tuple(problems)


@router.post("/export-registration", response_class=HTMLResponse, response_model=None)
async def export_registration_post(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    confirm: Annotated[str, Form(alias="confirm")] = "",
) -> HTMLResponse:
    """Write ``workstation-registration.zip``, refusing a useless one first.

    The pre-flight reads the **live** endpoint rather than the saved config,
    because those are not the same thing: a server built from config reports
    ``port = 0`` as ``0`` where the running one reports the port the OS
    actually assigned, and the operator can have saved a change that failed to
    bind. Exporting the live values is what makes the registration describe the
    endpoint PersonaCore will really reach.

    Problems do not block the export outright -- the operator may be preparing
    a registration ahead of bringing the endpoint up, which is legitimate --
    but they are shown first and the export only proceeds on a second,
    explicit click.
    """
    server = ctx.network_mcp
    if server is None:
        return _render(
            request,
            ctx,
            export_error=(
                "There is no endpoint to export a registration for yet. Switch the "
                "endpoint on above, then export."
            ),
        )

    info, info_error = _read_info(server)
    if info is None:
        return _render(
            request,
            ctx,
            export_error=info_error or "Could not read the endpoint's current state.",
        )

    problems = registration_problems(info) + _multi_address_problems(info)
    if problems and not confirm:
        return _render(request, ctx, export_problems=problems)

    try:
        result = export_registration_from_endpoint(info, output_dir=export_dir())
    except Exception as exc:
        log.exception("network-mcp: export failed")
        return _render(request, ctx, export_error=f"Could not write the registration: {exc}")

    log.info("network-mcp: registration exported to %s", result.path)
    return _render(request, ctx, export_result=result, export_problems=problems)


@router.get("/registration.zip", response_class=FileResponse, response_model=None)
async def download_registration(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> FileResponse | HTMLResponse:
    """Hand the most recently exported registration to the browser.

    Verified against this application's actual shell: pywebview 4.4.1 on the
    WebView2 runtime does download a ``Content-Disposition: attachment``
    response to the user's Downloads folder. It carries no download UI of its
    own that we control, though, so the page also shows the on-disk path this
    file was served from -- two ways to the same bytes, because a download
    that lands silently is easy to miss.

    Deliberately serves only what
    :func:`export_registration_post` already wrote, and never generates
    anything: building a registration calls ``info()``, which creates the
    certificate and token if they do not exist. A GET must not do that.
    """
    path = export_dir() / REGISTRATION_ZIP_NAME
    try:
        present = path.is_file()
    except OSError:
        log.warning("network-mcp: could not stat %s", path, exc_info=True)
        present = False
    if not present:
        return _render(
            request,
            ctx,
            export_error=(
                "No registration has been exported yet. Use Export Registration "
                "above first."
            ),
        )
    return FileResponse(
        path,
        media_type="application/zip",
        filename=REGISTRATION_ZIP_NAME,
    )
