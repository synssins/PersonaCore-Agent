"""Sending the Join — step 1 of the enrolment handshake ``enrolment.py`` receives.

``enrolment.py`` is the *receiver* for step 3 and says why step 1 was not built
alongside it: the request's shape was not frozen. It is now. Every constant and
every rule below was read out of the core's shipped source —
``personacore/enrolment/workstation.py`` and ``personacore/admin/api_enrol.py`` —
rather than guessed at, and each is cited where it is used.

The call this module makes
--------------------------
``POST http://<core-address>/enrol/workstation``, **plaintext HTTP, carrying no
credential of any kind**, with exactly these seven fields and no others::

    {"code", "display_name", "url", "tls_fingerprint",
     "agent_version", "contract_version", "tools"}

The core holds those names in a ``frozenset`` (``REQUEST_FIELDS``) and calls
``_refuse_unknown_fields``, so an eighth field is a ``400`` rather than an
ignored key — and a field whose name contains ``token`` or ``secret`` gets a
refusal written specifically to say *do not send one*. **There is deliberately
no token in this direction.** The core mints the token itself and pushes it back
over our own TLS, pinned to the fingerprint this request supplies. Adding a
credential here would not harden the leg; it would break it.

Two things the core derives and we must not send: the plugin name
(``workstation-<slug>``, from the display name) and the secret name
(``workstation_<slug>_token``). Slug collisions are **refused outright, never
auto-suffixed**, so two machines whose names normalise alike produce a refusal
that has to reach the operator intact — see :class:`CoreRefusedError`.

Why the window is opened before the call, and closed after a failure
--------------------------------------------------------------------
The core's own order is *redeem, validate, mint, push, then persist*. Its push
therefore lands on our ``POST /enrol/token`` **while our own POST is still
open**: our request does not return until the core has already pushed, installed
the registration and reloaded its plugin list. So the window has to be open
before we dial, or the push arrives at a closed door and the enrolment fails.

That leaves the hazard this module's first acceptance criterion is about. A
window is an unauthenticated route standing open, secured by nothing but a short
pairing code, for the remainder of its TTL. If the outbound leg then fails —
connection refused, timeout, a non-2xx, an answer we cannot read, or a bug of
our own — the window must not be left standing. :func:`join_core` therefore
opens it in a ``try`` whose ``finally`` cancels it on **every** exit that is not
a completed Join, ``CancelledError`` included: a UI that abandons the Join must
close the window too. Cancelling a window the push already consumed is a no-op
(:meth:`~...enrolment.EnrolmentReceiver.cancel_join` is safe with nothing
pending), so the success path needs no special case and the failure path cannot
forget one.

The tool list has one source
----------------------------
:func:`~workstation_agent.network_mcp.tools.served_tool_names` — the same
function ``registration_export.py`` builds ``manifest.toml`` from and the same
one :class:`~workstation_agent.network_mcp.server.NetworkMCPServer` answers
``tools/list`` from. The core reconciles the registration's tool list against
the list the endpoint serves at load time and **a mismatch is a terminal load
failure** (contract §2), so "the tools we enrol with" and "the tools we
advertise" must be the same list rather than two lists someone keeps in sync.
``risk`` is **injected here** (:data:`TOOL_RISK`) exactly as the export
hard-codes it, because the served table is not the authority on risk and must
not become one: the core's ``ACCEPTED_RISK`` is ``{"safe"}`` and nothing else.

The pairing code
----------------
A short-lived secret that must never reach a log line, an audit row, or an
exception message. Nothing in this module logs it, no exception built here
carries it, and no ``raise ... from exc`` chains to an httpx exception — an
``httpx.Request`` keeps the body it sent, and the body is where the code is, so
a chained exception would put the code one attribute access away from any
handler that formats ``__cause__``. Every transport failure is re-raised
``from None`` with the exception's *type name* only, which is the same choice
``llm/client.py`` and ``registration_export._safe_repr`` make for the same
reason.

One Join at a time
------------------
:func:`join_core` refuses a second Join while one is in flight rather than
queueing it. Two of them racing is not a theoretical tidiness problem: the
second ``begin_join`` *replaces* the first window, and whichever of the two
fails first cancels it -- closing the window belonging to the Join that was
about to succeed, so the core's push arrives at a shut door and the enrolment
fails for a reason the owner has no way to diagnose. Refused rather than
serialised because a queued Join would run against a pairing code that is spent
by the time its turn came, and "one at a time" is the true thing to tell them.

A Join whose answer never arrives
---------------------------------
The outbound POST can fail *after* the core has already pushed. The core's order
is redeem, mint, **push**, persist, reply, so a read timeout or a dropped
connection leaves the network unable to say whether anything happened -- but
this process is not the network. **The push arrives at our own receiver.** If a
token landed for the window this Join opened, we are holding it, it is stored,
and it is the bearer this endpoint now requires: the enrolment worked, whatever
the socket did afterwards. :func:`join_and_report` asks
:meth:`~...enrolment.EnrolmentReceiver.completed` before it reports a failure,
by window id so that neither an earlier Join's token nor a window closed some
other way can be mistaken for this one's.

What that cannot establish is what the *core* did after pushing. It persists
after the push and can still fail there, rolling back and answering ``500``. So
an enrolment recovered this way is recorded with ``confirmed=False`` and says so
to the operator, rather than claiming a plugin name and a health state nobody
told us.

What this module persists, and what "remove" has to mean
--------------------------------------------------------
A successful Join writes a row to ``enrolled.json`` beside the token and the
certificate. :func:`remove_enrolled_core` drops the row **and rotates the bearer
token**, because the owner asked that removal actually prevent reconnection
rather than hide a listing.

**In operator terms**, because this is not something the next reader should have
to derive from "there is one token":

* Enrolling this workstation with a **second core displaces the first**. The
  second core's push overwrites the one token this endpoint has, and the first
  core's calls start coming back ``401``.
* **Removing any enrolled core locks out every enrolled core.** Rotation is what
  makes removal mean something, and there is one value to rotate. Anything still
  listed on the page has to join again.

Neither is a limitation of this module: this endpoint holds exactly one bearer
token (see ``credentials.py``). It is also not the axis the owner asked about --
he wants N workstations on one core, and the core gives each of them its own
``workstation_<slug>_token``; this is one workstation on N cores, which is the
rare direction for a household with one core. **A token per enrolled core is
real future work and is deliberately not built here.**
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol
from urllib.parse import urlsplit

import httpx

from workstation_agent.network_mcp.credentials import DEFAULT_STATE_DIR, ensure_token
from workstation_agent.network_mcp.enrolment import ENDPOINT_NOT_RUNNING, EnrolmentError
from workstation_agent.network_mcp.hardening import validate_json_body
from workstation_agent.network_mcp.tools import served_tool_names
from workstation_agent.registration_export import CONTRACT_VERSION, agent_version

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

log = logging.getLogger(__name__)

#: The core's route, from ``personacore.enrolment.workstation.ENROL_PATH``.
#:
#: Named with a ``CORE_`` prefix on purpose: ``enrolment.ENROL_PATH`` is *our*
#: route (``/enrol/token``) and the two are opposite ends of the same handshake.
#: A single unqualified ``ENROL_PATH`` in this package would be an invitation to
#: import the wrong one, and the failure would be a 404 against a stranger's
#: address rather than anything that looked like a mix-up.
CORE_ENROL_PATH: Final = "/enrol/workstation"

#: The only risk level the core accepts at enrolment.
#:
#: ``ACCEPTED_RISK = frozenset({RiskLevel.SAFE.value})`` — deliberately narrower
#: than the core's own manifest, and its source says why in as many words: that
#: core has no confirmation channel wired, so a tool declared ``confirm`` or
#: ``restricted`` would enrol looking healthy and then be refused on every call.
#: Injected at serialisation rather than read off the served table, because the
#: served table describes what the *Agent* gates and this field describes what
#: the *core* will accept.
TOOL_RISK: Final = "safe"

#: Seconds to establish the TCP connection to the core. The core allows itself
#: exactly this for its own push; there is no reason to be more patient dialling
#: an address the operator just typed.
CONNECT_TIMEOUT_SECONDS: Final = 5.0

#: Seconds to wait for the core's answer, and **much longer than the core's own
#: 10-second read budget on purpose.**
#:
#: Our POST does not return when the core has read our request; it returns when
#: the core has redeemed the code, validated, minted, *pushed the token to us*
#: (its own 5s connect + 10s read), installed the registration and reloaded its
#: plugin list. A 10-second read timeout here would abandon Joins that are
#: succeeding — and abandoning one is not free: the push would land, our window
#: would be consumed, and we would report a failure for an enrolment that
#: completed. Generous is the safe direction; see :func:`join_core` for what
#: happens if this expires anyway.
READ_TIMEOUT_SECONDS: Final = 60.0

#: Ceiling on how much of the core's answer is read before parsing.
#:
#: The reply comes from an unauthenticated remote address the operator typed,
#: which is the same posture ``enrolment.py`` takes towards the push and the
#: core takes towards our answer to it (its ``MAX_PUSH_RESPONSE_BYTES`` is this
#: value). An enrolment answer is a few hundred bytes.
MAX_RESPONSE_BYTES: Final = 64 * 1024

#: Nesting ceiling applied to the core's answer before it is walked.
_MAX_JSON_DEPTH: Final = 8

#: The file the enrolled-core rows live in, beside ``token`` and ``server.crt``.
_ENROLLED_FILE_NAME: Final = "enrolled.json"

#: Schema marker on that file, so a future shape change can be recognised rather
#: than mis-read as a corrupt file.
_ENROLLED_VERSION: Final = 1

#: The prefix the core puts on every plugin it derives from a display name
#: (``PLUGIN_NAME_PREFIX``). Stripped to get the slug back out.
_PLUGIN_PREFIX: Final = "workstation-"

#: Ceiling on a locally built row handle. The core's own ``MAX_SLUG_CHARS`` is
#: what is left of a 64-character plugin name after ``workstation-``; matching
#: it keeps a local handle the same size as the real thing.
_MAX_SLUG_CHARS: Final = 64 - len(_PLUGIN_PREFIX)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class JoinError(EnrolmentError):
    """A Join could not be completed once the window was open.

    Subclasses :class:`~workstation_agent.network_mcp.enrolment.EnrolmentError`
    so a caller has **one** ``except`` clause for the whole handshake. The two
    families genuinely are one thing from the operator's side: ``EnrolmentError``
    means the window could not be opened (endpoint stopped, bound to loopback,
    unusable code) and ``JoinError`` means it was opened and the call past it
    failed. Both carry a message written to be shown verbatim, and neither ever
    carries the pairing code.
    """


class CoreUnreachableError(JoinError):
    """The core did not answer: refused, unresolvable, timed out, TLS, proxy.

    Never chains to the underlying httpx exception. That exception holds the
    :class:`httpx.Request`, and the request holds the body — which is where the
    pairing code is.
    """


class CoreRefusedError(JoinError):
    """The core answered, and the answer was not a success.

    Attributes:
        status_code: The HTTP status the core answered with.
        reason: **The core's own sentence, verbatim**, or ``None`` when its
            answer was not in a shape this Agent could read one out of.

    The core's refusals are written as operator-facing English that names the
    actual problem — "that address is too long to be a workstation address",
    "``'…'`` has no letters or digits in it, so there is no name to give this
    workstation", the collision message that says which machine already holds
    the name. Rewording any of those loses the diagnosis, so ``str(exc)`` **is**
    ``reason`` when there is one. When there is not, the message says exactly
    that rather than inventing a plausible cause.
    """

    def __init__(self, status_code: int, reason: str | None) -> None:
        if reason:
            message = reason
        else:
            message = (
                f"PersonaCore refused this workstation and answered {status_code}, but "
                f"its answer was not in the shape this Agent understands, so there is "
                f"no explanation to show. Check that the address is a PersonaCore "
                f"core and not something else answering on that port, then look at "
                f"the core's own log for the reason."
            )
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason


class CoreAnswerUnreadableError(JoinError):
    """The core answered 2xx, but not with an enrolment result.

    Treated as a failure of the Join rather than smoothed over. A 2xx from
    something that is not this core's enrolment route means we do not know
    whether a machine was enrolled, under what name, or whether a token was
    pushed — and recording a row from a guess is worse than reporting that we
    cannot tell.
    """


# ---------------------------------------------------------------------------
# The endpoint this module joins on behalf of
# ---------------------------------------------------------------------------


class JoinEndpoint(Protocol):
    """The part of :class:`~...server.NetworkMCPServer` a Join needs.

    A protocol rather than an import, in both directions and for two reasons:
    ``server.py`` imports *this* module (to register itself), so importing it
    back would be a cycle; and the whole surface used here is five members, which
    a test can supply without building a TLS listener.
    """

    @property
    def state_dir(self) -> Path:
        """Where the token, the certificate and the enrolled-core rows live."""
        ...

    def info(self) -> Any:  # noqa: ANN401 — a duck-typed NetworkEndpointInfo
        """The endpoint's ``NetworkEndpointInfo``: url, port, fingerprint.

        Typed ``Any`` and read defensively for the reason
        ``registration_export.registration_problems`` gives for its own
        ``info``: importing the real dataclass here would be the import cycle
        this protocol exists to avoid.
        """
        ...

    def begin_join(self, code: str) -> Any:  # noqa: ANN401 — a duck-typed JoinStatus
        """Open the enrolment window. Raises ``EnrolmentError`` if it cannot.

        Only ``join_id`` is read off what comes back, and it is read with
        :func:`getattr` and a default, for the reason :meth:`info` is typed the
        way it is: narrowing this to :class:`~...enrolment.JoinStatus` would
        make anything standing in for an endpoint construct one to satisfy a
        shape this module barely touches.
        """
        ...

    def cancel_join(self) -> None:
        """Close any pending window. Safe when there is none."""
        ...

    def join_completed(self, join_id: int) -> bool:
        """Whether the window *join_id* was closed by an accepted push."""
        ...

    def revoke_token(self) -> str:
        """Rotate the bearer token and put the new one in force immediately."""
        ...


#: The live endpoint, if one is serving.
#:
#: Registered by :meth:`~...server.NetworkMCPServer.start` once it has bound and
#: dropped by :meth:`~...server.NetworkMCPServer.stop`, so what is here is an
#: endpoint that can actually receive a push rather than merely one that was
#: constructed. The alternative — having the UI thread its ``ctx.network_mcp``
#: through every call — was rejected because the interface P16b builds against
#: is ``join_core(core_address, pairing_code, listen_address)``, three strings
#: and nothing else, and a fourth argument that must not be forgotten is a
#: fourth argument that will be.
_endpoint: JoinEndpoint | None = None


#: True while a :func:`join_core` is between opening its window and finishing.
#:
#: A plain flag rather than an :class:`asyncio.Lock`, for two reasons. It is
#: read and written with no ``await`` between the test and the set, which on a
#: single event loop is as atomic as a lock would be. And a lock would *queue*
#: the second Join, which is the wrong answer: by the time its turn came its
#: pairing code would be spent, and it would fail with the core's "that pairing
#: code is not valid" -- a true sentence about the wrong problem. Refusing says
#: the real one.
_join_in_flight = False


def register_endpoint(endpoint: JoinEndpoint) -> None:
    """Make *endpoint* the one :func:`join_core` uses when none is passed."""
    global _endpoint  # noqa: PLW0603 — one process, one serving endpoint
    _endpoint = endpoint


def unregister_endpoint(endpoint: JoinEndpoint | None = None) -> None:
    """Drop the registered endpoint.

    With *endpoint* given, drops it only if it is still the registered one, so a
    stop() racing a start() cannot unregister the endpoint that just replaced it.
    """
    global _endpoint  # noqa: PLW0603 — see register_endpoint
    if endpoint is None or _endpoint is endpoint:
        _endpoint = None


def _resolve_endpoint(endpoint: JoinEndpoint | None) -> JoinEndpoint:
    """The endpoint to act on, or an operator-facing refusal saying there is none."""
    resolved = endpoint if endpoint is not None else _endpoint
    if resolved is None:
        # The receiver's sentence, not a second one of our own. Nothing is
        # registered until ``start`` has bound, so "no endpoint here" and
        # ``begin_join``'s "not running" are the same wall by two routes --
        # see ``enrolment.ENDPOINT_NOT_RUNNING``.
        raise EnrolmentError(ENDPOINT_NOT_RUNNING)
    return resolved


def _state_dir_for(endpoint: JoinEndpoint | None, override: Path | None) -> Path:
    """Where the enrolled-core rows live for this call.

    An explicit *override* wins; otherwise the live endpoint's own state
    directory, so the rows sit beside the token they are about; otherwise the
    package default. Resolved in one place because a listing read from one
    directory and a removal applied to another is a bug with no symptom.
    """
    if override is not None:
        return override
    resolved = endpoint if endpoint is not None else _endpoint
    if resolved is not None:
        directory = getattr(resolved, "state_dir", None)
        if isinstance(directory, Path):
            return directory
    return DEFAULT_STATE_DIR


# ---------------------------------------------------------------------------
# Building the request
# ---------------------------------------------------------------------------


def default_display_name() -> str:
    """This machine's own name, whitespace-collapsed and **case preserved**.

    Case preserved deliberately, and the core preserves it too: its
    ``normalise_display_name`` collapses whitespace and leaves case alone,
    because "the uppercase form is what is printed on the machine and quietly
    lowercasing it makes the row harder to recognise, not easier". So a
    workstation called ``FRONT-DESK`` joins as ``FRONT-DESK`` and appears in the
    core's plugin list as ``workstation-front-desk`` — the core lowercases only
    the derived slug.

    No local validation against the core's ``_DISPLAY_NAME_RE``. A hostname this
    core will not take is something the operator has to hear about in the core's
    own words ("… cannot be used as a workstation name. Use up to 64 letters,
    digits, spaces, dots, hyphens or underscores, starting with a letter or a
    digit"), and a second copy of that rule here is a second copy to keep right.
    """
    try:
        raw = socket.gethostname()
    except OSError:  # pragma: no cover — gethostname does not fail in practice
        raw = ""
    return " ".join(raw.split())


def core_enrol_url(core_address: str) -> str:
    """``192.168.1.150:8053`` → ``http://192.168.1.150:8053/enrol/workstation``.

    The operator types an address, not a URL, so a bare host, a host and port, a
    bracketed IPv6 literal and a full ``http://…`` URL all have to arrive here
    and mean the obvious thing. Anything the operator typed after the authority
    is dropped: the route is fixed by the core at ``/enrol/workstation`` and
    appending it to a path someone pasted would produce ``/admin/enrol/…``.

    ``https`` is accepted when it is written explicitly — a core behind a
    reverse proxy is a reasonable deployment — but the scheme is never *upgraded*
    silently, because this leg is plaintext by design and a silent upgrade would
    hide a misconfiguration rather than fix one.

    Raises:
        EnrolmentError: if there is no address here to dial.
    """
    typed = core_address.strip()
    if not typed:
        msg = (
            "Type the address PersonaCore is reachable at — its IP address or "
            "hostname, and its port if it is not the usual one."
        )
        raise EnrolmentError(msg)

    try:
        parts = urlsplit(_as_url(typed, scheme="http"))
        host = parts.hostname
        port = parts.port
    except ValueError:
        # urlsplit raises on a malformed authority, and its message quotes the
        # offending fragment — see registration_export._reject_userinfo for the
        # same trap. The address is not a secret, but echoing an unparsed string
        # into an operator message is a habit worth not having.
        msg = "That is not an address this Agent can read. Type PersonaCore's address and port."
        raise EnrolmentError(msg) from None

    scheme = (parts.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        msg = f"PersonaCore is reached over http, not {scheme}. Type its address and port."
        raise EnrolmentError(msg)
    if not host:
        msg = "That address does not name a machine to reach. Type PersonaCore's address and port."
        raise EnrolmentError(msg)
    if parts.username or parts.password:
        msg = (
            "That address carries a username or a password. Enrolment sends no "
            "credential in this direction; type PersonaCore's address and port on "
            "their own."
        )
        raise EnrolmentError(msg)

    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}{CORE_ENROL_PATH}"


def listen_url(listen_address: str, *, default_port: int) -> str:
    """The ``url`` field: this endpoint's own externally reachable address.

    *listen_address* is what the operator picked from the P13 multi-bind set — a
    host, a ``host:port``, a bracketed IPv6 literal, or a full ``https://…/mcp``
    URL. The port defaults to the one this endpoint is actually bound to, and
    the path is always ``/mcp``, which is what
    :attr:`~...server.NetworkEndpointInfo.url` reports and what the core will
    write into the manifest it builds.

    **Loopback is not checked here.** The core refuses a loopback, unspecified
    or link-local literal with a sentence of its own ("… is not an address
    another machine can be reached at. Give the workstation's address on the
    network the core is on"), and
    :meth:`~...server.NetworkMCPServer.begin_join` already refuses to open a
    window on a loopback-bound endpoint before anything is sent. A third copy of
    the rule here would only be a third place for it to drift.

    Raises:
        EnrolmentError: if there is no address here to advertise.
    """
    typed = listen_address.strip()
    if not typed:
        msg = (
            "Choose the address PersonaCore should reach this workstation at. It has "
            "to be an address on the network the core is on."
        )
        raise EnrolmentError(msg)

    try:
        parts = urlsplit(_as_url(typed, scheme="https"))
        host = parts.hostname
        port = parts.port
    except ValueError:
        msg = (
            "That is not an address this Agent can advertise. Choose one of this "
            "machine's own addresses."
        )
        raise EnrolmentError(msg) from None

    if not host:
        msg = (
            "That address does not name this machine. Choose one of this machine's "
            "own addresses."
        )
        raise EnrolmentError(msg)

    authority = f"[{host}]" if _is_ipv6(host) else host
    authority = f"{authority}:{port if port is not None else default_port}"
    return f"https://{authority}/mcp"


def _as_url(typed: str, *, scheme: str) -> str:
    """Make *typed* something :func:`urlsplit` can read an authority out of.

    Two things happen here, and the second is not optional.

    A value with no ``//`` gets *scheme* put in front of it, because an operator
    types an address and not a URL.

    A **bare IPv6 literal gets brackets**. ``urlsplit`` reads a port by
    partitioning the authority on the first colon, so ``fd00::5`` parses as the
    host ``fd00`` with the port ``:5`` and then raises ``ValueError`` when that
    is cast to an integer — an address the operator's own machine reported would
    be refused as unreadable. Brackets are what the URL grammar uses to say "the
    colons in here are part of the host", and two or more colons in something
    with no scheme and no brackets cannot be anything else.
    """
    if "//" in typed:
        return typed
    authority = typed
    if "[" not in authority and authority.count(":") >= 2:  # noqa: PLR2004 — host:port has one
        authority = f"[{authority}]"
    return f"{scheme}://{authority}"


def _is_ipv6(host: str) -> bool:
    """True if *host* is an IPv6 literal and therefore needs brackets."""
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


def tool_entries() -> list[dict[str, str]]:
    """The ``tools`` field: ``[{"name": ..., "risk": "safe"}, ...]``.

    Built from :func:`~...tools.served_tool_names`, which is the single source
    ``registration_export.py`` uses, so the list we enrol with and the list we
    advertise cannot drift — the core reconciles the two at load and a mismatch
    is a terminal load failure (contract §2).

    ``risk`` is injected here and is not read off the served table. The table
    happens to carry a ``risk`` attribute today, but what belongs in this field
    is not "what the Agent thinks of this tool", it is "the only value this core
    accepts", and those two are the same only by coincidence. Hard-coding it is
    what the export does, for the same reason.
    """
    return [{"name": name, "risk": TOOL_RISK} for name in served_tool_names()]


def build_request(
    *,
    pairing_code: str,
    display_name: str,
    url: str,
    tls_fingerprint: str,
) -> dict[str, Any]:
    """The complete request body — exactly the core's seven fields.

    Written out as a literal rather than assembled key by key, so that the set
    of keys is visible in one glance and comparable against the core's
    ``REQUEST_FIELDS``. An eighth key here is a ``400``, not a dropped field.

    The fingerprint is passed through as given: the core's ``normalise_fingerprint``
    accepts both the bare 64 hex digits and the ``sha256:``-prefixed spelling
    ``certs.fingerprint_of`` produces, lowercases it, and stores the prefixed
    form. Normalising it a second time here would be a second implementation of
    a rule we already satisfy.
    """
    return {
        "code": pairing_code,
        "display_name": display_name,
        "url": url,
        "tls_fingerprint": tls_fingerprint,
        "agent_version": agent_version(),
        "contract_version": CONTRACT_VERSION,
        "tools": tool_entries(),
    }


# ---------------------------------------------------------------------------
# The call
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JoinResult:
    """What the core said it did. Never a token, never the code.

    Mirrors the core's ``EnrolmentAccepted`` model field for field.
    """

    plugin: str
    """The name it was enrolled under: ``workstation-<slug>``."""
    display_name: str
    """The name as the core normalised it, which is what its plugin list shows."""
    state: str
    """``ok``, ``failing`` or ``unknown`` — the health row a moment after it was
    switched on. ``unknown`` is not a failure to enrol; the core says so."""
    message: str
    """The core's own one-line summary, written to be shown to the operator."""
    confirmed: bool = True
    """Whether the **core** confirmed this, or only our own receiver did.

    ``False`` means the outbound POST never came back with a readable answer but
    the core's token had already arrived here, so the enrolment is established
    on this side and unconfirmed on the core's. :attr:`plugin` is empty in that
    case, because the plugin name is the core's to derive and inventing one
    would be a claim about a machine we never heard from.
    """


async def join_core(  # noqa: PLR0913 — three positional are the frozen interface
    core_address: str,
    pairing_code: str,
    listen_address: str,
    *,
    display_name: str | None = None,
    endpoint: JoinEndpoint | None = None,
    client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> None:
    """Enrol this workstation with the PersonaCore at *core_address*.

    The three positional arguments are the whole of what the operator supplies:
    the address they typed, the pairing code they read off the core's console,
    and the address they picked for this machine. Everything else — the display
    name, the fingerprint, the versions, the tool list — is derived here, because
    the standing product rule is that no setting is ever configured by hand.

    Returns ``None`` on success. The core's answer is recorded (see
    :func:`list_enrolled_cores`) rather than returned, so the caller cannot come
    to depend on a shape the core owns; :func:`join_and_report` returns it for
    the one caller that wants to render it.

    **Order, and why it is this order.** The window is opened *before* the POST,
    because the core pushes the token while our request is still open — see the
    module docstring. Everything that can fail without a round trip (the
    addresses, the endpoint being there at all) happens *before* the window is
    opened, so those failures never leave one behind. And every exit from the
    call itself that is not a completed Join cancels the window in a ``finally``,
    ``CancelledError`` included.

    **One honest gap.** If :data:`READ_TIMEOUT_SECONDS` expires while the core is
    still working, the push may already have landed: the enrolment succeeded, we
    report :class:`CoreUnreachableError`, and the operator is told to try again with a
    fresh code — which the core will then refuse for a slug collision, naming the
    machine that already holds the name. That is a legible ending rather than a
    silent one, and the timeout is set well above the core's own worst case to
    keep it rare. It cannot be closed from this side: the core does not offer a
    "did that Join land" call.

    Args:
        core_address: PersonaCore's address, as typed. A bare host, ``host:port``
            or a full URL; ``http`` unless ``https`` is written explicitly.
        pairing_code: The code the core is showing. Never logged, never stored,
            never put in an exception.
        listen_address: The address this workstation should be reached at, from
            the operator's pick of this machine's bound addresses.
        display_name: Overrides :func:`default_display_name`, which is this
            machine's hostname.
        endpoint: The endpoint to enrol. Defaults to the one currently serving.
        client_factory: Builds the HTTP client. Injected by tests; the default
            is :func:`_client`.

    Raises:
        EnrolmentError: the window could not be opened — no endpoint, an address
            that is not one, or a code the receiver will not hold. Nothing was
            sent and no window exists.
        CoreUnreachableError: the core did not answer.
        CoreRefusedError: the core answered with a refusal. ``str(exc)`` is the core's
            own sentence, verbatim.
        CoreAnswerUnreadableError: the core answered 2xx with something that was not
            an enrolment result.
    """
    await join_and_report(
        core_address,
        pairing_code,
        listen_address,
        display_name=display_name,
        endpoint=endpoint,
        client_factory=client_factory,
    )


async def join_and_report(  # noqa: PLR0913 — see join_core
    core_address: str,
    pairing_code: str,
    listen_address: str,
    *,
    display_name: str | None = None,
    endpoint: JoinEndpoint | None = None,
    client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> JoinResult:
    """:func:`join_core`, returning what the core said. See it for everything."""
    global _join_in_flight  # noqa: PLW0603 — one process, one Join at a time

    target = _resolve_endpoint(endpoint)
    enrol_url = core_enrol_url(core_address)

    info = target.info()
    url = listen_url(listen_address, default_port=int(getattr(info, "port", 0) or 0))
    name = display_name if display_name is not None else default_display_name()
    body = build_request(
        pairing_code=pairing_code,
        display_name=name,
        url=url,
        tls_fingerprint=str(getattr(info, "fingerprint", "")),
    )

    # Tested and set with nothing awaited in between, so no second Join can slip
    # through the gap. See :data:`_join_in_flight` for why this refuses rather
    # than queues.
    if _join_in_flight:
        msg = (
            "A Join is already in progress. Wait for it to finish, or cancel it, "
            "then try again with a fresh pairing code."
        )
        raise EnrolmentError(msg)
    # Bound before the flag is set, and every one of them a bare literal — no
    # call, no attribute lookup, nothing that can raise, so they add no gap
    # below. **They must be bound before the ``try``, not inside it**: the
    # ``finally`` reads ``opened`` and ``joined``, and a name that is still
    # unbound when it gets there raises ``UnboundLocalError`` *from the cleanup*
    # — which replaces whatever the Join actually failed with, the exact
    # substitution :func:`_cancel_quietly` exists further down to prevent.
    opened = False
    joined = False
    join_id = 0
    _join_in_flight = True
    # **The ``try`` opens on the line after the flag is set, and nothing goes
    # between them.** Not tidiness: anything unwinding in that gap would never
    # reach the ``finally``, and the flag would stay set for the life of the
    # process — every later Join refused with "a Join is already in progress"
    # and no way for the owner to clear it short of restarting the Agent. That
    # is the least recoverable state in this module, and from outside it looks
    # like a product that simply does not work.
    try:
        status = target.begin_join(pairing_code)
        # KNOWN, NOT CLOSED: between ``begin_join`` returning and ``opened``
        # being set, a window exists that the ``finally`` below would not
        # cancel. It cannot fire today — this region is synchronous, and
        # ``CancelledError`` is only delivered at an await point — and the two
        # ways to close it are both worse than the gap. Hoisting ``opened``
        # above the call reintroduces the bug it exists to prevent: cancelling a
        # window the UI's own ``POST /network-mcp/join`` opened, which is a real
        # failure traded for a theoretical one. Closing it properly means asking
        # the receiver "is *my* window still open" instead of trusting a local —
        # a ``join_status`` member on :class:`JoinEndpoint`, a window-id
        # snapshot taken before the call, and a comparison inside a ``finally``
        # that must itself never raise. That is machinery on the path that is
        # hardest to exercise, for a window with no await in it. Left open
        # deliberately; this note is here so the next reader does not rediscover
        # it as a fresh bug.
        opened = True
        join_id = int(getattr(status, "join_id", 0) or 0)
        try:
            result = await _post_join(enrol_url, body, client_factory=client_factory)
        except CoreUnreachableError:
            # The socket could not say what happened. Our own receiver can —
            # see the module docstring. Asked by window id, so a token from an
            # earlier Join cannot be read as this one's.
            result = _recovered(target, join_id, display_name=name)
            if result is None:
                raise
        joined = True
    finally:
        # Released first, and unconditionally: a guard that leaks on a failure
        # locks the owner out of retrying for the life of the process, which is
        # a worse bug than the race it exists to prevent.
        _join_in_flight = False
        # Only a window *this* call opened. A ``begin_join`` that raised opened
        # nothing, and cancelling then could close a window the UI's own
        # ``POST /network-mcp/join`` had opened alongside us.
        if opened and not joined:
            _cancel_quietly(target)
        # The pairing code is a live secret for the length of the window, and
        # these are the references this frame holds to it.
        #
        # ``body.clear()``, **not** ``body = {}``. Rebinding changes only what
        # this frame's name points at; :func:`_post_join` was handed the same
        # dict and its own local still references the original, so a traceback
        # capturing *that* frame would carry the code out of a scrub that looked
        # like it had worked. Emptying the object is seen by every frame holding
        # it, which is the whole of what is needed and one call to do it.
        #
        # ``pairing_code`` is rebound rather than reached after: it is an
        # immutable string, so this frame is the only one a rebind can help, and
        # unbinding it in the callee's frame would be a contortion for a value
        # that is single-use and expires in minutes.
        pairing_code = ""
        body.clear()

    _record_enrolment(target, result, core_address=core_address)
    log.info(
        "enrolled with PersonaCore as %r (%s)",
        result.plugin or result.display_name,
        result.state,
    )
    return result


def _recovered(
    endpoint: JoinEndpoint, join_id: int, *, display_name: str,
) -> JoinResult | None:
    """A result for a Join whose answer was lost but whose token arrived.

    ``None`` when no token arrived for *join_id*, which is the caller's signal
    to report the transport failure it was about to report.

    What is claimed here is only what is known. ``plugin`` is left empty rather
    than derived: ``workstation-<slug>`` is the core's to build from the name we
    sent, and a second copy of its slug rule living here would be a second copy
    to keep right — for a row that would be asserting something the core never
    told us. ``state`` is ``"unknown"``, which is the value the core's own
    health enum has for exactly this.
    """
    if not endpoint.join_completed(join_id):
        return None
    log.info(
        "the Join answer never arrived, but PersonaCore's token did: this "
        "workstation is enrolled and the pushed token is in force",
    )
    return JoinResult(
        plugin="",
        display_name=display_name,
        state="unknown",
        message=(
            f"{display_name} is enrolled: PersonaCore sent this workstation its token "
            f"and it is in force. The core did not answer afterwards, so this Agent "
            f"could not read back what it was enrolled as. Check the core's Plugins "
            f"screen; if there is no row there, get a fresh code and join again."
        ),
        confirmed=False,
    )


def _cancel_quietly(endpoint: JoinEndpoint) -> None:
    """Close the window, whatever else is going wrong.

    Runs on the failure path, usually while an exception is propagating, so it
    must not raise: an exception here would replace the reason the Join failed
    with the reason the cleanup failed, and would *also* leave the window open,
    which is the one outcome this whole arrangement exists to prevent. A
    ``cancel_join`` that somehow throws is logged and swallowed.

    ``BaseException``, not ``Exception``, and that is the load-bearing word.
    :class:`asyncio.CancelledError` and :class:`KeyboardInterrupt` do not derive
    from ``Exception``, so a shutdown or a Ctrl-C landing *during the cleanup*
    would sail straight through an ``except Exception`` and do both of the
    things this function exists to prevent at once — mask the real failure and
    leave the window open. Cleanup that only survives the interruptions nobody
    minds is not cleanup.
    """
    try:
        endpoint.cancel_join()
    except BaseException:
        log.exception("the enrolment window could not be closed after a failed Join")
    else:
        log.info("enrolment window closed after a failed Join")


def _client() -> httpx.AsyncClient:
    """The client the Join is sent over. Every argument is a refusal.

    * ``follow_redirects=False`` — a 3xx from the address the operator typed must
      not walk this request, body and all, somewhere else. The body is not a
      credential, but the pairing code in it is a secret with a live window.
    * ``trust_env=False`` — no ``HTTP_PROXY`` from the machine's environment gets
      to sit between this Agent and the core. The core makes the same choice for
      the same reason on its own push.
    * Bounded timeouts — see :data:`CONNECT_TIMEOUT_SECONDS` and
      :data:`READ_TIMEOUT_SECONDS`.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            READ_TIMEOUT_SECONDS,
            connect=CONNECT_TIMEOUT_SECONDS,
        ),
        follow_redirects=False,
        trust_env=False,
    )


async def _post_join(
    enrol_url: str,
    body: dict[str, Any],
    *,
    client_factory: Callable[[], httpx.AsyncClient] | None,
) -> JoinResult:
    """Send one Join and turn the answer into a result or a typed refusal.

    Streamed rather than ``client.post``, which buffers the whole reply before
    this code sees any of it: a cap applied after buffering is a cap that has
    already been exceeded, and this reply comes from an address an
    unauthenticated stranger could be answering on. That is the same reasoning
    ``llm/client._read_body_bounded`` and the core's own ``_read_capped`` give.

    *body* is emptied by the caller once the call is over, in
    :func:`join_and_report`'s ``finally`` — it is the same object this frame
    holds, so there is nothing to scrub here and a second scrub here would only
    rebind this name away from the object that actually needs emptying.

    **No exception raised here is chained to an httpx exception, and none is
    raised from inside an ``except`` block either.** ``raise ... from None``
    clears ``__cause__`` and suppresses the context when a traceback is
    *printed*, but ``__context__`` still holds the original — and an httpx
    exception holds the :class:`httpx.Request`, and the request holds the body,
    and the body holds the pairing code. Anything walking the exception chain
    (a structured logger, an error tracker) would reach it. So the failure is
    recorded as a plain string and the raise happens after the ``except`` block
    has been left, where there is no context to inherit.
    """
    factory = client_factory or _client
    unreachable: str | None = None
    status = 0
    raw = b""
    try:
        async with (
            factory() as client,
            client.stream("POST", enrol_url, json=body) as response,
        ):
            status = response.status_code
            raw = await _read_capped(response)
    except httpx.TimeoutException:
        unreachable = (
            f"PersonaCore did not answer within {READ_TIMEOUT_SECONDS:.0f} seconds. "
            f"If it is working on the enrolment it may still complete; check its "
            f"Plugins screen before joining again."
        )
    except (httpx.HTTPError, OSError) as exc:
        # The type name and nothing else. str(exc) on an httpx error can quote
        # the request, and the request carries the pairing code.
        unreachable = (
            f"This Agent could not reach PersonaCore ({type(exc).__name__}). Check the "
            f"address and that the core is running, then try again with a fresh code."
        )
    if unreachable is not None:
        raise CoreUnreachableError(unreachable)

    if not (200 <= status < 300):  # noqa: PLR2004 — 2xx is the contract, spelled out
        raise CoreRefusedError(status, _refusal_of(raw))

    return _result_of(status, raw)


async def _read_capped(response: httpx.Response) -> bytes:
    """Read at most :data:`MAX_RESPONSE_BYTES` of *response*, then stop.

    Truncated silently rather than marked: unlike ``llm/client``'s reader, which
    hands its bytes to a human as an error body, everything read here is parsed
    as JSON, and a truncation marker appended to JSON would only turn "too big"
    into "malformed" one layer later. A reply this long is not an enrolment
    answer, and the parse below says so.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        room = MAX_RESPONSE_BYTES - total
        if room <= 0:
            break
        chunks.append(chunk[:room])
        total += len(chunk[:room])
    return b"".join(chunks)


def _decode(raw: bytes) -> Any:  # noqa: ANN401 — a JSON document is Any, honestly
    """Parse *raw* as a JSON document, or ``None``. Never raises.

    Reuses the receiver's bound on nesting rather than inventing one: this is
    the same class of input — a document from an address nobody has
    authenticated — and ``json.loads`` on deeply nested input is a
    ``RecursionError`` waiting for a stack.
    """
    if validate_json_body(raw, max_depth=_MAX_JSON_DEPTH) is not None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError, UnicodeDecodeError):  # pragma: no cover
        # Unreachable through validate_json_body, which decoded and parsed this
        # exact document. Kept because "cannot fail" is the assumption that
        # produced three of this repository's pre-auth crashes — see
        # ``enrolment._parse_push``, which keeps the same guard for the reason.
        return None


def _refusal_of(raw: bytes) -> str | None:
    """The core's own refusal sentence, or ``None`` if there is not one to read.

    The core builds every refusal through ``api_shared._fail``, which raises a
    FastAPI ``HTTPException`` whose ``detail`` is
    ``{"error": <sentence>, "problems": [...]}``. FastAPI serialises that as
    ``{"detail": {"error": ..., "problems": [...]}}``, so that is the shape read
    first.

    A plain ``{"detail": "..."}`` is read too: that is what FastAPI's *own*
    errors look like (a 404 for a core too old to have this route, a 422), and
    those sentences are worth showing as well.

    Anything else returns ``None``, and :class:`CoreRefusedError` says plainly that
    there was no explanation rather than manufacturing one. Guessing here is
    exactly the failure this is written to avoid: an invented message that reads
    like the core's would send the operator to look at the wrong thing.
    """
    document = _decode(raw)
    if not isinstance(document, dict):
        return None
    detail = document.get("detail")
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    if isinstance(detail, dict):
        error = detail.get("error")
        if isinstance(error, str) and error.strip():
            return error.strip()
    # Not the surface's shape, but a bare {"error": ...} is cheap to accept and
    # is what a reverse proxy in front of the core might answer with.
    error = document.get("error")
    if isinstance(error, str) and error.strip():
        return error.strip()
    return None


def _result_of(status: int, raw: bytes) -> JoinResult:
    """The core's ``EnrolmentAccepted`` body, or :class:`CoreAnswerUnreadableError`.

    ``plugin`` and ``display_name`` are required, because they are the row this
    Agent records and a row built from a default is a record of something that
    did not happen. ``state`` and ``message`` are defaulted: both are the core's
    commentary on an enrolment that has already succeeded, and refusing a Join
    that worked over a missing summary line would be the wrong trade.
    """
    document = _decode(raw)
    if not isinstance(document, dict):
        msg = (
            f"PersonaCore answered {status}, but not with an enrolment result, so this "
            f"Agent cannot tell whether the workstation was enrolled. Check the core's "
            f"Plugins screen before joining again."
        )
        raise CoreAnswerUnreadableError(msg)

    plugin = document.get("plugin")
    display_name = document.get("display_name")
    if not isinstance(plugin, str) or not plugin or not isinstance(display_name, str):
        msg = (
            f"PersonaCore answered {status} without saying what it enrolled this "
            f"workstation as, so this Agent cannot record it. Check the core's Plugins "
            f"screen before joining again."
        )
        raise CoreAnswerUnreadableError(msg)

    state = document.get("state")
    message = document.get("message")
    return JoinResult(
        plugin=plugin,
        display_name=display_name,
        state=state if isinstance(state, str) and state else "unknown",
        message=message if isinstance(message, str) else "",
    )


# ---------------------------------------------------------------------------
# The enrolled-core listing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrolledCore:
    """One core this workstation has joined.

    Carries nothing secret: the token lives in ``token`` and the pairing code
    stopped existing when the window closed.
    """

    slug: str
    """``front-desk`` — the handle :func:`remove_enrolled_core` takes.

    Normally the plugin name with the core's ``workstation-`` prefix removed.
    For an unconfirmed row (see :attr:`confirmed`) there is no plugin name to
    take it from, so it is built from the display name locally — as a **label
    for a row on a page**, not as a claim about what the core called this
    machine. Removal does not depend on it matching: what removal does is rotate
    the one bearer token, and that works whatever the row is called.
    """
    plugin: str
    """``workstation-front-desk`` — the name the core knows this machine by, or
    ``""`` when the core never got to tell us. See :attr:`confirmed`."""
    display_name: str
    """The name as the core normalised it — or, for an unconfirmed row, as this
    Agent sent it. Those differ only in whitespace, which is already collapsed
    before it goes on the wire."""
    core_address: str
    """The address the operator typed, kept as typed so the row says where this
    machine joined rather than where this Agent guessed it joined."""
    joined_at: dt.datetime
    """When the core answered, in UTC."""
    confirmed: bool = True
    """Whether the core confirmed the enrolment, or only our own receiver did.

    ``False`` is not a doubt about the *token* — that arrived, is stored and is
    in force. It is a doubt about what the core did after pushing it, which the
    core persists and can still fail at. A page showing one of these should say
    so and point at the core's Plugins screen.
    """


def list_enrolled_cores(*, state_dir: Path | None = None) -> tuple[EnrolledCore, ...]:
    """Every core this workstation has joined, oldest first.

    Returns an empty tuple when there is no file, when it cannot be read, and
    when what is in it is not the shape this wrote. A listing is a read-only
    view on a page the operator is looking at; failing it closed with an
    exception would take away the Remove button they need in order to fix
    whatever is wrong.
    """
    path = _state_dir_for(None, state_dir) / _ENROLLED_FILE_NAME
    try:
        raw = path.read_bytes()
    except OSError:
        return ()

    document = _decode(raw)
    if not isinstance(document, dict):
        log.warning("the enrolled-core listing at %s could not be read", path)
        return ()
    rows = document.get("cores")
    if not isinstance(rows, list):
        return ()

    cores: list[EnrolledCore] = []
    for row in rows:
        core = _row_to_core(row)
        if core is not None:
            cores.append(core)
    return tuple(cores)


def remove_enrolled_core(slug: str, *, state_dir: Path | None = None) -> None:
    """Remove an enrolled core, and stop it being able to come back.

    Two things happen, and the second is the one the owner asked for by name:
    the row is dropped, **and the bearer token is rotated**. Dropping the row
    alone would hide a listing while leaving a core holding a credential that
    still opens every tool on this machine — removal that removes nothing.

    Rotation is applied to the *running* endpoint, not merely to the file, so
    the next call from the removed core gets a ``401`` rather than working until
    the next restart. See :meth:`~...server.NetworkMCPServer.revoke_token`.

    **The single-token consequence, stated rather than hidden.** This endpoint
    holds one token (``credentials.py``), so rotating it revokes every enrolled
    core, not only this one. Any core still listed here has to join again. The
    alternative — leaving the token alone so the others keep working — leaves
    the removed core working too, which is not a trade this function is allowed
    to make on the operator's behalf.

    Removing a slug that is not enrolled still rotates. That is deliberate: the
    operator pressed Remove because they want a core to lose access, and a row
    already gone (a hand-edited file, a half-finished Join) is not evidence that
    it has.

    Raises:
        EnrolmentError: if the listing cannot be written back. The token has
            already been rotated by then — see the order below — so the core is
            already locked out; what the operator is being told is that the row
            will reappear on the next read, which is a stale listing rather than
            a removal that did not happen.
    """
    directory = _state_dir_for(None, state_dir)
    wanted = slug.strip().lower()
    remaining = [core for core in list_enrolled_cores(state_dir=directory) if core.slug != wanted]

    # **Revoke first, then write, and the order is the safety property.** The
    # thing the owner asked for is that the removed core stops being able to
    # call; the row is bookkeeping about that. Writing first would mean a failed
    # write aborts before the revocation and leaves a core that is gone from the
    # page still holding a working credential — removal that removed nothing,
    # reported as an error about a file. This way round, the worst case is a
    # stale row beside a core that can no longer connect, and the operator is
    # told about it.
    _revoke_token(directory)
    _write_enrolled(directory, remaining)
    log.info(
        "removed enrolled core %r and rotated the bearer token; %d core(s) remain listed "
        "and must join again",
        wanted,
        len(remaining),
    )


def _revoke_token(directory: Path) -> None:
    """Rotate the bearer token and put the new one in force where it can be.

    Through the live endpoint when there is one, because rotating the *file*
    alone leaves the running listener still accepting the old value until the
    next restart — which is precisely the window a removal is meant to close.
    With no endpoint running there is nothing serving, so rotating the file is
    the whole of what "in force" can mean.
    """
    endpoint = _endpoint
    if endpoint is not None:
        revoke = getattr(endpoint, "revoke_token", None)
        if callable(revoke):
            revoke()
            return
    ensure_token(directory, rotate=True)


def _row_to_core(row: object) -> EnrolledCore | None:
    """One stored row, or ``None`` if it is not one.

    Every field is checked rather than trusted. The file is on a machine that
    runs arbitrary commands, and a row that is half a row would otherwise reach
    the page as a ``None`` in a template or a slug that removes nothing.
    """
    if not isinstance(row, dict):
        return None
    plugin = row.get("plugin")
    display_name = row.get("display_name")
    core_address = row.get("core_address")
    joined_at = row.get("joined_at")
    slug = row.get("slug")
    if not isinstance(plugin, str) or not isinstance(display_name, str):
        return None
    if not isinstance(core_address, str):
        return None
    # A row needs *a* handle, and either column can be the one that carries it:
    # rows written before there were unconfirmed ones have a plugin and may have
    # no slug, and an unconfirmed row has a slug and no plugin. A row with
    # neither is not a row.
    handle = slug if isinstance(slug, str) and slug else slug_of(plugin)
    if not handle:
        return None
    try:
        when = dt.datetime.fromisoformat(joined_at) if isinstance(joined_at, str) else None
    except ValueError:
        when = None
    if when is None:
        when = dt.datetime.fromtimestamp(0, dt.UTC)
    elif when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    # Absent means confirmed: every row written before this column existed came
    # from a core that answered.
    confirmed = row.get("confirmed")
    return EnrolledCore(
        slug=handle,
        plugin=plugin,
        display_name=display_name,
        core_address=core_address,
        joined_at=when,
        confirmed=confirmed if isinstance(confirmed, bool) else True,
    )


def slug_of(plugin: str) -> str:
    """``workstation-front-desk`` → ``front-desk``.

    The core derives the plugin name from the display name and never sends the
    slug on its own, so it is recovered here rather than invented: the prefix is
    the core's ``PLUGIN_NAME_PREFIX`` and is fixed. A plugin name that does not
    carry it is returned whole, which is the safe direction — a slug that is
    still unique is worth more than one that looks tidier.
    """
    lowered = plugin.strip().lower()
    if lowered.startswith(_PLUGIN_PREFIX):
        return lowered[len(_PLUGIN_PREFIX) :]
    return lowered


def _local_slug(display_name: str) -> str:
    """A row handle for an enrolment the core never named.

    Only reached when :func:`_recovered` built the result, so there is no plugin
    name to take a slug from. Runs of anything that is not a letter or a digit
    become one hyphen, which is what the core does to derive *its* slug — but
    this is not that and must not be read as it: the core owns
    ``workstation-<slug>``, and a row built here says ``confirmed=False`` and
    leaves :attr:`EnrolledCore.plugin` empty precisely so nobody mistakes the
    two. What this needs to be is stable, file-safe, and unlikely to collide
    with another machine's row on the same page.

    Falls back to a fixed word when the name has nothing usable in it, because a
    row with no handle is a row with no Remove button.
    """
    handle = "".join(ch if ch.isalnum() else "-" for ch in display_name.lower())
    handle = "-".join(part for part in handle.split("-") if part)
    return handle[:_MAX_SLUG_CHARS] or "unconfirmed"


def _record_enrolment(
    endpoint: JoinEndpoint, result: JoinResult, *, core_address: str,
) -> None:
    """Add a row for a completed Join, replacing any row for the same plugin.

    Replacing rather than appending: a machine that is re-enrolled under the
    same name is the same row with a newer date, and two rows for one plugin
    would give the operator two Remove buttons for one credential.

    Never raises. The enrolment has already completed on both sides by the time
    this runs — the token is stored and in force — so a failure to write the
    listing is a cosmetic failure, and turning it into an exception here would
    report a Join that worked as a Join that did not.
    """
    directory = _state_dir_for(endpoint, None)
    slug = slug_of(result.plugin) if result.plugin else _local_slug(result.display_name)
    rows = [
        core for core in list_enrolled_cores(state_dir=directory) if core.slug != slug
    ]
    rows.append(
        EnrolledCore(
            slug=slug,
            plugin=result.plugin,
            display_name=result.display_name,
            core_address=core_address.strip(),
            joined_at=dt.datetime.now(dt.UTC),
            confirmed=result.confirmed,
        ),
    )
    try:
        _write_enrolled(directory, rows)
    except EnrolmentError:
        log.warning(
            "the Join with %r completed but the enrolled-core listing could not be "
            "updated; the row will be missing from the Workstations page",
            result.plugin,
        )


def _write_enrolled(directory: Path, cores: list[EnrolledCore]) -> None:
    """Write the listing atomically, the way ``credentials._write_token`` does.

    ``Path.replace`` is atomic on NTFS, so a reader sees either the previous
    listing or the new one and never a half-written file. This one is not
    hardened with a DACL: unlike the token beside it, every field here is
    already visible on the Workstations page.

    Raises:
        EnrolmentError: if the file cannot be written. Worded for the operator,
            because the one caller that lets it out is
            :func:`remove_enrolled_core`, and a listing that did not persist is
            something they have to know about.
    """
    payload = {
        "version": _ENROLLED_VERSION,
        "cores": [
            {
                "slug": core.slug,
                "plugin": core.plugin,
                "display_name": core.display_name,
                "core_address": core.core_address,
                "joined_at": core.joined_at.isoformat(),
                "confirmed": core.confirmed,
            }
            for core in cores
        ],
    }
    path = directory / _ENROLLED_FILE_NAME
    tmp = directory / (_ENROLLED_FILE_NAME + ".tmp")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        msg = (
            f"The list of enrolled cores could not be saved to {path}. Check that the "
            f"folder exists and is writable, then try again."
        )
        raise EnrolmentError(msg) from exc


__all__ = [
    "CONNECT_TIMEOUT_SECONDS",
    "CORE_ENROL_PATH",
    "MAX_RESPONSE_BYTES",
    "READ_TIMEOUT_SECONDS",
    "TOOL_RISK",
    "CoreAnswerUnreadableError",
    "CoreRefusedError",
    "CoreUnreachableError",
    "EnrolledCore",
    "JoinEndpoint",
    "JoinError",
    "JoinResult",
    "build_request",
    "core_enrol_url",
    "default_display_name",
    "join_and_report",
    "join_core",
    "list_enrolled_cores",
    "listen_url",
    "register_endpoint",
    "remove_enrolled_core",
    "slug_of",
    "tool_entries",
    "unregister_endpoint",
]
