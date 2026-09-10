"""Same-origin enforcement for every state-changing request on the settings UI.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Why this exists
---------------

The settings UI binds ``127.0.0.1:0`` and :func:`create_app` refuses any request
whose client address is not ``127.0.0.1``. **That is not a CSRF defence.** A
page in the owner's ordinary browser can submit a form to
``http://127.0.0.1:<port>/...``; the browser makes that request from the owner's
own machine, so it arrives from ``127.0.0.1`` and the address check waves it
through. Everything on this surface is then reachable: config saves, the
endpoint apply/restart path, the enrolment Join, and — worst — ``POST
/network-mcp/enrolled/remove``, which rotates the bearer token and locks out
every enrolled PersonaCore.

The ephemeral port is not a control either. It raises the cost of finding the
target; it does not stop anything. A page can scan, and the port is written to
``%APPDATA%\\WorkstationAgent\\ui-port`` for the webview to read.

What this module checks
-----------------------

Two headers, both set by the browser and both on the Fetch spec's forbidden
list, so page script cannot set, change or suppress either of them:

``Origin``
    Sent on every cross-origin form POST, and on same-origin POSTs by every
    current browser. Compared against this app's *own* origin, computed per
    request — there is no list of permitted origins anywhere, and nothing for
    the owner to configure.

``Sec-Fetch-Site``
    Says what the *browser* thought the relationship was: ``same-origin``,
    ``same-site``, ``cross-site`` or ``none``. Only ``same-origin`` is accepted.

Each is checked when it is present, so the two are independent: a request has to
survive both, and a quirk in either one cannot on its own let a cross-origin
POST through or refuse a legitimate one.

The expected origin, and why the ``Host`` header is checked too
---------------------------------------------------------------

"Our own origin" has to come from somewhere. The obvious source is the request's
own ``Host`` header — but taken alone that makes the comparison vacuous. An
attacker who points ``rebind.example.com`` at ``127.0.0.1`` and serves a page
from ``http://rebind.example.com:<port>/`` gets a browser that sends ``Host:
rebind.example.com:<port>``, ``Origin: http://rebind.example.com:<port>`` and
``Sec-Fetch-Site: same-origin``. Origin would equal Host-derived-origin and the
check would pass, having proved nothing.

So the expected origin is ``<scheme>://<Host>`` **only when the ``Host`` names a
loopback address literally** (:data:`_LOOPBACK_HOSTNAMES`). That set is three
literals in this file, not configuration: it is the fixed set of names that
always mean "this machine" and that no one else can ever be delegated. A request
arriving under any other name is refused, because for such a request there is no
honest way to say what this app's origin is.

The missing-header decision
---------------------------

**A state-changing request carrying neither header is refused.**

Both answers are defensible and this one was chosen deliberately:

* Any browser that can be aimed at this surface sends at least one of the two.
  A request with neither did not come from a browser, and CSRF is by definition
  an attack carried out *through* a browser. Refusing costs the attack nothing
  it had; allowing gains it nothing it lacked.
* But that reasoning cuts the other way too, and that is the point. Allowing the
  no-header case would make the outcome of this check depend on a header the
  request may simply omit. It would hold only for as long as every browser that
  ever reaches this port keeps sending one — a property of other people's
  software that this code cannot verify. Trusting an unverifiable property of
  the caller is the exact shape of the hole being closed here: "it came from
  127.0.0.1, so it is fine."
* The population that legitimately sends no ``Origin`` is not open-ended. It is
  the programs in this repository that call this app over HTTP, it is
  enumerable, and it is ours. At the time of writing it is exactly one — the
  system tray (``ui/systray/tray.py``), whose two POSTs now name the origin they
  are calling. Making it explicit cost two lines and no configuration.
* The two failure directions are not symmetrical. Refusing wrongly produces a
  visible, worded refusal on the owner's own machine, in front of the person who
  triggered it, and is noticed at once. Allowing wrongly produces nothing at all
  until every enrolled PersonaCore is locked out.
* Fail-closed is also the only version of this check that can be *shown* to
  work. Remove the header, watch the refusal. A check that passes when the
  evidence is absent cannot be demonstrated to be doing anything.

Scope
-----

State-changing methods only. ``GET``, ``HEAD``, ``OPTIONS`` and ``TRACE`` are
untouched, so every page still renders exactly as before.

This runs as ASGI middleware over the whole settings app rather than as a token
threaded through each form, so a route added later is covered the day it is
added. There is nothing for the author of the next form to remember, which is
the only kind of check that stays true.

The network-MCP endpoint (``workstation_agent/network_mcp/``) is a different
application with its own bearer-token authentication and its own threat model.
It is not served by this app and nothing here touches it.
"""

from __future__ import annotations

import html
import logging
from typing import TYPE_CHECKING, Any

from fastapi import Request, Response

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

log = logging.getLogger(__name__)

#: Methods that do not change state and are therefore not checked. A CSRF check
#: on a GET would break every page in the UI and protect nothing: the routes
#: behind these methods read.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

#: Host names that mean "this machine" and that cannot be delegated to anybody.
#: Not a configurable allow-list -- see the module docstring on why the expected
#: origin cannot simply be whatever ``Host`` says.
_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})

#: The one ``Sec-Fetch-Site`` value that means "this came from us". ``same-site``
#: is not enough: for an IP host it covers a different port on the same
#: loopback address, which is a different origin and, on a machine running a
#: hostile local server, a different program.
_SAME_ORIGIN: str = "same-origin"

#: How much of an untrusted ``Host`` is echoed back into the refusal page. Long
#: enough for any real name to be recognisable, short enough that the page stays
#: a page. The value is HTML-escaped as well -- it is attacker-chosen text.
_HOST_ECHO_LIMIT: int = 64

# ---------------------------------------------------------------------------
# Refusals
#
# Worded the way network_mcp_routes.py words its refusals: say what happened,
# say that nothing changed, and say what the person in front of it should do
# now. A bare 403 reads as "the button is broken", and the most likely way to
# meet this legitimately -- a Settings window left open across an Agent restart,
# which lands on a new port every launch -- is precisely the case where the
# owner needs to be told to reopen the window rather than to go hunting.
# ---------------------------------------------------------------------------

CROSS_ORIGIN_REFUSAL: str = (
    "This request came from a different page, not from the Agent's own Settings "
    "window, so it was refused and nothing was changed. If you were using "
    "Settings, that window has most likely been open since before the Agent last "
    "restarted: the Agent listens on a new address every time it starts, and a "
    "page left over from the previous one is refused like this. Close the "
    "Settings window, open it again from the tray icon, and make the change "
    "there. If you were not using Settings just now, then a site open in your "
    "browser tried to change this Agent's settings without asking you, and it "
    "was stopped."
)

MISSING_ORIGIN_REFUSAL: str = (
    "This request did not say which page it came from, so the Agent could not "
    "confirm it came from its own Settings window, and it was refused without "
    "changing anything. Open Settings from the tray icon and make the change "
    "there. A program calling this address directly has to send an Origin header "
    "naming the same address it is calling."
)

UNKNOWN_HOST_REFUSAL: str = (
    "This request reached the Agent under a name that is not the Agent's own "
    "({host}), so it was refused and nothing was changed. Settings is only "
    "reachable at http://127.0.0.1 on this machine, and a name that merely "
    "points there is not the same thing. Open Settings from the tray icon and "
    "make the change there."
)

_REFUSAL_PAGE: str = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Request refused</title>
<link rel="stylesheet" href="/static/skeleton.css">
</head>
<body>
<main>
<h1>Request refused</h1>
<p>{message}</p>
</main>
</body>
</html>
"""


def _hostname(host_header: str | None) -> str | None:
    """The host part of *host_header*, port stripped, or ``None`` if unusable.

    ``Host`` arrives as ``127.0.0.1:51423``, or ``[::1]:51423`` for an IPv6
    literal, or occasionally bare. Splitting on the *last* colon is what makes
    the bare-IPv6 case (``::1``, no brackets, no port) come back as itself
    rather than as ``::``.
    """
    if not host_header:
        return None
    host = host_header.strip()
    if not host:
        return None
    if host.startswith("["):
        # [::1] or [::1]:51423 -- the bracketed form always delimits the address.
        closing = host.find("]")
        if closing == -1:
            return None
        return host[1:closing].casefold()
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.casefold()


def expected_origin(scheme: str, host_header: str | None) -> str | None:
    """This app's own origin for the request in hand, or ``None``.

    ``None`` means the request did not arrive under a name that means "this
    machine", so there is no honest answer to "what is our origin here" and the
    caller must refuse rather than compare against something it made up.
    """
    hostname = _hostname(host_header)
    if hostname is None or hostname not in _LOOPBACK_HOSTNAMES:
        return None
    return f"{scheme.casefold()}://{(host_header or '').strip().casefold()}"


def refusal_for(
    method: str,
    scheme: str,
    host_header: str | None,
    origin: str | None,
    sec_fetch_site: str | None,
) -> str | None:
    """The refusal this request has earned, or ``None`` to let it through.

    Pure, so the decision can be tested without an app, a socket or a browser.

    Args:
        method: HTTP method, e.g. ``"POST"``.
        scheme: Request scheme, e.g. ``"http"``.
        host_header: The ``Host`` header as received, or ``None``.
        origin: The ``Origin`` header as received, or ``None`` if absent.
        sec_fetch_site: The ``Sec-Fetch-Site`` header, or ``None`` if absent.

    Returns:
        A sentence for the operator, or ``None`` when the request is
        same-origin and may proceed.
    """
    if method.upper() in SAFE_METHODS:
        return None

    ours = expected_origin(scheme, host_header)
    if ours is None:
        shown = (host_header or "no name at all").strip()[:_HOST_ECHO_LIMIT]
        return UNKNOWN_HOST_REFUSAL.format(host=shown)

    # Both checks run. Neither is a fallback for the other: a request that
    # carries both headers has to satisfy both, and a request that carries one
    # is judged on the one it carries.
    saw_evidence = False

    if sec_fetch_site is not None:
        saw_evidence = True
        if sec_fetch_site.strip().casefold() != _SAME_ORIGIN:
            return CROSS_ORIGIN_REFUSAL

    if origin is not None:
        saw_evidence = True
        if origin.strip().casefold() != ours:
            return CROSS_ORIGIN_REFUSAL

    if not saw_evidence:
        # The documented decision. See "The missing-header decision" above.
        return MISSING_ORIGIN_REFUSAL

    return None


def refusal_response(message: str) -> Response:
    """A 403 carrying *message* as a page a person can read.

    HTML rather than plain text because the overwhelmingly likely reader is
    looking at a browser window that has just done nothing; the non-browser
    caller that also meets this ignores the body either way.
    """
    return Response(
        status_code=403,
        content=_REFUSAL_PAGE.format(message=html.escape(message)),
        media_type="text/html; charset=utf-8",
    )


async def same_origin_guard(
    request: Request,
    call_next: Callable[[Request], Coroutine[Any, Any, Response]],
) -> Response:
    """ASGI middleware: refuse any state-changing request that is not our own.

    Registered in :func:`workstation_agent.ui.backend.app.create_app` over the
    whole application, so it covers every router already mounted and every route
    added after it.
    """
    message = refusal_for(
        request.method,
        request.url.scheme,
        request.headers.get("host"),
        request.headers.get("origin"),
        request.headers.get("sec-fetch-site"),
    )
    if message is not None:
        # The path is logged; the headers are not echoed into the log, only
        # classified, so a hostile Origin cannot write arbitrary text into the
        # operator's log file.
        log.warning(
            "Refused a cross-origin %s to %s (origin present=%s, "
            "sec-fetch-site present=%s)",
            request.method,
            request.url.path,
            request.headers.get("origin") is not None,
            request.headers.get("sec-fetch-site") is not None,
        )
        return refusal_response(message)
    return await call_next(request)
