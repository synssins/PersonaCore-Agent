"""The security boundary in front of the MCP endpoint.

Everything hostile that reaches this workstation over the LAN hits this module
first. The MCP SDK's ASGI app is *behind* it and never sees a request that has
not cleared every check here.

Why this is a separate, systematic layer
----------------------------------------
Subtask B0 hit four remote **pre-authentication** crashes in the named-pipe
transport, each found in a separate verification round, each a different member
of the same family. Case-by-case is what cost it four rounds. So the input space
is enumerated once, here, as a table, and each row has a test:

============================  ==================================  =========================
hostile input                 where it is stopped                 answer
============================  ==================================  =========================
plaintext HTTP                ``scope["scheme"]`` check           ``403``, token never read
missing token                 header check                        ``401``, body never read
non-ASCII token bytes         ``compare_digest`` on **bytes**     ``401``, body never read
duplicated ``Authorization``  header check                        ``401``, body never read
wrong path, no token          answered as ``401``                 no surface to enumerate
wrong path, valid token       :meth:`Hardening.__call__`          ``404``, body never read
wrong method, valid token     :meth:`Hardening.__call__`          ``405``, body never read
too many requests in flight   in-flight counter                   ``503``, body never read
oversized ``Content-Length``  header check                        ``413``, body never read
oversized streamed body       counted during the drain            ``413``, drain aborted
slow-loris partial send       ``asyncio.timeout`` on the drain    ``408``, drain aborted
client vanishes mid-body      ``http.disconnect`` during drain    return, no response
empty body                    :func:`validate_json_body`          ``400``
invalid UTF-8 on the wire     ``bytes.decode("utf-8")`` strict    ``400``
unpaired surrogate in JSON    escape prefilter + iterative walk   ``400``
deeply nested JSON            iterative depth scan, no recursion  ``400``
malformed / no separator      ``json.loads``                      ``400``
non-object, non-array body    type check                          ``400``
============================  ==================================  =========================

Two properties hold for every row: **the handler returns, it never raises**, and
**the server is unharmed** — an individual connection is closed but the listener,
the session manager and every other connection survive.

The one route that is not behind the token
------------------------------------------
``POST /enrol/token`` exists so PersonaCore can push the bearer token it minted
during enrolment (see ``enrolment.py`` for the handshake). It cannot be behind
the bearer gate, because the token is the thing being established. That is a real
change to the posture above — "answer ``401`` from the scope and never read the
body" no longer holds for every path — so it is bounded separately and far more
tightly, and it answers **exactly one thing**:

============================  ==================================  =========================
enrolment input               where it is stopped                 answer
============================  ==================================  =========================
correct code, Join pending    :meth:`EnrolmentReceiver.redeem`    ``204``, token in force
wrong code                    ``compare_digest`` on 32-byte       ``401``, as below
                              digests, never on raw codes
no Join pending               same comparison, against a random   ``401``, as below
                              decoy of the same width
expired window                monotonic deadline                  ``401``, as below
code already used             the Join is cleared under a lock    ``401``, as below
malformed / hostile body      :func:`validate_json_body`, then    ``401``, as below
                              the same comparison anyway
non-``POST``                  method check                        ``401``, as below
carries an ``Origin``         header presence check               ``401``, body never read
oversized ``Content-Length``  header check                        ``401``, body never read
too many attempts             fixed-window rate limit             ``401``, body never read
too many in flight            enrolment in-flight counter         ``401``, body never read
============================  ==================================  =========================

"As below" is literal. Every refusal goes through :meth:`Hardening._refuse`, the
same helper that answers every bearerless request to every other path, so a
refused enrolment push is byte-identical to what a stranger gets for ``GET /``:
``401``, empty body, ``WWW-Authenticate: Bearer``. Nothing in the answer says
whether a Join is in progress, which is the property contract-side asked for
explicitly. The body is read **whether or not a Join is pending**, and
``redeem`` runs its comparison on every path including the malformed one, for
the same reason: refusing early — because there is no Join, or because the body
would not parse — would make the timing itself the disclosure.

The four B0 crash classes, mapped
---------------------------------
1. ``compare_digest`` raising ``TypeError`` on non-ASCII ``str``. Gone by
   construction: ASGI hands us header values as :class:`bytes` and we never
   decode them. ``compare_digest`` on two ``bytes`` objects accepts any byte
   values at all.
2. ``.encode("utf-8")`` raising ``UnicodeEncodeError`` on an unpaired surrogate.
   No token path encodes anything, and a surrogate anywhere in a request body is
   rejected by :func:`validate_json_body` before the SDK can encode it.
3. A long line overrunning a 64 KiB read buffer. HTTP frames by ``Content-Length``
   rather than by newline, and the bound is checked on the header, before the
   read.
4. ``RecursionError`` from deeply nested JSON, which ``json.JSONDecodeError`` does
   not cover. Prevented rather than caught: an iterative pre-scan rejects the
   body before ``json.loads`` is ever called, and ``RecursionError`` is *also*
   caught as a belt.

See ``DECISION.md`` in this package for the bound and its justification.
"""
# ruff: noqa: ANN401
# ANN401: ASGI's ``app``, ``receive`` and ``send`` are structurally typed
# callables with no exported Protocol in this dependency set. Inventing local
# Protocols for them would add indirection to the one module that most needs to
# be read straight through.

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    # Type-checking only, so there is no runtime import cycle: ``enrolment``
    # imports :func:`validate_json_body` from here.
    from workstation_agent.network_mcp.enrolment import EnrolmentReceiver

log = logging.getLogger(__name__)

Scope = dict[str, Any]
Message = dict[str, Any]

#: The request-line-plus-headers bound, passed to uvicorn's h11 parser so the
#: number is ours and stated rather than an implementation default. This is the
#: **only** memory an unauthenticated peer can make this process hold: the
#: pre-authentication body bound is zero bytes, because authentication is decided
#: from the ASGI scope before ``receive()`` is ever called. See ``DECISION.md`` §2.
MAX_HEADER_BYTES: Final = 16 * 1024

#: Post-authentication body bound. ~17x the largest legitimate payload (§5.3 caps
#: results at 60,000 characters and arguments are smaller), well under the SDK's
#: own 4 MiB default.
DEFAULT_MAX_BODY_BYTES: Final = 1024 * 1024

#: JSON nesting depth ceiling. MCP messages are shallow; 64 is far beyond any
#: legitimate tool-argument object and far below CPython's recursion limit.
DEFAULT_MAX_JSON_DEPTH: Final = 64

#: Seconds allowed for a client to finish streaming a request body. Bounds
#: slow-loris style partial sends.
DEFAULT_BODY_READ_TIMEOUT: Final = 10.0

#: Concurrent in-flight requests, including long-lived SSE streams.
DEFAULT_MAX_CONCURRENT: Final = 16

#: Concurrent MCP sessions one authenticated peer may hold. Replaces the SDK's
#: ``max_sessions``, which exists only on 2.2's ``streamable_http_app``.
DEFAULT_MAX_SESSIONS: Final = 8

#: Seconds of inactivity after which a session stops counting against the cap.
#: Must match what the SDK's session manager reaps on.
DEFAULT_SESSION_IDLE_TIMEOUT: Final = 300.0

_ALLOWED_METHODS: Final = frozenset({"POST", "GET", "DELETE"})

# -- bounds for the one unauthenticated route -------------------------------
# Separate constants rather than reuse of the post-authentication ones above,
# because these bound work done for a peer who has proved nothing. Each is
# roughly two orders of magnitude tighter than its authenticated counterpart.

#: Body ceiling for an enrolment push. ``{"code": ..., "token": ...}`` with the
#: widest values ``enrolment.py`` accepts is under 700 bytes; 4 KiB is generous
#: for a field that may grow and still small enough that the worst an anonymous
#: peer can make this process hold is ``ENROL_MAX_CONCURRENT`` * 4 KiB.
ENROL_MAX_BODY_BYTES: Final = 4 * 1024

#: Seconds an enrolment push gets to finish streaming. Shorter than the
#: authenticated timeout: this body is small and arrives from a core on the same
#: LAN, so a slow send is a slow-loris rather than a large upload.
#:
#: Also, and separately, it must stay **under the core's 10-second read
#: timeout**. A bound above that would make the worst case a core that gives up
#: on an enrolment this endpoint was still willing to complete.
ENROL_BODY_READ_TIMEOUT: Final = 5.0

#: Enrolment pushes read concurrently. The core sends exactly one; anything past
#: two at once is not the core.
ENROL_MAX_CONCURRENT: Final = 2

#: Fixed-window rate limit on enrolment pushes: at most this many in any
#: :data:`ENROL_RATE_WINDOW` seconds, counted across all peers because the
#: attacker picks their own source address.
#:
#: Chosen to leave brute force out of reach without denying the core its one
#: push: a 300-second window allows ~600 attempts, against a code space of at
#: least 36**6 given :data:`~workstation_agent.network_mcp.enrolment.MIN_CODE_CHARS`.
#: A flood *can* delay the core's push into a later window; it cannot exhaust the
#: window, because the limit refuses without reading a body or allocating.
ENROL_MAX_ATTEMPTS: Final = 20
ENROL_RATE_WINDOW: Final = 10.0

#: The answer to a successful enrolment push. The core treats any 2xx as
#: success and never reads the body, so ``204 No Content`` is the exact thing
#: being said. A ``3xx`` would be read as a *failure* — the core's client does
#: not follow redirects — so this route never produces one.
ENROL_SUCCESS_STATUS: Final = 204

#: The single reason string logged for every enrolment refusal. One string, on
#: purpose: a log that distinguished "wrong code" from "no Join pending" would
#: put back, in a file, the disclosure the response shape is careful not to make.
_ENROL_REASON: Final = "enrolment push refused"

#: A lone surrogate cannot appear as raw bytes in a body that already decoded as
#: strict UTF-8, so the only way to smuggle one in is a ``\uD800``-``\uDFFF``
#: escape. Matching that cheaply in C lets the expensive iterative walk run only
#: on bodies that could possibly contain one. Paired surrogates also match the
#: prefilter, and are then correctly cleared by the walk, because ``json.loads``
#: has already combined a valid pair into a single non-surrogate character.
#:
#: The third hex digit must cover ``8``-``f``: D800-DBFF are the high half and
#: DC00-DFFF the low half, and *either* alone is unpaired. An earlier version of
#: this pattern listed only ``[89abAB]`` and let every lone **low** surrogate
#: through — caught by the parametrized matrix in
#: ``tests/unit/network_mcp/test_hardening.py``, which is the entire reason that
#: file enumerates the input space instead of listing remembered bugs.
_SURROGATE_ESCAPE: Final = re.compile(r"\\[uU][dD][89a-fA-F]")

# Log-flooding is itself a resource-exhaustion vector once this is on a LAN, so
# rejections are logged at WARNING on the first occurrence and then only every
# _LOG_EVERY-th, carrying the running total so nothing is actually hidden.
_LOG_EVERY: Final = 50


def _check_depth(text: str, max_depth: int) -> str | None:  # noqa: C901
    """Reject JSON nested deeper than *max_depth*, without recursing.

    Runs before :func:`json.loads`, so ``RecursionError`` is prevented rather
    than caught. The scan is a single left-to-right pass that tracks string and
    escape state so brackets inside string literals do not count, and it bails
    the moment the limit is exceeded rather than scanning the whole body.

    A cheap C-level prefilter skips the Python-level pass entirely when the body
    cannot possibly nest too deeply: if the total number of opening brackets is
    at most *max_depth*, neither can the depth be. That is the common shape for
    a large legitimate payload (one big string, a handful of brackets).
    """
    if text.count("[") + text.count("{") <= max_depth:
        return None

    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                return f"JSON nests deeper than {max_depth} levels"
        elif ch in "]}":
            depth -= 1
    return None


def _has_lone_surrogate(value: object) -> bool:
    """True if any string anywhere in *value* cannot be encoded as UTF-8.

    Iterative, with an explicit stack: a recursive walk would reintroduce the
    very ``RecursionError`` this module exists to prevent. Dictionary *keys* are
    walked as well as values — ``json.loads`` will happily produce a key holding
    an unpaired surrogate.
    """
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(item, dict):
            for key, val in item.items():
                stack.append(key)
                stack.append(val)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def validate_json_body(  # noqa: PLR0911 — one return per rejected input class; see the table
    raw: bytes,
    *,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> str | None:
    """Structurally validate a request body. Returns a reason, or None if clean.

    This never raises for any input. Ordering matters and is deliberate: bytes
    are decoded strictly before anything looks at them, depth is checked before
    the parser runs, and the surrogate walk runs only on already-parsed data.

    Args:
        raw: The complete request body as it arrived on the wire.
        max_depth: Nesting ceiling.

    Returns:
        A short, non-revealing reason string, or ``None`` when the body is a
        well-formed JSON object or array safe to hand to the SDK.
    """
    if not raw.strip():
        return "empty request body"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Invalid UTF-8 on the wire, as distinct from an escape inside a JSON
        # string. Rejected rather than decoded with errors="replace": a
        # replacement policy maps many different malformed inputs onto the same
        # text, and this body is about to be interpreted as commands.
        return "request body is not valid UTF-8"

    depth_problem = _check_depth(text, max_depth)
    if depth_problem is not None:
        return depth_problem

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return "request body is not valid JSON"
    except RecursionError:  # pragma: no cover — _check_depth gets there first
        return "request body nests too deeply"

    if not isinstance(parsed, (dict, list)):
        return "request body is not a JSON-RPC message"

    if _SURROGATE_ESCAPE.search(text) and _has_lone_surrogate(parsed):
        return "request body contains an unpaired surrogate"

    return None


def _has_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bool:
    """True if *name* appears at all, however many times.

    Distinct from :func:`_single_header`, which treats a duplicate as absent.
    Used where the *presence* of a header is itself disqualifying, and where
    "send it twice" must therefore not be a way around the check.
    """
    return any(key == name for key, _ in headers)


def _single_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    """Return the sole value of *name*, or None if absent or duplicated.

    A duplicated ``Authorization`` header is ambiguous — different intermediaries
    resolve it differently — so it is treated as absent rather than guessed at.
    """
    found: bytes | None = None
    for key, value in headers:
        if key == name:
            if found is not None:
                return None
            found = value
    return found


class Hardening:
    """ASGI middleware: the endpoint's path, auth, bounds and caps.

    Wraps the MCP SDK's Starlette app. Lifespan messages pass straight through
    (the SDK's session manager runs in its lifespan); every HTTP request runs the
    table at the top of this module.

    Args:
        app: The wrapped ASGI application.
        token: The expected bearer token. Compared as bytes, never decoded.
        path: The only path served. Anything else is ``404``.
        max_body_bytes: Post-authentication body ceiling.
        max_json_depth: Nesting ceiling for :func:`validate_json_body`.
        max_concurrent: In-flight request cap, including SSE streams.
        body_read_timeout: Seconds a client gets to finish streaming a body.
        max_sessions: Concurrent MCP sessions an authenticated peer may hold.
        session_idle_timeout: Seconds after which an untouched session stops
            counting against ``max_sessions``. **Must be the value the SDK's
            session manager reaps on**, or the two views of "live session"
            diverge.
        enrolment: Optional
            :class:`~workstation_agent.network_mcp.enrolment.EnrolmentReceiver`.
            When given, ``POST`` to its ``path`` is answered *ahead of* the
            bearer check — the only route on this endpoint that is. ``None``
            means the route does not exist at all; a receiver with no pending
            Join means it behaves as though it does not, which is a different
            statement and the one that matters, since the two must be
            indistinguishable from outside.
    """

    def __init__(  # noqa: PLR0913 — each argument is a separately justified bound
        self,
        app: Any,
        *,
        token: str,
        path: str = "/mcp",
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_json_depth: int = DEFAULT_MAX_JSON_DEPTH,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        body_read_timeout: float = DEFAULT_BODY_READ_TIMEOUT,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        session_idle_timeout: float = DEFAULT_SESSION_IDLE_TIMEOUT,
        enrolment: EnrolmentReceiver | None = None,
    ) -> None:
        self._app = app
        # Pre-encoded once, at construction, from *our own* token. The token is
        # generated by this package as 64 hex characters, so this encode cannot
        # fail; nothing a client sends is ever encoded or decoded on the auth
        # path, which is what makes B0 crash classes 1 and 2 unreachable here.
        self._expected_token = token.encode("ascii")
        self._path = path
        self._max_body_bytes = max_body_bytes
        self._max_json_depth = max_json_depth
        self._max_concurrent = max_concurrent
        self._body_read_timeout = body_read_timeout
        self._max_sessions = max_sessions
        self._session_idle_timeout = session_idle_timeout
        self._in_flight = 0
        self._rejections = 0
        #: Session id -> monotonic time of last activity. Mirrors the SDK's own
        #: session map; see :meth:`_session_gate`.
        self._sessions: dict[bytes, float] = {}
        self._enrolment = enrolment
        #: Enrolment pushes currently being read. Counted separately from
        #: ``_in_flight``, which by design only ever counts authenticated work.
        self._enrol_in_flight = 0
        #: Monotonic timestamps of recent enrolment attempts, for the fixed
        #: window rate limit. Bounded by :data:`ENROL_MAX_ATTEMPTS`.
        self._enrol_attempts: deque[float] = deque()

    # -- observability ---------------------------------------------------

    @property
    def in_flight(self) -> int:
        """Requests currently being served."""
        return self._in_flight

    @property
    def rejections(self) -> int:
        """Total requests rejected by this middleware since start."""
        return self._rejections

    @property
    def live_sessions(self) -> int:
        """MCP sessions currently counting against the cap."""
        self._expire_sessions()
        return len(self._sessions)

    # -- session accounting ----------------------------------------------

    def _now(self) -> float:
        return time.monotonic()

    def _expire_sessions(self) -> None:
        """Drop sessions idle past the timeout the SDK also reaps on."""
        cutoff = self._now() - self._session_idle_timeout
        for sid in [s for s, seen in self._sessions.items() if seen < cutoff]:
            del self._sessions[sid]

    def _session_gate(self, scope: Scope, method: str, session_id: bytes | None) -> bool:
        """Account for this request's session; False means "refuse it".

        Replaces the SDK's ``max_sessions``, which exists only on 2.2's
        ``streamable_http_app`` signature while the core runs 2.1.1. Doing it
        here rather than reaching into the SDK keeps the bound in the layer that
        already owns every other limit, and keeps it working on both versions.

        The accounting deliberately mirrors the SDK's own lifecycle so the two
        cannot drift:

        * A ``POST`` with no ``Mcp-Session-Id`` is a session-creating
          ``initialize``. That is the only thing the cap refuses, and it refuses
          it *before* the SDK allocates a transport.
        * Any request carrying a known id refreshes it, exactly as the SDK
          pushes back its idle deadline on activity.
        * Idle expiry uses the same timeout handed to the session manager, so a
          session we stop counting is one the SDK has also reaped.

        Expiring is not optional. Counting only creations and teardowns would
        turn a peer that reconnects without sending ``DELETE`` — which is what
        happens every time the core restarts — into a permanent slot leak, and
        after ``max_sessions`` restarts the endpoint would refuse the core
        outright. That converts the SDK's memory leak into an outage, which is
        strictly worse than the thing the cap is for.
        """
        self._expire_sessions()
        if session_id is not None:
            if session_id in self._sessions:
                self._sessions[session_id] = self._now()
            return True
        if method != "POST":
            return True
        if len(self._sessions) >= self._max_sessions:
            self._reject_log(scope, 503, "session cap reached")
            return False
        return True

    def _watch_session_headers(self, send: Any, method: str, session_id: bytes | None) -> Any:
        """Wrap ``send`` to learn which session ids the SDK issues and drops."""

        async def _send(message: Message) -> None:
            if message.get("type") == "http.response.start":
                status = message.get("status", 0)
                issued = _single_header(message.get("headers", []), b"mcp-session-id")
                if issued is not None and 200 <= status < 300:  # noqa: PLR2004
                    self._sessions[issued] = self._now()
                elif (
                    method == "DELETE"
                    and session_id is not None
                    and 200 <= status < 300  # noqa: PLR2004
                ):
                    # An accepted teardown; the SDK has dropped it too.
                    self._sessions.pop(session_id, None)
            await send(message)

        return _send

    def _reject_log(self, scope: Scope, status: int, reason: str) -> None:
        self._rejections += 1
        client = scope.get("client")
        peer = f"{client[0]}:{client[1]}" if client else "unknown"
        if self._rejections == 1 or self._rejections % _LOG_EVERY == 0:
            log.warning(
                "network MCP rejected %s: %d %s (%d rejections total)",
                peer, status, reason, self._rejections,
            )
        else:
            log.debug("network MCP rejected %s: %d %s", peer, status, reason)

    # -- ASGI ------------------------------------------------------------

    async def __call__(  # noqa: C901, PLR0911, PLR0912, PLR0915
        self, scope: Scope, receive: Any, send: Any,
    ) -> None:
        """ASGI entry point. Returns for every input; never raises.

        The branch count is the point, not an accident: this is the rejection
        table at the top of this module, in order, one branch each. Splitting it
        into helpers would hide the order, and the order is the security
        property — transport before identity, identity before everything else,
        size before parsing.
        """
        if scope["type"] == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope["type"] != "http":
            # No websocket surface exists on this endpoint.
            await send({"type": "websocket.close", "code": 1008})
            return

        # --- transport, before the token is even looked at ---------------
        # First, because reading a bearer token off a plaintext connection is
        # already the harm: by the time we could compare it, it has crossed the
        # LAN in the clear. A missing `scheme` is treated as plaintext — the ASGI
        # spec always populates it for an http scope, so its absence means we are
        # not being driven by something that can vouch for the transport.
        #
        # This module is a reusable ASGI middleware, and `NetworkMCPServer` is
        # not the only thing that could mount it. Asserting the transport here
        # makes "never plain HTTP" a property of this file rather than of a
        # uvicorn config three files away.
        if scope.get("scheme") != "https":
            self._reject_log(scope, 403, f"scheme {scope.get('scheme')!r}")
            await _respond(send, 403, b"https required")
            return

        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])

        # --- enrolment, the one route ahead of the token ------------------
        # Ahead of the bearer check because the token it carries is the token
        # being established; there is nothing yet to authenticate with. Behind
        # the transport check because the whole handshake depends on the core
        # having pinned this endpoint's certificate — a push over plaintext is
        # not the core, and is refused as 403 with everything else plaintext.
        #
        # Everything past this point is unchanged for every other path: the
        # bearer gate below still runs for /mcp and for anything else, and a
        # pending Join does not open any of it.
        if self._enrolment is not None and scope.get("path") == self._enrolment.path:
            await self._enrol(scope, headers, receive, send)
            return

        # --- authentication, before anything an anonymous peer could map --
        # Ahead of the path and method checks on purpose. Answering 404 for an
        # unknown path and 405 for an unknown method *before* checking the token
        # lets an anonymous peer enumerate this surface by telling the three
        # answers apart — which paths exist, which methods each takes — and lets
        # it fill the log without ever constructing an Authorization header.
        # Everything an unauthenticated peer sends now gets the same answer.
        authorization = _single_header(headers, b"authorization")
        if not self._token_ok(authorization):
            self._reject_log(scope, 401, "bad or missing bearer token")
            await self._refuse(send)
            return

        if scope.get("path") != self._path:
            self._reject_log(scope, 404, "unknown path")
            await _respond(send, 404)
            return

        method = scope.get("method", "")
        if method not in _ALLOWED_METHODS:
            self._reject_log(scope, 405, f"method {method}")
            await _respond(send, 405, extra_headers=[(b"allow", b"POST, GET, DELETE")])
            return

        # --- caps and bounds, on authenticated work only -----------------
        # The cap is checked *after* authentication on purpose. ``_in_flight``
        # only ever counts authenticated requests, so answering an
        # unauthenticated peer 503 rather than 401 would tell it how busy this
        # machine is while also letting a flood of anonymous requests deny the
        # core its slot. Anonymous connection volume is bounded a layer down, by
        # uvicorn's own ``limit_concurrency`` and by the header bound.
        if self._in_flight >= self._max_concurrent:
            self._reject_log(scope, 503, "connection cap reached")
            await _respond(send, 503, b"busy")
            return

        session_id = _single_header(headers, b"mcp-session-id")
        if not self._session_gate(scope, method, session_id):
            await _respond(send, 503, b"too many sessions")
            return
        send = self._watch_session_headers(send, method, session_id)


        content_length = _single_header(headers, b"content-length")
        declared: int | None = None
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                self._reject_log(scope, 400, "unparseable Content-Length")
                await _respond(send, 400, b"bad request")
                return
            if declared < 0 or declared > self._max_body_bytes:
                self._reject_log(scope, 413, f"Content-Length {declared}")
                await _respond(send, 413, b"request too large")
                return

        self._in_flight += 1
        try:
            if method != "POST":
                # GET (SSE stream) and DELETE (session teardown) carry no body.
                await self._app(scope, receive, send)
                return

            raw, status, reason = await self._drain(receive)
            if raw is None:
                if status != _DISCONNECTED:
                    self._reject_log(scope, status, reason)
                    await _respond(send, status, reason.encode("ascii", "replace"))
                # status == _DISCONNECTED: the peer is gone; nobody to answer.
                return

            problem = validate_json_body(raw, max_depth=self._max_json_depth)
            if problem is not None:
                self._reject_log(scope, 400, problem)
                await _respond(send, 400, problem.encode("ascii", "replace"))
                return

            await self._app(scope, _replaying(raw, receive), send)
        finally:
            self._in_flight -= 1

    async def _refuse(self, send: Any) -> None:
        """The single unauthenticated answer this endpoint ever gives.

        Contract §3: ``401``, no body detail. Every caller that refuses without
        proof of identity goes through here rather than composing its own — the
        bearer gate, and every enrolment refusal. That is not tidiness: it is how
        "a wrong pairing code, an expired window and no Join at all are
        indistinguishable" is *held* rather than merely intended. There is one
        response to keep identical, so there is nothing to drift.
        """
        await _respond(send, 401, extra_headers=[(b"www-authenticate", b"Bearer")])

    def set_token(self, token: str) -> None:
        """Replace the expected bearer token while the endpoint is serving.

        Called when an enrolment push is accepted, so the token PersonaCore
        minted is in force for the very next request rather than after a
        restart. In-flight requests that already cleared the gate are unaffected;
        anything presenting the previous token from here on gets the same
        ``401`` as a stranger, which is the intended meaning of enrolling.

        Args:
            token: Printable-ASCII token.
                :func:`~workstation_agent.network_mcp.enrolment._acceptable_token`
                has already established that of anything arriving over the wire.

        Raises:
            UnicodeEncodeError: if *token* is not ASCII. Deliberately not caught
                here: a token this cannot encode is one
                :meth:`_token_ok` could never match, so silently keeping the old
                one would leave the endpoint claiming an enrolment that did not
                happen.
        """
        self._expected_token = token.encode("ascii")

    # -- enrolment (the one unauthenticated route) ------------------------

    def _enrol_rate_ok(self) -> bool:
        """Concurrency and fixed-window rate limit for enrolment pushes.

        Checked *before* the body is read, so exceeding either costs this
        process nothing. Both limits are independent of whether a Join is
        pending — a limit that only applied mid-enrolment would itself be the
        disclosure.
        """
        if self._enrol_in_flight >= ENROL_MAX_CONCURRENT:
            return False
        now = self._now()
        window = self._enrol_attempts
        while window and window[0] <= now - ENROL_RATE_WINDOW:
            window.popleft()
        if len(window) >= ENROL_MAX_ATTEMPTS:
            return False
        window.append(now)
        return True

    async def _enrol(
        self, scope: Scope, headers: list[tuple[bytes, bytes]], receive: Any, send: Any,
    ) -> None:
        """Answer ``POST /enrol/token``. Returns for every input; never raises.

        Success is the only outcome with its own shape. Everything else — a
        wrong method, an oversized declaration, a body that never finishes
        arriving, a malformed body, a wrong code, an expired window, no Join at
        all — is :meth:`_refuse`, byte for byte.
        """
        receiver = self._enrolment
        if receiver is None:  # pragma: no cover — the caller checked
            await self._refuse(send)
            return

        # The method check and the limits come first because they are decided
        # from the scope alone and cost nothing, and because neither answer
        # depends on the Join: a peer learns only what it already knew about its
        # own request rate.
        # ``Origin`` is refused outright, and its mere presence is enough.
        #
        # The SDK's DNS-rebinding protection lives inside the app this route is
        # answered *in front of*, so this route does not inherit it. The vector
        # that matters is a page in the owner's browser POSTing here — a JSON
        # body is reachable cross-origin as a "simple request", and while the
        # page could not read the reply, a guessed code would still enrol.
        # PersonaCore is an HTTP client, not a browser: it sends no ``Origin``,
        # and a browser always sends one on a cross-origin POST. Refusing on
        # presence costs the core nothing and removes the browser entirely.
        # ``_has_header`` rather than ``_single_header`` so sending it twice is
        # not the way around it.
        if (
            scope.get("method") != "POST"
            or _has_header(headers, b"origin")
            or not self._enrol_rate_ok()
        ):
            self._reject_log(scope, 401, _ENROL_REASON)
            await self._refuse(send)
            return

        declared = _single_header(headers, b"content-length")
        if declared is not None and not _within(declared, ENROL_MAX_BODY_BYTES):
            # 401 rather than the 413 the authenticated path gives: this route
            # has exactly one refusal, and a 413 here would say "you found the
            # enrolment route" to anyone who sent a large body.
            self._reject_log(scope, 401, _ENROL_REASON)
            await self._refuse(send)
            return

        self._enrol_in_flight += 1
        try:
            raw, status, _reason = await self._drain(
                receive,
                max_bytes=ENROL_MAX_BODY_BYTES,
                read_timeout=ENROL_BODY_READ_TIMEOUT,
            )
            if raw is None:
                if status != _DISCONNECTED:
                    self._reject_log(scope, 401, _ENROL_REASON)
                    await self._refuse(send)
                # status == _DISCONNECTED: the peer is gone; nobody to answer.
                return

            try:
                accepted = await receiver.redeem(raw)
            except Exception:  # pragma: no cover — redeem() is written not to raise
                # Belt. A receiver that raised would otherwise become a 500 from
                # uvicorn, which is a response shape this route does not have and
                # would announce the route's existence.
                log.exception("network MCP enrolment receiver raised; refusing")
                accepted = False

            if accepted:
                # 204, exactly. The core reads the status code and nothing else
                # — any 2xx is success and it streams the body away without
                # parsing it — so the precise answer against a tolerant reader
                # is "succeeded, nothing to say". And never a 3xx: the core's
                # client has redirects disabled and would read one as a failed
                # enrolment.
                await _respond(send, ENROL_SUCCESS_STATUS)
                return
            self._reject_log(scope, 401, _ENROL_REASON)
            await self._refuse(send)
        finally:
            self._enrol_in_flight -= 1

    def _token_ok(self, authorization: bytes | None) -> bool:
        """Constant-time bearer check on raw bytes.

        ``authorization`` is whatever the peer sent: arbitrary bytes, possibly
        non-ASCII, possibly empty. It is never decoded, so there is no encoding
        step that can raise. ``secrets.compare_digest`` accepts any two
        ``bytes`` objects; only the length is observable.
        """
        if authorization is None:
            return False
        scheme, _, credentials = authorization.strip().partition(b" ")
        # The scheme is not secret, so a plain comparison is fine here. It is
        # case-insensitive per RFC 7235.
        if scheme.lower() != b"bearer":
            return False
        return secrets.compare_digest(credentials.strip(), self._expected_token)

    async def _drain(
        self,
        receive: Any,
        *,
        max_bytes: int | None = None,
        read_timeout: float | None = None,
    ) -> tuple[bytes | None, int, str]:
        """Read the body under a byte bound and a time bound.

        Returns ``(body, 0, "")`` on success. On failure the body is ``None``
        and the status is either an HTTP status to answer with or
        :data:`_DISCONNECTED`, meaning the peer vanished mid-body and there is
        nobody left to answer.

        Args:
            receive: The ASGI ``receive`` callable.
            max_bytes: Byte ceiling; the instance's authenticated bound if
                omitted. The enrolment route passes its own, much smaller one.
            read_timeout: Seconds allowed for the whole read; the instance's
                authenticated bound if omitted. Named for the thing it bounds
                rather than plain ``timeout``, which ``ASYNC109`` reads as an
                invitation for the caller to supply its own cancellation.
        """
        limit = self._max_body_bytes if max_bytes is None else max_bytes
        deadline = self._body_read_timeout if read_timeout is None else read_timeout
        chunks: list[bytes] = []
        total = 0
        try:
            async with asyncio.timeout(deadline):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return None, _DISCONNECTED, "client disconnected"
                    body: bytes = message.get("body", b"")
                    total += len(body)
                    if total > limit:
                        # Abort mid-stream rather than buffering the rest to
                        # reply politely.
                        return None, 413, "request too large"
                    chunks.append(body)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return None, 408, "request body timed out"
        except (ConnectionError, OSError):
            return None, _DISCONNECTED, "client disconnected"
        return b"".join(chunks), 0, ""


#: Sentinel status: the peer went away, so no response is possible or wanted.
_DISCONNECTED: Final = -1

#: The one status this module sends that must carry no ``Content-Length``.
_NO_CONTENT: Final = 204


def _within(declared: bytes, ceiling: int) -> bool:
    """True if a raw ``Content-Length`` header parses and is within *ceiling*.

    Returns ``False`` for anything unparseable, negative or too large, so the
    caller has one answer to give rather than three. The authenticated path
    deliberately keeps its own three-way handling (``400`` vs ``413``), which is
    useful information to give a peer that has already proved who it is.
    """
    try:
        length = int(declared)
    except ValueError:
        return False
    return 0 <= length <= ceiling


def _replaying(raw: bytes, receive: Any) -> Any:
    """An ASGI ``receive`` that replays the already-drained body once.

    After the replay it falls through to the real ``receive`` so the wrapped app
    still observes ``http.disconnect``.
    """
    delivered = False

    async def _receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": raw, "more_body": False}
        return await receive()

    return _receive


async def _respond(
    send: Any,
    status: int,
    body: bytes = b"",
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    """Send a minimal response and close the connection.

    ``Connection: close`` is deliberate: a peer we just rejected does not get to
    keep a slot on a keep-alive connection. The enrolment success answer uses it
    too — the core pushes once and is done, and closing means a push cannot hold
    a connection open past the Join it just consumed.

    ``204`` is framed without ``Content-Length``: RFC 9110 forbids one on a
    response that cannot have content, and h11 — the parser this endpoint pins —
    enforces that rather than tolerating it.
    """
    headers: list[tuple[bytes, bytes]] = [(b"connection", b"close")]
    if status != _NO_CONTENT:
        headers.insert(0, (b"content-length", str(len(body)).encode("ascii")))
    if body:
        headers.append((b"content-type", b"text/plain; charset=utf-8"))
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
