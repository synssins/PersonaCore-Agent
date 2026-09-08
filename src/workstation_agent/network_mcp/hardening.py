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
from typing import Any, Final

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
            # Contract §3: 401, no body detail.
            await _respond(
                send, 401,
                extra_headers=[(b"www-authenticate", b"Bearer")],
            )
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

    async def _drain(self, receive: Any) -> tuple[bytes | None, int, str]:
        """Read the body under a byte bound and a time bound.

        Returns ``(body, 0, "")`` on success. On failure the body is ``None``
        and the status is either an HTTP status to answer with or
        :data:`_DISCONNECTED`, meaning the peer vanished mid-body and there is
        nobody left to answer.
        """
        chunks: list[bytes] = []
        total = 0
        try:
            async with asyncio.timeout(self._body_read_timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return None, _DISCONNECTED, "client disconnected"
                    body: bytes = message.get("body", b"")
                    total += len(body)
                    if total > self._max_body_bytes:
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
    keep a slot on a keep-alive connection.
    """
    headers: list[tuple[bytes, bytes]] = [
        (b"content-length", str(len(body)).encode("ascii")),
        (b"connection", b"close"),
    ]
    if body:
        headers.append((b"content-type", b"text/plain; charset=utf-8"))
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
