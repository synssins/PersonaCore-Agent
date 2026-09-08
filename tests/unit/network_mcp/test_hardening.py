"""Systematic hostile-input coverage for the network endpoint's boundary.

This file is deliberately organised as a *matrix over the input space*, not as a
list of remembered bugs. B0 found four remote pre-authentication crashes in four
separate verification rounds because it tested case by case; the point of this
file is that a fifth case of the same family should already be covered by a row
that exists.

The axes are:

* **Framing** — what arrives on the wire: no body, empty body, oversized body,
  body streamed in pieces, body that stops arriving, peer that vanishes.
* **Encoding** — invalid UTF-8 on the wire, a valid-UTF-8 escape naming an
  unpaired surrogate, non-ASCII bytes in a header.
* **Structure** — not JSON, JSON that is not a message, JSON nested arbitrarily
  deep.
* **Identity** — absent, malformed, wrong-scheme, wrong-length, duplicated, and
  non-ASCII credentials.
* **Volume** — more concurrent requests than the cap.

Every row asserts the same two invariants: the handler **returns rather than
raises**, and the wrapped application was reached only when it should have been.
"""
# ruff: noqa: ANN204, ARG002
# The fakes in this file implement the ASGI callable signature, which is
# structural: unused parameters and an untyped __call__ are the shape being
# imitated, not an oversight.

from __future__ import annotations

import asyncio
import json

import pytest

from workstation_agent.network_mcp.hardening import (
    DEFAULT_MAX_JSON_DEPTH,
    Hardening,
    validate_json_body,
)

TOKEN = "a" * 64
AUTH = (b"authorization", b"Bearer " + TOKEN.encode())


class RecordingApp:
    """The wrapped ASGI app. Records what got through and echoes 200."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.bodies: list[bytes] = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope)
        if scope["type"] == "http" and scope.get("method") == "POST":
            chunks = []
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            self.bodies.append(b"".join(chunks))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


class Sender:
    """Collects the ASGI response messages the middleware emits."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, message):
        self.messages.append(message)

    @property
    def status(self) -> int | None:
        for m in self.messages:
            if m["type"] == "http.response.start":
                return m["status"]
        return None

    @property
    def body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.messages if m["type"] == "http.response.body"
        )

    def header(self, name: bytes) -> bytes | None:
        for m in self.messages:
            if m["type"] == "http.response.start":
                for key, value in m["headers"]:
                    if key == name:
                        return value
        return None


def scope(
    *,
    method: str = "POST",
    path: str = "/mcp",
    headers: list[tuple[bytes, bytes]] | None = None,
    body_len: int | None = None,
    scheme: str | None = "https",
) -> dict:
    hdrs: list[tuple[bytes, bytes]] = list(headers) if headers is not None else [AUTH]
    if body_len is not None:
        hdrs.append((b"content-length", str(body_len).encode()))
    built = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": hdrs,
        "client": ("192.168.1.9", 55000),
    }
    if scheme is not None:
        built["scheme"] = scheme
    return built


def body_receive(*chunks: bytes):
    """A ``receive`` that yields *chunks* then stops."""
    queue = list(chunks)

    async def _receive():
        if queue:
            piece = queue.pop(0)
            return {"type": "http.request", "body": piece, "more_body": bool(queue)}
        return {"type": "http.disconnect"}

    return _receive


def never_receive():
    """A ``receive`` that must never be called (pre-auth rejections)."""

    async def _receive():
        pytest.fail("the body was read for a request that should have been rejected first")

    return _receive


def stalling_receive(first: bytes = b'{"jsonrpc"'):
    """A slow-loris: sends a partial body, then never sends anything else."""
    sent = False

    async def _receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": first, "more_body": True}
        await asyncio.sleep(3600)
        raise AssertionError  # pragma: no cover

    return _receive


def make(app: RecordingApp | None = None, **kwargs) -> tuple[Hardening, RecordingApp]:
    inner = app or RecordingApp()
    return Hardening(inner, token=TOKEN, **kwargs), inner


# ---------------------------------------------------------------------------
# Transport: checked before the token, because a token read off a plaintext
# connection has already crossed the LAN in the clear
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scheme",
    [
        pytest.param("http", id="plain-http"),
        pytest.param("HTTPS", id="wrong-case"),
        pytest.param("ws", id="websocket-scheme"),
        pytest.param("", id="empty"),
        pytest.param(None, id="absent-from-the-scope"),
    ],
)
async def test_anything_but_https_is_refused_before_the_token_is_read(scheme):
    mw, app = make()
    send = Sender()
    await mw(scope(scheme=scheme, body_len=10), never_receive(), send)
    assert send.status == 403
    assert app.calls == []


async def test_a_valid_token_over_plaintext_is_still_refused():
    """The guarantee is local to this middleware, not to a uvicorn config."""
    mw, app = make()
    send = Sender()
    await mw(scope(scheme="http", headers=[AUTH]), never_receive(), send)
    assert send.status == 403
    assert app.calls == []


# ---------------------------------------------------------------------------
# Identity: the axis B0's four crashes all lived on
# ---------------------------------------------------------------------------

BAD_CREDENTIALS = [
    pytest.param([], id="no-authorization-header"),
    pytest.param([(b"authorization", b"")], id="empty-value"),
    pytest.param([(b"authorization", b"Bearer")], id="scheme-only-no-separator"),
    pytest.param([(b"authorization", b"Bearer ")], id="scheme-and-empty-credential"),
    pytest.param([(b"authorization", TOKEN.encode())], id="credential-without-scheme"),
    pytest.param([(b"authorization", b"Basic " + TOKEN.encode())], id="wrong-scheme"),
    pytest.param([(b"authorization", b"Bearer " + b"a" * 63)], id="one-byte-short"),
    pytest.param([(b"authorization", b"Bearer " + b"a" * 65)], id="one-byte-long"),
    pytest.param([(b"authorization", b"Bearer " + b"b" * 64)], id="right-length-wrong-value"),
    # B0 crash class 1: compare_digest raises TypeError on non-ASCII str. Here
    # the value never becomes a str at all.
    pytest.param(
        [(b"authorization", "Bearer éèê".encode())],
        id="non-ascii-utf8-credential",
    ),
    pytest.param([(b"authorization", b"Bearer \xff\xfe\x00\x80")], id="invalid-utf8-credential"),
    # B0 crash class 2: an unpaired surrogate. It cannot be encoded as UTF-8 at
    # all, so this is the WTF-8/surrogateescape byte form of "\ud800".
    pytest.param([(b"authorization", b"Bearer \xed\xa0\x80")], id="surrogate-bytes-credential"),
    pytest.param([(b"authorization", b"Bearer " + b"\x00" * 64)], id="nul-bytes-credential"),
    pytest.param([(b"authorization", b"Bearer " + b"\n" * 64)], id="newlines-credential"),
    # Ambiguous: different intermediaries resolve duplicates differently.
    pytest.param([AUTH, AUTH], id="duplicated-authorization"),
    pytest.param(
        [AUTH, (b"authorization", b"Bearer " + b"b" * 64)],
        id="duplicated-one-good-one-bad",
    ),
]


@pytest.mark.parametrize("headers", BAD_CREDENTIALS)
async def test_bad_credentials_are_401_and_never_read_the_body(headers):
    """Every malformed identity is a 401 decided before ``receive()`` is called."""
    mw, app = make()
    send = Sender()
    await mw(scope(headers=headers, body_len=10), never_receive(), send)
    assert send.status == 401
    assert send.body == b"", "contract §3: 401 carries no body detail"
    assert send.header(b"www-authenticate") == b"Bearer"
    assert app.calls == []


async def test_good_token_reaches_the_app():
    mw, app = make()
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    send = Sender()
    await mw(scope(body_len=len(payload)), body_receive(payload), send)
    assert send.status == 200
    assert app.bodies == [payload]


async def test_bearer_scheme_is_case_insensitive():
    """RFC 7235: the auth scheme is case-insensitive; the credential is not."""
    mw, app = make()
    payload = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    send = Sender()
    await mw(
        scope(headers=[(b"authorization", b"bEaReR " + TOKEN.encode())], body_len=len(payload)),
        body_receive(payload),
        send,
    )
    assert send.status == 200
    assert len(app.bodies) == 1


async def test_token_is_never_echoed_in_a_rejection():
    mw, _ = make()
    send = Sender()
    await mw(scope(headers=[(b"authorization", b"Bearer wrong")]), never_receive(), send)
    assert TOKEN.encode() not in send.body


# ---------------------------------------------------------------------------
# Routing and method
# ---------------------------------------------------------------------------

UNKNOWN_PATHS = ["/", "/mcp/", "/MCP", "/mcp/../mcp", "/.env", "/mcp?x=1", ""]
UNEXPECTED_METHODS = ["PUT", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", ""]


@pytest.mark.parametrize("path", UNKNOWN_PATHS)
async def test_unknown_paths_are_404_without_reading_the_body(path):
    mw, app = make()
    send = Sender()
    await mw(scope(path=path, body_len=99), never_receive(), send)
    assert send.status == 404
    assert app.calls == []


@pytest.mark.parametrize("method", UNEXPECTED_METHODS)
async def test_unexpected_methods_are_405_without_reading_the_body(method):
    mw, app = make()
    send = Sender()
    await mw(scope(method=method, body_len=99), never_receive(), send)
    assert send.status == 405
    assert send.header(b"allow") == b"POST, GET, DELETE"
    assert app.calls == []


@pytest.mark.parametrize("path", UNKNOWN_PATHS)
async def test_an_anonymous_peer_cannot_tell_a_missing_path_from_a_present_one(path):
    """404-before-401 would let an anonymous peer map this surface."""
    mw, app = make()
    unknown, present = Sender(), Sender()
    await mw(scope(path=path, headers=[]), never_receive(), unknown)
    await mw(scope(path="/mcp", headers=[]), never_receive(), present)
    assert unknown.status == 401
    assert unknown.status == present.status
    assert unknown.body == present.body == b""
    assert app.calls == []


@pytest.mark.parametrize("method", UNEXPECTED_METHODS)
async def test_an_anonymous_peer_cannot_tell_which_methods_are_accepted(method):
    """405-before-401 would advertise the accepted methods to anyone asking."""
    mw, app = make()
    rejected, accepted = Sender(), Sender()
    await mw(scope(method=method, headers=[]), never_receive(), rejected)
    await mw(scope(method="POST", headers=[]), never_receive(), accepted)
    assert rejected.status == 401
    assert rejected.status == accepted.status
    assert rejected.header(b"allow") is None, "the method list must not leak"
    assert app.calls == []


async def test_get_and_delete_pass_through_without_a_body_read():
    """The SSE stream and session teardown carry no body."""
    for method in ("GET", "DELETE"):
        mw, app = make()
        send = Sender()
        await mw(scope(method=method), never_receive(), send)
        assert send.status == 200
        assert len(app.calls) == 1


async def test_websocket_scope_is_refused():
    mw, app = make()
    send = Sender()
    await mw({"type": "websocket", "path": "/mcp", "headers": []}, never_receive(), send)
    assert send.messages == [{"type": "websocket.close", "code": 1008}]
    assert app.calls == []


async def test_lifespan_passes_straight_through():
    """The SDK's session manager runs in the app's lifespan; it must reach it."""
    mw, app = make()
    send = Sender()
    await mw({"type": "lifespan"}, never_receive(), send)
    assert len(app.calls) == 1


# ---------------------------------------------------------------------------
# Framing and volume
# ---------------------------------------------------------------------------

async def test_oversized_content_length_is_413_without_reading_the_body():
    mw, app = make(max_body_bytes=1024)
    send = Sender()
    await mw(scope(body_len=1024 * 1024), never_receive(), send)
    assert send.status == 413
    assert app.calls == []


@pytest.mark.parametrize("value", [b"abc", b"", b"-1", b"1e6", b"12 34", b"\xff"])
async def test_unparseable_or_negative_content_length_is_rejected(value):
    mw, app = make()
    send = Sender()
    await mw(
        scope(headers=[AUTH, (b"content-length", value)]),
        never_receive(),
        send,
    )
    assert send.status in {400, 413}
    assert app.calls == []


async def test_oversized_streamed_body_aborts_the_drain():
    """No Content-Length: the bound is enforced while reading, not after."""
    mw, app = make(max_body_bytes=100)
    send = Sender()
    await mw(scope(), body_receive(b"x" * 60, b"x" * 60, b"x" * 60), send)
    assert send.status == 413
    assert app.calls == []


async def test_slow_loris_partial_send_times_out():
    mw, app = make(body_read_timeout=0.05)
    send = Sender()
    await mw(scope(), stalling_receive(), send)
    assert send.status == 408
    assert app.calls == []


async def test_client_vanishing_mid_body_produces_no_response():
    """Nothing to answer, and nothing raised."""
    mw, app = make()

    async def _receive():
        return {"type": "http.disconnect"}

    send = Sender()
    await mw(scope(), _receive, send)
    assert send.messages == []
    assert app.calls == []


async def test_concurrency_cap_answers_503():
    mw, app = make(max_concurrent=1)
    released = asyncio.Event()

    class Blocking(RecordingApp):
        async def __call__(self, scope, receive, send):
            self.calls.append(scope)
            await released.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    blocking = Blocking()
    mw, _ = make(blocking, max_concurrent=1)

    first = asyncio.create_task(mw(scope(method="GET"), never_receive(), Sender()))
    await asyncio.sleep(0.02)
    second = Sender()
    await mw(scope(method="GET"), never_receive(), second)
    assert second.status == 503
    assert mw.in_flight == 1

    released.set()
    await first
    assert mw.in_flight == 0
    assert app.calls == []


async def test_an_unauthenticated_request_gets_401_even_when_the_cap_is_full():
    """Identity before the cap: a flood must not deny the core its slot."""
    released = asyncio.Event()

    class Blocking:
        async def __call__(self, scope, receive, send):
            await released.wait()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    mw = Hardening(Blocking(), token=TOKEN, max_concurrent=1)
    first = asyncio.create_task(mw(scope(method="GET"), never_receive(), Sender()))
    await asyncio.sleep(0.02)

    anonymous = Sender()
    await mw(scope(method="GET", headers=[]), never_receive(), anonymous)
    assert anonymous.status == 401, "503 would leak how busy this machine is"

    released.set()
    await first


async def test_in_flight_returns_to_zero_even_when_the_app_raises():
    """A failure inside the SDK must not permanently consume a cap slot."""

    class Exploding:
        async def __call__(self, scope, receive, send):
            msg = "boom"
            raise RuntimeError(msg)

    mw = Hardening(Exploding(), token=TOKEN)
    with pytest.raises(RuntimeError):
        await mw(scope(method="GET"), never_receive(), Sender())
    assert mw.in_flight == 0


async def test_rejections_are_counted_and_rate_limited(caplog):
    mw, _ = make()
    with caplog.at_level("WARNING", logger="workstation_agent.network_mcp.hardening"):
        for _ in range(60):
            await mw(scope(headers=[]), never_receive(), Sender())
    assert mw.rejections == 60
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 2, "first, then every 50th — never one line per hostile packet"


async def test_every_rejection_closes_the_connection():
    """A refused peer does not keep a keep-alive slot against the cap."""
    for headers, expected in [([], 401), ([AUTH, AUTH], 401)]:
        mw, _ = make()
        send = Sender()
        await mw(scope(headers=headers), never_receive(), send)
        assert send.status == expected
        assert send.header(b"connection") == b"close"


# ---------------------------------------------------------------------------
# Session cap. Replaces the SDK's `max_sessions`, which exists only on 2.2's
# streamable_http_app signature while the core runs 2.1.1.
# ---------------------------------------------------------------------------


class SessionIssuingApp:
    """Mimics the SDK: issues an Mcp-Session-Id on a POST that has none."""

    def __init__(self) -> None:
        self.calls = 0
        self.issued: list[bytes] = []
        self.status = 200

    async def __call__(self, scope, receive, send):
        self.calls += 1
        headers = []
        if scope["method"] == "POST" and not any(
            k == b"mcp-session-id" for k, _ in scope["headers"]
        ):
            sid = f"session-{len(self.issued)}".encode()
            self.issued.append(sid)
            headers.append((b"mcp-session-id", sid))
        await send({"type": "http.response.start", "status": self.status,
                    "headers": headers})
        await send({"type": "http.response.body", "body": b""})


def session_scope(sid: bytes | None = None, method: str = "POST") -> dict:
    headers: list[tuple[bytes, bytes]] = [AUTH]
    if sid is not None:
        headers.append((b"mcp-session-id", sid))
    return scope(method=method, headers=headers)


async def creating_request(mw) -> int | None:
    send = Sender()
    await mw(session_scope(), body_receive(b'{"jsonrpc":"2.0","id":1,"method":"x"}'), send)
    return send.status


async def test_sessions_are_counted_as_the_sdk_issues_them():
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=3)
    assert mw.live_sessions == 0
    for expected in (1, 2, 3):
        assert await creating_request(mw) == 200
        assert mw.live_sessions == expected


async def test_the_session_cap_refuses_a_further_creation():
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=2)
    await creating_request(mw)
    await creating_request(mw)
    before = app.calls
    assert await creating_request(mw) == 503
    assert app.calls == before, "the SDK must not allocate a transport we refused"


async def test_a_request_on_an_existing_session_is_never_refused_by_the_cap():
    """The cap bounds creation, not use; a full endpoint still serves its peer."""
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=1)
    await creating_request(mw)
    sid = app.issued[0]
    for method in ("POST", "GET"):
        send = Sender()
        await mw(session_scope(sid, method), body_receive(b'{"a":1}'), send)
        assert send.status == 200
    assert mw.live_sessions == 1


async def test_an_accepted_delete_frees_the_slot():
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=1)
    await creating_request(mw)
    sid = app.issued[0]
    assert await creating_request(mw) == 503

    send = Sender()
    await mw(session_scope(sid, "DELETE"), never_receive(), send)
    assert send.status == 200
    assert mw.live_sessions == 0
    assert await creating_request(mw) == 200


async def test_a_refused_delete_does_not_free_the_slot():
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=1)
    await creating_request(mw)
    sid = app.issued[0]
    app.status = 404
    await mw(session_scope(sid, "DELETE"), never_receive(), Sender())
    assert mw.live_sessions == 1


async def test_an_idle_session_stops_counting():
    """Without expiry the cap would turn a leak into an outage.

    A peer that reconnects without sending DELETE — which is what happens every
    time the core restarts — would otherwise leak a slot per restart, and after
    `max_sessions` restarts the endpoint would refuse the core outright.
    """
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=1, session_idle_timeout=0.05)
    assert await creating_request(mw) == 200
    assert await creating_request(mw) == 503
    await asyncio.sleep(0.08)
    assert mw.live_sessions == 0
    assert await creating_request(mw) == 200


async def test_activity_keeps_a_session_alive():
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=4, session_idle_timeout=0.15)
    await creating_request(mw)
    sid = app.issued[0]
    for _ in range(4):
        await asyncio.sleep(0.05)
        await mw(session_scope(sid, "GET"), never_receive(), Sender())
    assert mw.live_sessions == 1, "an actively used session must not be reaped"


async def test_an_unknown_session_id_is_passed_through_for_the_sdk_to_judge():
    """Whether a session id is valid is the SDK's call, not the gate's."""
    app = SessionIssuingApp()
    app.status = 404
    mw = Hardening(app, token=TOKEN, max_sessions=1)
    send = Sender()
    await mw(session_scope(b"never-issued", "GET"), never_receive(), send)
    assert app.calls == 1
    assert send.status == 404
    assert mw.live_sessions == 0


async def test_the_session_cap_never_blocks_an_unauthenticated_401():
    """Identity still comes first; a full session table is not a 503 to anyone."""
    app = SessionIssuingApp()
    mw = Hardening(app, token=TOKEN, max_sessions=1)
    await creating_request(mw)
    send = Sender()
    await mw(scope(headers=[]), never_receive(), send)
    assert send.status == 401


# ---------------------------------------------------------------------------
# Encoding and structure: validate_json_body, over the whole input space
# ---------------------------------------------------------------------------

CLEAN_BODIES = [
    pytest.param(b'{"jsonrpc":"2.0","id":1,"method":"ping"}', id="request"),
    pytest.param(b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', id="batch"),
    pytest.param(b'{"a":"\\ud83d\\ude00"}', id="astral-char-as-a-valid-surrogate-pair"),
    pytest.param('{"a":"café ü 中"}'.encode(), id="non-ascii-utf8-strings"),
    pytest.param(b'  {"a":1}  ', id="surrounding-whitespace"),
    pytest.param(b'{"a":"' + b"x" * 100_000 + b'"}', id="one-very-large-string"),
    pytest.param(
        json.dumps({"deep": {"a": [{"b": [{"c": 1}]}]}}).encode(),
        id="ordinary-nesting",
    ),
]

DIRTY_BODIES = [
    pytest.param(b"", "empty request body", id="empty"),
    pytest.param(b"   \n\t ", "empty request body", id="whitespace-only"),
    # Invalid UTF-8 *on the wire*, as distinct from an escape inside a string.
    pytest.param(b"\xff\xfe\xfd", "not valid UTF-8", id="invalid-utf8-bom-ish"),
    pytest.param(b'{"a":"\xc3"}', "not valid UTF-8", id="truncated-utf8-sequence"),
    pytest.param(b'{"a":"\xed\xa0\x80"}', "not valid UTF-8", id="raw-surrogate-bytes"),
    # B0 crash class 2: json.loads accepts this happily; .encode() would raise.
    pytest.param(b'{"a":"\\ud800"}', "unpaired surrogate", id="lone-high-surrogate"),
    pytest.param(b'{"a":"\\udfff"}', "unpaired surrogate", id="lone-low-surrogate"),
    pytest.param(b'{"a":"\\uD800\\uD800"}', "unpaired surrogate", id="two-high-surrogates"),
    pytest.param(b'{"\\ud800":1}', "unpaired surrogate", id="surrogate-in-a-key"),
    pytest.param(
        b'{"a":[[["\\udccc"]]]}', "unpaired surrogate", id="surrogate-nested-in-arrays",
    ),
    # B0 crash class 4: RecursionError, which JSONDecodeError does not cover.
    pytest.param(b"[" * 200 + b"]" * 200, "nests deeper", id="deep-arrays"),
    pytest.param(b"{" * 5000, "nests deeper", id="deep-unclosed-objects"),
    pytest.param(
        b'{"a":' * 100_000 + b"1" + b"}" * 100_000, "nests deeper", id="very-deep-objects",
    ),
    pytest.param(b"not json at all", "not valid JSON", id="plain-text"),
    pytest.param(b'{"a":1', "not valid JSON", id="truncated-object"),
    pytest.param(b'{"a" 1}', "not valid JSON", id="no-separator"),
    pytest.param(b"{}{}", "not valid JSON", id="two-documents"),
    pytest.param(b'"just a string"', "not a JSON-RPC message", id="bare-string"),
    pytest.param(b"12345", "not a JSON-RPC message", id="bare-number"),
    pytest.param(b"null", "not a JSON-RPC message", id="bare-null"),
    pytest.param(b"true", "not a JSON-RPC message", id="bare-bool"),
]


@pytest.mark.parametrize("raw", CLEAN_BODIES)
def test_valid_bodies_are_accepted(raw):
    assert validate_json_body(raw) is None


@pytest.mark.parametrize(("raw", "expected"), DIRTY_BODIES)
def test_hostile_bodies_are_rejected_with_a_reason(raw, expected):
    problem = validate_json_body(raw)
    assert problem is not None, "hostile body was accepted"
    assert expected in problem


@pytest.mark.parametrize(("raw", "_expected"), DIRTY_BODIES)
async def test_hostile_bodies_are_400_over_asgi_and_never_reach_the_app(raw, _expected):
    mw, app = make()
    send = Sender()
    await mw(scope(), body_receive(raw), send)
    assert send.status == 400
    assert app.calls == []


@pytest.mark.parametrize(("raw", "_expected"), DIRTY_BODIES)
def test_validate_json_body_never_raises(raw, _expected):
    """The whole point: every input returns, nothing propagates."""
    assert isinstance(validate_json_body(raw), (str, type(None)))


def test_depth_limit_is_enforced_exactly():
    at_limit = ("[" * DEFAULT_MAX_JSON_DEPTH + "]" * DEFAULT_MAX_JSON_DEPTH).encode()
    over = ("[" * (DEFAULT_MAX_JSON_DEPTH + 1) + "]" * (DEFAULT_MAX_JSON_DEPTH + 1)).encode()
    assert validate_json_body(at_limit) is None
    assert "nests deeper" in (validate_json_body(over) or "")


def test_brackets_inside_strings_do_not_count_toward_depth():
    raw = json.dumps({"a": "[" * 500 + "{" * 500}).encode()
    assert validate_json_body(raw) is None


def test_escaped_quotes_inside_strings_do_not_confuse_the_scanner():
    raw = json.dumps({"a": '\\" [[[[' * 40}).encode()
    assert validate_json_body(raw) is None


def test_deep_nesting_would_have_crashed_a_recursive_parser():
    """Proof the guard is load-bearing: json.loads itself blows up on this."""
    raw = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(RecursionError):
        json.loads(raw.decode())
    assert "nests deeper" in (validate_json_body(raw) or "")


def test_unpaired_surrogate_would_have_crashed_an_encode():
    """Proof the guard is load-bearing: this is exactly B0's crash class 2."""
    raw = b'{"a":"\\ud800"}'
    parsed = json.loads(raw.decode())
    with pytest.raises(UnicodeEncodeError):
        parsed["a"].encode("utf-8")
    assert "unpaired surrogate" in (validate_json_body(raw) or "")


async def test_a_rejected_request_leaves_the_middleware_usable():
    """The server is unharmed: a good request works right after a hostile one."""
    mw, app = make()
    for param in DIRTY_BODIES:
        raw = param.values[0]
        assert isinstance(raw, bytes)
        await mw(scope(), body_receive(raw), Sender())
    good = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    send = Sender()
    await mw(scope(), body_receive(good), send)
    assert send.status == 200
    assert app.bodies == [good]
    assert mw.in_flight == 0


async def test_body_streamed_in_many_chunks_is_reassembled_for_the_app():
    mw, app = make()
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
    pieces = [payload[i:i + 3] for i in range(0, len(payload), 3)]
    send = Sender()
    await mw(scope(), body_receive(*pieces), send)
    assert send.status == 200
    assert app.bodies == [payload]


async def test_the_app_sees_disconnect_after_the_replayed_body():
    """The replay must not swallow later ASGI events."""
    seen: list[str] = []

    class Watcher:
        async def __call__(self, scope, receive, send):
            seen.append((await receive())["type"])
            seen.append((await receive())["type"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    mw = Hardening(Watcher(), token=TOKEN)
    await mw(scope(), body_receive(b'{"a":1}'), Sender())
    assert seen == ["http.request", "http.disconnect"]
