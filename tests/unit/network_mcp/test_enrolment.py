"""The one route on this endpoint that is not behind the bearer token.

``POST /enrol/token`` receives the token PersonaCore mints during enrolment
(``network_mcp/enrolment.py``, step 3 of the handshake). Adding an
unauthenticated route to an endpoint whose entire design was "answer 401 from
the ASGI scope and never read the body" is a real change of posture, so this
file is organised around the properties that make it safe rather than around
the happy path:

* **Reachable only during a Join.** With no window open the route must behave as
  though it does not exist.
* **Uniform refusal.** A wrong code, no Join, an expired window, a used code and
  every shape of hostile body must be *indistinguishable* — same status, same
  headers, same body, and the body read either way so the timing does not
  disclose what the response refuses to.
* **Constant-time comparison on bytes.** The class of bug that bit this
  repository three times (commit ``844a96b``) is enumerated here as a matrix,
  not remembered case by case.
* **Single use, bounded, rate-limited.**
* **The existing gate is untouched.** ``/mcp`` still refuses an unauthenticated
  caller while a Join is pending.
"""
# ruff: noqa: ANN204, ARG002
# The fakes implement the ASGI callable signature, which is structural: unused
# parameters and an untyped __call__ are the shape being imitated.

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest

from workstation_agent.network_mcp.credentials import ensure_token, store_token
from workstation_agent.network_mcp.enrolment import (
    DEFAULT_JOIN_TTL,
    ENROL_PATH,
    MAX_CODE_CHARS,
    MAX_JOIN_TTL,
    EnrolmentError,
    EnrolmentReceiver,
)
from workstation_agent.network_mcp.hardening import (
    ENROL_MAX_ATTEMPTS,
    ENROL_MAX_BODY_BYTES,
    ENROL_SUCCESS_STATUS,
    Hardening,
)

TOKEN = "a" * 64
AUTH = (b"authorization", b"Bearer " + TOKEN.encode())
CODE = "PAIR-4417"
PUSHED = "b" * 48


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class RecordingApp:
    """The wrapped ASGI app. Records what got through and echoes 200."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope)
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

    @property
    def signature(self) -> tuple:
        """Everything a caller can observe, normalised for comparison.

        Header *order* is not something a caller can rely on across HTTP
        implementations, so it is sorted out of the comparison; everything else
        — status, header set, body bytes — is compared exactly.
        """
        headers: list[tuple[bytes, bytes]] = []
        for m in self.messages:
            if m["type"] == "http.response.start":
                headers = sorted(m["headers"])
        return (self.status, tuple(headers), self.body)


class Applier:
    """Stands in for ``NetworkMCPServer._accept_pushed_token``."""

    def __init__(self, *, succeed: bool = True) -> None:
        self.tokens: list[str] = []
        self.succeed = succeed

    def __call__(self, token: str) -> bool:
        self.tokens.append(token)
        return self.succeed


class FakeClock:
    """A monotonic clock a test can move, so expiry needs no sleeping."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------------------
# Scope / receive helpers
# ---------------------------------------------------------------------------


def scope(
    *,
    method: str = "POST",
    path: str = ENROL_PATH,
    headers: list[tuple[bytes, bytes]] | None = None,
    body_len: int | None = None,
    scheme: str = "https",
) -> dict:
    hdrs: list[tuple[bytes, bytes]] = list(headers) if headers is not None else []
    if body_len is not None:
        hdrs.append((b"content-length", str(body_len).encode()))
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": hdrs,
        "client": ("192.168.1.9", 55000),
        "scheme": scheme,
    }


class Receiver:
    """A ``receive`` that yields one body and records that it was called."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.reads = 0

    async def __call__(self):
        self.reads += 1
        if self.reads == 1:
            return {"type": "http.request", "body": self.body, "more_body": False}
        return {"type": "http.disconnect"}


def never_receive():
    """A ``receive`` that must never be called."""

    async def _receive():
        pytest.fail("the body was read for a request that should have been refused first")

    return _receive


def push_body(code=CODE, token=PUSHED) -> bytes:
    return json.dumps({"code": code, "token": token}).encode()


def make(*, join: str | None = CODE, clock=None, applier=None, ttl=DEFAULT_JOIN_TTL):
    """A middleware with an enrolment receiver, optionally mid-Join."""
    applier = applier or Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=clock or FakeClock())
    if join is not None:
        receiver.open_join(join, ttl_seconds=ttl)
    app = RecordingApp()
    return Hardening(app, token=TOKEN, enrolment=receiver), receiver, applier, app


async def post(mw, body: bytes, **scope_kwargs) -> tuple[Sender, Receiver]:
    send, receive = Sender(), Receiver(body)
    await mw(scope(body_len=len(body), **scope_kwargs), receive, send)
    return send, receive


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


async def test_a_correct_code_enrols_and_the_pushed_token_takes_effect():
    mw, receiver, applier, app = make()

    send, _ = await post(mw, push_body())

    assert send.status == ENROL_SUCCESS_STATUS, "the core reads only the status; 204 is the answer"
    assert send.body == b"", "204 carries no content"
    assert not any(
        k == b"content-length" for m in send.messages
        if m["type"] == "http.response.start" for k, _ in m["headers"]
    ), "RFC 9110 forbids Content-Length on a 204, and h11 enforces it"
    assert applier.tokens == [PUSHED]
    assert receiver.status() is None, "a completed enrolment closes the Join"
    assert app.calls == [], "the push is answered here; it never reaches the MCP app"


async def test_the_pushed_token_becomes_the_bearer_the_endpoint_requires():
    """Not merely stored: in force for the very next request."""
    applier = Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join(CODE)
    app = RecordingApp()
    mw = Hardening(app, token=TOKEN, enrolment=receiver)

    send, _ = await post(mw, push_body())
    assert send.status == ENROL_SUCCESS_STATUS

    # The real applier is NetworkMCPServer._accept_pushed_token, which calls
    # set_token; here that step is performed explicitly so this test pins the
    # middleware half of it.
    mw.set_token(PUSHED)

    old = Sender()
    await mw(scope(path="/mcp", headers=[AUTH]), never_receive(), old)
    assert old.status == 401, "the token issued before enrolment no longer works"

    new = Sender()
    payload = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    await mw(
        scope(path="/mcp", headers=[(b"authorization", b"Bearer " + PUSHED.encode())],
              body_len=len(payload)),
        Receiver(payload),
        new,
    )
    assert new.status == 200
    assert len(app.calls) == 1


async def test_a_code_with_surrounding_whitespace_still_matches():
    """The owner pastes; the core may not trim. Neither side's spaces matter."""
    mw, _receiver, applier, _app = make(join="  PAIR-4417  ")
    send, _ = await post(mw, push_body(code="PAIR-4417\n"))
    assert send.status == ENROL_SUCCESS_STATUS
    assert applier.tokens == [PUSHED]


# ---------------------------------------------------------------------------
# Uniform refusal — the property the whole subtask turns on
# ---------------------------------------------------------------------------


def _hostile_bodies() -> list:
    return [
        pytest.param(json.dumps({"code": "WRONG-9999", "token": PUSHED}).encode(),
                     id="wrong-code"),
        pytest.param(json.dumps({"code": CODE[:-1], "token": PUSHED}).encode(),
                     id="code-one-character-short"),
        pytest.param(json.dumps({"code": CODE + "x", "token": PUSHED}).encode(),
                     id="code-one-character-long"),
        # compare_digest raises TypeError on non-ASCII *str*; here the code never
        # becomes anything but bytes.
        pytest.param(json.dumps({"code": "PAIR-éèêöü", "token": PUSHED}).encode(),
                     id="non-ascii-code"),
        # json.loads accepts this happily; .encode("utf-8") on it raises.
        pytest.param(b'{"code": "PAIR-\\ud800AAAA", "token": "' + PUSHED.encode() + b'"}',
                     id="unpaired-high-surrogate-in-code"),
        pytest.param(b'{"code": "PAIR-\\udc00AAAA", "token": "' + PUSHED.encode() + b'"}',
                     id="unpaired-low-surrogate-in-code"),
        pytest.param(b'{"code": "' + CODE.encode() + b'", "token": "\\ud800bbbbbbbbbbbbbbbb"}',
                     id="unpaired-surrogate-in-token"),
        pytest.param(json.dumps({"code": CODE, "token": "tok en" + "b" * 40}).encode(),
                     id="token-containing-a-space"),
        pytest.param(json.dumps({"code": CODE, "token": "tök" + "b" * 40}).encode(),
                     id="non-ascii-token"),
        pytest.param(json.dumps({"code": CODE, "token": "b" * 4}).encode(),
                     id="token-too-short"),
        pytest.param(json.dumps({"code": CODE, "token": "b" * 5000}).encode(),
                     id="token-too-long"),
        pytest.param(json.dumps({"code": CODE}).encode(), id="missing-token"),
        pytest.param(json.dumps({"token": PUSHED}).encode(), id="missing-code"),
        pytest.param(json.dumps({"code": 4417, "token": PUSHED}).encode(),
                     id="code-is-a-number"),
        pytest.param(json.dumps({"code": None, "token": None}).encode(), id="both-null"),
        pytest.param(json.dumps({"code": [CODE], "token": PUSHED}).encode(),
                     id="code-is-a-list"),
        pytest.param(json.dumps({"code": {"v": CODE}, "token": PUSHED}).encode(),
                     id="code-is-an-object"),
        pytest.param(json.dumps([CODE, PUSHED]).encode(), id="body-is-an-array"),
        pytest.param(b'"' + CODE.encode() + b'"', id="body-is-a-bare-string"),
        pytest.param(b"", id="empty-body"),
        pytest.param(b"   ", id="whitespace-only-body"),
        pytest.param(b'{"code": ', id="truncated-json"),
        pytest.param(b"{'code': 'x'}", id="not-json-at-all"),
        pytest.param(b"\xff\xfe\x00\x80", id="invalid-utf8-on-the-wire"),
        pytest.param(b"[" * 200 + b"]" * 200, id="deeply-nested-json"),
    ]


#: Refused by the *byte bound* rather than by the receiver, so it belongs only
#: to the tests that go through the middleware. The fields are otherwise
#: perfectly valid, which is the point: the bound is what stops it.
_OVERSIZED = pytest.param(
    json.dumps({"code": CODE, "token": PUSHED, "pad": "x" * (ENROL_MAX_BODY_BYTES * 2)}).encode(),
    id="body-past-the-bound",
)


def _hostile_wire_bodies() -> list:
    return [*_hostile_bodies(), _OVERSIZED]


async def _refusal_signature(body: bytes, *, join: str | None) -> tuple:
    mw, _receiver, applier, app = make(join=join)
    send, _ = await post(mw, body)
    assert applier.tokens == [], "a refused push must never reach the token applier"
    assert app.calls == [], "a refused push must never reach the MCP app"
    return send.signature


async def _bearerless_signature() -> tuple:
    """What a stranger gets for an ordinary path with no token: the baseline."""
    mw, _receiver, _applier, _app = make()
    send = Sender()
    await mw(scope(path="/some/other/path", method="GET"), never_receive(), send)
    return send.signature


@pytest.mark.parametrize("body", _hostile_wire_bodies())
async def test_every_hostile_body_is_refused_identically(body):
    baseline = await _bearerless_signature()
    assert await _refusal_signature(body, join=CODE) == baseline


@pytest.mark.parametrize("body", _hostile_wire_bodies())
async def test_hostile_bodies_are_refused_identically_with_no_join_pending(body):
    """The same answer whether or not the owner is mid-enrolment."""
    baseline = await _bearerless_signature()
    assert await _refusal_signature(body, join=None) == baseline


async def test_no_join_pending_is_indistinguishable_from_a_wrong_code():
    """The contract's explicit requirement, asserted directly."""
    correct = await _refusal_signature(push_body(), join=None)
    wrong = await _refusal_signature(push_body(code="WRONG-9999"), join=CODE)
    assert correct == wrong == await _bearerless_signature()


# ---------------------------------------------------------------------------
# What the response cannot say, the *work* must not say either
#
# These are deliberately not wall-clock measurements. A timing assertion on a
# loaded CI box flakes, and a flaky test gets deleted, which is worse than no
# test. They assert the two structural facts a timing difference would have to
# come from: that the comparison runs on every path, and that its operands are
# always the same width.
# ---------------------------------------------------------------------------


@pytest.fixture
def comparisons(monkeypatch):
    """Record every ``compare_digest`` the receiver performs, with operand sizes."""
    import workstation_agent.network_mcp.enrolment as mod

    seen: list[tuple[int, int]] = []
    real = mod.secrets.compare_digest

    def _spy(a, b):
        seen.append((len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(mod.secrets, "compare_digest", _spy)
    return seen


TIMING_PROBES = [
    pytest.param(push_body(code="WRONG-4417"), id="wrong-code-the-same-length"),
    pytest.param(push_body(code="W" * MAX_CODE_CHARS), id="wrong-code-far-longer"),
    pytest.param(push_body(code="WRONG-" + "x" * 60), id="wrong-code-a-third-length"),
    pytest.param(b"not json at all", id="malformed-body"),
    pytest.param(b"", id="empty-body"),
    pytest.param(json.dumps({"nope": 1}).encode(), id="missing-both-fields"),
]


@pytest.mark.parametrize("body", TIMING_PROBES)
@pytest.mark.parametrize("join", [CODE, None], ids=["join-pending", "no-join"])
async def test_the_comparison_runs_on_every_path_over_fixed_width_operands(
    body, join, comparisons,
):
    """The two structural facts behind uniform timing.

    ``compare_digest`` is constant-time *only* for equal-length operands —
    Python says so outright — so comparing a submitted code against a raw
    pairing code leaks the code's length, and against a differently-sized decoy
    leaks whether a Join exists at all. And an early return for a body that
    would not parse refuses it faster than a wrong code, which is the same
    disclosure through the cheapest probe there is.
    """
    mw, _receiver, _applier, _app = make(join=join)

    send, _ = await post(mw, body)

    assert send.signature == await _bearerless_signature()
    assert len(comparisons) == 1, (
        "exactly one comparison per push, on every path, whatever the body was "
        "and whether or not a Join is pending"
    )
    assert comparisons[0] == (32, 32), (
        "both operands are SHA-256 digests, so neither the length of the "
        "owner's code nor the existence of a Join is observable in the "
        "comparison"
    )


async def test_a_correct_push_compares_over_the_same_fixed_width(comparisons):
    """The success path is not a special case: same one comparison, same width."""
    mw, _receiver, _applier, _app = make()
    send, _ = await post(mw, push_body())
    assert send.status == ENROL_SUCCESS_STATUS
    assert comparisons == [(32, 32)]


async def test_the_pairing_code_itself_is_not_kept_in_memory():
    """A digest is compared, so the plaintext need not outlive ``open_join``."""
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    receiver.open_join(CODE)
    pending = receiver._pending
    assert pending is not None
    assert CODE.encode() not in pending.code_digest
    assert len(pending.code_digest) == 32
    assert not hasattr(pending, "code")


async def test_two_concurrent_correct_pushes_enrol_exactly_once():
    """Single use has to survive concurrency, not only sequence.

    ``ENROL_MAX_CONCURRENT`` is 2, so two pushes really can be in flight at
    once. Read, compare, apply and clear must be indivisible or both see the
    same live Join and a spent code is accepted twice.
    """
    mw, receiver, applier, _app = make()

    first, second = await asyncio.gather(
        post(mw, push_body()),
        post(mw, push_body()),
    )

    statuses = [first[0].status, second[0].status]
    assert statuses.count(ENROL_SUCCESS_STATUS) == 1, "exactly one push enrolled"
    assert statuses.count(401) == 1, "and the other was refused like anything else"
    assert first[0].signature != second[0].signature
    assert applier.tokens == [PUSHED], "the token was installed once, not twice"
    assert receiver.status() is None


async def test_many_concurrent_correct_pushes_enrol_exactly_once():
    """The same property under more pressure than the cap actually allows."""
    applier = Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join(CODE)

    results = await asyncio.gather(*(receiver.redeem(push_body()) for _ in range(20)))

    assert results.count(True) == 1
    assert applier.tokens == [PUSHED]
    assert receiver.status() is None


async def test_redemption_is_mutually_exclusive_not_merely_uninterrupted():
    """Why the two tests above are not the whole story.

    ``_apply_token`` is synchronous today, so read-compare-apply-clear happens
    between two await points and asyncio serialises it whether or not anything
    asks it to. Those tests would therefore pass with no lock at all — they pin
    the outcome, not the reason for it, and the reason is one edit away from
    changing: the first time the token store becomes awaitable, "uninterrupted"
    stops following from "synchronous" and a spent code is accepted twice.

    So this asserts the exclusion directly: while the critical section is held,
    a second redemption waits rather than proceeding.
    """
    applier = Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join(CODE)

    await receiver._lock.acquire()
    waiting = asyncio.create_task(receiver.redeem(push_body()))
    try:
        await asyncio.sleep(0)
        assert not waiting.done(), "a redemption does not proceed while one is in flight"
        assert applier.tokens == [], "and it has not applied anything either"
    finally:
        receiver._lock.release()

    assert await waiting is True
    assert applier.tokens == [PUSHED]


async def test_no_join_pending_still_reads_the_body():
    """Refusing early with no Join would make the *timing* the disclosure."""
    mw, _receiver, _applier, _app = make(join=None)
    _send, receive = await post(mw, push_body())
    assert receive.reads >= 1, (
        "with no Join the body must still be read, or a prober learns from how "
        "fast it was refused that the owner is mid-enrolment"
    )


async def test_an_expired_window_is_refused_identically():
    clock = FakeClock()
    mw, receiver, applier, _app = make(clock=clock, ttl=60.0)
    clock.advance(60.1)

    send, _ = await post(mw, push_body())

    assert send.signature == await _bearerless_signature()
    assert applier.tokens == []
    assert receiver.status() is None


@pytest.mark.parametrize(
    "second",
    [
        pytest.param(push_body(), id="byte-identical-replay"),
        pytest.param(push_body(token="d" * 48), id="same-code-different-token"),
    ],
)
async def test_a_second_push_against_a_used_code_is_refused(second):
    """Single use, strictly. There is deliberately no idempotent replay: the
    core does not retry, a failed push fails the whole enrolment, and the owner
    issues a fresh code — so this endpoint carries no idempotency it does not
    need, and a spent code is refused like anything else."""
    mw, _receiver, applier, _app = make()

    first, _ = await post(mw, push_body())
    assert first.status == ENROL_SUCCESS_STATUS

    repeat, _ = await post(mw, second)
    assert repeat.signature == await _bearerless_signature()
    assert applier.tokens == [PUSHED], "the token applier ran once, not twice"


# ---------------------------------------------------------------------------
# Bounds: an unauthenticated route must not become a way to make us allocate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", ""])
async def test_only_post_is_answered_and_the_body_is_never_read(method):
    mw, _receiver, _applier, _app = make()
    send = Sender()
    await mw(scope(method=method, body_len=40), never_receive(), send)
    assert send.signature == await _bearerless_signature()


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([(b"origin", b"https://evil.example")], id="cross-origin"),
        pytest.param([(b"origin", b"null")], id="opaque-origin"),
        pytest.param([(b"origin", b"")], id="empty-origin"),
        pytest.param([(b"Origin", b"https://evil.example")], id="capitalised"),
        pytest.param(
            [(b"origin", b"https://a.example"), (b"origin", b"https://b.example")],
            id="duplicated-so-single-header-would-see-none",
        ),
    ],
)
async def test_a_push_carrying_an_origin_header_is_refused_unread(headers):
    """PersonaCore is an HTTP client and sends no Origin; a browser always does
    on a cross-origin POST. Refusing on presence removes the browser vector."""
    mw, _receiver, applier, _app = make()
    send = Sender()
    # Lower-cased as ASGI servers deliver them, plus one capitalised case to pin
    # that this does not accidentally depend on the server's normalisation.
    await mw(scope(headers=[(k.lower(), v) for k, v in headers]), never_receive(), send)
    assert send.signature == await _bearerless_signature()
    assert applier.tokens == []


@pytest.mark.parametrize(
    "declared",
    [
        pytest.param(str(ENROL_MAX_BODY_BYTES + 1).encode(), id="one-byte-over"),
        pytest.param(b"1048576", id="an-authenticated-sized-body"),
        pytest.param(b"-1", id="negative"),
        pytest.param(b"not-a-number", id="unparseable"),
        pytest.param(b"9" * 400, id="absurd"),
    ],
)
async def test_an_oversized_or_unparseable_content_length_is_refused_unread(declared):
    mw, _receiver, _applier, _app = make()
    send = Sender()
    await mw(
        scope(headers=[(b"content-length", declared)]),
        never_receive(),
        send,
    )
    assert send.signature == await _bearerless_signature()


async def test_a_body_that_overruns_the_bound_mid_stream_is_refused():
    """A lying Content-Length does not get to buy more memory than the bound."""
    mw, _receiver, applier, _app = make()
    chunks = [b"x" * 1024] * 8

    async def _receive():
        if chunks:
            return {"type": "http.request", "body": chunks.pop(0), "more_body": bool(chunks)}
        return {"type": "http.disconnect"}

    send = Sender()
    await mw(scope(body_len=10), _receive, send)
    assert send.signature == await _bearerless_signature()
    assert applier.tokens == []


async def test_a_stalled_push_is_refused_rather_than_held_open():
    mw, _receiver, _applier, _app = make()
    started = False

    async def _receive():
        nonlocal started
        if not started:
            started = True
            return {"type": "http.request", "body": b'{"code"', "more_body": True}
        await asyncio.sleep(3600)
        raise AssertionError  # pragma: no cover

    send = Sender()
    # The middleware's own 5s bound is what ends this; the outer timeout is only
    # so a regression fails the test rather than hanging the suite.
    async with asyncio.timeout(30):
        await mw(scope(body_len=40), _receive, send)
    assert send.signature == await _bearerless_signature()


async def test_a_peer_that_vanishes_mid_push_gets_no_response():
    mw, _receiver, _applier, _app = make()

    async def _receive():
        return {"type": "http.disconnect"}

    send = Sender()
    await mw(scope(body_len=40), _receive, send)
    assert send.messages == [], "there is nobody left to answer"


async def test_the_attempt_rate_is_bounded():
    mw, _receiver, applier, _app = make()
    wrong = push_body(code="WRONG-9999")

    reads = []
    for _ in range(ENROL_MAX_ATTEMPTS + 5):
        send, receive = await post(mw, wrong)
        assert send.signature == await _bearerless_signature()
        reads.append(receive.reads)

    assert sum(1 for r in reads if r == 0) >= 5, (
        "past the window's budget a push must be refused without its body "
        "being read at all"
    )
    assert applier.tokens == []


async def test_the_rate_limit_does_not_leak_whether_a_join_is_pending():
    """Refusals past the budget look like every other refusal."""
    baseline = await _bearerless_signature()
    for join in (CODE, None):
        mw, _receiver, _applier, _app = make(join=join)
        for _ in range(ENROL_MAX_ATTEMPTS + 3):
            send, _ = await post(mw, push_body(code="WRONG-9999"))
            assert send.signature == baseline


# ---------------------------------------------------------------------------
# The existing gate is untouched
# ---------------------------------------------------------------------------


async def test_mcp_still_returns_401_unauthenticated_while_a_join_is_pending():
    """The whole point: opening a Join opens the enrolment window, nothing else."""
    mw, receiver, _applier, app = make()
    assert receiver.status() is not None

    for headers in ([], [(b"authorization", b"Bearer " + b"b" * 64)], [(b"authorization", b"")]):
        send = Sender()
        await mw(scope(path="/mcp", headers=headers, body_len=40), never_receive(), send)
        assert send.status == 401
        assert send.body == b""
        assert app.calls == []


async def test_a_pending_join_does_not_open_any_other_path():
    mw, _receiver, _applier, app = make()
    for path in ("/", "/enrol", "/enrol/token/", "/enrol/tokens", "/mcp/enrol/token"):
        send = Sender()
        await mw(scope(path=path), never_receive(), send)
        assert send.signature == await _bearerless_signature()
        assert app.calls == []


async def test_an_enrolment_push_over_plaintext_is_refused_before_anything_is_read():
    """Transport first: the core pins this endpoint's certificate, so a push
    that did not come over TLS did not come from the core."""
    mw, _receiver, applier, _app = make()
    send = Sender()
    await mw(scope(scheme="http", body_len=40), never_receive(), send)
    assert send.status == 403
    assert applier.tokens == []


async def test_the_route_does_not_exist_when_no_receiver_is_mounted():
    app = RecordingApp()
    mw = Hardening(app, token=TOKEN)
    send = Sender()
    await mw(scope(), never_receive(), send)
    assert send.status == 401
    assert app.calls == []


async def test_an_authenticated_caller_cannot_use_the_route_to_swap_the_token():
    """Holding the current token is not authority to mint the next one."""
    mw, _receiver, applier, _app = make(join=CODE)
    send, _ = await post(mw, push_body(code="WRONG-9999"), headers=[AUTH])
    assert send.signature == await _bearerless_signature()
    assert applier.tokens == []


# ---------------------------------------------------------------------------
# The receiver on its own
# ---------------------------------------------------------------------------


def test_status_never_carries_the_code_or_a_token():
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    status = receiver.open_join(CODE)
    rendered = repr(status) + repr(receiver.status())
    assert CODE not in rendered
    assert not hasattr(status, "code")
    assert not hasattr(status, "token")


async def test_opening_a_join_replaces_the_previous_one():
    """A mistyped code retyped must not leave the first attempt live."""
    applier = Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join("FIRST-CODE")
    receiver.open_join("SECOND-CODE")

    assert await receiver.redeem(push_body(code="FIRST-CODE")) is False
    assert await receiver.redeem(push_body(code="SECOND-CODE")) is True


async def test_cancelling_closes_the_window():
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    receiver.open_join(CODE)
    receiver.cancel_join()
    assert receiver.status() is None
    assert await receiver.redeem(push_body()) is False
    receiver.cancel_join()  # idempotent


def test_status_expires_on_its_own_without_a_push():
    clock = FakeClock()
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=clock)
    receiver.open_join(CODE, ttl_seconds=30.0)
    assert receiver.status() is not None
    clock.advance(29.9)
    assert receiver.status() is not None
    clock.advance(0.2)
    assert receiver.status() is None


def test_the_default_window_outlasts_the_core_countdown():
    """The core's clock is the authoritative one: its code lives 300 seconds and
    it shows the owner a countdown against that. A window that closed first
    would refuse a code the console still called valid, with nothing on either
    screen to explain it. Ours is a backstop against a Join nobody completes."""
    core_code_ttl = 300.0
    core_connect_and_read = 15.0
    assert core_code_ttl + core_connect_and_read <= DEFAULT_JOIN_TTL


def test_the_window_length_is_clamped():
    clock = FakeClock()
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=clock)
    status = receiver.open_join(CODE, ttl_seconds=10_000_000.0)
    assert status.expires_in == MAX_JOIN_TTL


async def test_attempts_are_counted_for_the_owner_to_see():
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    receiver.open_join(CODE)
    for _ in range(3):
        await receiver.redeem(push_body(code="WRONG-9999"))
    status = receiver.status()
    assert status is not None
    assert status.attempts == 3


async def test_a_failure_to_store_the_token_refuses_and_keeps_the_join_open():
    """The core persists only after a success, so a success we cannot keep is
    worse than a refusal."""
    applier = Applier(succeed=False)
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join(CODE)

    assert await receiver.redeem(push_body()) is False
    assert receiver.status() is not None, "the owner can have the core push again"

    applier.succeed = True
    assert await receiver.redeem(push_body()) is True


@pytest.mark.parametrize(
    "code",
    [
        pytest.param("", id="empty"),
        pytest.param("   ", id="whitespace-only"),
        pytest.param("12345", id="one-character-under-the-floor"),
        pytest.param("x" * 200, id="past-the-ceiling"),
        pytest.param("PAIR-\ud800", id="unpaired-surrogate"),
    ],
)
def test_a_code_that_cannot_secure_a_window_is_refused_with_a_message(code):
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    with pytest.raises(EnrolmentError) as excinfo:
        receiver.open_join(code)
    assert str(excinfo.value)
    assert receiver.status() is None, "a refused Join must not leave a window open"


async def test_redeem_never_raises_for_any_input():
    """Nothing a stranger can put in a body may escape as an exception."""
    receiver = EnrolmentReceiver(apply_token=Applier(), clock=FakeClock())
    receiver.open_join(CODE)
    for case in _hostile_bodies():
        assert await receiver.redeem(case.values[0]) is False


# ---------------------------------------------------------------------------
# Persistence: the token has to survive a restart (contract §11 item 8)
# ---------------------------------------------------------------------------


def test_a_stored_token_is_what_the_next_start_reads_back(tmp_path):
    ensure_token(tmp_path)  # first-run generation
    store_token(PUSHED, tmp_path)
    assert ensure_token(tmp_path) == PUSHED


def test_storing_leaves_no_temporary_file_behind(tmp_path):
    store_token(PUSHED, tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["token"]


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("", id="empty"),
        pytest.param("tök" + "b" * 40, id="non-ascii"),
        pytest.param("tok en" + "b" * 40, id="contains-a-space"),
        pytest.param("tok\x00" + "b" * 40, id="contains-a-nul"),
        pytest.param("tok\n" + "b" * 40, id="contains-a-newline"),
    ],
)
def test_a_token_that_cannot_round_trip_through_the_file_is_refused(tmp_path, token):
    with pytest.raises(ValueError, match="printable ASCII"):
        store_token(token, tmp_path)
    assert not (tmp_path / "token").exists()


async def test_a_push_carrying_extra_fields_is_still_accepted():
    """Forward compatibility, stated as a decision rather than left to chance:
    the core may add fields to this body later, and an Agent that refused them
    would be an Agent that stops enrolling on a core upgrade."""
    applier = Applier()
    receiver = EnrolmentReceiver(apply_token=applier, clock=FakeClock())
    receiver.open_join(CODE)
    body = json.dumps({"code": CODE, "token": PUSHED, "issued_at": "2026-09-09"}).encode()
    assert await receiver.redeem(body) is True
    assert applier.tokens == [PUSHED]


# ---------------------------------------------------------------------------
# NetworkMCPServer: the reachability checks, and installing the token
# ---------------------------------------------------------------------------


def _server(tmp_path, *, bind_host="192.168.1.50"):
    from workstation_agent.config.schema import NetworkMcpConfig
    from workstation_agent.network_mcp.server import NetworkMCPServer

    config = NetworkMcpConfig(enabled=True, bind_host=bind_host, port=8765)
    return NetworkMCPServer(config, state_dir=tmp_path)


async def _never_returns() -> None:
    await asyncio.Event().wait()


@contextlib.asynccontextmanager
async def _serving(server):
    """Make ``server.running`` true without binding a socket.

    ``running`` is "the serve task exists and has not finished", so a real task
    that never finishes is the honest stand-in — a duck-typed stub would be
    asserting against a shape rather than against the property.
    """
    task = asyncio.create_task(_never_returns())
    server._task = task
    try:
        yield
    finally:
        server._task = None
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def test_a_join_is_refused_while_the_endpoint_is_stopped(tmp_path):
    """A window nothing can reach is worse than no window: the owner would type
    the code and be told nothing until it expired."""
    server = _server(tmp_path)
    assert server.running is False
    with pytest.raises(EnrolmentError, match="not running"):
        server.begin_join(CODE)
    assert server.join_status() is None


async def test_a_join_is_refused_on_a_loopback_bind(tmp_path):
    server = _server(tmp_path, bind_host="127.0.0.1")
    async with _serving(server):
        with pytest.raises(EnrolmentError, match="this machine only"):
            server.begin_join(CODE)
    assert server.join_status() is None


async def test_a_join_opens_on_a_reachable_endpoint(tmp_path):
    server = _server(tmp_path)
    async with _serving(server):
        status = server.begin_join(CODE, ttl_seconds=120.0)
    assert status.expires_in == pytest.approx(120.0, abs=5.0)
    assert server.join_status() is not None
    server.cancel_join()
    assert server.join_status() is None


def test_accepting_a_pushed_token_persists_it_and_puts_it_in_force(tmp_path):
    server = _server(tmp_path)
    app = RecordingApp()
    hardening = Hardening(app, token=TOKEN, enrolment=server._enrolment)
    server._hardening = hardening

    assert server._accept_pushed_token(PUSHED) is True

    assert ensure_token(tmp_path) == PUSHED, "on disk, for the next start"
    assert server.info().token == PUSHED
    assert hardening._token_ok(b"Bearer " + PUSHED.encode()) is True
    assert hardening._token_ok(b"Bearer " + TOKEN.encode()) is False


def test_a_pushed_token_that_cannot_be_stored_is_refused(tmp_path):
    """Persist first, then swap. A success we cannot keep across a restart is
    one the core would persist against and then be unable to use."""
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("this is a file", encoding="utf-8")
    server = _server(blocked)

    assert server._accept_pushed_token(PUSHED) is False
    assert server._token is None, "nothing was swapped in on a failed write"
