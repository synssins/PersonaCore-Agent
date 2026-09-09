"""Unit tests for LLM-backend credential-failure messages (subtask P14).

The product-owner requirement: a 401/403 from the configured LLM backend
must say *which* credential was involved, *what* happened to it, and *what*
to do next -- without ever printing the key's value, and without leaving the
value reachable from anywhere on the raised exception (message, args, or the
``request``/``response`` objects httpx attaches).  These tests exercise
:class:`~workstation_agent.llm.client.OpenAICompatClient` end-to-end through
an ``httpx.MockTransport`` standing in for the real backend, so the
assertions cover the exact path a real 401/403 takes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from workstation_agent.llm.client import (
    _MAX_ERROR_BODY_BYTES,
    LLMAccessDeniedError,
    LLMCredentialError,
    OpenAICompatClient,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_PLANTED_SECRET = "sk-super-secret-value-do-not-leak-1234567890"  # noqa: S105 -- planted test value


def _make_client(
    handler: object,
    *,
    api_key: str = "",
    api_key_ref: str = "",
) -> OpenAICompatClient:
    """Build a client whose HTTP traffic is served by *handler* (no network)."""
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]

    class _MockedClient(OpenAICompatClient):
        def _build_http_client(self) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                transport=transport,
                base_url=self._base_url,
                timeout=self._timeout,
            )

    return _MockedClient(
        base_url="http://fake-llm-backend",
        model="gpt-fake",
        api_key=api_key,
        api_key_ref=api_key_ref,
    )


def _status_handler(status: int, *, body: str = "") -> object:
    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(status, text=body)

    return handler


async def _drain(client: OpenAICompatClient) -> None:
    async for _ in client.chat([{"role": "user", "content": "hi"}]):
        pass


def _all_exception_text(exc: BaseException) -> str:
    """Every scrap of text an exception could be made to render.

    Covers ``str(exc)``, each element of ``.args`` and -- the part this
    subtask's rework added -- the ``request``/``response`` objects httpx
    attaches, whose headers are exactly where the raw key used to hide.
    """
    parts = [str(exc), *[str(a) for a in exc.args]]
    request = getattr(exc, "request", None)
    if request is not None:
        parts.append(str(dict(request.headers)))
    response = getattr(exc, "response", None)
    if response is not None:
        parts.append(str(dict(response.headers)))
        resp_request = getattr(response, "request", None)
        if resp_request is not None:
            parts.append(str(dict(resp_request.headers)))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 401 -- unambiguous: the key was sent and rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rejected_key_names_role_and_states_what_happened() -> None:
    client = _make_client(
        _status_handler(401),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    message = str(excinfo.value)
    # Which credential.
    assert "API key" in message
    assert "LLM backend" in message
    assert "llm-primary" in message
    # What happened.
    assert "rejected" in message
    assert "401" in message
    # What to do.
    assert "Settings" in message
    assert "try again" in message


@pytest.mark.asyncio
async def test_rejected_key_does_not_leak_the_credential_value_anywhere() -> None:
    """The one most worth writing: a planted secret must never surface.

    Checked not just in the message but in every place httpx would
    otherwise have stashed the real ``Authorization`` header: the
    exception's own ``request``, and ``response.request`` too (the two
    places a rework of this subtask found the value could still leak from
    even though the message text was already clean).
    """
    client = _make_client(
        _status_handler(401, body="unauthorized"),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    exc = excinfo.value
    everything = _all_exception_text(exc)
    assert _PLANTED_SECRET not in everything

    # Be explicit about the two attributes that used to carry it.
    assert _PLANTED_SECRET not in str(dict(exc.request.headers))
    assert _PLANTED_SECRET not in str(dict(exc.response.request.headers))
    # The Authorization header itself is still present (as a marker that
    # scrubbing replaced its value rather than deleting evidence there was
    # ever a credential), just not the real one.
    assert exc.request.headers.get("authorization") == "Bearer [redacted]"
    assert exc.response.request.headers.get("authorization") == "Bearer [redacted]"


@pytest.mark.asyncio
async def test_rejected_key_response_body_is_readable() -> None:
    """A caller doing the natural ``e.response.text`` must not get ResponseNotRead."""
    client = _make_client(
        _status_handler(401, body="invalid api key"),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    # Must not raise httpx.ResponseNotRead.
    assert excinfo.value.response.text == "invalid api key"
    # The documented path agrees with the convenience one.
    assert excinfo.value.response_body == b"invalid api key"


@pytest.mark.asyncio
async def test_large_error_body_is_truncated_not_fully_buffered() -> None:
    """Rework cycle 2, finding 3: an unbounded read is a memory/hang risk.

    A WAF or hostile server can return an arbitrarily large body (or
    trickle it slowly enough that httpx's between-bytes read timeout never
    trips). The body is capped at :data:`_MAX_ERROR_BODY_BYTES` with a
    truncation marker rather than read in full.
    """
    huge_body = "x" * (_MAX_ERROR_BODY_BYTES * 4)
    client = _make_client(
        _status_handler(401, body=huge_body),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    content = excinfo.value.response.content
    assert len(content) < len(huge_body)
    assert content.endswith(b"...[truncated]")
    # response_body agrees with the (best-effort) response.content.
    assert excinfo.value.response_body == content


@pytest.mark.asyncio
async def test_redaction_preserves_the_request_body() -> None:
    """Rework cycle 2, finding 2: scrubbing must not drop the request body.

    An earlier version of ``_redact_request`` rebuilt a bare
    ``httpx.Request`` from only method/url/headers, silently dropping the
    JSON payload -- so anything later reading ``exc.request.content`` to
    log what was sent behind a failing call would have found nothing there.
    Redacting the header in place instead keeps the body intact.
    """
    client = _make_client(
        _status_handler(401),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    body = excinfo.value.request.content
    assert b"gpt-fake" in body  # the model name from the chat payload
    assert b"hi" in body  # the user message content


# ---------------------------------------------------------------------------
# 401 with no key configured at all -- a different problem, different fix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_key_is_distinguished_from_rejected_key() -> None:
    client = _make_client(_status_handler(401), api_key="", api_key_ref="")

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    message = str(excinfo.value)
    assert "no API key is configured" in message
    assert "not set" in message
    # Must NOT claim the (nonexistent) key was "rejected" -- that would be
    # the wrong diagnosis and point the owner at the wrong fix.
    assert "rejected" not in message
    assert "Settings" in message


@pytest.mark.asyncio
async def test_missing_key_names_the_empty_ref_when_one_is_set_but_key_absent() -> None:
    """api_key_ref set but the resolved key is empty (e.g. load failed upstream).

    Still reported as "not configured" (the key was never sent), but the
    configured ref name is surfaced for context.
    """
    client = _make_client(_status_handler(401), api_key="", api_key_ref="llm-primary")

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    message = str(excinfo.value)
    assert "no API key is configured" in message
    assert "llm-primary" in message


# ---------------------------------------------------------------------------
# 403 -- ambiguous: the key is only one possible cause, so no forced remedy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_denied_403_does_not_assert_the_key_is_at_fault() -> None:
    client = _make_client(
        _status_handler(403),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMAccessDeniedError) as excinfo:
        await _drain(client)

    assert not isinstance(excinfo.value, LLMCredentialError)
    message = str(excinfo.value)
    # Which credential, named as context.
    assert "API key" in message
    assert "llm-primary" in message
    # What happened -- but framed as one of several possible causes.
    assert "403" in message
    assert "does not necessarily mean" in message
    assert "quota" in message
    assert "permission" in message
    # Must NOT confidently prescribe "re-enter the key" -- a 403 does not
    # establish the key is wrong, and this subtask's rework specifically
    # rejected that instruction as unactionable/wrong for this status.
    assert "Re-enter the LLM API key" not in message


@pytest.mark.asyncio
async def test_access_denied_403_does_not_leak_the_credential_value() -> None:
    client = _make_client(
        _status_handler(403, body="forbidden"),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMAccessDeniedError) as excinfo:
        await _drain(client)

    exc = excinfo.value
    assert _PLANTED_SECRET not in _all_exception_text(exc)
    assert exc.response.text == "forbidden"
    assert exc.response_body == b"forbidden"


@pytest.mark.asyncio
async def test_access_denied_403_with_no_key_configured() -> None:
    client = _make_client(_status_handler(403), api_key="", api_key_ref="")

    with pytest.raises(LLMAccessDeniedError) as excinfo:
        await _drain(client)

    message = str(excinfo.value)
    assert "403" in message
    assert "no API key was sent" in message
    assert "not set" in message


# ---------------------------------------------------------------------------
# Rework cycle 2, finding 1: a pre-response connection failure must not leak
# the key either -- there is no Response to scrub through in that case, only
# the exception's own .request.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connection_failure_before_any_response_is_scrubbed() -> None:
    """httpx.ConnectError is one of the three retried network-error types.

    Exercises the retry-exhaustion re-raise path (three attempts, each
    failing before a Response ever exists), not just an immediate one.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        msg = "connection refused"
        raise httpx.ConnectError(msg, request=request)

    client = _make_client(handler, api_key=_PLANTED_SECRET, api_key_ref="llm-primary")

    with pytest.raises(httpx.ConnectError) as excinfo:
        await _drain(client)

    exc = excinfo.value
    assert _PLANTED_SECRET not in _all_exception_text(exc)
    assert exc.request.headers.get("authorization") == "Bearer [redacted]"


@pytest.mark.asyncio
async def test_non_retried_connection_failure_is_also_scrubbed() -> None:
    """A RequestError subtype outside the three retried types must be scrubbed too.

    ``httpx.ConnectTimeout`` is a ``TimeoutException``, not a
    ``ConnectError`` -- it was never one of the three types this client
    explicitly retries, so before this fix it would propagate on the very
    first attempt with its original, unscrubbed request still attached.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        msg = "timed out"
        raise httpx.ConnectTimeout(msg, request=request)

    client = _make_client(handler, api_key=_PLANTED_SECRET, api_key_ref="llm-primary")

    with pytest.raises(httpx.ConnectTimeout) as excinfo:
        await _drain(client)

    exc = excinfo.value
    assert _PLANTED_SECRET not in _all_exception_text(exc)
    assert exc.request.headers.get("authorization") == "Bearer [redacted]"


# ---------------------------------------------------------------------------
# Rework cycle 3: two forward-compatibility guards, so a future httpx change
# degrades gracefully instead of failing silently or masking the credential
# error this whole module exists to surface.
# ---------------------------------------------------------------------------


class _NoAcloseAsyncIterator:
    """A minimal async iterator with no ``.aclose()``, unlike an async generator.

    Stands in for a hypothetical future ``httpx.Response.aiter_bytes()``
    that returns a class-based iterator instead of today's async generator.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)

    def __aiter__(self) -> _NoAcloseAsyncIterator:
        return self

    async def __anext__(self) -> bytes:
        try:
            return next(self._chunks)
        except StopIteration:
            raise StopAsyncIteration from None


@pytest.mark.asyncio
async def test_missing_aclose_on_body_iterator_does_not_mask_the_credential_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 1: ``.aclose()`` must be optional, not assumed.

    If a future httpx returns a class-based async iterator without
    ``.aclose()``, reading the error body must not itself raise
    ``AttributeError`` -- that would replace the credential error this
    module exists to surface with an unrelated crash, the opposite of the
    goal.
    """
    def fake_aiter_bytes(
        _self: httpx.Response,
        _chunk_size: int | None = None,
    ) -> _NoAcloseAsyncIterator:
        return _NoAcloseAsyncIterator([b"unauthorized"])

    monkeypatch.setattr(httpx.Response, "aiter_bytes", fake_aiter_bytes)

    client = _make_client(
        _status_handler(401),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    assert excinfo.value.response_body == b"unauthorized"


class _RawByteStream(httpx.AsyncByteStream):
    """Yields fixed chunks without triggering ``httpx.Response``'s eager read.

    Passing ``text=``/``content=`` to ``httpx.Response.__init__`` reads the
    body immediately, which would set ``_content`` before
    ``_NoPrivateContentResponse`` below gets a chance to reject it. Passing
    ``stream=`` instead defers reading until something actually iterates,
    matching how a real streamed response behaves.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


class _NoPrivateContentResponse(httpx.Response):
    """Simulates a future httpx where ``_content`` can no longer be set directly.

    Used to prove the defensive write in ``_read_body_bounded`` degrades
    gracefully -- ``response_body`` and the raised exception itself must
    survive; only the ``response.text``/``.content`` convenience is allowed
    to regress to ``ResponseNotRead``.
    """

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_content":
            msg = "_content is no longer settable (simulated future httpx)"
            raise AttributeError(msg)
        super().__setattr__(name, value)


@pytest.mark.asyncio
async def test_private_content_field_rename_does_not_crash_or_lose_the_body() -> None:
    """Finding 2: writing ``response._content`` is best-effort, not load-bearing.

    If a future httpx release renames or restricts that field, this must
    degrade to "the documented ``response_body`` attribute still works,
    ``response.text`` regresses to ResponseNotRead" -- not a crash, and not
    a silent lie where ``.text`` looks readable but returns nothing useful.
    """

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return _NoPrivateContentResponse(401, stream=_RawByteStream([b"unauthorized"]))

    client = _make_client(handler, api_key=_PLANTED_SECRET, api_key_ref="llm-primary")

    with pytest.raises(LLMCredentialError) as excinfo:
        await _drain(client)

    exc = excinfo.value
    # The documented, guaranteed path: unaffected.
    assert exc.response_body == b"unauthorized"
    assert _PLANTED_SECRET not in _all_exception_text(exc)
    # The best-effort convenience is allowed to degrade -- but only to a
    # clear "not read" error, never to a wrong or empty-looking success.
    with pytest.raises(httpx.ResponseNotRead):
        _ = exc.response.text


# ---------------------------------------------------------------------------
# Regression: non-credential statuses are unaffected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_credential_client_error_is_not_wrapped() -> None:
    """A plain 400 is not a credential failure and must not become one."""
    client = _make_client(_status_handler(400), api_key="sk-whatever", api_key_ref="x")

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        await _drain(client)

    assert not isinstance(excinfo.value, LLMCredentialError)
    assert not isinstance(excinfo.value, LLMAccessDeniedError)


@pytest.mark.asyncio
async def test_generic_error_status_also_has_its_request_scrubbed() -> None:
    """The pre-existing generic path (``raise_for_status()``) leaked the key too.

    Not specific to 401/403: any status that falls through to
    ``response.raise_for_status()`` previously carried the live,
    unscrubbed request (and therefore the real ``Authorization`` header) on
    the resulting ``httpx.HTTPStatusError``. Fixed by scrubbing
    ``response.request`` once, unconditionally, before any status-code
    branch runs.
    """
    client = _make_client(
        _status_handler(400),
        api_key=_PLANTED_SECRET,
        api_key_ref="llm-primary",
    )

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        await _drain(client)

    assert _PLANTED_SECRET not in _all_exception_text(excinfo.value)


@pytest.mark.asyncio
async def test_retryable_5xx_status_is_still_retried_not_treated_as_credential() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["n"] += 1
        return httpx.Response(503)

    client = _make_client(handler, api_key="sk-whatever", api_key_ref="x")

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        await _drain(client)

    assert not isinstance(excinfo.value, LLMCredentialError)
    assert not isinstance(excinfo.value, LLMAccessDeniedError)
    assert calls["n"] == 3  # _MAX_RETRIES


# ---------------------------------------------------------------------------
# The stranger-facing network-MCP 401 is out of scope and must be unchanged.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_mcp_stranger_401_contract_is_untouched() -> None:
    """Characterisation guard for subtask P14's boundary.

    This subtask is expressly forbidden from touching
    ``network_mcp/hardening.py`` or making its unauthenticated refusal more
    helpful -- that ``401`` is answered to an unauthenticated stranger on the
    LAN and its uninformative, uniform shape is a security property with its
    own tests.  This test does not re-implement that contract (see
    ``tests/unit/network_mcp/test_hardening.py``); it only pins the public
    entry point this subtask must not alter, so a future edit inside this
    subtask's own allowed paths cannot accidentally reach into it.
    """
    from workstation_agent.network_mcp import hardening

    assert hasattr(hardening, "Hardening")
    # The one unauthenticated answer is still built with no body detail.
    import inspect

    source = inspect.getsource(hardening.Hardening._refuse)
    assert "401" in source
    assert "www-authenticate" in source.lower()
