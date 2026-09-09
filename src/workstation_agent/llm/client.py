"""OpenAI-compatible streaming chat client.

Uses ``httpx.AsyncClient`` with server-sent events (SSE) to stream chat
completion deltas.  All code paths are streaming-only — there is no
non-streaming fallback in v1.

API key handling
----------------
The key is never written to logs or exception messages.  Every log line that
could carry key material calls ``security.dpapi.redact_key`` first.

Credential failures
--------------------
A 401 from the configured base URL is unambiguous: the API key was refused,
or none was sent.  That is raised as :class:`LLMCredentialError` with a
plain-English message naming the credential's *role* — "the API key for the
LLM backend", identified by its ``api_key_ref`` name — and what happened, per
contract §11 item 6 ("denied in plain English").

A 403 is *not* unambiguous — WAF/IP/geo blocks, quota limits, and a valid key
lacking permission for the requested model all come back as 403 too — so it
is raised as :class:`LLMAccessDeniedError` instead, which names the key as
one possible cause rather than asserting it and does not tell the reader to
replace it.

``api_key_ref`` is a reference to a DPAPI blob on disk, not the secret
itself, so it is safe to quote in full in either message; the key's *value*
never appears in either one, nor is it reachable via the exception's
``request``/``response`` attributes (see ``_redact_request``).

Both exceptions carry ``response_body`` — the bounded error body, read once
and exposed directly — as the documented way to see what the backend said.
``exc.response.text`` is kept working too, but only as a best-effort
convenience; see ``_read_body_bounded`` for why ``response_body`` is the one
to reach for in new code.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import httpx

from workstation_agent.security.dpapi import redact_key

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Delta types emitted by OpenAICompatClient.chat()
# ---------------------------------------------------------------------------


@dataclass
class TextChunk:
    """A fragment of assistant text."""

    kind: Literal["text_chunk"] = field(default="text_chunk", init=False)
    text: str = ""


@dataclass
class ToolCallStart:
    """The LLM has started a tool call."""

    kind: Literal["tool_call_start"] = field(default="tool_call_start", init=False)
    index: int = 0
    call_id: str = ""
    name: str = ""


@dataclass
class ToolCallArgsDelta:
    """A fragment of the JSON args for a tool call."""

    kind: Literal["tool_call_args_delta"] = field(
        default="tool_call_args_delta",
        init=False,
    )
    index: int = 0
    args_fragment: str = ""


@dataclass
class ToolCallComplete:
    """All args for a tool call have been received."""

    kind: Literal["tool_call_complete"] = field(
        default="tool_call_complete",
        init=False,
    )
    index: int = 0
    call_id: str = ""
    name: str = ""
    args_json: str = ""


@dataclass
class FinishReason:
    """The LLM has stopped generating."""

    kind: Literal["finish_reason"] = field(default="finish_reason", init=False)
    reason: str = "stop"


# Union of all delta types
ChatDelta = (
    TextChunk | ToolCallStart | ToolCallArgsDelta | ToolCallComplete | FinishReason
)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_MAX_RETRIES = 3
_RETRY_STATUSES = {429, 500, 502, 503, 504}

#: 401 is unambiguous: the server looked at the credential and refused it
#: (or refused the request because none was sent).  Not retried: retrying
#: an empty or rejected key just repeats the same failure three times
#: slower — 401 was never in ``_RETRY_STATUSES`` to begin with.
_REJECTED_STATUS = 401

#: 403 is *not* unambiguous.  WAF/IP/geo blocks, quota enforcement, and a
#: valid key that simply lacks permission for the requested model all come
#: back as 403 too, so it gets its own message that names the key as one
#: possible cause rather than asserting it is *the* cause.  Also not
#: retried, and also never was.
_ACCESS_DENIED_STATUS = 403

_NON_STREAMING_MSG = "Non-streaming mode is not supported in v1."

#: A few kilobytes is plenty to make an error body legible to a person.
#: Reading further costs memory for no benefit, and reading *all* of it is
#: worse than that: httpx's read timeout only measures inactivity *between*
#: bytes, so a WAF page — often large HTML rather than a small JSON error —
#: trickled one byte every few seconds would hold the read open without ever
#: tripping it. Bounded here instead: a truncated body with a note beats an
#: unbounded one that can hang or exhaust memory.
_MAX_ERROR_BODY_BYTES = 4096


def _redact_request(request: httpx.Request) -> httpx.Request:
    """Replace any ``Authorization`` header value on *request*, in place.

    httpx attaches the literal request it sent — headers and all — to both
    the ``request=`` argument callers pass to :class:`httpx.HTTPStatusError`
    and to ``response.request`` (the same object, read back through a
    property).  Left alone, either would keep the raw API key reachable
    from a raised exception for as long as it lives: a structured log call,
    an error tracker, or a bare ``str(exc.request.headers)`` would all see
    it.  ``request.headers`` is mutable, so this mutates it directly rather
    than rebuilding the request — which also means ``content``, cookies and
    extensions survive untouched, unlike an earlier version of this
    function that reconstructed a bare ``httpx.Request`` from only method,
    url and headers and silently dropped everything else a caller might
    later want (e.g. logging the body behind a 400).

    Returns *request* for convenient chaining; the return value and the
    mutated input are the same object.
    """
    if "authorization" in request.headers:
        request.headers["authorization"] = "Bearer [redacted]"
    return request


def _redact_exception_request(exc: httpx.HTTPError) -> None:
    """Scrub ``exc.request`` in place, if httpx has set one.

    Covers the failure path :func:`_redact_request`'s call site in
    :meth:`OpenAICompatClient._stream_with_retry` cannot reach: a
    connection failure (DNS error, refused connection, a timeout waiting
    for headers) raises before any :class:`httpx.Response` exists, so there
    is nothing to scrub *through* — the credential is reachable only via
    the raised exception's own ``request`` attribute instead.  httpx's
    ``HTTPError.request`` is a property that raises :class:`RuntimeError`
    rather than returning ``None`` when unset; caught here so scrubbing an
    exception that happens not to carry a request yet never turns into a
    second, unrelated crash while handling the first.
    """
    try:
        request = exc.request
    except RuntimeError:
        return
    _redact_request(request)


async def _read_body_bounded(
    response: httpx.Response,
    limit: int = _MAX_ERROR_BODY_BYTES,
) -> bytes:
    """Read up to *limit* bytes of *response*'s body, then stop, and return them.

    The return value is the authoritative, documented body: callers should
    read ``exc.response_body`` on :class:`LLMCredentialError` /
    :class:`LLMAccessDeniedError` rather than ``exc.response.text``, which
    this function also keeps *working* — as a convenience for whoever
    reaches for the obvious thing first — but does not *guarantee*.  See
    below for why the distinction matters.

    A truncation marker is appended when the body ran longer than *limit*,
    so the reader knows it was cut rather than mistaking it for the whole
    thing.  Bounded rather than an unqualified :meth:`httpx.Response.aread`
    so a hostile or merely large WAF page cannot be pulled fully into
    memory first (see :data:`_MAX_ERROR_BODY_BYTES`).

    Two things here guard against httpx changing under us, deliberately:

    * ``response.aiter_bytes()`` is typed as the narrower ``AsyncIterator``,
      but is implemented today as an async generator, which is where
      ``.aclose()`` (used below to close it promptly on an early break)
      comes from.  Accessed via ``getattr(..., None)`` rather than assumed,
      so a future httpx returning a class-based iterator without
      ``.aclose()`` degrades to "don't close early" rather than raising
      ``AttributeError`` and masking the credential error this body was
      being read *for*.
    * ``exc.response.text``/``.content`` are made to work by setting the
      same private ``_content`` field :meth:`httpx.Response.aread` sets
      internally — httpx has no public "read some, not all" API. That
      assignment is wrapped in ``contextlib.suppress``: if a future httpx
      release renames or restricts that field, this silently gives up on
      the convenience rather than crashing (or, worse, appearing to
      succeed while lying about the response's state). The *documented*
      ``response_body`` returned here is unaffected either way, since it
      does not depend on httpx's internal representation at all.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    body_iter = response.aiter_bytes()
    try:
        async for chunk in body_iter:
            room = limit - total
            if room <= 0:
                truncated = True
                break
            if len(chunk) > room:
                chunks.append(chunk[:room])
                total += room
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        # Breaking out of the loop above early leaves the underlying
        # iterator un-exhausted; explicitly closing it (rather than
        # relying on GC to do so later) runs its cleanup promptly and
        # avoids a "coroutine was never awaited" warning -- but only if
        # this iterator actually has a close method to call.
        aclose = getattr(body_iter, "aclose", None)
        if aclose is not None:
            await aclose()
    body = b"".join(chunks)
    if truncated:
        body += b"...[truncated]"
    with contextlib.suppress(AttributeError, TypeError):
        response._content = body  # noqa: SLF001 -- best-effort convenience; see docstring
    return body


class _LLMBackendRefusalError(httpx.HTTPStatusError):
    """Common base for :class:`LLMCredentialError` and :class:`LLMAccessDeniedError`.

    Adds ``response_body``: the bounded body :func:`_read_body_bounded`
    already read, exposed as the *documented* way to inspect what the
    backend said.  ``self.response.text``/``.content`` are also kept
    working, as a convenience for a caller who reaches for the obvious
    attribute first, but that convenience depends on setting a private
    field on ``httpx.Response`` that a future httpx release could rename —
    see :func:`_read_body_bounded`'s docstring.  ``response_body`` does not
    depend on that and cannot regress the same way, so prefer it in new
    code.
    """

    def __init__(
        self,
        message: str,
        *,
        request: httpx.Request,
        response: httpx.Response,
        response_body: bytes,
    ) -> None:
        super().__init__(message, request=request, response=response)
        self.response_body = response_body


class LLMCredentialError(_LLMBackendRefusalError):
    """The LLM backend rejected the configured API key (HTTP 401 only).

    Raised instead of a bare status code so the message names the
    credential's role (the LLM API key, by its ``api_key_ref`` name) and
    states what happened and what to do — contract §11 item 6's "denied in
    plain English" — without ever containing the key's value: not in the
    message, and not reachable via ``self.request`` or
    ``self.response.request`` either (see :func:`_redact_request`).  The
    message also distinguishes a key that was sent and rejected from one
    that was never configured in the first place, since those have
    different fixes.
    """


class LLMAccessDeniedError(_LLMBackendRefusalError):
    """The LLM backend returned HTTP 403 to the configured request.

    Unlike :class:`LLMCredentialError`, this does *not* assert the API key
    was the problem — a 403 can equally mean a WAF/IP/geo block, an
    exhausted quota, or a valid key without permission for the requested
    model.  The message names the key as one possible cause among several
    and tells the reader what to check, rather than confidently prescribing
    "re-enter the key" when that may not be the fix at all.  Never contains
    the key's value, for the same reason and by the same means as
    :class:`LLMCredentialError`.
    """


def _credential_failure_message(*, api_key_present: bool, api_key_ref: str) -> str:
    """Build the plain-English message for a 401 from the LLM backend.

    Takes *whether* a key was sent, never the key itself — the caller must
    not pass the raw value in, since a bool argument cannot leak through
    frame-locals inspection the way a string one could.  Only ever names
    *api_key_ref*, which is a DPAPI blob name on disk, not the secret, so
    quoting it in full is safe.
    """
    ref_note = (
        f"llm.api_key_ref is {api_key_ref!r}" if api_key_ref else "llm.api_key_ref is not set"
    )
    if not api_key_present:
        return (
            "The LLM backend refused the request because no API key is "
            f"configured for it ({ref_note}). Add the LLM API key in "
            "Settings, then try again."
        )
    return (
        "The API key for the LLM backend was rejected by the server "
        f"(HTTP {_REJECTED_STATUS}, {ref_note}). Re-enter the LLM API key "
        "in Settings, then try again."
    )


def _access_denied_message(*, api_key_present: bool, api_key_ref: str) -> str:
    """Build the plain-English message for a 403 from the LLM backend.

    Same no-raw-value contract as :func:`_credential_failure_message`.
    Deliberately does not tell the reader to replace the key: a 403 does
    not establish that the key is at fault, and a confidently wrong
    instruction is worse than an honest "check these things instead."
    """
    if not api_key_present:
        ref_note = (
            f"llm.api_key_ref is {api_key_ref!r}" if api_key_ref else "llm.api_key_ref is not set"
        )
        return (
            f"The LLM backend refused the request with HTTP {_ACCESS_DENIED_STATUS} "
            f"(access denied), and no API key was sent ({ref_note}). If the "
            "backend requires one, add it in Settings; if it does not, the "
            "block is something else -- permissions, quota, or the server "
            "refusing this connection outright."
        )
    ref_note = f"llm.api_key_ref: {api_key_ref!r}" if api_key_ref else "no api_key_ref configured"
    return (
        f"The LLM backend refused the request with HTTP {_ACCESS_DENIED_STATUS} "
        f"(access denied). This does not necessarily mean the API key "
        f"({ref_note}) is wrong -- 403 can also mean the key lacks permission "
        "for this model, a quota was exceeded, or the server is blocking the "
        "connection outright. Check the backend's permissions and quota "
        "before replacing the key."
    )


class OpenAICompatClient:
    """Streaming chat client for any OpenAI-compatible endpoint.

    Parameters
    ----------
    base_url:
        Root of the API, e.g. ``https://api.openai.com``.
    model:
        Model identifier, e.g. ``gpt-4o``.
    api_key:
        Secret key — never logged.
    api_key_ref:
        Name of the DPAPI blob the key was loaded from (``llm.api_key_ref``
        in config). Not secret — used only to name the credential's role in
        :class:`LLMCredentialError`/:class:`LLMAccessDeniedError` messages
        when the backend refuses the request.
    timeout:
        httpx timeout in seconds (default 120).
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        api_key_ref: str = "",
        timeout: float = 120.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._api_key_ref = api_key_ref
        self._timeout = timeout
        log.debug(
            "OpenAICompatClient initialised",
            extra={
                "base_url": base_url,
                "key_prefix": redact_key(api_key),
                "api_key_ref": api_key_ref,
            },
        )

    def _build_http_client(self) -> httpx.AsyncClient:
        """Construct the httpx client for one streaming request.

        Extracted from :meth:`_stream_with_retry` so tests can substitute a
        transport (``httpx.MockTransport``) without duplicating the
        retry/credential-detection logic.
        """
        return httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        stream: bool = True,
    ) -> AsyncIterator[ChatDelta]:
        """Stream chat completion deltas.

        Yields :class:`ChatDelta` objects in order.
        Handles ``data: [DONE]`` SSE terminator and retries on transient errors.
        """
        if not stream:
            raise ValueError(_NON_STREAMING_MSG)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        # Built inline rather than bound to a `headers` local here: this
        # method's own frame lives for the whole request (it is itself an
        # async generator, suspended at `yield delta` below), so a named
        # local would sit in it, holding the raw key in a plain dict, for
        # as long as any error-tracker capturing frame locals could see.
        # `_stream_with_retry` still has to bind its own `headers`
        # parameter for as long as it needs to retry with it -- this does
        # not remove the key from the stack, only from one extra frame of
        # it, since `self._api_key` remains reachable via `self` either way.
        async for delta in self._stream_with_retry(
            payload,
            {
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
        ):
            yield delta

    async def _stream_with_retry(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> AsyncIterator[ChatDelta]:
        last_exc: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with (
                    self._build_http_client() as client,
                    client.stream(
                        "POST",
                        "/v1/chat/completions",
                        json=payload,
                        headers=headers,
                    ) as response,
                ):
                    # Scrub the Authorization header off the request httpx
                    # attaches to this response *before* any error path can
                    # hand it out -- every exception raised below (here, or
                    # by raise_for_status()) reads this same attribute.
                    # Mutates in place; response.request already points at
                    # the returned object, so no reassignment is needed.
                    _redact_request(response.request)

                    if response.status_code == _REJECTED_STATUS:
                        # Read (a bound amount of) the body now: the
                        # returned bytes become response_body, the
                        # documented way to read it; e.response.text is
                        # kept working too, best-effort (see
                        # _read_body_bounded's docstring).
                        body = await _read_body_bounded(response)
                        message = _credential_failure_message(
                            api_key_present=bool(self._api_key),
                            api_key_ref=self._api_key_ref,
                        )
                        raise LLMCredentialError(
                            message,
                            request=response.request,
                            response=response,
                            response_body=body,
                        )
                    if response.status_code == _ACCESS_DENIED_STATUS:
                        body = await _read_body_bounded(response)
                        message = _access_denied_message(
                            api_key_present=bool(self._api_key),
                            api_key_ref=self._api_key_ref,
                        )
                        raise LLMAccessDeniedError(
                            message,
                            request=response.request,
                            response=response,
                            response_body=body,
                        )
                    if response.status_code in _RETRY_STATUSES:
                        log.warning(
                            "Transient HTTP error, will retry",
                            extra={
                                "attempt": attempt,
                                "status": response.status_code,
                            },
                        )
                        last_exc = httpx.HTTPStatusError(
                            f"HTTP {response.status_code}",
                            request=response.request,
                            response=response,
                        )
                        continue
                    response.raise_for_status()
                    async for delta in _parse_sse_stream(response):
                        yield delta
                    return
            except httpx.RequestError as exc:
                # Scrub before anything else touches *exc*: a connection
                # failure (DNS error, refused connection, a timeout waiting
                # for headers -- e.g. httpx.ConnectTimeout, which is not one
                # of the three retried types below) raises before any
                # Response exists, so there is nothing to scrub *through*
                # the way the branches above do via response.request.  The
                # credential is only reachable via this exception's own
                # .request, so that is what gets scrubbed, for every
                # RequestError subtype, not only the retried ones.
                _redact_exception_request(exc)
                if not isinstance(
                    exc,
                    (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout),
                ):
                    raise
                log.warning(
                    "Network error during stream, will retry",
                    extra={"attempt": attempt, "error": str(exc)},
                )
                last_exc = exc
                if attempt == _MAX_RETRIES:
                    raise

        if last_exc is not None:
            raise last_exc


# ---------------------------------------------------------------------------
# SSE parsing helpers
# ---------------------------------------------------------------------------

_ToolCallState = dict[str, str]  # {call_id, name, args}


def _flush_tool_calls(
    tool_calls: dict[int, _ToolCallState],
) -> list[ToolCallComplete]:
    """Emit ToolCallComplete for every accumulated tool call."""
    return [
        ToolCallComplete(
            index=idx,
            call_id=state.get("call_id", ""),
            name=state.get("name", ""),
            args_json=state.get("args", ""),
        )
        for idx, state in sorted(tool_calls.items())
    ]


def _process_tool_call_delta(
    tc_delta: dict[str, Any],
    tool_calls: dict[int, _ToolCallState],
) -> list[TextChunk | ToolCallStart | ToolCallArgsDelta]:
    """Update *tool_calls* state and return events for one tool-call delta."""
    events: list[TextChunk | ToolCallStart | ToolCallArgsDelta] = []
    idx: int = tc_delta.get("index", 0)
    func: dict[str, Any] = tc_delta.get("function") or {}

    if idx not in tool_calls:
        call_id = tc_delta.get("id", "")
        name = func.get("name", "")
        tool_calls[idx] = {"call_id": call_id, "name": name, "args": ""}
        events.append(ToolCallStart(index=idx, call_id=call_id, name=name))
    else:
        if tc_delta.get("id"):
            tool_calls[idx]["call_id"] = tc_delta["id"]
        if func.get("name"):
            tool_calls[idx]["name"] = func["name"]

    args_fragment = func.get("arguments", "")
    if args_fragment:
        tool_calls[idx]["args"] += args_fragment
        events.append(ToolCallArgsDelta(index=idx, args_fragment=args_fragment))

    return events


def _parse_sse_line(
    data_str: str,
    tool_calls: dict[int, _ToolCallState],
) -> list[ChatDelta] | None:
    """Parse one SSE data line and return deltas, or None to signal [DONE]."""
    if data_str == "[DONE]":
        return None  # sentinel

    try:
        chunk = json.loads(data_str)
    except json.JSONDecodeError:
        log.debug("Skipping non-JSON SSE data", extra={"data": data_str[:80]})
        return []

    choices = chunk.get("choices", [])
    if not choices:
        return []

    choice = choices[0]
    delta = choice.get("delta", {})
    finish = choice.get("finish_reason")
    events: list[ChatDelta] = []

    content = delta.get("content")
    if content:
        events.append(TextChunk(text=content))

    for tc_delta in delta.get("tool_calls", []):
        events.extend(_process_tool_call_delta(tc_delta, tool_calls))

    if finish:
        events.extend(_flush_tool_calls(tool_calls))
        tool_calls.clear()
        events.append(FinishReason(reason=finish))

    return events


async def _parse_sse_stream(
    response: httpx.Response,
) -> AsyncIterator[ChatDelta]:
    """Parse an SSE stream and yield :class:`ChatDelta` objects.

    Handles ``data: [DONE]`` terminator.
    """
    tool_calls: dict[int, _ToolCallState] = {}

    async for raw_line in response.aiter_lines():
        line = raw_line.strip()
        if not line or not line.startswith("data:"):
            continue

        data_str = line[len("data:") :].strip()
        result = _parse_sse_line(data_str, tool_calls)
        if result is None:
            # [DONE] — flush any remaining tool calls and stop
            for complete in _flush_tool_calls(tool_calls):
                yield complete
            return

        for event in result:
            yield event
