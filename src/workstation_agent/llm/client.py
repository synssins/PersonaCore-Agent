"""OpenAI-compatible streaming chat client.

Uses ``httpx.AsyncClient`` with server-sent events (SSE) to stream chat
completion deltas.  All code paths are streaming-only — there is no
non-streaming fallback in v1.

API key handling
----------------
The key is never written to logs or exception messages.  Every log line that
could carry key material calls ``security.dpapi.redact_key`` first.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

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

_NON_STREAMING_MSG = "Non-streaming mode is not supported in v1."


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
    timeout:
        httpx timeout in seconds (default 120).
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        timeout: float = 120.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout
        log.debug(
            "OpenAICompatClient initialised",
            extra={"base_url": base_url, "key_prefix": redact_key(api_key)},
        )

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

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }

        async for delta in self._stream_with_retry(payload, headers):
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
                    httpx.AsyncClient(
                        base_url=self._base_url,
                        timeout=self._timeout,
                    ) as client,
                    client.stream(
                        "POST",
                        "/v1/chat/completions",
                        json=payload,
                        headers=headers,
                    ) as response,
                ):
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
            except (
                httpx.RemoteProtocolError,
                httpx.ConnectError,
                httpx.ReadTimeout,
            ) as exc:
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
