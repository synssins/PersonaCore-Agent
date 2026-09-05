"""Fake OpenAI-compatible API server for tests.

Implements ``POST /v1/chat/completions`` as a FastAPI ASGI app that streams
SSE responses.  The response content is driven by a configurable
:class:`ScenarioQueue` so tests can set up multi-round tool-call sequences
without hitting a real API.

Reusability
-----------
This fake is intentionally generic — it can be reused by SPEC-08 and any
other SPEC that needs an OpenAI-compatible mock.  Callers configure it via
:class:`ScenarioQueue` before each test.

Typical usage (pytest, with pytest-asyncio + httpx)::

    from tests.fakes.fake_openai import build_app, ScenarioQueue

    queue = ScenarioQueue()
    queue.push([
        # First call: LLM asks for a tool
        tool_call_response("call_1", "get_time", "{}"),
        # Second call: LLM gives a final answer
        text_response("The time is noon."),
    ])

    app = build_app(queue)
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# Scenario primitives
# ---------------------------------------------------------------------------


def _sse(data: dict[str, Any]) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _done() -> str:
    return "data: [DONE]\n\n"


def text_chunk(text: str, finish: str | None = None) -> dict[str, Any]:
    """Build one SSE delta chunk carrying text content."""
    choice: dict[str, Any] = {
        "index": 0,
        "delta": {"content": text},
        "finish_reason": finish,
    }
    return {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "choices": [choice]}


def tool_call_chunk(
    index: int,
    call_id: str,
    name: str,
    args_fragment: str,
    finish: str | None = None,
) -> dict[str, Any]:
    """Build one SSE delta chunk carrying a tool-call fragment."""
    tc: dict[str, Any] = {
        "index": index,
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": args_fragment},
    }
    choice: dict[str, Any] = {
        "index": 0,
        "delta": {"tool_calls": [tc]},
        "finish_reason": finish,
    }
    return {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "choices": [choice]}


def text_response(text: str) -> list[dict[str, Any]]:
    """Convenience: full single-chunk text response."""
    return [
        text_chunk(""),                    # role delta
        text_chunk(text),                  # content delta
        text_chunk("", finish="stop"),     # finish chunk
    ]


def tool_call_response(
    call_id: str,
    tool_name: str,
    args_json: str,
) -> list[dict[str, Any]]:
    """Convenience: full tool-call response sequence."""
    return [
        tool_call_chunk(0, call_id, tool_name, "", finish=None),          # start
        tool_call_chunk(0, call_id, tool_name, args_json, finish=None),   # args
        tool_call_chunk(0, call_id, tool_name, "", finish="tool_calls"),  # finish
    ]


# ---------------------------------------------------------------------------
# Scenario queue
# ---------------------------------------------------------------------------


class ScenarioQueue:
    """Thread-safe queue of SSE chunk sequences.

    Push a list-of-chunk-lists (one inner list per request) before the test
    starts.  The server pops one inner list per incoming request.
    """

    def __init__(self) -> None:
        self._q: deque[list[list[dict[str, Any]]]] = deque()

    def push(self, scenarios: list[list[dict[str, Any]]]) -> None:
        """Push *scenarios* as the upcoming sequence of responses."""
        self._q.append(scenarios)

    def pop_next(self) -> list[dict[str, Any]]:
        """Pop the next scenario (list of chunks for one request)."""
        if not self._q:
            return text_response("(no scenario configured)")
        outer = self._q[0]
        if not outer:
            self._q.popleft()
            return text_response("(scenario exhausted)")
        chunks = outer.pop(0)
        if not outer:
            self._q.popleft()
        return chunks


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------


def build_app(queue: ScenarioQueue) -> FastAPI:
    """Return a FastAPI ASGI app backed by *queue*."""
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> StreamingResponse:  # noqa: ARG001
        chunks = queue.pop_next()

        async def _stream() -> AsyncIterator[str]:
            for chunk in chunks:
                yield _sse(chunk)
                await asyncio.sleep(0)
            yield _done()

        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    return app
