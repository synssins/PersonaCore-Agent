"""Canned event stream stub for the claude-agent-sdk.

Implements the :class:`Transport` ABC so the real ``query()`` function can use
it without spawning a real ``claude`` subprocess.  Callers inject it via the
``transport=`` argument to ``query()`` or ``ClaudeCodeDriver``.

The SDK uses a bidirectional control protocol over the transport:

1. The SDK sends ``control_request`` JSON lines via ``transport.write()``.
2. ``read_messages()`` must yield ``control_response`` frames for each, then
   yield the actual canned message events.

``FakeTransport`` achieves this with a shared asyncio Queue:
- ``write()`` parses inbound control requests and enqueues a synthetic
  ``control_response`` back into the queue.
- ``read_messages()`` yields from the queue first (so control responses are
  delivered), then yields canned messages as they become available.

Usage::

    from tests.fakes.fake_claude_sdk import FakeTransport, make_text_message, make_result_message

    transport = FakeTransport([
        make_text_message("The answer is 42."),
        make_result_message(),
    ])
    driver = ClaudeCodeDriver(transport=transport)

A ``tool_use`` variant is used to test voice-mediated approval::

    transport = FakeTransport([
        make_tool_use_message("Bash", {"cmd": "ls"}),
        make_result_message(),
    ])
"""
# ruff: noqa: ANN401, TC003, FBT001, FBT002

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

from claude_agent_sdk._internal.transport import Transport  # type: ignore[import]

_SENTINEL = object()  # marks end of canned messages


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------

def _msg_to_wire(msg: Any) -> dict[str, Any]:
    """Convert an SDK message object to the raw JSON dict the Transport yields."""
    cls_name = type(msg).__name__

    if cls_name == "AssistantMessage":
        content_blocks = []
        for block in msg.content:
            block_cls = type(block).__name__
            if block_cls == "TextBlock":
                content_blocks.append({"type": "text", "text": block.text})
            elif block_cls == "ToolUseBlock":
                content_blocks.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
            else:
                content_blocks.append({"type": "unknown"})
        return {
            "type": "assistant",
            "message": {
                "id": getattr(msg, "message_id", "fake-msg-id"),
                "type": "message",
                "role": "assistant",
                "content": content_blocks,
                "model": getattr(msg, "model", "claude-fake"),
                "stop_reason": getattr(msg, "stop_reason", "end_turn"),
                "usage": getattr(msg, "usage", {"input_tokens": 1, "output_tokens": 1}),
            },
            "session_id": getattr(msg, "session_id", "fake-session"),
            "parent_tool_use_id": getattr(msg, "parent_tool_use_id", None),
        }

    if cls_name == "ResultMessage":
        return {
            "type": "result",
            "subtype": getattr(msg, "subtype", "success"),
            "is_error": getattr(msg, "is_error", False),
            "duration_ms": getattr(msg, "duration_ms", 100),
            "duration_api_ms": getattr(msg, "duration_api_ms", 100),
            "num_turns": getattr(msg, "num_turns", 1),
            "session_id": getattr(msg, "session_id", "fake-session"),
            "stop_reason": getattr(msg, "stop_reason", None),
            "total_cost_usd": getattr(msg, "total_cost_usd", 0.0),
            "result": getattr(msg, "result", ""),
            "usage": getattr(msg, "usage", {}),
        }

    if cls_name == "SystemMessage":
        return {
            "type": "system",
            "subtype": getattr(msg, "subtype", "init"),
            "session_id": getattr(msg, "session_id", "fake-session"),
        }

    return {"type": "unknown"}


class FakeTransport(Transport):
    """Replay a canned list of SDK message objects, handling the control protocol.

    The SDK sends ``control_request`` frames via ``write()`` before reading
    messages; we auto-reply with matching ``control_response`` frames via the
    shared queue so the ``initialize`` handshake completes.

    Parameters
    ----------
    messages:
        Sequence of SDK message objects (AssistantMessage, ResultMessage, …)
        to replay after the handshake completes.
    """

    def __init__(self, messages: list[Any]) -> None:
        self._wire: list[dict[str, Any]] = [_msg_to_wire(m) for m in messages]
        self._ready = False
        # Queue receives: control_response frames (from write) + canned msgs + sentinel
        self._queue: asyncio.Queue[Any] = asyncio.Queue()
        self._feeder_task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        self._ready = True
        # Kick off a background task that will push canned messages into the
        # queue after a brief yield (so control handshake can complete first).
        self._feeder_task = asyncio.create_task(self._feed_messages())

    async def _feed_messages(self) -> None:
        """Push canned messages into the queue after a small yield."""
        # Yield once to let the SDK send its initialize control_request first.
        await asyncio.sleep(0)
        for msg in self._wire:
            await self._queue.put(msg)
        await self._queue.put(_SENTINEL)

    async def write(self, data: str) -> None:
        """Receive outbound data from the SDK; auto-respond to control_request."""
        line = data.strip()
        if not line:
            return
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return

        if msg.get("type") == "control_request":
            request = msg.get("request", {})
            req_id = msg.get("request_id") or request.get("request_id") or "fake-req-id"
            subtype = request.get("subtype", "")

            # Build a synthetic control_response
            response_payload: dict[str, Any] = {
                "request_id": req_id,
                "subtype": subtype,
            }
            if subtype == "initialize":
                response_payload["supported_commands"] = []

            control_response = {
                "type": "control_response",
                "response": response_payload,
            }
            await self._queue.put(control_response)

    async def read_messages(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        """Yield control responses then canned messages from the shared queue."""
        while True:
            item = await self._queue.get()
            if item is _SENTINEL:
                break
            yield item  # type: ignore[misc]

    async def close(self) -> None:
        self._ready = False
        if self._feeder_task is not None:
            self._feeder_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._feeder_task
            self._feeder_task = None

    def is_ready(self) -> bool:
        return self._ready

    async def end_input(self) -> None:
        """No-op — fake transport has no real stdin to close."""


# ---------------------------------------------------------------------------
# Convenience factories
# ---------------------------------------------------------------------------

def make_text_message(text: str, model: str = "claude-fake") -> Any:
    """Return an AssistantMessage with a single TextBlock."""
    from claude_agent_sdk.types import AssistantMessage, TextBlock

    return AssistantMessage(
        content=[TextBlock(text=text)],
        model=model,
        parent_tool_use_id=None,
        error=None,
        usage={"input_tokens": 1, "output_tokens": 1},
        message_id="fake-msg-id",
        stop_reason="end_turn",
        session_id="fake-session",
        uuid="fake-uuid",
    )


def make_tool_use_message(
    tool_name: str, tool_input: dict[str, Any], model: str = "claude-fake",
) -> Any:
    """Return an AssistantMessage with a single ToolUseBlock."""
    from claude_agent_sdk.types import AssistantMessage, ToolUseBlock

    return AssistantMessage(
        content=[ToolUseBlock(id="fake-tool-id", name=tool_name, input=tool_input)],
        model=model,
        parent_tool_use_id=None,
        error=None,
        usage={"input_tokens": 1, "output_tokens": 1},
        message_id="fake-msg-id",
        stop_reason="tool_use",
        session_id="fake-session",
        uuid="fake-uuid",
    )


def make_result_message(is_error: bool = False, result: str = "") -> Any:
    """Return a ResultMessage."""
    from claude_agent_sdk.types import ResultMessage

    # Some fields (deferred_tool_use, api_error_status, terminal_reason, origin)
    # exist at runtime but may not be in the pyright-visible stub; use **kwargs.
    extra_kwargs: dict[str, Any] = {
        "deferred_tool_use": None,
        "api_error_status": None,
        "terminal_reason": None,
        "origin": None,
    }
    return ResultMessage(
        subtype="error" if is_error else "success",
        duration_ms=100,
        duration_api_ms=100,
        is_error=is_error,
        num_turns=1,
        session_id="fake-session",
        stop_reason=None,
        total_cost_usd=0.0,
        result=result,
        structured_output=None,
        model_usage=None,
        permission_denials=None,
        errors=None,
        uuid="fake-uuid",
        **extra_kwargs,  # type: ignore[arg-type]
    )


def canned_events(*messages: Any) -> list[Any]:
    """Return a flat list of SDK messages for use with FakeTransport."""
    return list(messages)
