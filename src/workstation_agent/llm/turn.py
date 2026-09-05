"""LLMTurn — orchestrates one user turn through the full multi-round tool loop.

Flow per turn
-------------
1. Load tool schemas from MCPHost.
2. Build the messages list (system prompt + session history + new user message).
3. Call OpenAICompatClient.chat() (streaming).
4. Collect deltas:
   - Yield TextChunk text to the caller (for TTS / UI).
   - Accumulate tool calls; on ToolCallComplete dispatch via ToolRouter.
5. If finish_reason == "tool_calls" feed tool results back and loop (capped at
   ``max_rounds``).
6. Persist every message to SessionStore.
7. Emit progress events to UI.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from workstation_agent.llm.client import (
    FinishReason,
    OpenAICompatClient,
    TextChunk,
    ToolCallComplete,
)
from workstation_agent.llm.system_prompt import effective_system_prompt
from workstation_agent.llm.tool_bridge import ToolRouter, to_openai_schema

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from workstation_agent.llm.session_store import SessionId, SessionStore
    from workstation_agent.protocols import MCPHost

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Progress events
# ---------------------------------------------------------------------------


@dataclass
class TextChunkEvent:
    """A fragment of assistant text ready for TTS."""

    kind: Literal["text_chunk"] = field(default="text_chunk", init=False)
    text: str = ""


@dataclass
class ToolCallStartedEvent:
    """A tool call has started."""

    kind: Literal["tool_call_started"] = field(default="tool_call_started", init=False)
    name: str = ""
    call_id: str = ""


@dataclass
class ToolCallDoneEvent:
    """A tool call completed."""

    kind: Literal["tool_call_done"] = field(default="tool_call_done", init=False)
    name: str = ""
    call_id: str = ""


@dataclass
class FinishedEvent:
    """The turn is finished; no more text will be emitted."""

    kind: Literal["finished"] = field(default="finished", init=False)
    total_rounds: int = 0


TurnEvent = TextChunkEvent | ToolCallStartedEvent | ToolCallDoneEvent | FinishedEvent


# ---------------------------------------------------------------------------
# LLMTurn
# ---------------------------------------------------------------------------

_DEFAULT_MAX_ROUNDS = 8


@dataclass
class LLMTurnConfig:
    """Configuration bundle for :class:`LLMTurn` to avoid arg-count lint errors."""

    client: OpenAICompatClient
    host: MCPHost
    store: SessionStore
    session_id: SessionId
    max_rounds: int = _DEFAULT_MAX_ROUNDS
    system_prompt: str | None = None


class LLMTurn:
    """Orchestrates one user turn: tool loop, streaming, session persistence.

    Accepts either a :class:`LLMTurnConfig` as its sole argument, or keyword
    arguments matching the config fields for convenience.

    The ``system_prompt`` field defaults to ``None``, in which case the
    built-in default is used.

    # TODO(orchestrator-integrate): read config.llm.system_prompt when
    #   SPEC-02 config schema is extended to include
    #   ``system_prompt: str | None``.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        client: OpenAICompatClient,
        host: MCPHost,
        store: SessionStore,
        session_id: SessionId,
        max_rounds: int = _DEFAULT_MAX_ROUNDS,
        system_prompt: str | None = None,
    ) -> None:
        self._client = client
        self._host = host
        self._store = store
        self._session_id = session_id
        self._max_rounds = max_rounds
        self._system_prompt = effective_system_prompt(system_prompt)
        self._router = ToolRouter(host)

    async def run(self, user_text: str) -> AsyncIterator[TurnEvent]:
        """Execute one turn and yield :class:`TurnEvent` objects.

        Persists every message (user, assistant, tool) to the session store.
        """
        self._store.append(self._session_id, "user", content=user_text)

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_prompt},
        ]
        messages.extend(self._store.history(self._session_id))

        descriptors = await self._host.tools()
        openai_tools = to_openai_schema(descriptors)

        async for event in self._run_loop(messages, openai_tools, 0):
            yield event

    def _should_loop(
        self,
        finish: FinishReason | None,
        pending_tool_calls: list[dict[str, Any]],
        rounds: int,
    ) -> bool:
        return (
            finish is not None
            and finish.reason in ("tool_calls", "function_call")
            and bool(pending_tool_calls)
            and rounds < self._max_rounds
        )

    async def _persist_assistant(
        self,
        full_text: str | None,
        pending_tool_calls: list[dict[str, Any]],
        messages: list[dict[str, Any]],
    ) -> None:
        if pending_tool_calls:
            self._store.append(
                self._session_id,
                "assistant",
                content=full_text,
                tool_calls=pending_tool_calls,
            )
            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "tool_calls": pending_tool_calls,
            }
            if full_text:
                assistant_msg["content"] = full_text
            messages.append(assistant_msg)
        elif full_text:
            self._store.append(self._session_id, "assistant", content=full_text)

    async def _run_loop(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        rounds: int,
    ) -> AsyncIterator[TurnEvent]:
        """Inner multi-round loop."""
        accumulated_text: list[str] = []
        pending_tool_calls: list[dict[str, Any]] = []
        finish: FinishReason | None = None

        async for delta in self._client.chat(messages, tools):
            if isinstance(delta, TextChunk):
                accumulated_text.append(delta.text)
                yield TextChunkEvent(text=delta.text)
            elif delta.kind == "tool_call_start":
                yield ToolCallStartedEvent(name=delta.name, call_id=delta.call_id)
            elif isinstance(delta, ToolCallComplete):
                async for ev in self._handle_tool_call(delta, pending_tool_calls, messages):
                    yield ev
            elif isinstance(delta, FinishReason):
                finish = delta

        full_text = "".join(accumulated_text) or None
        await self._persist_assistant(full_text, pending_tool_calls, messages)

        rounds += 1
        if self._should_loop(finish, pending_tool_calls, rounds):
            log.debug(
                "Tool calls detected, starting round %d/%d",
                rounds + 1,
                self._max_rounds,
            )
            async for event in self._run_loop(messages, tools, rounds):
                yield event
        else:
            yield FinishedEvent(total_rounds=rounds)

    async def _handle_tool_call(
        self,
        delta: ToolCallComplete,
        pending_tool_calls: list[dict[str, Any]],
        messages: list[dict[str, Any]],
    ) -> AsyncIterator[TurnEvent]:
        result_msg = await self._router.dispatch(delta)
        pending_tool_calls.append(
            {
                "id": delta.call_id,
                "type": "function",
                "function": {
                    "name": delta.name,
                    "arguments": delta.args_json,
                },
            },
        )
        yield ToolCallDoneEvent(name=delta.name, call_id=delta.call_id)
        messages.append(result_msg)
        self._store.append(
            self._session_id,
            "tool",
            content=result_msg["content"],
            tool_call_id=delta.call_id,
        )
