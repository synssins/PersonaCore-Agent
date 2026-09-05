"""LLM subsystem: OpenAI-compatible chat, tool bridging, session store.

Public re-exports for convenience:

    from workstation_agent.llm import OpenAICompatClient, LLMTurn, SessionStore
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from workstation_agent.llm.client import (
    ChatDelta,
    FinishReason,
    OpenAICompatClient,
    TextChunk,
    ToolCallArgsDelta,
    ToolCallComplete,
    ToolCallStart,
)
from workstation_agent.llm.session_store import SessionMode, SessionStore
from workstation_agent.llm.system_prompt import default_system_prompt, effective_system_prompt
from workstation_agent.llm.tool_bridge import ToolRouter, to_openai_schema
from workstation_agent.llm.turn import LLMTurn, TurnEvent

__all__ = [
    "ChatDelta",
    "FinishReason",
    "LLMTurn",
    "OpenAICompatClient",
    "SessionMode",
    "SessionStore",
    "TextChunk",
    "ToolCallArgsDelta",
    "ToolCallComplete",
    "ToolCallStart",
    "ToolRouter",
    "TurnEvent",
    "default_system_prompt",
    "effective_system_prompt",
    "to_openai_schema",
]
