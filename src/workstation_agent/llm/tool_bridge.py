"""MCP-to-OpenAI tool schema bridge and tool-call router.

``to_openai_schema`` converts MCP :class:`~workstation_agent.protocols.ToolDescriptor`
objects into the ``tools=[{"type":"function","function":{...}}]`` format that
OpenAI-compatible APIs expect.

``ToolRouter`` collects streamed tool-call events from
:class:`~workstation_agent.llm.client.OpenAICompatClient`, waits until each
tool call's arguments are complete, then dispatches to
:class:`~workstation_agent.protocols.MCPHost` and formats the result back
into an OpenAI ``tool`` role message.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from workstation_agent.protocols import MCPHost

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema conversion
# ---------------------------------------------------------------------------


def _get_attr(obj: object, key: str, default: object) -> object:
    """Get *key* from *obj* whether it is a dict or an object with attributes."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def to_openai_schema(descriptors: Sequence[object]) -> list[dict[str, Any]]:
    """Convert MCP tool descriptors to the OpenAI function-tool format.

    Each descriptor is expected to expose (via attribute or dict-key access):

    * ``name`` — tool identifier string
    * ``description`` — human-readable description (optional)
    * ``input_schema`` — JSON Schema dict for the function parameters (optional)

    Returns a list suitable for the ``tools`` parameter of an OpenAI chat
    completion request.
    """
    result: list[dict[str, Any]] = []
    for desc in descriptors:
        name = str(_get_attr(desc, "name", ""))
        description = str(_get_attr(desc, "description", ""))
        input_schema = _get_attr(desc, "input_schema", None)
        if input_schema is None:
            input_schema = _get_attr(
                desc, "parameters", {"type": "object", "properties": {}},
            )

        function_def: dict[str, Any] = {"name": name}
        if description:
            function_def["description"] = description
        function_def["parameters"] = input_schema or {"type": "object", "properties": {}}

        result.append({"type": "function", "function": function_def})
    return result


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _serialise_result(result: object) -> str:
    """Convert a ToolResult to a JSON string for the OpenAI tool message."""
    if isinstance(result, dict):
        return json.dumps(result)
    # Try Pydantic v2 model_dump via duck-typing without accessing the attribute
    # directly so pyright doesn't complain about unknown attributes on ToolResult.
    model_dump = getattr(result, "model_dump", None)
    if callable(model_dump):
        return json.dumps(model_dump())
    obj_dict = getattr(result, "__dict__", None)
    if obj_dict is not None:
        return json.dumps(obj_dict)
    return str(result)


# ---------------------------------------------------------------------------
# Tool router
# ---------------------------------------------------------------------------


class ToolRouter:
    """Dispatch completed tool calls to MCPHost and produce result messages.

    Usage::

        router = ToolRouter(mcp_host)
        # Feed streaming events from OpenAICompatClient:
        for delta in ...:
            if isinstance(delta, ToolCallComplete):
                result_msg = await router.dispatch(delta)
                # append result_msg to the conversation
    """

    def __init__(self, host: MCPHost) -> None:
        self._host = host

    async def dispatch(self, call: object) -> dict[str, Any]:
        """Invoke the tool described by *call* and return an OpenAI tool message.

        Parameters
        ----------
        call:
            A :class:`~workstation_agent.llm.client.ToolCallComplete` instance.

        Returns
        -------
        dict
            An OpenAI-format message with ``role="tool"``.
        """
        tool_id: str = str(getattr(call, "name", ""))
        call_id: str = str(getattr(call, "call_id", ""))
        args_json: str = str(getattr(call, "args_json", ""))

        try:
            args: dict[str, Any] = json.loads(args_json) if args_json else {}
        except json.JSONDecodeError:
            log.warning("Invalid JSON args for tool %r — treating as empty", tool_id)
            args = {}

        log.debug("Dispatching tool call", extra={"tool": tool_id, "call_id": call_id})

        try:
            result = await self._host.invoke(tool_id, args)
        except Exception:
            log.exception("Tool %r raised an error", tool_id)
            content = json.dumps({"error": f"Tool '{tool_id}' failed"})
        else:
            content = _serialise_result(result)

        return {
            "role": "tool",
            "tool_call_id": call_id,
            "content": content,
        }
