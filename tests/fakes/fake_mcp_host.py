"""Fake MCPHost for unit and integration tests.

Implements the :class:`~workstation_agent.protocols.MCPHost` Protocol with
configurable tool descriptors and hardcoded invocation results.
"""

from __future__ import annotations

from typing import Any


class FakeToolDescriptor:
    """Simple tool descriptor for tests."""

    def __init__(
        self,
        name: str,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema or {"type": "object", "properties": {}}


class FakeMCPHost:
    """In-memory MCPHost that returns configurable tool results.

    Parameters
    ----------
    tools:
        List of :class:`FakeToolDescriptor` objects to expose.
    results:
        Mapping of ``tool_name`` -> result dict.  If a tool is not in the map
        the host returns ``{"ok": True}``.
    """

    def __init__(
        self,
        tools: list[FakeToolDescriptor] | None = None,
        results: dict[str, Any] | None = None,
    ) -> None:
        self._tools = tools or []
        self._results = results or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def tools(self) -> list[FakeToolDescriptor]:
        """Return the list of available fake tools."""
        return list(self._tools)

    async def invoke(self, tool_id: str, args: dict[str, Any]) -> dict[str, Any]:
        """Record the call and return the configured result."""
        self.calls.append((tool_id, args))
        return self._results.get(tool_id, {"ok": True})

    async def plugins(self) -> list[Any]:
        """Return empty plugin list."""
        return []

    async def reload(self, plugin_id: str) -> None:
        """No-op reload."""
        _ = plugin_id
