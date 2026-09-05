"""Cross-cutting protocol definitions for all subsystems."""

from typing import Any, Protocol


class ToolDescriptor(Protocol):
    """Tool metadata. SPEC-03 produces, SPEC-05 consumes."""


class ToolResult(Protocol):
    """Result of tool invocation. SPEC-03 produces, SPEC-05 consumes."""


class PluginInfo(Protocol):
    """Plugin metadata. SPEC-03B produces, SPEC-07 consumes."""


class MCPHost(Protocol):
    """MCP host for tools and plugins. SPEC-03B produces, SPEC-05/07/08 consume."""

    async def tools(self) -> list[ToolDescriptor]:
        """List available tools."""
        ...

    async def invoke(self, tool_id: str, args: dict[str, Any]) -> ToolResult:
        """Invoke a tool by ID with given arguments."""
        ...

    async def plugins(self) -> list[PluginInfo]:
        """List loaded plugins."""
        ...

    async def reload(self, plugin_id: str) -> None:
        """Reload a plugin by ID."""
        ...


class ConfirmationRequest(Protocol):
    """Confirmation prompt for destructive operations. SPEC-03B produces."""


class ConfirmationCallback(Protocol):
    """Confirmation response handler. SPEC-07 implements."""

    async def __call__(self, req: ConfirmationRequest) -> bool:
        """Handle a confirmation request, return user's decision."""
        ...


class AudioSession(Protocol):
    """Audio session state machine. SPEC-04 produces, SPEC-05 consumes."""


class AbortableTask(Protocol):
    """Long-running audio task that can be aborted. SPEC-04 produces."""


class TTSSpeaker(Protocol):
    """Text-to-speech interface. SPEC-04 produces, SPEC-05/08 consume."""

    async def speak(self, text: str) -> AbortableTask:
        """Speak text and return an abortable task."""
        ...


class LLMSession(Protocol):
    """LLM conversation session. SPEC-05 produces, SPEC-10 consumes."""


class Updater(Protocol):
    """Update manager. SPEC-06 produces, SPEC-10 consumes."""


class ToastPresenter(Protocol):
    """Toast notification interface. SPEC-07B produces, SPEC-06/08 consume."""


class UpdateAvailableCallback(Protocol):
    """Callback for update availability. SPEC-06 produces, SPEC-07B consumes."""
