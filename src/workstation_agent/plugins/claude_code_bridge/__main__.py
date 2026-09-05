"""Claude Code bridge MCP server (subprocess plugin entry point).

Exposes three tools over JSON-RPC 2.0 / stdin-stdout:

- ``claude_code.invoke`` — run a Claude Code session.
- ``claude_code.presence`` — detect whether CC is running.
- ``claude_code.list_recent_sessions`` — enumerate ~/.claude/projects/*.

Streaming events from ``claude_code.invoke`` are sent back as JSON-RPC
notifications (``notifications/claude_code.event``) while the tool_call is
still in-flight; the final response is the complete list of events.
"""
# ruff: noqa: ANN401, PLR0911, PLW2901, PLC0415, C901, FBT001, ARG001

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any


def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def _notify(method: str, params: dict[str, Any]) -> None:
    _send({"jsonrpc": "2.0", "method": method, "params": params})


_TOOLS: list[dict[str, Any]] = [
    {
        "name": "claude_code.invoke",
        "description": (
            "Run a Claude Code session for the given prompt. "
            "Streams events back as MCP notifications. "
            "Returns {events: [...]} when complete."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Prompt for Claude Code."},
                "cwd": {"type": "string", "description": "Optional working directory."},
                "voice_approval": {
                    "type": "boolean",
                    "description": "Whether to use voice-mediated tool approval.",
                    "default": True,
                },
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "claude_code.presence",
        "description": "Return {running: bool, cwd?: str} for a running Claude Code process.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "claude_code.list_recent_sessions",
        "description": "List recent Claude Code sessions from ~/.claude/projects/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum sessions to return.",
                    "default": 20,
                },
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _tool_presence() -> dict[str, Any]:
    from workstation_agent.claude_code.presence import active_project, is_running

    running = is_running()
    proj = active_project()
    result: dict[str, Any] = {"running": running}
    if proj is not None:
        result["cwd"] = str(proj)
    return result


def _tool_list_recent_sessions(limit: int = 20) -> dict[str, Any]:
    projects_dir = Path.home() / ".claude" / "projects"
    if not projects_dir.exists():
        return {"sessions": []}

    sessions: list[dict[str, Any]] = []
    for project_dir in sorted(
        projects_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True,
    ):
        if not project_dir.is_dir():
            continue
        sessions.append({"project": project_dir.name, "path": str(project_dir)})
        if len(sessions) >= limit:
            break
    return {"sessions": sessions}


def _tool_invoke_sync(
    prompt: str,
    cwd: str | None,
    voice_approval: bool,
    request_id: Any,
) -> dict[str, Any]:
    """Run ClaudeCodeDriver synchronously and return collected events."""
    events: list[dict[str, Any]] = []

    async def _run() -> None:
        from workstation_agent.claude_code.driver import ClaudeCodeDriver

        driver = ClaudeCodeDriver()
        cwd_path = Path(cwd) if cwd else None

        async for event in driver.run(prompt, cwd=cwd_path):
            ev_dict = {
                "kind": event.kind,
                "tool_name": event.tool_name,
                "approved": event.approved,
            }
            events.append(ev_dict)
            # Emit a notification so the host can stream events in real-time.
            _notify(
                "notifications/claude_code.event",
                {"request_id": str(request_id), "event": ev_dict},
            )

    asyncio.run(_run())
    return {"events": events}


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _ok_content(result: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(result)}], "isError": False}


def _err_content(exc: Exception) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": str(exc)}], "isError": True}


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


def _handle(msg: dict[str, Any]) -> bool:
    """Process one message; return False to stop the server loop."""
    method = msg.get("method")
    request_id = msg.get("id")

    # Notifications (no id) — silently ignore.
    if request_id is None:
        return True

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "claude_code_bridge", "version": "0.1.0"},
            },
        )
        return True

    if method == "ping":
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": _TOOLS})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}

        if tool_name == "claude_code.presence":
            try:
                result = _tool_presence()
                _reply(request_id, _ok_content(result))
            except Exception as exc:  # noqa: BLE001
                _reply(request_id, _err_content(exc))
            return True

        if tool_name == "claude_code.list_recent_sessions":
            try:
                limit = int(arguments.get("limit", 20))
                result = _tool_list_recent_sessions(limit)
                _reply(request_id, _ok_content(result))
            except Exception as exc:  # noqa: BLE001
                _reply(request_id, _err_content(exc))
            return True

        if tool_name == "claude_code.invoke":
            try:
                prompt = str(arguments.get("prompt", ""))
                cwd = arguments.get("cwd")
                voice_approval = bool(arguments.get("voice_approval", True))
                result = _tool_invoke_sync(prompt, cwd, voice_approval, request_id)
                _reply(request_id, _ok_content(result))
            except Exception as exc:  # noqa: BLE001
                _reply(request_id, _err_content(exc))
            return True

        _error(request_id, -32601, f"unknown tool: {tool_name}")
        return True

    if method == "shutdown":
        _reply(request_id, {})
        return False

    _error(request_id, -32601, f"unknown method: {method}")
    return True


def main() -> None:
    """Main entry point: process stdin line by line."""
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not _handle(msg):
            break


if __name__ == "__main__":
    main()
