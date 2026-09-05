"""MCP server for Desktop Control.

Exposes 5 tools with stub implementations returning not_implemented status.
Runs as a line-delimited JSON-RPC 2.0 server over stdin/stdout.
"""
# ruff: noqa: ANN401, PLR0911, PLW2901

from __future__ import annotations

import json
import sys
from typing import Any


def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


_TOOLS = [
    {
        "name": "desktop.click",
        "description": "Click at screen coordinates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer", "description": "X coordinate."},
                "y": {"type": "integer", "description": "Y coordinate."},
            },
            "required": ["x", "y"],
        },
    },
    {
        "name": "desktop.type",
        "description": "Type text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to type."}},
            "required": ["text"],
        },
    },
    {
        "name": "desktop.key",
        "description": "Press a keyboard key combination.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "combo": {"type": "string", "description": "Key combination (e.g. 'ctrl+a')."},
            },
            "required": ["combo"],
        },
    },
    {
        "name": "desktop.list_windows",
        "description": "List open windows.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "desktop.focus_window",
        "description": "Focus a window by title pattern.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title_pattern": {"type": "string", "description": "Window title pattern."},
            },
            "required": ["title_pattern"],
        },
    },
]


def _handle(msg: dict[str, Any]) -> bool:
    """Process one message; return False to stop the event loop."""
    method = msg.get("method")
    request_id = msg.get("id")

    # Notifications from client (no id) → ignore
    if request_id is None:
        return True

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "desktop_control", "version": "0.1.0"},
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
        tool_name = params.get("name")

        # Return not_implemented for all tools
        _reply(
            request_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "status": "not_implemented",
                                "plugin": "desktop_control",
                                "tool": tool_name,
                                "note": "framework stub — implementation lands in v0.2",
                            },
                        ),
                    },
                ],
                "isError": False,
            },
        )
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
