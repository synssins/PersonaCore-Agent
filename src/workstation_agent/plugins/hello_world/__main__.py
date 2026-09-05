"""Hello-world canary MCP server.

Exposes a single tool: ``hello_world.echo(text: str) -> {text: str}``.
Runs as a line-delimited JSON-RPC 2.0 server over stdin/stdout.
Dependency-free so it can survive inside a low-integrity Job Object.
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


_TOOL = {
    "name": "hello_world.echo",
    "description": "Echoes the given text back to the caller.",
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string", "description": "Text to echo."}},
        "required": ["text"],
    },
}


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
                "serverInfo": {"name": "hello_world", "version": "0.1.0"},
            },
        )
        return True

    if method == "ping":
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": [_TOOL]})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if tool_name == "hello_world.echo":
            text = str(arguments.get("text", ""))
            _reply(
                request_id,
                {"content": [{"type": "text", "text": text}], "isError": False},
            )
        else:
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
