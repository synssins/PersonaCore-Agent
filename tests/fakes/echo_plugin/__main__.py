"""Tiniest possible MCP server used by SPEC-03A + SPEC-03B tests.

Speaks line-delimited JSON-RPC 2.0 over stdin/stdout. Implements the subset the
SPEC-03A client exercises: `initialize`, `tools/list`, `tools/call` (single
`hello.echo(text)` tool), `ping`, `shutdown`, plus a `notifications/hello`
notification emitted right after `initialize`.

Kept dependency-free so it can be spawned by `python -m tests.fakes.echo_plugin`
inside a low-integrity, job-object-wrapped subprocess with the SPEC-03A env
whitelist applied.
"""
# ruff: noqa: ANN401, PLR0911, PLW2901

from __future__ import annotations

import json
import os
import sys
from typing import Any


def _send(msg: dict[str, Any]) -> None:
    line = json.dumps(msg, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


TOOL_DESCRIPTOR = {
    "name": "hello.echo",
    "description": "Echoes the given text back to the caller.",
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
}


def _handle(msg: dict[str, Any]) -> bool:
    """Handle one message; return False to stop the loop."""
    method = msg.get("method")
    request_id = msg.get("id")

    # Notifications from client -> ignore silently.
    if request_id is None:
        return True

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "echo_plugin", "version": "0.0.1"},
            },
        )
        # Emit a hello notification the client's async iterator can pick up.
        _send({"jsonrpc": "2.0", "method": "notifications/hello", "params": {"who": "echo"}})
        return True

    if method == "ping":
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": [TOOL_DESCRIPTOR]})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name")
        args = params.get("arguments") or {}
        if tool_name == "hello.echo":
            text = args.get("text", "")
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

    if method == "env/dump":
        # Test-only method: dump the current env so the whitelist test can
        # assert the subprocess sees exactly the SPEC-03A allow list.
        _reply(request_id, {"env": dict(os.environ)})
        return True

    _error(request_id, -32601, f"unknown method: {method}")
    return True


def main() -> None:
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
