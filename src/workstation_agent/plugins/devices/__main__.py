"""MCP server for the ``devices`` family.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Line-delimited JSON-RPC 2.0 over stdin/stdout, matching the other bundled
plugins.  The tool name advertised here is the **dotted** ``devices.list``:
``host.invoke`` resolves a tool by matching this name exactly, and the
underscore wire spelling ``devices_list`` is translated at the network
endpoint and never reaches the gate.
"""
# ruff: noqa: ANN401

from __future__ import annotations

import json
import sys
from typing import Any

from workstation_agent.plugins.devices import devices_list


def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


TOOLS = [
    {
        "name": "devices.list",
        "description": (
            "List everything currently attached to the workstation: USB devices, "
            "ADB devices, and COM ports."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a §5.2 result object as an MCP ``tools/call`` result.

    ``isError`` mirrors ``ok`` so the host's envelope agrees with the JSON body;
    ``conform_result`` derives its own ``ok`` from ``isError`` and the two
    disagreeing is how a failure reaches the model looking like a success.
    """
    return {
        "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
        "isError": not payload.get("ok", False),
    }


def call_tool(name: str, _arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one ``tools/call``."""
    if name == "devices.list":
        return _tool_result(devices_list())
    return _tool_result({
        "ok": False,
        "code": "not_found",
        "reason": "This workstation has no such tool in the devices family.",
    })


def handle(msg: dict[str, Any]) -> bool:  # noqa: PLR0911 — one branch per JSON-RPC method
    """Process one message; return False to stop the event loop."""
    method = msg.get("method")
    request_id = msg.get("id")

    if request_id is None:
        return True

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "devices", "version": "0.1.0"},
            },
        )
        return True

    if method == "ping":
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": TOOLS})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        _reply(request_id, call_tool(str(params.get("name")), arguments))
        return True

    if method == "shutdown":
        _reply(request_id, {})
        return False

    _error(request_id, -32601, f"unknown method: {method}")
    return True


def main() -> None:
    """Process stdin line by line."""
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        if not handle(msg):
            break


if __name__ == "__main__":
    main()
