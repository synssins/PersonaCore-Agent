"""MCP server for the ``adb`` family.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Line-delimited JSON-RPC 2.0 over stdin/stdout, matching the other bundled
plugins.  Tool names advertised here are the **dotted** ``adb.devices``,
``adb.shell``, ``adb.push``, ``adb.pull``, ``adb.install`` and ``adb.logcat``:
``host.invoke`` matches this name exactly against the manifest's ``args:``
declarations, and the underscore wire spelling (``adb_pull``) is translated at
the network endpoint and never reaches the gate.  A mismatch here would produce
tools nobody can call, because the gate is default-deny.
"""
# ruff: noqa: ANN401

from __future__ import annotations

import json
import sys
from typing import Any

from workstation_agent.plugins.adb import (
    adb_devices,
    adb_install,
    adb_logcat,
    adb_pull,
    adb_push,
    adb_shell,
    sanitise_reason,
)


def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


_SERIAL = {
    "type": "string",
    "description": "The ADB device serial. Optional when exactly one device is attached.",
}
_WAIT_S = {
    "type": "integer",
    "description": "Seconds to wait before returning a job handle instead of a result. "
                   "Default 20, maximum 25.",
    "minimum": 0,
    "maximum": 25,
    "default": 20,
}
_WS_PATH = {
    "type": "string",
    "description": "A path on the workstation, inside a declared root. "
                   "A path outside the declared roots is denied.",
}

TOOLS = [
    {
        "name": "adb.devices",
        "description": "List the Android devices ADB can see, with their state and model.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "adb.shell",
        "description": (
            "Run a shell command on an attached Android device. "
            "Long-running commands return a job id."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": _SERIAL,
                "command": {"type": "string", "description": "The command to run on the device."},
                "wait_s": _WAIT_S,
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "adb.push",
        "description": (
            "Copy a file from the workstation onto an attached Android device. "
            "The workstation path must be inside a declared root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": _SERIAL,
                "workstation_path": _WS_PATH,
                "device_path": {
                    "type": "string",
                    "description": "Destination path on the device.",
                },
            },
            "required": ["workstation_path", "device_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "adb.pull",
        "description": (
            "Read a text file from an attached Android device. "
            "Binary transfer is not available yet."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": _SERIAL,
                "device_path": {"type": "string", "description": "Path on the device to read."},
            },
            "required": ["device_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "adb.install",
        "description": (
            "Install an APK from the workstation onto an attached Android device. "
            "The workstation path must be inside a declared root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"serial": _SERIAL, "workstation_path": _WS_PATH},
            "required": ["workstation_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "adb.logcat",
        "description": "Capture logcat from an attached Android device for a few seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": _SERIAL,
                "seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 5,
                    "description": "How long to capture. Maximum 20.",
                },
                "filter": {
                    "type": "string",
                    "description": "An optional logcat filter expression.",
                },
            },
            "additionalProperties": False,
        },
    },
]


def _tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a §5.2 result object as an MCP ``tools/call`` result.

    ``isError`` mirrors ``ok`` so the host's envelope agrees with the JSON body;
    ``conform_result`` derives its own ``ok`` from ``isError``, and the two
    disagreeing is how a failure reaches the model looking like a success.
    """
    return {
        "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
        "isError": not payload.get("ok", False),
    }


def _str_or_none(value: Any) -> str | None:
    """Coerce an optional argument to ``str`` without inventing one."""
    return value if isinstance(value, str) else None


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911
    """Dispatch one ``tools/call`` to the family.

    Every branch is wrapped by :func:`handle`'s guard rather than here, so an
    unexpected exception becomes a §5.2 ``error`` with a sanitised reason and
    never a traceback on the wire.
    """
    serial = _str_or_none(arguments.get("serial"))
    if name == "adb.devices":
        return _tool_result(adb_devices())
    if name == "adb.shell":
        return _tool_result(
            adb_shell(
                command=_str_or_none(arguments.get("command")) or "",
                serial=serial,
                wait_s=arguments.get("wait_s"),
            ),
        )
    if name == "adb.push":
        return _tool_result(
            adb_push(
                workstation_path=_str_or_none(arguments.get("workstation_path")) or "",
                device_path=_str_or_none(arguments.get("device_path")) or "",
                serial=serial,
            ),
        )
    if name == "adb.pull":
        return _tool_result(
            adb_pull(
                device_path=_str_or_none(arguments.get("device_path")) or "",
                serial=serial,
            ),
        )
    if name == "adb.install":
        return _tool_result(
            adb_install(
                workstation_path=_str_or_none(arguments.get("workstation_path")) or "",
                serial=serial,
            ),
        )
    if name == "adb.logcat":
        return _tool_result(
            adb_logcat(
                serial=serial,
                seconds=arguments.get("seconds"),
                # The schema argument is `filter`, which is a Python builtin;
                # the parameter is `log_filter` and the mapping happens here.
                log_filter=_str_or_none(arguments.get("filter")),
            ),
        )
    return _tool_result({
        "ok": False,
        "code": "not_found",
        "reason": "This workstation has no such tool in the adb family.",
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
                "serverInfo": {"name": "adb", "version": "0.1.0"},
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
        try:
            result = call_tool(str(params.get("name")), arguments)
        except Exception as exc:  # noqa: BLE001 — a traceback must never reach the wire
            result = _tool_result({
                "ok": False,
                "code": "error",
                "reason": sanitise_reason(str(exc)) or "The command failed on this workstation.",
            })
        _reply(request_id, result)
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
