"""Line-delimited JSON-RPC 2.0 server for the ``shell``/``files``/``jobs`` families.

Why this loop is threaded, when every other bundled plugin's is not
-------------------------------------------------------------------
``mcp_host/watchdog.py`` pings every plugin every 10 s and gives it 5 s to
answer; a plugin that misses the window is **terminated** and reported dead.
Every other bundled plugin answers instantly, so a ``for raw in sys.stdin``
loop is fine for them.  This one blocks: ``jobs_wait`` is defined by §5.4 to
block for up to 25 s.  A single-threaded loop would therefore stop answering
``ping`` for longer than the watchdog tolerates and get itself killed —
reliably, on real hardware, while doing exactly what the contract asks.

So ``tools/call`` runs on a worker thread and the reader thread stays free for
``ping``.  ``MCPStdioClient`` matches replies by JSON-RPC id and holds a future
per request, so out-of-order replies are expected, not merely tolerated.
"""
# ruff: noqa: ANN401, T201
# ANN401: JSON-RPC ids and params are whatever the peer sent; Any is what a
#         JSON document actually is.
# T201:   stderr is this process's log channel — the supervisor pumps it into
#         the Agent's logger.  It never reaches the model.

from __future__ import annotations

import json
import sys
import threading
from typing import Any, Final

from workstation_agent.plugins.shell_files_jobs import (
    MAX_RESULT_CHARS,
    MAX_WAIT_S,
    REGISTRY,
    dispatch,
    render,
)

_WRITE_LOCK = threading.Lock()

_PROTOCOL_VERSION: Final = "2024-11-05"
_PLUGIN_ID: Final = "shell_files_jobs"
_VERSION: Final = "0.1.0"

#: §5.2 codes that are a normal outcome rather than a fault.  ``host``'s
#: ``ToolResultImpl`` draws the same line: "A refused or unconfirmed call is a
#: normal result (§5.2), not an error".
_NOT_A_FAULT: Final = frozenset({"denied", "unconfirmed", "unknown_job", "unknown_session"})

_PATH: Final = {
    "type": "string",
    "description": (
        "A path on the workstation, inside a declared root. "
        "A path outside the declared roots is denied."
    ),
}
_WAIT_S: Final = {
    "type": "integer",
    "description": (
        "Seconds to wait before returning a job handle instead of a result. "
        "Default 20, maximum 25."
    ),
    "minimum": 0,
    "maximum": MAX_WAIT_S,
    "default": 20,
}
_JOB_ID: Final = {"type": "string", "description": "A job id from a previous call."}
_FROM_BYTE: Final = {
    "type": "integer",
    "minimum": 0,
    "default": 0,
    "description": "Byte offset to start reading from.",
}
_MAX_BYTES: Final = {
    "type": "integer",
    "minimum": 1,
    "maximum": MAX_RESULT_CHARS,
    "description": f"Most bytes to return. Capped at {MAX_RESULT_CHARS}.",
}


def _obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


#: Transcribed from ``network_mcp/tools.py``'s ``SERVED_TOOLS`` so the plugin's
#: advertised schemas and the endpoint's frozen ones agree.  Contract §2 makes
#: a disagreement between what is served and what is registered a **terminal
#: load failure** on the core, so ``test_schemas_match_the_served_list`` pins
#: the two together.
_TOOLS: Final[list[dict[str, Any]]] = [
    {
        "name": "shell.run",
        "description": (
            "Run a command on the workstation and return its exit code, stdout and stderr. "
            "Long-running commands return a job id instead; page the output with jobs_output."
        ),
        "inputSchema": _obj(
            {
                "command": {"type": "string", "description": "The command line to run."},
                "cwd": {
                    "type": "string",
                    "description": "Working directory. Defaults to a declared root.",
                },
                "shell": {
                    "type": "string",
                    "enum": ["powershell", "cmd"],
                    "default": "powershell",
                    "description": "Which shell interprets the command.",
                },
                "wait_s": _WAIT_S,
            },
            ["command"],
        ),
    },
    {
        "name": "files.list",
        "description": (
            "List the entries of a directory on the workstation, inside a declared root."
        ),
        "inputSchema": _obj({"path": _PATH}, ["path"]),
    },
    {
        "name": "files.read",
        "description": (
            "Read a text file on the workstation, inside a declared root. "
            "Binary files are refused; large files are paged with from_byte."
        ),
        "inputSchema": _obj(
            {"path": _PATH, "from_byte": _FROM_BYTE, "max_bytes": _MAX_BYTES},
            ["path"],
        ),
    },
    {
        "name": "files.write",
        "description": (
            "Write text to a file on the workstation, inside a declared root. "
            "Overwrites unless append is true."
        ),
        "inputSchema": _obj(
            {
                "path": _PATH,
                "content": {"type": "string", "description": "The text to write."},
                "append": {
                    "type": "boolean",
                    "default": False,
                    "description": "Append instead of overwriting. Defaults to false.",
                },
            },
            ["path", "content"],
        ),
    },
    {
        "name": "jobs.wait",
        "description": "Wait for a running job to finish, or until wait_s elapses.",
        "inputSchema": _obj({"job_id": _JOB_ID, "wait_s": _WAIT_S}, ["job_id"]),
    },
    {
        "name": "jobs.output",
        "description": "Page the captured output of a job.",
        "inputSchema": _obj(
            {"job_id": _JOB_ID, "from_byte": _FROM_BYTE, "max_bytes": _MAX_BYTES},
            ["job_id"],
        ),
    },
    {
        "name": "jobs.list",
        "description": "List running jobs and jobs that finished in the last 30 minutes.",
        "inputSchema": _obj({}),
    },
    {
        "name": "jobs.kill",
        "description": "Terminate a running job and its process tree.",
        "inputSchema": _obj({"job_id": _JOB_ID}, ["job_id"]),
    },
]


def _send(msg: dict[str, Any]) -> None:
    """Write one JSON-RPC message.

    ``ensure_ascii`` is left at its default so the line is pure ASCII whatever
    the console codepage happens to be.  The payload was already proved
    UTF-8-encodable by ``finalise``; this is about the pipe, not the content.
    """
    line = json.dumps(msg, separators=(",", ":")) + "\n"
    with _WRITE_LOCK:
        sys.stdout.write(line)
        sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _prompt_seconds(params: dict[str, Any]) -> float | None:
    """Read the host's confirmation-prompt duration, if it sent one.

    Nothing sends this today.  ``clamp_wait`` explains why the number matters
    and what it falls back to without it; accepting it here means the host
    change, when it lands, needs no change on this side.
    """
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    value = meta.get("prompt_ms")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0.0, float(value) / 1000.0)


def _run_tool(request_id: Any, params: dict[str, Any]) -> None:
    tool = str(params.get("name", ""))
    try:
        args = params.get("arguments")
        payload = dispatch(
            tool,
            args if isinstance(args, dict) else {},
            prompt_s=_prompt_seconds(params),
        )
    except BaseException:  # noqa: BLE001 - see below
        # A worker thread that dies without replying is a request the host
        # waits 30 s for and then reports as a dead plugin.  `dispatch` already
        # turns every Exception into an envelope; this catches what it cannot
        # (a MemoryError, a RecursionError raised while building the envelope)
        # so the caller always gets an answer.
        print(f"[{tool}] worker failed; see the Agent log", file=sys.stderr)
        payload = {
            "ok": False,
            "code": "error",
            "reason": "the tool failed on this workstation",
        }
    code = payload.get("code")
    is_error = not payload.get("ok", False) and code not in _NOT_A_FAULT
    # `render`, not a local json.dumps: `finalise` measured the cap against
    # this exact string, and a second spelling here would let a payload it
    # approved arrive longer than 60,000 characters after all.
    _reply(
        request_id,
        {"content": [{"type": "text", "text": render(payload)}], "isError": is_error},
    )


def _handle(msg: dict[str, Any]) -> bool:  # noqa: PLR0911 - one return per JSON-RPC method
    """Process one message; return False to stop the event loop."""
    method = msg.get("method")
    request_id = msg.get("id")
    if request_id is None:  # a notification
        return True

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": _PLUGIN_ID, "version": _VERSION},
            },
        )
        return True

    if method == "ping":
        # Answered on the reader thread, never queued behind a blocking tool.
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": _TOOLS})
        return True

    if method == "tools/call":
        params = msg.get("params") or {}
        threading.Thread(
            target=_run_tool,
            args=(request_id, params if isinstance(params, dict) else {}),
            name=f"call-{request_id}",
            daemon=True,
        ).start()
        return True

    if method == "shutdown":
        # §5.4: jobs die with the Agent.  The Job Object would collect them
        # anyway, but only once the *host* exits; a plugin reload would
        # otherwise leave orphans running against a registry that no longer
        # knows their ids.
        REGISTRY.kill_all()
        _reply(request_id, {})
        return False

    _send({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"unknown method: {method}"},
    })
    return True


def main() -> None:
    """Read JSON-RPC messages from stdin until the peer shuts us down."""
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
        if not _handle(msg):
            break
    REGISTRY.kill_all()


if __name__ == "__main__":
    main()
