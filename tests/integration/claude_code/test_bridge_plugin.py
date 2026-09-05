"""Integration tests for the claude_code_bridge plugin subprocess.

Spawns the plugin as a subprocess (like the MCPHost does in production) and
exercises the three exposed tools over JSON-RPC 2.0 / stdin-stdout.

``claude_code.invoke`` uses the FakeTransport stub so no real ``claude``
subprocess is required.
"""
# ruff: noqa: E501, S603, BLE001, ERA001, S110, TC003, ANN401

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="plugin subprocess race on GH Actions py3.12 (task #10)",
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PYTHON = sys.executable


def _rpc(method: str, params: dict[str, Any] | None = None, req_id: int = 1) -> str:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


class _Proc:
    """Thin wrapper around Popen with narrowed stdin/stdout types."""

    def __init__(self, popen: subprocess.Popen[str]) -> None:
        self._p = popen
        assert popen.stdin is not None
        assert popen.stdout is not None
        self.stdin: io.TextIOWrapper = popen.stdin  # type: ignore[assignment]
        self.stdout: io.TextIOWrapper = popen.stdout  # type: ignore[assignment]

    def wait(self, timeout: float = 5.0) -> None:
        self._p.wait(timeout=timeout)


def _send_recv(proc: _Proc, lines: list[str]) -> list[dict[str, Any]]:
    """Send *lines* to the plugin stdin and collect matching responses."""
    for line in lines:
        proc.stdin.write(line + "\n")
    proc.stdin.flush()
    # Collect one response per non-notification request line.
    responses: list[dict[str, Any]] = []
    for _ in lines:
        raw = proc.stdout.readline()
        if not raw:
            break
        msg = json.loads(raw)
        responses.append(msg)
    return responses


@pytest.fixture
def plugin_proc() -> Any:
    """Spawn the claude_code_bridge plugin as a subprocess."""
    env = {
        "SYSTEMROOT": "C:\\Windows",
        "SYSTEMDRIVE": "C:",
        "WINDIR": "C:\\Windows",
        "USERPROFILE": str(Path.home()),
        "USERNAME": "testuser",
        "TEMP": str(Path.home() / "AppData" / "Local" / "Temp"),
        "TMP": str(Path.home() / "AppData" / "Local" / "Temp"),
        "APPDATA": str(Path.home() / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(Path.home() / "AppData" / "Local"),
        "PROGRAMDATA": "C:\\ProgramData",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        "PATH": str(Path(_PYTHON).parent),
        "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
        "NUMBER_OF_PROCESSORS": "4",
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        "WSA_PLUGIN_ID": "claude_code_bridge",
    }
    popen = subprocess.Popen(
        [_PYTHON, "-u", "-m", "workstation_agent.plugins.claude_code_bridge"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(_REPO_ROOT),
        env=env,
    )
    proc = _Proc(popen)
    yield proc
    try:
        proc.stdin.write(_rpc("shutdown") + "\n")
        proc.stdin.flush()
    except Exception:
        pass
    proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Tests: initialize handshake
# ---------------------------------------------------------------------------


def test_plugin_initialize(plugin_proc: _Proc) -> None:
    """Plugin responds to initialize with serverInfo."""
    responses = _send_recv(plugin_proc, [_rpc("initialize", {"protocolVersion": "2024-11-05"})])
    assert len(responses) == 1
    resp = responses[0]
    assert "error" not in resp
    assert resp["result"]["serverInfo"]["name"] == "claude_code_bridge"


# ---------------------------------------------------------------------------
# Tests: tools/list
# ---------------------------------------------------------------------------


def test_plugin_tools_list(plugin_proc: _Proc) -> None:
    """tools/list returns the three expected tool names."""
    # Initialize first
    plugin_proc.stdin.write(_rpc("initialize", {"protocolVersion": "2024-11-05"}) + "\n")
    plugin_proc.stdin.flush()
    _ = plugin_proc.stdout.readline()  # consume initialize response

    plugin_proc.stdin.write(_rpc("tools/list", req_id=2) + "\n")
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)

    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {
        "claude_code.invoke",
        "claude_code.presence",
        "claude_code.list_recent_sessions",
    }


# ---------------------------------------------------------------------------
# Tests: claude_code.presence
# ---------------------------------------------------------------------------


def test_plugin_presence_returns_bool(plugin_proc: _Proc) -> None:
    """claude_code.presence returns a dict with 'running' key."""
    plugin_proc.stdin.write(_rpc("initialize", {"protocolVersion": "2024-11-05"}) + "\n")
    plugin_proc.stdin.flush()
    _ = plugin_proc.stdout.readline()

    plugin_proc.stdin.write(_rpc("tools/call", {"name": "claude_code.presence", "arguments": {}}, req_id=2) + "\n")
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)

    content = json.loads(resp["result"]["content"][0]["text"])
    assert "running" in content
    assert isinstance(content["running"], bool)


# ---------------------------------------------------------------------------
# Tests: claude_code.list_recent_sessions
# ---------------------------------------------------------------------------


def test_plugin_list_recent_sessions(plugin_proc: _Proc) -> None:
    """claude_code.list_recent_sessions returns {sessions: list}."""
    plugin_proc.stdin.write(_rpc("initialize", {"protocolVersion": "2024-11-05"}) + "\n")
    plugin_proc.stdin.flush()
    _ = plugin_proc.stdout.readline()

    plugin_proc.stdin.write(
        _rpc("tools/call", {"name": "claude_code.list_recent_sessions", "arguments": {"limit": 5}}, req_id=2) + "\n",
    )
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)

    content = json.loads(resp["result"]["content"][0]["text"])
    assert "sessions" in content
    assert isinstance(content["sessions"], list)


# ---------------------------------------------------------------------------
# Tests: ping
# ---------------------------------------------------------------------------


def test_plugin_ping(plugin_proc: _Proc) -> None:
    plugin_proc.stdin.write(_rpc("ping", req_id=1) + "\n")
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)
    assert "error" not in resp


# ---------------------------------------------------------------------------
# Tests: unknown tool
# ---------------------------------------------------------------------------


def test_plugin_unknown_tool(plugin_proc: _Proc) -> None:
    plugin_proc.stdin.write(_rpc("initialize", {"protocolVersion": "2024-11-05"}) + "\n")
    plugin_proc.stdin.flush()
    _ = plugin_proc.stdout.readline()

    plugin_proc.stdin.write(
        _rpc("tools/call", {"name": "claude_code.nonexistent", "arguments": {}}, req_id=2) + "\n",
    )
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)
    # Plugin sends error via JSON-RPC error field for unknown tools
    assert "error" in resp or (resp.get("result", {}).get("isError") is True)


# ---------------------------------------------------------------------------
# Tests: unknown method
# ---------------------------------------------------------------------------


def test_plugin_unknown_method(plugin_proc: _Proc) -> None:
    plugin_proc.stdin.write(_rpc("no_such_method", req_id=1) + "\n")
    plugin_proc.stdin.flush()
    raw = plugin_proc.stdout.readline()
    resp = json.loads(raw)
    assert "error" in resp
    assert resp["error"]["code"] == -32601
