"""Unit tests for claude_code.presence — mocked process enumeration."""
# ruff: noqa: ERA001, SIM117, N806, E501

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from workstation_agent.claude_code.presence import (
    _find_claude_process,
    _is_claude_process,
    _iter_processes,
    active_project,
    is_running,
)

# ---------------------------------------------------------------------------
# Helpers: fake psutil process objects
# ---------------------------------------------------------------------------


def _make_proc(name: str, cmdline: list[str] | None = None, cwd: str = "/some/project") -> MagicMock:
    """Build a mock psutil.Process-like object."""
    proc = MagicMock()
    proc.info = {"name": name, "cmdline": cmdline or [], "pid": 1234}
    proc.cwd.return_value = cwd
    return proc


def _make_psutil_module(processes: list[MagicMock], proc_class: type = MagicMock) -> MagicMock:
    """Build a minimal mock psutil module."""
    psutil_mod = MagicMock()
    psutil_mod.process_iter.return_value = processes
    psutil_mod.Process = proc_class
    return psutil_mod


# ---------------------------------------------------------------------------
# Tests: _iter_processes
# ---------------------------------------------------------------------------


def test_iter_processes_returns_list_when_psutil_available() -> None:
    """_iter_processes calls psutil.process_iter and returns its result."""
    fake_proc = _make_proc("claude.exe")
    psutil_mod = _make_psutil_module([fake_proc])

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _iter_processes()
    assert result == [fake_proc]
    psutil_mod.process_iter.assert_called_once()


def test_iter_processes_returns_empty_on_import_error() -> None:
    """_iter_processes returns [] if psutil is unavailable."""
    with patch.dict(sys.modules, {"psutil": None}):  # type: ignore[dict-item]
        result = _iter_processes()
    assert result == []


def test_iter_processes_returns_empty_on_exception() -> None:
    """_iter_processes returns [] if psutil.process_iter raises."""
    psutil_mod = MagicMock()
    psutil_mod.process_iter.side_effect = RuntimeError("fail")

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _iter_processes()
    assert result == []


# ---------------------------------------------------------------------------
# Tests: _is_claude_process
# ---------------------------------------------------------------------------


def _make_psutil_process(name: str, cmdline: list[str] | None = None) -> MagicMock:
    """Return a mock that IS an instance of a class we control."""
    # We need isinstance(proc, psutil.Process) to work.
    # Use a real class as the psutil.Process type.
    class FakeProcess:
        def __init__(self) -> None:
            self.info = {"name": name, "cmdline": cmdline or [], "pid": 1}

    proc = FakeProcess()
    # Patch psutil.Process to be FakeProcess so isinstance works
    return proc, FakeProcess  # type: ignore[return-value]


def test_is_claude_process_claude_exe() -> None:
    """claude.exe → True."""
    proc, FakeProcess = _make_psutil_process("claude.exe")  # type: ignore[assignment]
    psutil_mod = MagicMock()
    psutil_mod.Process = FakeProcess

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is True


def test_is_claude_process_claude_no_ext() -> None:
    """claude (no .exe) → True."""
    proc, FakeProcess = _make_psutil_process("claude")  # type: ignore[assignment]
    psutil_mod = MagicMock()
    psutil_mod.Process = FakeProcess

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is True


def test_is_claude_process_node_with_claude_cmdline() -> None:
    """node.exe with claude in cmdline → True."""
    proc, FakeProcess = _make_psutil_process("node.exe", ["/usr/local/bin/claude"])  # type: ignore[assignment]
    psutil_mod = MagicMock()
    psutil_mod.Process = FakeProcess

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is True


def test_is_claude_process_node_without_claude_cmdline() -> None:
    """node.exe without claude in cmdline → False."""
    proc, FakeProcess = _make_psutil_process("node.exe", ["node.exe", "server.js"])  # type: ignore[assignment]
    psutil_mod = MagicMock()
    psutil_mod.Process = FakeProcess

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is False


def test_is_claude_process_python() -> None:
    """python.exe → False."""
    proc, FakeProcess = _make_psutil_process("python.exe", ["python.exe", "script.py"])  # type: ignore[assignment]
    psutil_mod = MagicMock()
    psutil_mod.Process = FakeProcess

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is False


def test_is_claude_process_not_psutil_process() -> None:
    """Object that is not an instance of psutil.Process → False."""
    psutil_mod = MagicMock()
    psutil_mod.Process = type("NeverMatch", (), {})  # type that no mock is instance of

    some_obj = MagicMock()
    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(some_obj)
    assert result is False


def test_is_claude_process_exception_returns_false() -> None:
    """Exception during inspection → False (no crash)."""
    proc = MagicMock()
    proc.info = MagicMock(side_effect=RuntimeError("crash"))

    psutil_mod = MagicMock()
    psutil_mod.Process = type("Cls", (), {})

    with patch.dict(sys.modules, {"psutil": psutil_mod}):
        result = _is_claude_process(proc)
    assert result is False


# ---------------------------------------------------------------------------
# Tests: _find_claude_process
# ---------------------------------------------------------------------------


def test_find_claude_process_returns_none_when_empty() -> None:
    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[]):
        result = _find_claude_process()
    assert result is None


def test_find_claude_process_returns_first_match() -> None:
    proc1 = _make_proc("python.exe")
    proc2 = _make_proc("claude.exe")

    def _fake_is_claude(p: object) -> bool:
        return p is proc2

    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[proc1, proc2]):
        with patch("workstation_agent.claude_code.presence._is_claude_process", side_effect=_fake_is_claude):
            result = _find_claude_process()
    assert result is proc2


# ---------------------------------------------------------------------------
# Tests: is_running
# ---------------------------------------------------------------------------


def test_is_running_detects_claude_exe() -> None:
    """claude.exe process → is_running() returns True."""
    proc = _make_proc("claude.exe", cwd="C:/Users/user/project")

    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[proc]):
        with patch("workstation_agent.claude_code.presence._is_claude_process", return_value=True):
            assert is_running() is True


def test_is_running_detects_claude_no_extension() -> None:
    """claude (no .exe) process → is_running() returns True."""
    proc = _make_proc("claude", cwd="/home/user/project")

    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[proc]):
        with patch("workstation_agent.claude_code.presence._is_claude_process", return_value=True):
            assert is_running() is True


def test_is_running_false_when_no_process() -> None:
    """No Claude process and no lockfile → is_running() returns False."""
    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[]):
        with patch("workstation_agent.claude_code.presence._CLAUDE_LOCK") as mock_lock:
            mock_lock.exists.return_value = False
            assert is_running() is False


def test_is_running_lockfile_fallback() -> None:
    """No process but lockfile exists → is_running() returns True."""
    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[]):
        with patch("workstation_agent.claude_code.presence._CLAUDE_LOCK") as mock_lock:
            mock_lock.exists.return_value = True
            assert is_running() is True


def test_is_running_unrelated_process_ignored() -> None:
    """An unrelated process (e.g. python.exe) is not detected as Claude."""
    proc = _make_proc("python.exe", cmdline=["python.exe", "myscript.py"])

    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[proc]):
        with patch("workstation_agent.claude_code.presence._is_claude_process", return_value=False):
            with patch("workstation_agent.claude_code.presence._CLAUDE_LOCK") as mock_lock:
                mock_lock.exists.return_value = False
                assert is_running() is False


def test_is_running_node_with_claude_cmdline() -> None:
    """node.exe running a claude script → detected."""
    proc = _make_proc("node.exe", cmdline=["node.exe", "/usr/local/bin/claude"])

    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[proc]):
        with patch("workstation_agent.claude_code.presence._is_claude_process", return_value=True):
            assert is_running() is True


def test_is_running_psutil_unavailable() -> None:
    """If _iter_processes returns empty, falls back to lockfile check."""
    with patch("workstation_agent.claude_code.presence._iter_processes", return_value=[]):
        with patch("workstation_agent.claude_code.presence._CLAUDE_LOCK") as mock_lock:
            mock_lock.exists.return_value = False
            result = is_running()
    assert result is False


# ---------------------------------------------------------------------------
# Tests: active_project
# ---------------------------------------------------------------------------


def test_active_project_returns_none_when_not_running() -> None:
    """No Claude process → active_project() returns None."""
    with patch("workstation_agent.claude_code.presence._find_claude_process", return_value=None):
        assert active_project() is None


def test_active_project_returns_cwd_path() -> None:
    """Detects cwd of Claude process as Path."""
    proc = MagicMock()
    proc.cwd.return_value = "C:/Users/user/myproject"

    with patch("workstation_agent.claude_code.presence._find_claude_process", return_value=proc):
        result = active_project()
    assert result == Path("C:/Users/user/myproject")


def test_active_project_returns_none_on_access_denied() -> None:
    """AccessDenied when reading cwd → returns None gracefully."""
    proc = MagicMock()
    proc.cwd.side_effect = PermissionError("access denied")

    with patch("workstation_agent.claude_code.presence._find_claude_process", return_value=proc):
        result = active_project()
    assert result is None


def test_active_project_returns_none_on_any_exception() -> None:
    """Any exception reading cwd → returns None gracefully."""
    proc = MagicMock()
    proc.cwd.side_effect = RuntimeError("unexpected")

    with patch("workstation_agent.claude_code.presence._find_claude_process", return_value=proc):
        result = active_project()
    assert result is None
