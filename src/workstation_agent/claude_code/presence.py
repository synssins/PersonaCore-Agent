"""Claude Code cross-process presence detection.

Uses :mod:`psutil` to enumerate running processes and identify whether a Claude
Code instance is active on the workstation. Falls back gracefully when process
inspection is denied (e.g. elevated processes, anti-cheat drivers).

Heuristics used (in order of reliability):

1. Process named ``claude.exe`` — the Claude Code desktop app.
2. A ``node.exe`` process whose command line contains ``claude`` (the CLI).
3. A lock-file written by Claude Code at ``~/.claude/.claude_lock`` (fallback
   when process inspection is denied by OS policy).

``active_project()`` attempts to read the cwd of the detected process via
``psutil.Process.cwd()``, which may fail for protected processes; it returns
``None`` rather than raising.
"""

# ruff: noqa: PLC0415, TRY300

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Lockfile written by the Claude Code desktop app / CLI.
_CLAUDE_LOCK = Path.home() / ".claude" / ".claude_lock"

# Executable names that indicate Claude Code is running.
_CC_EXE_NAMES = frozenset({"claude.exe", "claude"})


def _iter_processes() -> list[object]:
    """Return a list of psutil.Process objects, or empty list on import error."""
    try:
        import psutil  # type: ignore[import-not-found]
        return list(psutil.process_iter(["pid", "name", "cmdline"]))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        log.debug("psutil unavailable; skipping process enumeration")
        return []


def _is_claude_process(proc: object) -> bool:
    """Return True if *proc* looks like a Claude Code process."""
    try:
        import psutil  # type: ignore[import-not-found]

        if not isinstance(proc, psutil.Process):  # type: ignore[attr-defined]
            return False

        info = proc.info  # type: ignore[attr-defined]
        name: str = (info.get("name") or "").lower()

        # Direct match: claude.exe / claude (macOS/Linux CLI)
        if name in _CC_EXE_NAMES:
            return True

        # Node-based CLI: node.exe running a script that contains "claude"
        if name in {"node.exe", "node"}:
            cmdline: list[str] = info.get("cmdline") or []
            for part in cmdline:
                if "claude" in part.lower():
                    return True

        return False
    except Exception:  # noqa: BLE001
        return False


def _find_claude_process() -> object | None:
    """Return the first Claude Code process found, or None."""
    for proc in _iter_processes():
        if _is_claude_process(proc):
            return proc
    return None


def is_running() -> bool:
    """Return True if a Claude Code process is active.

    Checks running processes first, then falls back to the lockfile written by
    the Claude Code desktop app.
    """
    if _find_claude_process() is not None:
        return True

    # Lockfile fallback (desktop app / installer variant)
    if _CLAUDE_LOCK.exists():
        log.debug("Claude Code lockfile found at %s", _CLAUDE_LOCK)
        return True

    return False


def active_project() -> Path | None:
    """Return the cwd of the active Claude Code process, or None.

    Reads ``psutil.Process.cwd()`` which may raise ``AccessDenied`` for
    elevated or protected processes — the exception is suppressed and None
    is returned.
    """
    proc = _find_claude_process()
    if proc is None:
        return None

    try:
        cwd_str: str = proc.cwd()  # type: ignore[attr-defined]
        return Path(cwd_str)
    except Exception:
        log.debug("could not read cwd of Claude Code process", exc_info=True)
        return None
