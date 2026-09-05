"""Handoff to the standalone ``Updater.exe`` binary.

Writes ``pending_update.json`` atomically and spawns the updater as a
detached Windows process so it survives the agent shutting itself down.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workstation_agent.updater_client.manifest import UpdateManifest


# Windows CreateProcess flags — kept as module-level constants so we don't
# reach into the win32 API on non-Windows CI where this module still imports.
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000


def _appdata_dir() -> Path:
    """Return ``%APPDATA%\\WorkstationAgent`` (or ``PC_AGENT_APPDATA`` override)."""
    override = os.environ.get("PC_AGENT_APPDATA")
    if override:
        return Path(override)
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "WorkstationAgent"
    # Test / non-Windows fallback so imports don't blow up.
    return Path(tempfile.gettempdir()) / "WorkstationAgent"


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        Path(tmp_name).replace(path)
    except Exception:
        with contextlib.suppress(OSError):
            Path(tmp_name).unlink()
        raise


def stage_pending(
    manifest: UpdateManifest,
    *,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    agent_pid: int | None = None,
    appdata_dir: Path | None = None,
) -> Path:
    """Write ``pending_update.json`` atomically to ``%APPDATA%\\WorkstationAgent``.

    Args:
        manifest: the parsed :class:`UpdateManifest`.
        manifest_bytes: raw manifest bytes as fetched (so the updater can
            re-verify without trusting anything but its baked-in pubkey).
        signature_bytes: raw signature bytes.
        agent_pid: PID of the running agent so the updater knows whom to
            wait on. Defaults to ``os.getpid()``.
        appdata_dir: override for tests.

    Returns:
        The absolute :class:`Path` to the written ``pending_update.json``.
    """
    root = appdata_dir if appdata_dir is not None else _appdata_dir()
    payload = {
        "schema_version": 1,
        "verified": True,
        "agent_pid": agent_pid if agent_pid is not None else os.getpid(),
        "manifest": manifest.model_dump(mode="json"),
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
    }
    out = root / "pending_update.json"
    _atomic_write_bytes(out, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"))
    return out


def _locate_updater(install_root: Path | None = None) -> Path:
    """Locate ``Updater.exe`` next to the running ``Agent.exe``.

    Precedence:
      1. ``PC_AGENT_UPDATER_PATH`` env override (tests).
      2. ``<install_root>/current/Updater.exe`` if provided.
      3. Sibling of ``sys.executable`` (real-world PyInstaller build).
    """
    override = os.environ.get("PC_AGENT_UPDATER_PATH")
    if override:
        return Path(override)
    if install_root is not None:
        return install_root / "current" / "Updater.exe"
    return Path(sys.executable).parent / "Updater.exe"


def spawn_updater(
    *,
    install_root: Path | None = None,
    extra_args: list[str] | None = None,
) -> int:
    """Spawn ``Updater.exe --update`` as a detached process.

    Args:
        install_root: override to locate ``current/Updater.exe`` for tests.
        extra_args: additional CLI args after ``--update``.

    Returns:
        The child process ID.
    """
    updater = _locate_updater(install_root)
    args = [str(updater), "--update", *(extra_args or [])]

    if sys.platform == "win32":
        flags = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
        proc = subprocess.Popen(  # noqa: S603 - args from trusted paths
            args,
            creationflags=flags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        return proc.pid

    # Non-Windows fallback (tests can hit this on Linux CI).
    proc = subprocess.Popen(  # noqa: S603 - args from trusted paths
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return proc.pid
