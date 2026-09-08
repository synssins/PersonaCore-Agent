"""The bearer token for the network MCP endpoint (contract §3).

A 32-byte random token, generated once and **reused across restarts**. Contract
§11 item 8 requires that stopping and starting the Agent brings the endpoint back
without the operator touching PersonaCore: if the token were regenerated on every
boot, the value the operator pasted into the core's secret store as
``workstation_token`` would stop matching and every call would `401`.

The token is 32 bytes of :mod:`secrets` entropy rendered as 64 lowercase hex
characters, so it is ASCII-safe to paste into a config field and safe to compare
as bytes without any encoding step (see ``hardening.py`` for why that matters).
"""

from __future__ import annotations

import importlib
import logging
import os
import secrets
from pathlib import Path
from typing import Final

log = logging.getLogger(__name__)

_TOKEN_BYTES: Final = 32
_TOKEN_FILE_NAME: Final = "token"  # noqa: S105 — a filename, not a credential

_appdata_env = os.environ.get("APPDATA")
_APPDATA: Final = Path(_appdata_env) if _appdata_env else Path.home() / ".config"

#: Where the endpoint's cert, key and token live by default.
DEFAULT_STATE_DIR: Final = _APPDATA / "WorkstationAgent" / "network-mcp"


def _harden(path: Path) -> None:
    """Best-effort DACL hardening, mirroring ``mcp_host.mcp_server``.

    ``security.dpapi`` does not export ``harden_file`` today — the named-pipe
    server names it too, behind the same guard. Looked up as an optional
    attribute rather than imported, because that is honestly what it is: the
    symbol may or may not be there, and a static import of a symbol that is not
    there is a lie that both type checkers correctly object to.

    Deliberately not fatal. A token file with default ACLs is still far better
    than no endpoint at all, and the operator is told.
    """
    module = importlib.import_module("workstation_agent.security.dpapi")
    harden = getattr(module, "harden_file", None)
    if harden is None:
        log.warning("security.harden_file unavailable; %s is not ACL-hardened", path.name)
        return
    try:
        harden(path)
    except Exception:  # noqa: BLE001
        log.warning("security.harden_file failed; %s is not ACL-hardened", path.name)


def ensure_token(state_dir: Path | None = None, *, rotate: bool = False) -> str:
    """Return the endpoint's bearer token, creating it on first run.

    Args:
        state_dir: Directory holding the token file. Defaults to
            :data:`DEFAULT_STATE_DIR`.
        rotate: Generate a fresh token even if one exists. The UI's "rotate
            token" action. Rotating invalidates the value the operator pasted
            into PersonaCore's secret store, so it is never automatic.

    Returns:
        The 64-character lowercase hex token.
    """
    directory = state_dir if state_dir is not None else DEFAULT_STATE_DIR
    path = directory / _TOKEN_FILE_NAME

    if not rotate and path.exists():
        try:
            existing = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            log.warning(
                "network MCP token at %s is unreadable; generating a new one. "
                "PersonaCore's 'workstation_token' secret must be updated.",
                path,
            )
        else:
            if existing:
                return existing
            log.warning("network MCP token at %s is empty; generating a new one", path)

    directory.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(_TOKEN_BYTES)
    path.write_text(token, encoding="ascii")
    _harden(path)
    if rotate:
        log.warning(
            "network MCP bearer token rotated. PersonaCore's 'workstation_token' "
            "secret must be updated or the core will get 401 on every call.",
        )
    else:
        log.info("network MCP bearer token generated at %s", path)
    return token
