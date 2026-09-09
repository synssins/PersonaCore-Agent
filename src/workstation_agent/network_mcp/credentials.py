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

    Deliberately not fatal — including the *import*. This runs immediately after
    the atomic ``replace`` that commits a new token, so anything raising here
    would leave the token on disk while the caller reported a failure: the next
    start would demand a token PersonaCore was told we had refused, which is an
    endpoint nobody can reach. Nothing past the commit is allowed to fail.
    """
    try:
        module = importlib.import_module("workstation_agent.security.dpapi")
    except Exception:  # noqa: BLE001 — see above; nothing past the commit may raise
        log.warning("security.dpapi unavailable; %s is not ACL-hardened", path.name)
        return
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
    _write_token(directory, token)
    if rotate:
        log.warning(
            "network MCP bearer token rotated. PersonaCore's 'workstation_token' "
            "secret must be updated or the core will get 401 on every call.",
        )
    else:
        log.info("network MCP bearer token generated at %s", path)
    return token


def _write_token(directory: Path, token: str) -> None:
    """Write *token* into *directory* atomically, then harden it.

    Atomic because there are now two writers — first-run generation and an
    enrolment push — and a token file caught half-written is a token file the
    next start reads back as the whole truth. ``Path.replace`` is atomic on
    NTFS, so a reader sees either the previous token or the new one.
    """
    path = directory / _TOKEN_FILE_NAME
    tmp = directory / (_TOKEN_FILE_NAME + ".tmp")
    tmp.write_text(token, encoding="ascii")
    tmp.replace(path)
    _harden(path)


def store_token(token: str, state_dir: Path | None = None) -> None:
    """Persist an externally issued bearer token, replacing any stored one.

    This is how the token PersonaCore mints during enrolment survives an Agent
    restart. Contract §11 item 8 requires that stopping and starting the Agent
    brings the endpoint back without the owner touching PersonaCore, and after
    enrolment the value the core holds is this one — so it has to be on disk
    before the push is answered, not merely in memory.

    The value is **never logged**, here or anywhere: the line below records that
    a token was stored and where the file is, and nothing about the token.

    Args:
        token: The token the core pushed. Must be printable ASCII with no
            spaces — the band
            :func:`~workstation_agent.network_mcp.enrolment._acceptable_token`
            has already established for anything arriving over the wire.
        state_dir: Directory holding the token file. Defaults to
            :data:`DEFAULT_STATE_DIR`.

    Raises:
        ValueError: if *token* is outside that band. Checked here as well as at
            the door, because this function writes an ASCII file that
            :func:`ensure_token` reads back as ASCII: a value that cannot make
            that round trip must not reach the disk, whatever called us.
        OSError: if the file cannot be written.
    """
    if not token or not token.isascii() or not token.isprintable() or " " in token:
        msg = "a bearer token must be non-empty printable ASCII containing no spaces"
        raise ValueError(msg)
    directory = state_dir if state_dir is not None else DEFAULT_STATE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    _write_token(directory, token)
    log.info(
        "network MCP bearer token replaced by an enrolment push (stored at %s)",
        directory / _TOKEN_FILE_NAME,
    )
