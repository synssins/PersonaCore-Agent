"""Tracks which network-MCP credential values have already been shown once.

Contract §3: the operator sees the token and the certificate fingerprint
**once**, with a copy button each, then pastes them into PersonaCore. A page
that re-renders the raw token on every visit to ``/network-mcp`` defeats the
entire point of "shown once" — it turns a one-time reveal into a standing
leak to anyone who can load the page (which, granted, is loopback-only
per :func:`workstation_agent.ui.backend.app.create_app`'s middleware, but the
contract's "once" is a property of the *value*, not of who else can see it).

The state kept here is keyed to the value itself (a hash of the token, the
fingerprint string verbatim — never the raw token) rather than to "has this
page been visited before", so a **new** value — an operator rotating the
token or regenerating the certificate — is correctly revealed again exactly
once, while the *same* value across an Agent restart stays masked. The
network MCP endpoint's own certificate/token persistence
(``network_mcp/credentials.py``, ``network_mcp/certs.py``) already survives
restarts for the same reason (contract §11 item 8); this file's job is only
to remember whether the UI has already shown what those files hold.

**Fails closed in both directions.** A missing state file legitimately means
"nothing has ever been revealed" — that is the normal state on first run —
and is treated as such. But a state file that *exists* and cannot be read or
parsed (a torn write from a crash, a permissions change, a disk error) is a
different thing entirely, and an earlier revision conflated the two: both
read as "reveal everything," silently undoing the "shown once" guarantee on
the very corruption case a fail-closed write path exists to guard against.
:func:`consume_reveal` now raises :class:`RevealPersistenceError` for both
an unreadable *existing* file and a failed write, and only for those; a
plain absence still means "nothing revealed yet."
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import uuid
from pathlib import Path

log = logging.getLogger(__name__)

_FILE_NAME = "network-mcp-reveal.json"

#: Serialises the read-check-write below. A double-clicked button or two
#: near-simultaneous requests would otherwise both read the pre-update
#: state, both find no match, and both reveal.
#:
#: **In-process only, and that is a stated assumption, not an oversight.**
#: A :class:`threading.Lock` says nothing across process boundaries. It is
#: sufficient here because the Agent's UI backend runs as exactly one
#: `uvicorn.Server` in one process on the asyncio thread
#: (``app.py::Application._start_fastapi_backend`` passes no ``workers=``
#: and the module docstring documents the single-process threading
#: topology), and ``export-registration`` (the only other reader of this
#: state) never calls :func:`consume_reveal` — it reads the endpoint's
#: fingerprint straight off :class:`NetworkMCPServer`, not through the
#: reveal-tracking file. Either of two changes would break this assumption
#: and require real file locking instead: serving the UI backend behind a
#: multi-worker ASGI deployment, or a second process (a future CLI command,
#: say) that also calls :func:`consume_reveal`. Neither exists today.
_LOCK = threading.Lock()


class RevealPersistenceError(RuntimeError):
    """The reveal-state file could not be durably written or read back.

    Callers must treat this as "do not reveal" (fail closed) and surface
    the reason to the operator, rather than deciding on their own to show
    the value anyway.
    """


def _appdata_root() -> Path:
    override = os.environ.get("PC_AGENT_APPDATA")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA") or Path.home()
    return Path(str(base)) / "WorkstationAgent"


def _state_path() -> Path:
    return _appdata_root() / _FILE_NAME


def _load(path: Path) -> dict[str, str]:
    """Return the reveal state at *path*, or raise ``OSError``.

    Args:
        path: The state file. A path that does not exist yet is not an
            error — it is the ordinary first-run state — and returns ``{}``.

    Raises:
        OSError: if *path* exists but cannot be read or parsed as a JSON
            object. Distinct from "does not exist" on purpose: a file that
            is present and unreadable or corrupt must not read the same as
            "nothing revealed yet," or a torn write silently re-reveals
            everything the next time this is called.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"reveal state at {path} exists but could not be read or parsed"
        raise OSError(msg) from exc
    if not isinstance(data, dict):
        msg = f"reveal state at {path} is not a JSON object"
        raise OSError(msg)
    return data


def _save(path: Path, data: dict[str, str]) -> None:
    """Write *data* to *path* atomically, or raise ``OSError``.

    ``mkdir`` is inside the same unguarded sequence as the write itself, so
    a directory-creation failure is reported the same way a write failure
    is, rather than one being swallowed and the other raising uncaught.

    The temp file's name is unique per call (pid + a random suffix), not
    the static ``path.with_suffix(".tmp")`` an earlier revision used. A
    static name means one stuck temp file — antivirus holding a handle, a
    process that crashed mid-write, a read-only leftover — jams *every*
    future write to this path permanently; combined with failing closed,
    that would mean reveals disabled forever until someone finds and
    deletes a file nobody is looking for. A unique name means a jammed
    leftover from one failed write cannot block the next attempt, and the
    ``except`` below removes this call's own temp file if the write half
    succeeds but the atomic replace does not.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


def consume_reveal(kind: str, value: str, *, path: Path | None = None) -> bool:
    """Return whether *value* (identified by *kind*) should be shown now.

    Reveals — and records as revealed — the first time this exact *value* is
    seen for *kind*. A later call with the same value returns ``False``; a
    call with a **different** value (rotated token, regenerated certificate)
    reveals again, once, for the new value.

    Args:
        kind: A namespace for the value, e.g. ``"token"`` or ``"fingerprint"``.
            Callers pass a hash of the token, never the token itself, so
            this module's own on-disk state never carries the secret.
        value: The identity to check/record.
        path: Overrides the state file location. Tests pass a ``tmp_path``
            file; production leaves this as the default
            (``%APPDATA%\\WorkstationAgent\\network-mcp-reveal.json``).

    Raises:
        RevealPersistenceError: if the reveal state cannot be durably read
            or written. Fails closed in both directions: an existing file
            that cannot be read (corrupt, permissions, a torn write) is
            treated the same as a write that fails, not the same as a file
            that has simply never existed. Either way the caller must not
            reveal *value* and should tell the operator why, never fall
            back to revealing it anyway.

    Thread-safe within one process: the read-check-write sequence is
    serialised by a module lock (see its docstring for what that does and
    does not cover), so two overlapping requests for the same value cannot
    both observe "not yet revealed" and both reveal it.
    """
    state_path = path if path is not None else _state_path()
    with _LOCK:
        try:
            data = _load(state_path)
        except OSError as exc:
            log.exception(
                "credential_reveal: could not read reveal state at %s", state_path,
            )
            msg = f"could not read reveal state at {state_path}"
            raise RevealPersistenceError(msg) from exc

        if data.get(kind) == value:
            return False
        data[kind] = value
        try:
            _save(state_path, data)
        except OSError as exc:
            log.exception(
                "credential_reveal: could not persist reveal state for %r to %s",
                kind, state_path,
            )
            msg = f"could not persist reveal state for {kind!r} to {state_path}"
            raise RevealPersistenceError(msg) from exc
        return True
