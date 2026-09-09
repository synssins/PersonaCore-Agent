"""Config-file I/O: TOML load/save, atomic writes, DPAPI-backed secrets."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import tomlkit

from workstation_agent.config.schema import AgentConfig
from workstation_agent.config.schema import default as _default_cfg

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_APPDATA_DIR_NAME = "WorkstationAgent"


def _appdata_root() -> Path:
    """Return the application data root, honouring ``PC_AGENT_APPDATA`` env."""
    override = os.environ.get("PC_AGENT_APPDATA")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA") or Path.home()
    return Path(str(base)) / _APPDATA_DIR_NAME


def paths() -> dict[str, Path]:
    """Return resolved paths for every well-known location.

    Honours the ``PC_AGENT_APPDATA`` environment variable for test isolation.

    Returns:
        Dictionary with keys: ``config_file``, ``secrets_dir``, ``plugins_dir``,
        ``audit_db``, ``conversations_db``, ``logs_dir``.
    """
    root = _appdata_root()
    return {
        "config_file": root / "config.toml",
        "secrets_dir": root / "secrets",
        "plugins_dir": root / "plugins",
        "audit_db": root / "audit.db",
        "conversations_db": root / "conversations.db",
        "logs_dir": root / "logs",
    }


# ---------------------------------------------------------------------------
# ACL hardening (Windows-only)
# ---------------------------------------------------------------------------

# Deny mask covers FILE_GENERIC_READ equivalents
_ACL_DENY_MASK = 0x00120089
# Grant mask covers FILE_ALL_ACCESS for the owning user
_ACL_GRANT_MASK = 0x001F01FF


def harden_file(path: Path) -> None:
    """Apply a restrictive Windows DACL to *path*.

    Grants Read+Write to the current user only.  Explicitly denies Read to:

    * ``Everyone`` (``S-1-1-0``)
    * Low-integrity mandatory SID (``S-1-16-4096``) — prevents plugin
      subprocesses running at Low IL from reading DPAPI blobs.

    On non-Windows the call is a no-op with a WARN log.

    Args:
        path: Absolute path to the file to harden.
    """
    if sys.platform != "win32":
        log.warning("harden_file: ACL hardening skipped on non-Windows platform (%s)", path)
        return

    try:
        import win32api  # type: ignore[import]  # noqa: PLC0415
        import win32security  # type: ignore[import]  # noqa: PLC0415

        # Resolve current-user SID
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), 0x0008),
            win32security.TokenUser,
        )[0]

        low_il_sid = win32security.ConvertStringSidToSid("S-1-16-4096")

        # Build DACL.
        # The protected DACL flag (PROTECTED_DACL_SECURITY_INFORMATION) blocks
        # all inherited ACEs, so anyone not listed below is implicitly denied.
        # This achieves "deny Everyone" without an explicit DENY Everyone ACE
        # (which would also deny the current user, since Everyone includes them).
        # We add an explicit DENY for the Low-IL SID so that plugin subprocesses
        # running at Low integrity cannot read the DPAPI blob even if they share
        # the same user account.  Deny ACEs must precede Allow ACEs in DACL order.
        dacl = win32security.ACL()

        # Explicit DENY for Low-integrity processes (S-1-16-4096)
        dacl.AddAccessDeniedAce(
            win32security.ACL_REVISION,
            _ACL_DENY_MASK,
            low_il_sid,
        )

        # Grant current user full access — all others are denied implicitly
        # by the protected DACL (no Everyone allow, no inherited ACEs).
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            _ACL_GRANT_MASK,
            user_sid,
        )

        # Apply DACL — protected (no inheritance)
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        log.debug("harden_file: ACL applied to %s", path)
    except Exception:
        log.warning("harden_file: failed to apply ACL to %s", path, exc_info=True)


# ---------------------------------------------------------------------------
# Config load/save
# ---------------------------------------------------------------------------

def _toml_to_dict(doc: object) -> object:
    """Recursively convert a tomlkit document to a plain dict."""
    if hasattr(doc, "unwrap"):
        return doc.unwrap()  # type: ignore[union-attr]
    if isinstance(doc, dict):
        return {k: _toml_to_dict(v) for k, v in doc.items()}
    return doc


def load() -> AgentConfig:
    """Load and validate the agent configuration from disk.

    If the config file does not exist a default is written and returned.
    Validation is performed by Pydantic; any schema error propagates.

    Returns:
        Validated :class:`~workstation_agent.config.schema.AgentConfig`.
    """
    p = paths()
    cfg_path = p["config_file"]

    if not cfg_path.exists():
        cfg = _default_cfg()
        save(cfg)
        return cfg

    raw = cfg_path.read_text(encoding="utf-8")
    doc = tomlkit.loads(raw)
    data = _toml_to_dict(doc)
    return AgentConfig.model_validate(data)


def save(cfg: AgentConfig) -> None:
    """Persist *cfg* to disk atomically.

    The write goes to ``config.toml.tmp`` first, then ``Path.replace`` swaps
    it in.  If the target file already exists its TOML comments are preserved
    via a tomlkit round-trip (keys that still exist keep their comments).

    Args:
        cfg: Configuration to persist.
    """
    p = paths()
    cfg_path = p["config_file"]
    tmp_path = cfg_path.with_suffix(".toml.tmp")

    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    # If the file exists, do a round-trip to preserve comments
    if cfg_path.exists():
        existing_raw = cfg_path.read_text(encoding="utf-8")
        doc = tomlkit.loads(existing_raw)
        _merge_into_toml(doc, cfg.model_dump(mode="json"))
        output = tomlkit.dumps(doc)
    else:
        # Fresh write — use tomlkit to produce a clean document
        doc = tomlkit.document()
        _merge_into_toml(doc, cfg.model_dump(mode="json"))
        output = tomlkit.dumps(doc)

    tmp_path.write_text(output, encoding="utf-8")
    tmp_path.replace(cfg_path)


def _merge_into_toml(doc: object, data: dict[str, object]) -> None:
    """Merge *data* into *doc* (a tomlkit document or table) in-place.

    None values are skipped — TOML has no null type; absent key == None.
    """
    for key, value in data.items():
        if value is None:
            # TOML has no null; skip the key (absence means None on load)
            continue
        if isinstance(value, dict):
            if not isinstance(doc, dict) or key not in doc:  # type: ignore[operator]
                doc[key] = tomlkit.table()  # type: ignore[index]
            _merge_into_toml(doc[key], value)  # type: ignore[index]
        else:
            doc[key] = value  # type: ignore[index]


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _SecretInfo:
    """A secret's human role, plus the one true way to fix it (if known).

    The remedy travels with the role rather than being a single sentence
    bolted onto every message, because the fix genuinely differs per
    secret: re-entering a value only makes sense for a secret with a field
    somewhere to type it into. ``remedy == ""`` means "no verified fix" --
    the message names the role and states the failure, and stops there,
    rather than inventing an instruction that might send the operator
    looking for a control that does not exist.
    """

    role: str
    remedy: str


#: The re-enrolment remedy for a per-machine workstation token: unlike the
#: LLM API key, there is no field anywhere in this product for a person to
#: type this value into. PersonaCore mints it and pushes it to this Agent
#: over TLS during enrolment (contract: the operator never handles it by
#: hand), so the only real fix is to get a fresh pairing code and re-join.
_REENROL_REMEDY = (
    "Get a fresh pairing code from PersonaCore's Plugins screen and press "
    "Join on this machine to re-enrol."
)

#: Logical secret names this product defines, mapped to their role and
#: remedy. Keep this proportionate: it is a lookup table and a fallback,
#: not a subsystem. A secret added later that is not listed here still
#: gets a readable message via :func:`_secret_role`'s fallback -- it must
#: never look broken just because it is unmapped.
_SECRET_ROLES: dict[str, _SecretInfo] = {
    "llm_api_key": _SecretInfo(
        role="the API key for the LLM server",
        remedy="Enter it again in the API Key field.",
    ),
    "workstation_token": _SecretInfo(
        role="the network MCP bearer token PersonaCore uses to authenticate "
        "to this workstation",
        # Not currently reachable through load_secret -- network_mcp's own
        # token lives in a separate plain file (network_mcp/credentials.py),
        # not this DPAPI store -- so no remedy is verified for this fixed
        # name. Left blank rather than guessing; see _SecretInfo's docstring.
        remedy="",
    ),
}


#: PersonaCore's enrolment derives one bearer-token secret per enrolled
#: machine rather than a single fixed name: ``auth_secret_name()`` returns
#: ``workstation_<slug>_token``, where ``<slug>`` is the machine name the
#: operator chose (see PersonaCore's ``enrolment/workstation.py``). A static
#: table can never enumerate those, so this pattern is matched instead of
#: listed -- and it is worth getting right, since a DPAPI blob tied to the
#: Windows account is exactly what breaks on a profile change, a machine
#: move, or a restore from backup.
_WORKSTATION_TOKEN_RE = re.compile(r"^workstation_(.+)_token$")

#: Text whose origin we do not fully control -- a machine-name slug, or an
#: entirely unrecognised secret name -- is capped to this length before it
#: is ever folded into operator-facing text or the audit log.
_DISPLAY_MAX_LEN = 40


def _sanitize_for_display(text: str, *, max_len: int = _DISPLAY_MAX_LEN) -> str:
    """Strip *text* to a small safe character set and cap its length.

    Used on any string whose origin is not fully trusted before it reaches
    a sentence: it must never be able to carry formatting or structure, and
    must never be unbounded. Returns ``""`` if nothing safe is left.
    """
    return re.sub(r"[^A-Za-z0-9_-]", "", text)[:max_len]


def _humanize_slug(slug: str) -> str:
    """Render an untrusted machine-name *slug* as plain title-case words.

    Sanitises first (see :func:`_sanitize_for_display`), so the result can
    never carry formatting or structure into an operator-facing message --
    it only ever reads as one or two plain words. Returns ``""`` if nothing
    safe is left to show.
    """
    safe = _sanitize_for_display(slug)
    words = [w for w in re.split(r"[_-]+", safe) if w]
    return " ".join(words).title()


def _secret_role(name: str) -> _SecretInfo:
    """Return the human role and remedy for the secret *name*.

    Checks the fixed role table first, then the per-machine
    ``workstation_<slug>_token`` pattern, then falls back to naming the
    secret plainly (its logical name, not its value) when *name* is not one
    this product defines a role for yet.

    Both fallback paths sanitise before they ever embed *name* (or a piece
    of it) in operator-facing text: *name* comes from any caller, and a
    fallback exists precisely for names nobody anticipated. When nothing
    safe is left after sanitising, this returns a safe static phrase
    instead of echoing the (possibly unsafe) input -- never the reverse,
    since a sanitised path that is merely *skipped* on failure, falling
    through to an unsanitised default, sanitises nothing at all.
    """
    if name in _SECRET_ROLES:
        return _SECRET_ROLES[name]
    match = _WORKSTATION_TOKEN_RE.match(name)
    if match:
        slug_words = _humanize_slug(match.group(1))
        role = (
            f"the connection credential for the workstation {slug_words}"
            if slug_words
            else "the connection credential for an enrolled workstation (name unavailable)"
        )
        return _SecretInfo(role=role, remedy=_REENROL_REMEDY)
    safe_name = _sanitize_for_display(name)
    role = f"the '{safe_name}' credential" if safe_name else "an unrecognised credential"
    # No verified remedy for a name this product does not define a role
    # for -- a vague true sentence beats a specific false one.
    return _SecretInfo(role=role, remedy="")


def save_secret(name: str, plaintext: bytes) -> None:
    """Encrypt *plaintext* with DPAPI and write to ``secrets/<name>.dpapi``.

    After writing, :func:`harden_file` is called to apply a restrictive DACL
    preventing Low-IL plugin subprocesses from reading the blob.

    Args:
        name: Logical secret name (alphanumeric/dash/underscore).
        plaintext: Raw bytes to protect.
    """
    from workstation_agent.security.dpapi import protect  # noqa: PLC0415

    p = paths()
    secrets_dir = p["secrets_dir"]
    secrets_dir.mkdir(parents=True, exist_ok=True)

    blob = protect(plaintext)
    dest = secrets_dir / f"{name}.dpapi"
    tmp = dest.with_suffix(".dpapi.tmp")

    # Create the tmp file empty first, harden its ACL, then write the blob.
    # This eliminates the TOCTOU window where a Low-IL process could read the
    # file before the ACL is applied.
    tmp.write_bytes(b"")
    harden_file(tmp)
    tmp.write_bytes(blob)
    tmp.replace(dest)
    harden_file(dest)


def load_secret(name: str) -> bytes:
    """Decrypt and return the secret identified by *name*.

    Args:
        name: Logical secret name previously passed to :func:`save_secret`.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        KeyError: If the secret file does not exist. The message names the
            secret's role (a role is not a value — naming it is not a new
            info leak, since the logical name is already the ``KeyError``'s
            argument) and, only when one is verified for this secret (see
            :class:`_SecretInfo`), states the remedy — never a generic
            "enter it again" that would be wrong for a secret with no field
            to enter it into.
        DpapiError: If the stored blob exists but cannot be decrypted (e.g.
            after a Windows profile change, a machine move, or a restore
            from backup — the blob is tied to the Windows user account, so
            this is an expected failure mode, not an exotic one). The
            message names the secret's role and, when verified, its remedy;
            it never includes decrypted or encrypted content.
    """
    from workstation_agent.security.dpapi import DpapiError, unprotect  # noqa: PLC0415

    p = paths()
    dest = p["secrets_dir"] / f"{name}.dpapi"
    info = _secret_role(name)
    if not dest.exists():
        msg = f"No value is stored for {info.role}."
        if info.remedy:
            msg += f" {info.remedy}"
        raise KeyError(msg)
    blob = dest.read_bytes()
    try:
        return unprotect(blob)
    except DpapiError as exc:
        msg = (
            f"{info.role} could not be decrypted on this machine/account "
            "(this happens after a Windows profile change, a machine move, "
            "or a restore from backup)."
        )
        if info.remedy:
            msg += f" {info.remedy}"
        raise DpapiError(msg) from exc


def delete_secret(name: str) -> None:
    """Remove the secret file for *name*.

    Silently succeeds if the secret does not exist.

    Args:
        name: Logical secret name.
    """
    p = paths()
    dest = p["secrets_dir"] / f"{name}.dpapi"
    with contextlib.suppress(FileNotFoundError):
        dest.unlink()
