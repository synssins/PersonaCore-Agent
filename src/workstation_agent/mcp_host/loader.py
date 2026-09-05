"""Plugin discovery, manifest parsing, and signature verification.

Discovery sources (in precedence order — bundled first, then user-installed):

1. Bundled first-party plugins shipped inside the ``workstation_agent.plugins``
   package (``src/workstation_agent/plugins/*/plugin.toml``).
2. Python entry-points in group ``workstation_agent.plugins`` — allows third
   parties to ship installable plugins as ordinary wheel packages.
3. Folder scan of ``%APPDATA%\\WorkstationAgent\\plugins\\*\\plugin.toml`` via
   :func:`workstation_agent.config.store.paths`.

Each source yields :class:`PluginManifest` instances.  Duplicates (same
``plugin_id``) are resolved by keeping the first occurrence (bundled wins).

Signature verification computes::

    message = canonical_json(manifest_dict) + b"\\n" + sha256(entry_bytes[0]) + ...

and tries each supplied public key against the ``signature.sig`` file next to
``plugin.toml``.  If ``allow_unsigned`` is ``True`` a missing / zero-byte sig
file returns ``VerifyResult(status='unsigned')`` instead of ``'quarantined'``.
"""
# ruff: noqa: C901, PLR0912

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import importlib.util
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import tomlkit

import workstation_agent.config.store as _store
import workstation_agent.security.signature as _sig
from workstation_agent.security.first_party_pubkey import FIRST_PARTY_PUBKEY

log = logging.getLogger(__name__)

TRUSTED_PUBKEYS: list[bytes] = [FIRST_PARTY_PUBKEY]

_env_key = _sig.load_public_key()
if _env_key is not None:
    TRUSTED_PUBKEYS.append(_env_key)


@dataclass
class PluginManifest:
    """Parsed representation of a ``plugin.toml`` file (SPEC-03B §4.4)."""

    id: str
    name: str
    version: str
    runtime: str
    entry: list[str]
    plugin_dir: Path
    signature_file: Path
    declared_permissions: list[str] = field(default_factory=list)
    confirmable_conditions: list[str] = field(default_factory=list)
    compat: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"


@dataclass
class VerifyResult:
    """Outcome of :func:`verify`."""

    status: Literal["valid", "unsigned", "invalid", "quarantined"]
    reason: str = ""
    pubkey_id: str = ""


_SENTINEL_UNSIGNED = b"UNSIGNED"


def _parse_toml(path: Path, source: str = "unknown") -> PluginManifest | None:
    """Parse *path* and return a :class:`PluginManifest`, or ``None`` on error."""
    try:
        raw = path.read_text(encoding="utf-8")
        doc = tomlkit.loads(raw)
    except Exception:
        log.exception("failed to read plugin.toml at %s", path)
        return None

    try:
        plugin_id: str = str(doc["id"])
        name: str = str(doc.get("name", plugin_id))
        version: str = str(doc.get("version", "0.0.0"))
        runtime: str = str(doc.get("runtime", "python"))
        entry_raw = doc.get("entry", [])
        entry: list[str] = [str(e) for e in entry_raw] if isinstance(entry_raw, list) else []
        declared: list[str] = [str(p) for p in doc.get("declared_permissions", [])]
        confirmable: list[str] = [str(c) for c in doc.get("confirmable_conditions", [])]
        compat_raw = doc.get("compat", {})
        compat: dict[str, Any] = dict(compat_raw) if isinstance(compat_raw, dict) else {}
    except (KeyError, TypeError):
        log.exception("plugin.toml at %s missing required field", path)
        return None

    plugin_dir = path.parent
    return PluginManifest(
        id=plugin_id,
        name=name,
        version=version,
        runtime=runtime,
        entry=entry,
        plugin_dir=plugin_dir,
        signature_file=plugin_dir / "signature.sig",
        declared_permissions=declared,
        confirmable_conditions=confirmable,
        compat=compat,
        source=source,
    )


def _discover_bundled() -> list[PluginManifest]:
    """Yield manifests from ``src/workstation_agent/plugins/*/plugin.toml``."""
    manifests: list[PluginManifest] = []
    try:
        pkg = importlib.resources.files("workstation_agent.plugins")
    except (ModuleNotFoundError, TypeError):
        log.debug("workstation_agent.plugins package not found; skipping bundled discovery")
        return manifests

    try:
        for item in pkg.iterdir():  # type: ignore[attr-defined]
            try:
                toml_file = item / "plugin.toml"  # type: ignore[operator]
                real = Path(str(toml_file))
                if not real.exists():
                    continue
                m = _parse_toml(real, source="bundled")
                if m is not None:
                    manifests.append(m)
            except Exception:
                log.debug("skip bundled item %s", item, exc_info=True)
    except Exception:
        log.debug("bundled plugin scan failed", exc_info=True)
    return manifests


def _discover_entry_points() -> list[PluginManifest]:
    """Discover plugins registered via ``workstation_agent.plugins`` entry-point group."""
    manifests: list[PluginManifest] = []
    try:
        eps = importlib.metadata.entry_points(group="workstation_agent.plugins")
    except Exception:
        log.debug("entry_points discovery failed", exc_info=True)
        return manifests

    for ep in eps:
        try:
            loaded = ep.load()
            if callable(loaded):
                toml_path = Path(str(loaded()))
            elif isinstance(loaded, (str, Path)):
                toml_path = Path(str(loaded))
            else:
                log.debug(
                    "entry-point %s returned unrecognised type %s", ep.name, type(loaded),
                )
                continue
            if not toml_path.exists():
                log.debug(
                    "entry-point %s plugin.toml not found at %s", ep.name, toml_path,
                )
                continue
            m = _parse_toml(toml_path, source=f"entry_point:{ep.name}")
            if m is not None:
                manifests.append(m)
        except Exception:
            log.debug("entry-point %s failed to load", ep.name, exc_info=True)
    return manifests


def _discover_user_folder() -> list[PluginManifest]:
    """Scan ``%APPDATA%\\WorkstationAgent\\plugins\\*\\plugin.toml``."""
    manifests: list[PluginManifest] = []
    plugins_dir = _store.paths()["plugins_dir"]
    if not plugins_dir.exists():
        log.debug("user plugins_dir does not exist: %s", plugins_dir)
        return manifests

    for candidate in sorted(plugins_dir.iterdir()):
        if not candidate.is_dir():
            continue
        toml_path = candidate / "plugin.toml"
        if not toml_path.exists():
            continue
        m = _parse_toml(toml_path, source="user_folder")
        if m is not None:
            manifests.append(m)
    return manifests


def discover() -> list[PluginManifest]:
    """Return merged, deduplicated plugin manifests from all three sources.

    Precedence: bundled > entry-points > user-folder.
    Duplicates (same ``id``) keep the first occurrence.
    """
    seen: set[str] = set()
    result: list[PluginManifest] = []

    for source_fn in (_discover_bundled, _discover_entry_points, _discover_user_folder):
        for m in source_fn():
            if m.id in seen:
                log.debug("duplicate plugin_id=%s from source=%s; skipping", m.id, m.source)
                continue
            seen.add(m.id)
            result.append(m)

    log.info("discovered %d plugin(s): %s", len(result), [m.id for m in result])
    return result


def _manifest_dict(manifest: PluginManifest) -> dict[str, Any]:
    """Serialise the manifest fields that are covered by the signature."""
    return {
        "id": manifest.id,
        "name": manifest.name,
        "version": manifest.version,
        "runtime": manifest.runtime,
        "entry": manifest.entry,
        "declared_permissions": manifest.declared_permissions,
        "confirmable_conditions": manifest.confirmable_conditions,
        "compat": manifest.compat,
    }


def _resolve_module_paths(module_name: str) -> list[Path]:
    """Return the .py files backing *module_name* (single file or package)."""
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, ValueError):
        return []
    if spec is None:
        return []
    paths: list[Path] = []
    if spec.origin and spec.origin != "built-in":
        paths.append(Path(spec.origin))
    if spec.submodule_search_locations:  # it's a package
        for loc in spec.submodule_search_locations:
            pkg_dir = Path(loc)
            for name in ("__init__.py", "__main__.py"):
                p = pkg_dir / name
                if p.exists() and p not in paths:
                    paths.append(p)
    return paths


def _entry_file_paths(entry: list[str], plugin_dir: Path) -> list[Path]:
    """Resolve entry command to the set of code files whose hash is signed.

    For ``-m <module>`` entries, uses :func:`importlib.util.find_spec` to
    resolve the module.  For plain module files, hashes the single file.
    For packages, hashes ``__init__.py`` and ``__main__.py`` (both if present).
    Also collects any positional argument that resolves to an existing file
    on disk (either absolute or relative to *plugin_dir*).

    When a ``-m <module>`` entry cannot be resolved via ``sys.path`` (typical
    for external user-installed plugins under ``%APPDATA%\\WorkstationAgent
    \\plugins\\``), falls back to hashing every ``*.py`` file under
    *plugin_dir* (recursively, deterministic order) so the signature always
    covers the plugin's code.  Likewise, if the entry produces zero paths
    (e.g. entry is just ``["python"]``), falls back to hashing every ``*.py``
    under *plugin_dir* so the signature is never trivially empty.
    """
    paths: list[Path] = []
    it = iter(entry)
    for arg in it:
        if arg == "-m":
            module_name = next(it, None)
            if module_name is None:
                break
            resolved = _resolve_module_paths(module_name)
            if resolved:
                for p in resolved:
                    if p not in paths:
                        paths.append(p)
            else:
                # External plugin whose module isn't on sys.path.
                # Hash every .py file under plugin_dir (recursive, deterministic).
                for py_path in sorted(plugin_dir.rglob("*.py")):
                    if py_path not in paths:
                        paths.append(py_path)
        else:
            candidate = Path(arg)
            if not candidate.is_absolute():
                candidate = plugin_dir / arg
            if candidate.is_file():
                paths.append(candidate)
    # Fallback: if entry produced ZERO paths (e.g. entry is ["python"] with
    # no -m and no positional file), hash every .py in plugin_dir so the
    # signature is never trivially empty.
    if not paths:
        paths = sorted(plugin_dir.rglob("*.py"))
    return paths


def _verify_inner(
    manifest: PluginManifest,
    pubkeys: list[bytes],
    raw_sig: bytes,
) -> VerifyResult:
    """Inner logic: validate sig bytes against the manifest and pubkeys."""
    if len(raw_sig) != 64:  # noqa: PLR2004
        return VerifyResult(status="invalid", reason=f"bad signature length: {len(raw_sig)}")

    manifest_bytes = _sig.canonical_json(_manifest_dict(manifest))
    entry_paths = _entry_file_paths(manifest.entry, manifest.plugin_dir)
    entry_hash_parts = [hashlib.sha256(p.read_bytes()).digest() for p in entry_paths]

    message = manifest_bytes + b"\n" + b"".join(entry_hash_parts)

    for pubkey in pubkeys:
        if _sig.verify(pubkey, message, raw_sig):
            pubkey_id = hashlib.sha256(pubkey).hexdigest()
            return VerifyResult(status="valid", reason="", pubkey_id=pubkey_id)

    return VerifyResult(status="invalid", reason="no trusted pubkey matched the signature")


def verify(
    manifest: PluginManifest,
    pubkeys: list[bytes] | None = None,
    *,
    allow_unsigned: bool = False,
) -> VerifyResult:
    """Verify *manifest*'s signature.

    Args:
        manifest: The plugin whose signature we verify.
        pubkeys: List of trusted Ed25519 public keys (raw 32 bytes).
        allow_unsigned: If ``True``, a missing or sentinel signature file returns
                        ``VerifyResult(status='unsigned')`` instead of
                        ``'quarantined'``.

    Returns:
        A :class:`VerifyResult` describing the outcome.
    """
    if pubkeys is None:
        pubkeys = TRUSTED_PUBKEYS

    sig_path = manifest.signature_file
    if not sig_path.exists():
        if allow_unsigned:
            return VerifyResult(status="unsigned", reason="signature file absent")
        return VerifyResult(status="quarantined", reason="signature file absent")

    raw_sig = sig_path.read_bytes()
    if raw_sig in (b"", _SENTINEL_UNSIGNED):
        if allow_unsigned:
            return VerifyResult(status="unsigned", reason="sentinel signature")
        return VerifyResult(
            status="quarantined", reason="sentinel signature — not allowed in prod",
        )

    return _verify_inner(manifest, pubkeys, raw_sig)
