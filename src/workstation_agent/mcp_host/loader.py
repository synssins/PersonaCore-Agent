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

Signature verification computes (see :func:`signing_message`)::

    canonical_json(manifest) || b"\\n" || SCHEME || b"\\n"
        || sha256(label_i) || digest(file_i)   for each covered file, in order

and tries each supplied public key against the ``signature.sig`` file next to
``plugin.toml``.  If ``allow_unsigned`` is ``True`` a missing / zero-byte sig
file returns ``VerifyResult(status='unsigned')`` instead of ``'quarantined'``.

Four properties of that message matter enough to spell out:

**Line endings are normalised out of the hash for Python source.**
``digest()`` translates ``CRLF`` and lone ``CR`` to ``LF`` before hashing a
``*.py`` file (:func:`_file_digest`).  Without this, signature validity is a
property of the *checkout*, not of the plugin: git's ``core.autocrlf`` decides
what lands on disk, so a plugin signed in an ``autocrlf=false`` clone is
``invalid`` in an ``autocrlf=true`` one and vice versa — and since
``allow_unsigned`` defaults to false, the wrong clone ships with no working
plugins and an error message that never mentions line endings.

The normalisation is deliberately scoped to ``*.py``.  It makes the hash
non-injective — a CRLF file and its LF twin share one signature — so it is only
sound where the two byte sequences are *the same program*.  For Python source
they are: CPython's tokenizer performs exactly this translation before
compiling, so every member of a collision class produces an identical code
object.  Any other file type is hashed byte-for-byte, because for, say, a
``.ps1`` here-string or a data file the two forms are *not* equivalent and
collapsing them would be a real weakening of the signature.

The boundary of that guarantee, stated exactly: it covers the *compiled code
object*.  Code that reads its own raw source at runtime — ``inspect.getsource``,
``traceback`` rendering a source line, ``doctest``, ``Path(__file__).read_bytes()``
— sees the un-normalised bytes, so two members of a collision class can differ
there.  Nothing in the signature stops that, and a plugin that derives security
decisions from its own source text is outside what this scheme promises.

**Every importable file in a package plugin is covered.**
:func:`_resolve_module_files` walks the whole package tree, not just
``__init__.py`` / ``__main__.py``, and "importable" means every format CPython's
import machinery loads — source, sourceless bytecode, and extension modules
(``.pyd`` / ``.so`` / ``.dylib``), not merely ``*.py``.  Covering only the two
dunder sources left every other submodule outside the signature; covering only
``*.py`` left a native ``submodule.pyd`` outside it, which is the same hole one
file extension over.  Because the covered set is "all of them", adding,
renaming, moving, or editing any of them changes the message and the plugin
fails loudly as ``invalid``; there is no quiet path where a file is ignored.

**Each digest is bound to the file's name.**  The message pairs
``sha256(label)`` with each content digest.  Without that binding the message
was a bare concatenation of digests, so any rename or directory move that
preserved the sort order left the signed bytes byte-identical — and since the
sort key is the relative path, renaming ``a.py``/``b.py`` to
``a_evil.py``/``b_evil.py`` preserves it.  Deciding which module a given body of
code is imported as is a capability worth signing.
"""
# ruff: noqa: C901

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

# Files CPython's import machinery will load from inside a package.  Fixed and
# platform-independent on purpose: ``importlib.machinery.EXTENSION_SUFFIXES`` is
# whatever the *running* interpreter accepts, so keying off it would make the
# covered set depend on the signing host — a ``.so`` covered on Linux and
# invisible on Windows.  Matching is on the final suffix, lowercased, which is
# what ``Path.suffix`` yields for the decorated forms too
# (``m.cp312-win_amd64.pyd`` → ``.pyd``, ``m.abi3.so`` → ``.so``).
# ``test_importable_suffixes_cover_this_interpreter`` fails if CPython grows a
# suffix this set does not contain.
_IMPORTABLE_SUFFIXES = frozenset(
    {".py", ".pyw", ".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib"},
)

# The subset of the above that CPython compiles from text.  ``.pyw`` is in
# ``importlib.machinery.SOURCE_SUFFIXES`` on Windows and is imported exactly
# like ``.py``, so it gets the same newline normalisation; treating it as opaque
# bytes would make a ``.pyw`` submodule checkout-dependent all over again.
_SOURCE_SUFFIXES = frozenset({".py", ".pyw"})

# ``__pycache__`` is excluded from the covered set.  It is a derived cache that
# CPython rewrites on first import with the source's mtime and size baked in, so
# hashing it would invalidate every signature the moment the plugin ran once.
# The dangerous form of bytecode — a sourceless ``pkg/mod.pyc``, which the import
# machinery loads directly — does NOT live in ``__pycache__`` and IS covered.
# What remains uncovered is cache poisoning of an already-covered source file,
# which no file-set policy can catch; the mitigation for that is to launch
# plugins with bytecode writing disabled and hash-based .pyc checking forced,
# which belongs to the supervisor, not to the signature.
_BYTECODE_CACHE_DIR = "__pycache__"

# Domain separator for the signed message.  Bumping it makes a signature from an
# older scheme fail cleanly rather than being reinterpreted under the new rules.
_SIGNING_SCHEME = b"workstation-agent/plugin-signature/2"


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


def normalise_newlines(data: bytes) -> bytes:
    """Translate ``CRLF`` and lone ``CR`` to ``LF``.

    This is byte-for-byte what CPython's tokenizer does to a source file before
    compiling it, which is why applying it inside the signature hash is safe for
    Python source: the byte sequences it collapses together compile to the same
    code object.
    """
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _is_python_source(path: Path) -> bool:
    """Whether *path* is Python source, matched case-insensitively.

    Case folding is not cosmetic.  ``rglob`` matches ``EVIL.PY`` on a
    case-insensitive filesystem and not on a case-sensitive one, so a
    case-sensitive ``== ".py"`` test gave one file three different treatments
    depending on the host: normalised on Linux, hashed raw on Windows, invisible
    to discovery elsewhere.  The covered set and the way each file is hashed
    must both be properties of the plugin, not of the filesystem it sits on.
    """
    return path.suffix.lower() in _SOURCE_SUFFIXES


def _file_digest(path: Path) -> bytes:
    """SHA-256 of *path*, newline-normalised for Python source only.

    Python source is hashed after :func:`normalise_newlines` so the signature
    survives any ``core.autocrlf`` setting, any platform, and any archive that
    rewrites text.  Everything else — extension modules, bytecode, data — is
    hashed raw: for those the CRLF and LF forms are genuinely different content
    and must not share a signature.
    """
    data = path.read_bytes()
    if _is_python_source(path):
        data = normalise_newlines(data)
    return hashlib.sha256(data).digest()


def _sorted_importable_files(root: Path) -> list[Path]:
    """Every file under *root* that CPython can import, in an OS-independent order.

    "Importable" is not "``*.py``".  Python's import machinery loads extension
    modules (``.pyd`` on Windows, ``.so``/``.dylib`` on POSIX) and sourceless
    bytecode (``.pyc``) natively, so a set restricted to source leaves a
    ``submodule.pyd`` dropped beside the covered files hashed by nothing at all
    — arbitrary native code executing under a ``valid`` signature.

    The sort key is the ``/``-joined path relative to *root*.  Sorting
    :class:`~pathlib.Path` objects directly would not do: on Windows their
    comparison is case-insensitive and on POSIX it is not, so a package with
    files differing only in case would hash in a different order on each OS and
    the signature would again depend on where it was made.
    """
    files = [
        p
        for p in root.rglob("*")
        if p.suffix.lower() in _IMPORTABLE_SUFFIXES
        and _BYTECODE_CACHE_DIR not in p.relative_to(root).parts
        and p.is_file()
    ]
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def _resolve_module_files(module_name: str) -> list[tuple[str, Path]]:
    """Return ``(label, path)`` for every importable file backing *module_name*.

    For a package this is the **whole tree**, recursively.  Covering only
    ``__init__.py`` and ``__main__.py`` (as this once did) left every other
    submodule unsigned while :func:`verify` still answered ``valid``.

    The label is the module-relative name of the file, e.g.
    ``workstation_agent.plugins.browser/deep/tool.py``.  It is deliberately not
    the absolute path, which varies per install, and deliberately not omitted,
    which is what let a file be renamed inside a signed package for free.
    """
    try:
        spec = importlib.util.find_spec(module_name)
    except (ImportError, ValueError):
        return []
    if spec is None:
        return []

    if spec.submodule_search_locations:  # it's a package
        out: list[tuple[str, Path]] = []
        for loc in spec.submodule_search_locations:
            root = Path(loc)
            out.extend(
                (f"{module_name}/{p.relative_to(root).as_posix()}", p)
                for p in _sorted_importable_files(root)
            )
        return out

    if spec.origin and spec.origin != "built-in":
        origin = Path(spec.origin)
        if origin.is_file():
            return [(f"{module_name}{origin.suffix}", origin)]
    return []


def _resolve_module_paths(module_name: str) -> list[Path]:
    """Paths only, for callers that do not need the signing labels."""
    return [p for _label, p in _resolve_module_files(module_name)]


def _plugin_dir_files(plugin_dir: Path) -> list[tuple[str, Path]]:
    """Labelled fallback set: every importable file under *plugin_dir*."""
    return [
        (p.relative_to(plugin_dir).as_posix(), p) for p in _sorted_importable_files(plugin_dir)
    ]


def unresolved_entry_modules(entry: list[str]) -> list[str]:
    """Return the ``-m`` modules in *entry* that ``find_spec`` cannot resolve.

    Exists for the **signer**, and the reason is a footgun that produced a
    silently-wrong signature.  :func:`_covered_files` labels each digest with
    the module-relative name when a ``-m`` entry resolves, and falls back to
    plugin-dir-relative labels when it does not.  Both are legitimate — the
    fallback is how an external plugin under ``%APPDATA%`` gets covered at all
    — but they are *different messages* for the same files.

    Sign a bundled plugin from a git worktree, where the venv's editable
    install points at the main checkout, and the module is unresolvable: the
    signer takes the fallback and signs over ``__init__.py`` while the verifier,
    running where the package *is* importable, computes
    ``workstation_agent.plugins.<id>/__init__.py``.  The signature is written,
    the signer's own verify passes (it resolves the same wrong way), and the
    plugin quarantines for everyone else.  Nothing in the output says so.

    So the signer asks this first and refuses rather than guessing.
    """
    unresolved: list[str] = []
    it = iter(entry)
    for arg in it:
        if arg != "-m":
            continue
        module_name = next(it, None)
        if module_name is None:
            break
        if not _resolve_module_files(module_name):
            unresolved.append(module_name)
    return unresolved


def _covered_files(entry: list[str], plugin_dir: Path) -> list[tuple[str, Path]]:
    """Resolve entry command to the ``(label, path)`` pairs the signature covers.

    The *label* is the name the file is signed under.  It is what stops a file
    inside a signed package from being renamed or moved for free: the message
    used to be a bare concatenation of content digests, so any rename that
    preserved the sort order — and the sort key *is* the relative path — left
    the signed bytes identical.  Changing which module a given body of code is
    imported as is a real capability, so each digest is now bound to its name.

    Labels are location-independent: module-relative for a ``-m`` entry,
    plugin-dir-relative for the fallback scan, and the literal manifest argument
    for a positional file.  An absolute install path would differ per machine
    and reintroduce exactly the class of fragility this module exists to avoid.

    For ``-m <module>`` entries, uses :func:`importlib.util.find_spec` to
    resolve the module.  For a package this covers every importable file in the
    tree; for a plain module file, that one file.  Also collects any positional
    argument that resolves to an existing file on disk (either absolute or
    relative to *plugin_dir*).

    When a ``-m <module>`` entry cannot be resolved via ``sys.path`` (typical
    for external user-installed plugins under ``%APPDATA%\\WorkstationAgent
    \\plugins\\``), falls back to every importable file under *plugin_dir*
    (recursively, deterministic order) so the signature always covers the
    plugin's code.  Likewise, if the entry produces zero paths (e.g. entry is
    just ``["python"]``), falls back to the same scan so the signature is never
    trivially empty.
    """
    covered: list[tuple[str, Path]] = []
    seen: set[Path] = set()

    def _add(label: str, path: Path) -> None:
        if path not in seen:
            seen.add(path)
            covered.append((label, path))

    it = iter(entry)
    for arg in it:
        if arg == "-m":
            module_name = next(it, None)
            if module_name is None:
                break
            resolved = _resolve_module_files(module_name)
            if not resolved:
                # External plugin whose module isn't on sys.path.
                resolved = _plugin_dir_files(plugin_dir)
            for label, path in resolved:
                _add(label, path)
        else:
            candidate = Path(arg)
            if not candidate.is_absolute():
                candidate = plugin_dir / arg
            if candidate.is_file():
                _add(arg, candidate)

    if not covered:
        for label, path in _plugin_dir_files(plugin_dir):
            _add(label, path)
    return covered


def _entry_file_paths(entry: list[str], plugin_dir: Path) -> list[Path]:
    """Paths only, for callers that do not need the signing labels."""
    return [p for _label, p in _covered_files(entry, plugin_dir)]


def signing_message(manifest: PluginManifest) -> bytes:
    """Return the exact bytes a plugin signature is made over.

    Single source of truth for :func:`verify`, ``scripts/sign_plugin.py`` and
    the test fixtures, so the signer and the verifier cannot drift apart.

    Layout::

        canonical_json(manifest) || b"\\n" || SCHEME || b"\\n"
            || sha256(label_0) || digest(file_0)
            || sha256(label_1) || digest(file_1)
            || ...

    Each covered file contributes a fixed 64 bytes — 32 for its name, 32 for its
    content — so the encoding is unambiguous without a separator: no arrangement
    of labels can be reparsed as a different one, and ``a/b.py`` cannot collide
    with ``a`` plus ``/b.py``.

    Raises:
        OSError: if a file the signature must cover cannot be read.  Callers in
            :func:`verify` turn this into ``status='invalid'`` — a plugin whose
            covered code is unreadable is not a plugin we will run.
    """
    parts = [
        _sig.canonical_json(_manifest_dict(manifest)),
        b"\n",
        _SIGNING_SCHEME,
        b"\n",
    ]
    for label, path in _covered_files(manifest.entry, manifest.plugin_dir):
        parts.append(hashlib.sha256(label.encode("utf-8")).digest())
        parts.append(_file_digest(path))
    return b"".join(parts)


def _verify_inner(
    manifest: PluginManifest,
    pubkeys: list[bytes],
    raw_sig: bytes,
) -> VerifyResult:
    """Inner logic: validate sig bytes against the manifest and pubkeys."""
    if len(raw_sig) != 64:  # noqa: PLR2004
        return VerifyResult(status="invalid", reason=f"bad signature length: {len(raw_sig)}")

    try:
        message = signing_message(manifest)
    except OSError as exc:
        log.warning("plugin %s: cannot hash covered file: %s", manifest.id, exc)
        return VerifyResult(status="invalid", reason=f"unreadable signed file: {exc}")

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
