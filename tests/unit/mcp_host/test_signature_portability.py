"""Plugin signatures must not depend on how the repo was checked out.

Two defects are pinned here.

**1. Line endings.**  The hash used to run over the raw bytes of each ``*.py``
file.  This repo has ``core.autocrlf=true`` and no ``.gitattributes``, so the
bundled plugins land on disk as CRLF and were signed over CRLF bytes — but the
blobs in git are LF, so a clone made with ``core.autocrlf=false`` (or ``input``)
gets LF on disk and every one of those signatures becomes ``invalid``.  Since
``allow_unsigned`` defaults to false, that clone ships with no working plugins
and an error that never mentions line endings.  The tests below construct the
byte-form each ``core.autocrlf`` setting actually produces and verify the real
shipped ``signature.sig`` against every one of them.

**2. Submodule coverage.**  ``_resolve_module_files`` used to hash only
``__init__.py`` and ``__main__.py`` of a package plugin, so any other submodule
ran unsigned while ``verify()`` still answered ``valid``.  The tests below build
a real multi-module package, sign it, and prove that touching *or adding* any
submodule anywhere in the tree flips the result to ``invalid``.

**3. Importable-but-not-source.**  Covering ``*.py`` still left ``.pyd`` /
``.so`` / sourceless ``.pyc`` — all of which CPython imports natively — hashed
by nothing, which is defect 2 one file extension over.

**4. Unnamed digests.**  The message was a bare concatenation of content
digests, so any rename or move preserving the sort order left it byte-identical
and the signature valid.  Each digest is now bound to the file's name.

**5. Case-sensitive suffix matching.**  ``rglob("*.py")`` matches ``EVIL.PY`` on
a case-insensitive filesystem while ``suffix == ".py"`` does not, so one file
got three different treatments depending on the host.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import shutil
import subprocess
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from workstation_agent.mcp_host import loader
from workstation_agent.security.first_party_pubkey import FIRST_PARTY_PUBKEY

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PLUGINS_DIR = _REPO_ROOT / "src" / "workstation_agent" / "plugins"

# Bundled plugins carrying a real first-party signature.
SIGNED_PLUGINS = [
    "browser",
    "clipboard",
    "desktop_control",
    "filesystem",
    "powershell",
    "screen_vision",
]

# Bundled plugins that must stay on the b"UNSIGNED" sentinel.
SENTINEL_PLUGINS = ["hello_world", "claude_code_bridge"]

_SENTINEL = b"UNSIGNED"

# Snapshot taken at import (i.e. during collection, before any test body runs)
# because other modules in this suite legitimately overwrite hello_world's
# signature.sig for the duration of a test and restore it afterwards.
_SENTINEL_SIG_AT_IMPORT = {
    pid: (_PLUGINS_DIR / pid / "signature.sig").read_bytes() for pid in SENTINEL_PLUGINS
}


# --------------------------------------------------------------------------
# The three byte-forms `git checkout` can put on disk.
#
#   core.autocrlf=true   text blobs (LF in the index) are expanded to CRLF
#   core.autocrlf=false  no conversion — the working tree is the blob, i.e. LF
#   core.autocrlf=input  no conversion on checkout — also LF
#
# "cr_only" is not a git setting; it is the pathological classic-Mac form,
# included because CPython's tokenizer accepts a lone CR as a line terminator
# and therefore so must the hash.
# --------------------------------------------------------------------------


def _to_lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _to_crlf(data: bytes) -> bytes:
    return _to_lf(data).replace(b"\n", b"\r\n")


def _to_cr(data: bytes) -> bytes:
    return _to_lf(data).replace(b"\n", b"\r")


CHECKOUT_FORMS = {
    "autocrlf=true": _to_crlf,
    "autocrlf=false": _to_lf,
    "autocrlf=input": _to_lf,
    "cr_only": _to_cr,
}


def _materialise(plugin_id: str, dest: Path, transform) -> Path:
    """Copy a bundled plugin into *dest*, rewriting text files to one EOL form.

    ``signature.sig`` is copied byte-for-byte: it is the shipped signature and
    the whole point of the exercise is that it still verifies.
    """
    src = _PLUGINS_DIR / plugin_id
    out = dest / plugin_id
    out.mkdir(parents=True)
    for f in sorted(src.iterdir()):
        if not f.is_file():
            continue
        if f.suffix in {".py", ".toml"}:
            (out / f.name).write_bytes(transform(f.read_bytes()))
        else:
            shutil.copy2(f, out / f.name)
    return out


def _relocated_resolver(root: Path):
    """Stand-in for ``loader._resolve_module_files`` pointing at a copied tree.

    Reproduces the real labels exactly (``<module>/<relpath>``), so the message
    under test is the one the shipped signature was made over — the *only*
    difference being the bytes on disk.
    """

    def _resolve(module_name: str) -> list[tuple[str, Path]]:
        return [
            (f"{module_name}/{p.relative_to(root).as_posix()}", p)
            for p in loader._sorted_importable_files(root)
        ]

    return _resolve


@pytest.mark.parametrize("plugin_id", SIGNED_PLUGINS)
@pytest.mark.parametrize("form", sorted(CHECKOUT_FORMS))
def test_bundled_plugin_verifies_under_every_checkout_form(
    plugin_id, form, tmp_path, monkeypatch,
):
    """The shipped signature.sig verifies against every on-disk line-ending form.

    This is the regression that matters: a fresh clone on a machine with
    ``core.autocrlf=false`` must not turn every first-party plugin invalid.
    """
    out = _materialise(plugin_id, tmp_path / form.replace("=", "_"), CHECKOUT_FORMS[form])

    manifest = loader._parse_toml(out / "plugin.toml", source="test")
    assert manifest is not None

    # The entry is `-m workstation_agent.plugins.<id>`, which find_spec would
    # resolve back to the real (CRLF) source tree.  Point it at the copy so the
    # bytes under test are the ones we just wrote.
    monkeypatch.setattr(loader, "_resolve_module_files", _relocated_resolver(out))

    result = loader.verify(manifest, [FIRST_PARTY_PUBKEY], allow_unsigned=False)
    assert result.status == "valid", (
        f"{plugin_id} failed to verify with {form} line endings: {result.reason}"
    )


@pytest.mark.parametrize("plugin_id", SIGNED_PLUGINS)
def test_bundled_plugin_message_is_identical_across_checkout_forms(
    plugin_id, tmp_path, monkeypatch,
):
    """Stronger than 'all forms verify': all forms produce the same signed bytes.

    If this holds, signature validity cannot depend on the checkout at all —
    there is only one message to sign, whatever git wrote to disk.
    """
    messages = {}
    for form, transform in CHECKOUT_FORMS.items():
        out = _materialise(plugin_id, tmp_path / form.replace("=", "_"), transform)
        manifest = loader._parse_toml(out / "plugin.toml", source="test")
        assert manifest is not None
        monkeypatch.setattr(loader, "_resolve_module_files", _relocated_resolver(out))
        messages[form] = loader.signing_message(manifest)

    distinct = set(messages.values())
    assert len(distinct) == 1, f"{plugin_id} hashes differently per checkout form: {list(messages)}"


@pytest.mark.parametrize("plugin_id", SIGNED_PLUGINS)
def test_bundled_plugin_verifies_as_checked_out_here(plugin_id):
    """The plugins verify in this worktree exactly as they sit on disk."""
    manifest = next(m for m in loader._discover_bundled() if m.id == plugin_id)
    result = loader.verify(manifest, [FIRST_PARTY_PUBKEY], allow_unsigned=False)
    assert result.status == "valid", result.reason


@pytest.mark.parametrize("plugin_id", SIGNED_PLUGINS)
def test_bundled_plugin_verifies_against_the_committed_blob_bytes(
    plugin_id, tmp_path, monkeypatch,
):
    """Same check, but using the bytes git *actually stores*, read out of the object DB.

    ``autocrlf=false`` and ``autocrlf=input`` write the blob to disk verbatim,
    so this is not a reconstruction of that checkout — it is that checkout.
    """
    src = _PLUGINS_DIR / plugin_id
    out = tmp_path / plugin_id
    out.mkdir(parents=True)
    for f in sorted(src.iterdir()):
        if not f.is_file():
            continue
        rel = f.relative_to(_REPO_ROOT).as_posix()
        try:
            blob = subprocess.run(  # noqa: S603
                ["git", "cat-file", "-p", f"HEAD:{rel}"],  # noqa: S607
                cwd=_REPO_ROOT,
                capture_output=True,
                check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            pytest.skip(f"git object for {rel} unavailable: {exc}")
        (out / f.name).write_bytes(blob)

    # signature.sig was rewritten in this change and its blob is only in the
    # working tree until commit; use the on-disk signature with the blob code.
    shutil.copy2(src / "signature.sig", out / "signature.sig")

    manifest = loader._parse_toml(out / "plugin.toml", source="test")
    assert manifest is not None
    monkeypatch.setattr(loader, "_resolve_module_files", _relocated_resolver(out))

    result = loader.verify(manifest, [FIRST_PARTY_PUBKEY], allow_unsigned=False)
    assert result.status == "valid", (
        f"{plugin_id} does not verify against its committed blob bytes: {result.reason}"
    )


@pytest.mark.parametrize("plugin_id", SENTINEL_PLUGINS)
def test_sentinel_plugins_were_not_accidentally_signed(plugin_id, tmp_path):
    """hello_world and claude_code_bridge stay on the UNSIGNED sentinel.

    Asserted against ``_SENTINEL_SIG_AT_IMPORT`` rather than the live file:
    ``tests/unit/mcp_host/test_loader.py`` and the ``signed_hello_world_keypair``
    fixture temporarily overwrite ``hello_world/signature.sig`` with a real
    test-key signature and restore it on teardown, so reading it mid-run says
    nothing about what is committed.  Collection completes before any test body
    executes, so the import-time snapshot is the checked-out state.
    """
    sig = _SENTINEL_SIG_AT_IMPORT[plugin_id]
    assert sig == _SENTINEL, f"{plugin_id} signature.sig is no longer the sentinel"

    # …and the sentinel still means "unsigned", not "valid".
    out = _materialise(plugin_id, tmp_path, _to_lf)
    (out / "signature.sig").write_bytes(sig)
    manifest = loader._parse_toml(out / "plugin.toml", source="test")
    assert manifest is not None
    assert loader.verify(manifest, allow_unsigned=True).status == "unsigned"
    assert loader.verify(manifest, allow_unsigned=False).status == "quarantined"


# --------------------------------------------------------------------------
# The normalisation itself, and its deliberate limits.
# --------------------------------------------------------------------------


def test_file_digest_is_line_ending_independent_for_python(tmp_path):
    """A .py file hashes the same as CRLF, LF and CR."""
    body = b"import sys\n\n\ndef go():\n    return 'x'\n"
    digests = set()
    for name, transform in (("lf", _to_lf), ("crlf", _to_crlf), ("cr", _to_cr)):
        p = tmp_path / f"{name}.py"
        p.write_bytes(transform(body))
        digests.add(loader._file_digest(p))
    assert len(digests) == 1, "a .py file's digest still depends on its line endings"


def test_file_digest_is_byte_exact_for_non_python(tmp_path):
    """Normalisation stays scoped to Python source.

    The CRLF/LF collision is only sound because CPython's tokenizer collapses
    the same pairs, so the colliding byte strings are literally the same
    program.  That argument does not carry to a .ps1 here-string, a .json blob
    or an executable, so those must still be hashed byte-for-byte.  If someone
    widens the normalisation, this fails.
    """
    body = b"line one\nline two\n"
    lf = tmp_path / "data.json"
    crlf = tmp_path / "other.json"
    lf.write_bytes(body)
    crlf.write_bytes(_to_crlf(body))
    assert loader._file_digest(lf) != loader._file_digest(crlf)


def test_normalise_newlines_matches_cpython_tokenizer():
    """The three forms of a source file compile to the same code object.

    This is the security argument for hashing normalised bytes, executed rather
    than asserted: the byte strings that now share a signature are exactly the
    ones CPython cannot tell apart.
    """
    body = b"X = 1\nY = '''a\nb'''\n\n\ndef f():\n    return X, Y\n"
    codes = {
        compile(transform(body), "<t>", "exec").co_consts
        for transform in (_to_lf, _to_crlf, _to_cr)
    }
    assert len(codes) == 1
    normalised = {loader.normalise_newlines(t(body)) for t in (_to_lf, _to_crlf, _to_cr)}
    assert normalised == {_to_lf(body)}


def test_gitattributes_pins_signature_files_as_binary():
    """signature.sig must never be run through git's text conversion.

    Git currently guesses "binary" for a 64-byte Ed25519 signature from its
    non-printable byte ratio.  That is a guess, not a contract; if it ever went
    the other way, an autocrlf=true checkout would expand the 0x0A bytes and
    produce a signature that cannot verify anywhere.
    """
    attrs = (_REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    rules = [
        line.split("#", 1)[0].split()
        for line in attrs.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert any(
        parts and parts[0].endswith("signature.sig") and "binary" in parts[1:] for parts in rules
    ), ".gitattributes no longer pins plugin signature.sig as binary"


# --------------------------------------------------------------------------
# Submodule coverage: nothing in a package plugin escapes the signature.
# --------------------------------------------------------------------------


_PKG_NAME = "sig_coverage_probe_pkg"


@pytest.fixture
def signed_package_plugin(tmp_path, monkeypatch):
    """A real importable package plugin with submodules, signed with a test key.

    Yields ``(manifest, pubkey, pkg_dir)``.
    """
    root = tmp_path / "syspath_root"
    pkg = root / _PKG_NAME
    (pkg / "deep").mkdir(parents=True)
    (pkg / "__init__.py").write_bytes(b"VERSION = '1'\n")
    (pkg / "__main__.py").write_bytes(b"from . import helper\n\nhelper.go()\n")
    (pkg / "helper.py").write_bytes(b"def go():\n    return 'safe'\n")
    (pkg / "deep" / "__init__.py").write_bytes(b"")
    (pkg / "deep" / "tool.py").write_bytes(b"LIMIT = 1\n")

    monkeypatch.syspath_prepend(str(root))
    importlib.invalidate_caches()

    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.toml").write_text(
        'id = "probe"\nname = "Probe"\nversion = "0.0.1"\n'
        f'runtime = "python"\nentry = ["-m", "{_PKG_NAME}"]\n'
        "declared_permissions = []\nconfirmable_conditions = []\n",
        encoding="utf-8",
    )

    manifest = loader._parse_toml(plugin_dir / "plugin.toml", source="test")
    assert manifest is not None

    signing_key = SigningKey.generate()
    pubkey = bytes(signing_key.verify_key)
    manifest.signature_file.write_bytes(signing_key.sign(loader.signing_message(manifest)).signature)

    assert loader.verify(manifest, [pubkey], allow_unsigned=False).status == "valid"
    return manifest, pubkey, pkg


def test_package_signature_covers_every_submodule(signed_package_plugin):
    """Every .py in the package tree is in the hash set, not just __init__/__main__."""
    manifest, _pubkey, pkg = signed_package_plugin
    covered = {
        p.relative_to(pkg).as_posix()
        for p in loader._entry_file_paths(manifest.entry, manifest.plugin_dir)
    }
    assert covered == {
        "__init__.py",
        "__main__.py",
        "helper.py",
        "deep/__init__.py",
        "deep/tool.py",
    }, covered


@pytest.mark.parametrize("victim", ["helper.py", "deep/tool.py", "deep/__init__.py"])
def test_tampering_with_a_submodule_invalidates_the_signature(signed_package_plugin, victim):
    """Editing a submodule the old code ignored now fails loudly."""
    manifest, pubkey, pkg = signed_package_plugin
    target = pkg.joinpath(*victim.split("/"))
    target.write_bytes(target.read_bytes() + b"\nBACKDOOR = True\n")

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "invalid", (
        f"tampering with {victim} left the plugin verifying as {result.status}"
    )


def test_adding_a_submodule_invalidates_the_signature(signed_package_plugin):
    """A file smuggled into a signed package cannot be silently ignored."""
    manifest, pubkey, pkg = signed_package_plugin
    (pkg / "smuggled.py").write_bytes(b"import os\n\nos.environ['PWNED'] = '1'\n")

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "invalid", (
        f"an unsigned file added to the package left the plugin {result.status}"
    )


def test_removing_a_submodule_invalidates_the_signature(signed_package_plugin):
    """Deleting covered code is a change too."""
    manifest, pubkey, pkg = signed_package_plugin
    (pkg / "helper.py").unlink()

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "invalid", result.status


def test_package_signature_survives_line_ending_change_in_a_submodule(signed_package_plugin):
    """…but a pure line-ending change is not a change to the program."""
    manifest, pubkey, pkg = signed_package_plugin
    for py in loader._sorted_importable_files(pkg):
        py.write_bytes(_to_crlf(py.read_bytes()))

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "valid", result.reason


def test_sorted_importable_files_order_by_relative_posix_path(tmp_path):
    """Hash order is a pure function of the relative paths, not of OS collation."""
    root = tmp_path / "pkg"
    (root / "b").mkdir(parents=True)
    for rel in ("z.py", "a.py", "b/c.py", "b/A.py"):
        root.joinpath(*rel.split("/")).write_bytes(b"x = 1\n")

    order = [p.relative_to(root).as_posix() for p in loader._sorted_importable_files(root)]
    assert order == sorted(order), order
    assert order == ["a.py", "b/A.py", "b/c.py", "z.py"]


def test_unreadable_covered_file_fails_closed(tmp_path, monkeypatch):
    """A covered file that cannot be read yields 'invalid', not an exception."""
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.toml").write_text(
        'id = "gone"\nname = "Gone"\nversion = "0.0.1"\n'
        'runtime = "python"\nentry = ["python"]\n',
        encoding="utf-8",
    )
    (plugin_dir / "code.py").write_bytes(b"x = 1\n")
    manifest = loader._parse_toml(plugin_dir / "plugin.toml", source="test")
    assert manifest is not None
    manifest.signature_file.write_bytes(b"\x01" * 64)

    def _boom(path):
        # Stands in for the file being deleted between listing and hashing.
        msg = f"vanished: {path}"
        raise OSError(msg)

    monkeypatch.setattr(loader, "_file_digest", _boom)
    result = loader.verify(manifest, [b"\x00" * 32], allow_unsigned=False)
    assert result.status == "invalid"
    assert "unreadable" in result.reason


# --------------------------------------------------------------------------
# Rework cycle 1, finding 1: the covered set must be everything CPython
# imports, not everything that ends in .py.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "planted",
    [
        "native.pyd",  # Windows extension module
        "native.so",  # POSIX extension module
        "native.dylib",  # macOS extension module
        "native.dll",  # ctypes / legacy extension
        "sourceless.pyc",  # SourcelessFileLoader imports this directly
        "deep/native.pyd",  # ...at any depth
        "native.cp312-win_amd64.pyd",  # the decorated form Path.suffix trims
        "native.abi3.so",
    ],
)
def test_planted_importable_binary_invalidates_the_signature(signed_package_plugin, planted):
    """A native module dropped beside covered sources must not ride a valid signature.

    This is the original defect one file extension over: hashing ``*.py`` only
    leaves ``submodule.pyd`` covered by nothing, and Python's import machinery
    loads it natively -- arbitrary native code execution under ``status='valid'``.
    """
    manifest, pubkey, pkg = signed_package_plugin
    target = pkg.joinpath(*planted.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)  # PE-shaped; contents irrelevant

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "invalid", (
        f"planting {planted} left the plugin verifying as {result.status}"
    )


def test_importable_suffixes_cover_this_interpreter():
    """The fixed suffix set is a superset of what the running CPython will import.

    ``_IMPORTABLE_SUFFIXES`` is hard-coded rather than read from
    ``importlib.machinery`` so the covered set does not depend on the signing
    host.  That trade only holds while the constant is complete, so check it
    against the interpreter actually running.
    """
    machinery = importlib.machinery
    live = (
        list(machinery.SOURCE_SUFFIXES)
        + list(machinery.BYTECODE_SUFFIXES)
        + list(machinery.EXTENSION_SUFFIXES)
    )
    missing = [s for s in live if Path(f"m{s}").suffix.lower() not in loader._IMPORTABLE_SUFFIXES]
    assert not missing, f"CPython imports suffixes the signed set ignores: {missing}"


def test_bytecode_cache_is_excluded_so_signatures_survive_first_import(signed_package_plugin):
    """__pycache__ is derived state; hashing it would break every plugin on first run."""
    manifest, pubkey, pkg = signed_package_plugin
    cache = pkg / "__pycache__"
    cache.mkdir()
    (cache / "helper.cpython-312.pyc").write_bytes(b"\x00" * 32)

    covered = loader._entry_file_paths(manifest.entry, manifest.plugin_dir)
    assert all("__pycache__" not in p.parts for p in covered)
    assert loader.verify(manifest, [pubkey], allow_unsigned=False).status == "valid"


def test_sourceless_bytecode_beside_sources_is_covered(signed_package_plugin):
    """...but a .pyc OUTSIDE __pycache__ is a directly-importable module, so it counts."""
    manifest, _pubkey, pkg = signed_package_plugin
    (pkg / "standalone.pyc").write_bytes(b"\x00" * 32)

    covered = {p.name for p in loader._entry_file_paths(manifest.entry, manifest.plugin_dir)}
    assert "standalone.pyc" in covered


# --------------------------------------------------------------------------
# Rework cycle 1, finding 2: digests must be bound to file names.
# --------------------------------------------------------------------------


def _digests_only(manifest) -> bytes:
    """The pre-fix message shape: content digests concatenated, no names."""
    return b"".join(
        loader._file_digest(p)
        for p in loader._entry_file_paths(manifest.entry, manifest.plugin_dir)
    )


def test_rename_preserving_sort_order_invalidates_the_signature(signed_package_plugin):
    """Renaming a module inside a signed package is a change to what is signed.

    ``helper.py`` -> ``helper_shim.py`` keeps the sort position (it still falls
    after ``deep/``), so the old digests-only message was byte-identical and the
    signature stayed valid.  The test proves both halves: that the old shape
    really was blind to this, and that the current one is not.
    """
    manifest, pubkey, pkg = signed_package_plugin
    before = _digests_only(manifest)

    (pkg / "helper.py").rename(pkg / "helper_shim.py")
    importlib.invalidate_caches()

    after = _digests_only(manifest)
    assert before == after, (
        "precondition failed: this rename was supposed to preserve the old message"
    )

    result = loader.verify(manifest, [pubkey], allow_unsigned=False)
    assert result.status == "invalid", (
        f"a rename the old scheme could not see left the plugin {result.status}"
    )


def test_moving_a_module_between_directories_invalidates_the_signature(signed_package_plugin):
    """Same argument for a directory move rather than a rename.

    ``deep/tool.py`` → ``deep2/aaa.py`` is chosen so it keeps its sort position
    (``deep/`` < ``deep2/`` < ``helper``), which again leaves the old
    digests-only message byte-identical.  A move that reordered the set would
    have been caught by the old scheme too and would prove nothing.
    """
    manifest, pubkey, pkg = signed_package_plugin
    before = _digests_only(manifest)

    (pkg / "deep2").mkdir()
    (pkg / "deep" / "tool.py").rename(pkg / "deep2" / "aaa.py")
    importlib.invalidate_caches()

    assert _digests_only(manifest) == before, (
        "precondition failed: this move was supposed to preserve the old message"
    )
    assert loader.verify(manifest, [pubkey], allow_unsigned=False).status == "invalid"


def test_label_framing_is_unambiguous(tmp_path):
    """Identical content at different names produces different signed bytes.

    Each covered file contributes exactly 32 bytes of name digest and 32 of
    content digest, so ``a/b.py`` cannot be reparsed as ``a`` plus ``/b.py``.
    """
    messages = []
    for layout in (("a/b.py",), ("ab.py",), ("a.py", "b.py")):
        plugin_dir = tmp_path / f"p{len(messages)}"
        plugin_dir.mkdir()
        (plugin_dir / "plugin.toml").write_text(
            'id = "lbl"\nname = "Lbl"\nversion = "0.0.1"\n'
            'runtime = "python"\nentry = ["python"]\n',
            encoding="utf-8",
        )
        for rel in layout:
            target = plugin_dir.joinpath(*rel.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"SAME = 1\n")
        manifest = loader._parse_toml(plugin_dir / "plugin.toml", source="test")
        assert manifest is not None
        messages.append(loader.signing_message(manifest))

    assert len(set(messages)) == len(messages), "different layouts share a signed message"


def test_covered_labels_are_location_independent(signed_package_plugin):
    """Labels name the module, not the install path, so they survive relocation."""
    manifest, _pubkey, _pkg = signed_package_plugin
    labels = [label for label, _p in loader._covered_files(manifest.entry, manifest.plugin_dir)]
    assert labels == [
        f"{_PKG_NAME}/__init__.py",
        f"{_PKG_NAME}/__main__.py",
        f"{_PKG_NAME}/deep/__init__.py",
        f"{_PKG_NAME}/deep/tool.py",
        f"{_PKG_NAME}/helper.py",
    ], labels
    assert not any(sep in label for label in labels for sep in ("\\", ":"))


# --------------------------------------------------------------------------
# Rework cycle 1, finding 3: suffix matching must not inherit the filesystem's
# casing rules.
# --------------------------------------------------------------------------


def test_uppercase_source_extension_is_discovered_and_normalised(tmp_path):
    """EVIL.PY is found, and is treated as Python source, on every filesystem.

    ``rglob("*.py")`` matched it on Windows and not on Linux, while
    ``suffix == ".py"`` was False everywhere -- one file, three treatments.
    """
    root = tmp_path / "pkg"
    root.mkdir()
    upper = root / "EVIL.PY"
    upper.write_bytes(b"x = 1\r\ny = 2\r\n")

    found = [p.name for p in loader._sorted_importable_files(root)]
    assert "EVIL.PY" in found

    lower = tmp_path / "evil_lower.py"
    lower.write_bytes(b"x = 1\ny = 2\n")
    assert loader._file_digest(upper) == loader._file_digest(lower), (
        "an uppercase .PY was hashed raw instead of newline-normalised"
    )


def test_planted_uppercase_source_invalidates_the_signature(signed_package_plugin):
    """...and it cannot be smuggled into a signed package either."""
    manifest, pubkey, pkg = signed_package_plugin
    (pkg / "SMUGGLED.PY").write_bytes(b"import os\n")

    assert loader.verify(manifest, [pubkey], allow_unsigned=False).status == "invalid"
