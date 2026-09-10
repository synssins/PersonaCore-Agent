"""Unit tests for workstation_agent.mcp_host.loader."""

from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from tests.fakes.gen_test_keypair import copy_plugin, sign_plugin_copy
from workstation_agent.mcp_host import loader

_HELLO_WORLD_DIR = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "workstation_agent"
    / "plugins"
    / "hello_world"
)


def _make_manifest(tmp_path, **kwargs):
    plugin_id = kwargs.get("id", "test_plugin")
    toml_content = (
        f'id = "{plugin_id}"\n'
        'name = "Test"\n'
        'version = "0.0.1"\n'
        'runtime = "python"\n'
        "entry = []\n"
        "declared_permissions = []\n"
        "confirmable_conditions = []\n"
    )
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(toml_content, encoding="utf-8")
    sig_path = tmp_path / "signature.sig"
    sig_path.write_bytes(b"UNSIGNED")
    return loader._parse_toml(toml_path, source="test")


def test_parse_toml_valid(tmp_path):
    """Valid plugin.toml parses into a PluginManifest."""
    toml_content = """
id = "my_plugin"
name = "My Plugin"
version = "1.2.3"
runtime = "python"
entry = ["-m", "my_plugin"]
declared_permissions = ["tool:my_plugin.do_thing"]
confirmable_conditions = ["outside_declared_paths"]

[compat]
min_host_version = "0.1.0"
"""
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(toml_content, encoding="utf-8")
    m = loader._parse_toml(toml_path, source="test")
    assert m is not None
    assert m.id == "my_plugin"
    assert m.name == "My Plugin"
    assert m.version == "1.2.3"
    assert m.entry == ["-m", "my_plugin"]
    assert m.declared_permissions == ["tool:my_plugin.do_thing"]
    assert m.confirmable_conditions == ["outside_declared_paths"]
    assert m.compat == {"min_host_version": "0.1.0"}
    assert m.source == "test"


def test_parse_toml_missing_id(tmp_path):
    """plugin.toml without required 'id' returns None."""
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text('name = "no id"\n', encoding="utf-8")
    m = loader._parse_toml(toml_path)
    assert m is None


def test_parse_toml_bad_file(tmp_path):
    """Non-existent path returns None."""
    m = loader._parse_toml(tmp_path / "does_not_exist.toml")
    assert m is None


def test_discover_includes_hello_world():
    """discover() should find the bundled hello_world plugin."""
    manifests = loader.discover()
    ids = [m.id for m in manifests]
    assert "hello_world" in ids


def test_discover_hello_world_manifest():
    """hello_world manifest has expected fields."""
    manifests = loader.discover()
    hw = next(m for m in manifests if m.id == "hello_world")
    assert hw.name == "Hello World"
    assert hw.runtime == "python"
    assert hw.source == "bundled"


def test_discover_user_folder(tmp_path, monkeypatch):
    """discover() scans the user plugins_dir for plugin.toml files."""
    plugin_dir = tmp_path / "my_user_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.toml").write_text(
        (
            'id = "user_plugin"\nname = "User"\nversion = "0.0.1"\n'
            'runtime = "python"\nentry = []\n'
        ),
        encoding="utf-8",
    )
    (plugin_dir / "signature.sig").write_bytes(b"UNSIGNED")

    from workstation_agent.config import store
    original_paths = store.paths

    def fake_paths():
        p = original_paths()
        p["plugins_dir"] = tmp_path
        return p

    monkeypatch.setattr(store, "paths", fake_paths)

    manifests = loader.discover()
    ids = [m.id for m in manifests]
    assert "user_plugin" in ids


def test_verify_unsigned_allowed(tmp_path):
    """allow_unsigned=True + sentinel sig → status='unsigned'."""
    m = _make_manifest(tmp_path)
    assert m is not None
    result = loader.verify(m, [], allow_unsigned=True)
    assert result.status == "unsigned"


def test_verify_unsigned_not_allowed(tmp_path):
    """allow_unsigned=False + sentinel sig → status='quarantined'."""
    m = _make_manifest(tmp_path)
    assert m is not None
    result = loader.verify(m, [], allow_unsigned=False)
    assert result.status == "quarantined"


def test_verify_absent_sig_not_allowed(tmp_path):
    """Missing signature.sig + allow_unsigned=False → quarantined."""
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(
        'id = "x"\nname = "X"\nversion = "0.1"\nruntime = "python"\nentry = []\n',
        encoding="utf-8",
    )
    m = loader._parse_toml(toml_path)
    assert m is not None
    result = loader.verify(m, [], allow_unsigned=False)
    assert result.status == "quarantined"


def test_verify_absent_sig_allowed(tmp_path):
    """Missing signature.sig + allow_unsigned=True → unsigned."""
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(
        'id = "x"\nname = "X"\nversion = "0.1"\nruntime = "python"\nentry = []\n',
        encoding="utf-8",
    )
    m = loader._parse_toml(toml_path)
    assert m is not None
    result = loader.verify(m, [], allow_unsigned=True)
    assert result.status == "unsigned"


def test_verify_valid_signature(tmp_path):
    """A real Ed25519 signature produced by the test key verifies as 'valid'."""
    signing_key = SigningKey.generate()
    pubkey = bytes(signing_key.verify_key)

    toml_content = (
        'id = "signed_plugin"\nname = "Signed"\nversion = "1.0"\n'
        'runtime = "python"\nentry = []\n'
    )
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(toml_content, encoding="utf-8")
    m = loader._parse_toml(toml_path)
    assert m is not None

    signed = signing_key.sign(loader.signing_message(m))
    m.signature_file.write_bytes(signed.signature)

    result = loader.verify(m, [pubkey], allow_unsigned=False)
    assert result.status == "valid"
    assert result.pubkey_id == hashlib.sha256(pubkey).hexdigest()


def test_verify_wrong_key(tmp_path):
    """Signature from a different key → 'invalid'."""
    signing_key1 = SigningKey.generate()
    signing_key2 = SigningKey.generate()
    pubkey2 = bytes(signing_key2.verify_key)

    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(
        'id = "p"\nname = "P"\nversion = "1"\nruntime = "python"\nentry = []\n',
        encoding="utf-8",
    )
    m = loader._parse_toml(toml_path)
    assert m is not None

    signed = signing_key1.sign(loader.signing_message(m))
    m.signature_file.write_bytes(signed.signature)

    result = loader.verify(m, [pubkey2])
    assert result.status == "invalid"


def test_verify_bad_length_sig(tmp_path):
    """Signature that is not 64 bytes → 'invalid'."""
    toml_path = tmp_path / "plugin.toml"
    toml_path.write_text(
        'id = "p"\nname = "P"\nversion = "1"\nruntime = "python"\nentry = []\n',
        encoding="utf-8",
    )
    m = loader._parse_toml(toml_path)
    assert m is not None
    m.signature_file.write_bytes(b"tooshort")
    result = loader.verify(m, [])
    assert result.status == "invalid"


def test_discover_entry_point_source(tmp_path, monkeypatch):
    """Entry-point returning a Path to plugin.toml is discovered."""
    plugin_dir = tmp_path / "ep_plugin"
    plugin_dir.mkdir()
    toml_path = plugin_dir / "plugin.toml"
    toml_path.write_text(
        'id = "ep_plugin"\nname = "EP"\nversion = "0.1"\nruntime = "python"\nentry = []\n',
        encoding="utf-8",
    )
    (plugin_dir / "signature.sig").write_bytes(b"UNSIGNED")

    class FakeEP:
        name = "ep_plugin"

        def load(self):
            return str(toml_path)

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda group: [FakeEP()] if group == "workstation_agent.plugins" else [],
    )

    manifests = loader._discover_entry_points()
    assert any(m.id == "ep_plugin" for m in manifests)


def test_entry_file_paths_resolves_module_and_package():
    """_entry_file_paths for hello_world returns both __init__.py and __main__.py."""
    paths = loader._entry_file_paths(
        ["-m", "workstation_agent.plugins.hello_world"],
        _HELLO_WORLD_DIR,
    )
    names = {p.name for p in paths}
    # Package: at least __init__.py and __main__.py must be covered.
    assert "__init__.py" in names
    assert "__main__.py" in names


def test_entry_file_paths_handles_unknown_module(tmp_path):
    """Unknown module name falls back to hashing every .py in plugin_dir."""
    # Empty plugin_dir → fallback still yields empty list.
    paths = loader._entry_file_paths(
        ["-m", "this.module.does.not.exist_xyz"], tmp_path,
    )
    assert paths == []


def test_entry_file_paths_handles_dangling_dash_m(tmp_path):
    """`-m` with no following argument does not raise; empty dir → empty list."""
    paths = loader._entry_file_paths(["-m"], tmp_path)
    assert paths == []


def test_entry_file_paths_hashes_external_plugin_dir_when_module_not_on_syspath(tmp_path):
    """External plugin whose module isn't on sys.path → hash all .py in plugin_dir.

    Also verifies that tampering with the external plugin file flips the
    signature verification result to 'invalid', proving the code IS covered.
    """
    plugin_dir = tmp_path / "external_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.toml").write_text(
        (
            'id = "ext"\nname = "Ext"\nversion = "0.0.1"\n'
            'runtime = "python"\nentry = ["-m", "external_module_not_on_syspath_zzz"]\n'
        ),
        encoding="utf-8",
    )
    ext_module = plugin_dir / "external_module_not_on_syspath_zzz.py"
    ext_module.write_bytes(b'print("hello from external")\n')

    # Sanity: the module is NOT on sys.path (should return empty from _resolve_module_paths).
    assert loader._resolve_module_paths("external_module_not_on_syspath_zzz") == []

    # _entry_file_paths should now fall back and include the external .py file.
    paths = loader._entry_file_paths(
        ["-m", "external_module_not_on_syspath_zzz"], plugin_dir,
    )
    assert ext_module in paths, f"expected {ext_module} in {paths}"

    # Prove the file IS covered by the signature: tamper with it and expect 'invalid'.
    signing_key = SigningKey.generate()
    pubkey = bytes(signing_key.verify_key)
    m = loader._parse_toml(plugin_dir / "plugin.toml")
    assert m is not None
    signed = signing_key.sign(loader.signing_message(m))
    m.signature_file.write_bytes(signed.signature)

    # Unmodified: valid.
    assert loader.verify(m, [pubkey], allow_unsigned=False).status == "valid"

    # Tamper the external module file → signature must invalidate.
    ext_module.write_bytes(b'print("TAMPERED")\n')
    tampered = loader.verify(m, [pubkey], allow_unsigned=False)
    assert tampered.status == "invalid", (
        f"expected invalid after tampering external module, got {tampered.status}"
    )


def test_entry_file_paths_hashes_all_py_when_entry_has_no_files(tmp_path):
    """Entry with no -m and no file args → hash every .py under plugin_dir."""
    plugin_dir = tmp_path / "no_entry_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "a.py").write_bytes(b"a = 1\n")
    (plugin_dir / "b.py").write_bytes(b"b = 2\n")
    sub = plugin_dir / "sub"
    sub.mkdir()
    (sub / "c.py").write_bytes(b"c = 3\n")

    paths = loader._entry_file_paths(["python"], plugin_dir)
    py_files = {p.name for p in paths}
    assert py_files == {"a.py", "b.py", "c.py"}, f"got {py_files}"


@pytest.mark.parametrize("filename", ["__main__.py", "__init__.py"])
def test_tampering_with_any_covered_module_flips_verify_to_invalid(tmp_path, filename):
    """Tampering with a signed plugin's code flips verify → 'invalid'.

    Operates on a **copy**.  These two tests used to sign the tracked
    ``hello_world`` in place and then write ``# tampered`` into its
    ``__init__.py`` / ``__main__.py``, restoring both in a ``finally``.  A
    ``finally`` does not run when the session is killed — a pytest-timeout, a
    ``^C`` — so an interrupted run left a tracked plugin's *source* with a
    tamper marker in it and its signature rewritten, which is both a dirty
    working tree and a booby trap for the next run.
    """
    signing_key = SigningKey.generate()
    copy = copy_plugin(_HELLO_WORLD_DIR, tmp_path)
    pubkey = sign_plugin_copy(copy, signing_key)

    good = loader.verify(copy, [pubkey], allow_unsigned=False)
    assert good.status == "valid", good.reason

    target = copy.plugin_dir / filename
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")

    tampered = loader.verify(copy, [pubkey], allow_unsigned=False)
    assert tampered.status == "invalid", (
        f"expected invalid after {filename} tamper, got {tampered.status}"
    )


def test_a_test_run_never_modifies_a_tracked_plugin_signature():
    """The canary is committed as the sentinel and must stay that way.

    ``hello_world`` and ``claude_code_bridge`` are deliberately unsigned, and
    several tests need a *real* signature to check against.  Signing them in
    place made ``git status`` show a modified plugin signature after a run, and
    a half-restored one made an unrelated hang look like a code bug.
    """
    for plugin_id in ("hello_world", "claude_code_bridge"):
        sig = _HELLO_WORLD_DIR.parent / plugin_id / "signature.sig"
        assert sig.read_bytes() == b"UNSIGNED", (
            f"{plugin_id}/signature.sig was rewritten by a test; it is committed "
            f"as the UNSIGNED sentinel and tests must sign a copy instead"
        )


def test_discover_deduplication(tmp_path, monkeypatch):
    """Second occurrence of the same plugin_id is skipped by discover()."""
    for subdir in ("p1", "p2"):
        d = tmp_path / subdir
        d.mkdir()
        (d / "plugin.toml").write_text(
            (
                'id = "dup_plugin"\nname = "Dup"\nversion = "0.1"\n'
                'runtime = "python"\nentry = []\n'
            ),
            encoding="utf-8",
        )
        (d / "signature.sig").write_bytes(b"UNSIGNED")

    from workstation_agent.config import store

    def fake_paths():
        return {
            "plugins_dir": tmp_path,
            "audit_db": tmp_path / "audit.db",
            "config_file": tmp_path / "config.toml",
            "secrets_dir": tmp_path / "secrets",
            "conversations_db": tmp_path / "conv.db",
            "logs_dir": tmp_path / "logs",
        }

    monkeypatch.setattr(store, "paths", fake_paths)

    combined = loader.discover()
    ids = [m.id for m in combined]
    assert ids.count("dup_plugin") <= 1


# ---------------------------------------------------------------------------
# The signer must not silently sign the wrong message
# ---------------------------------------------------------------------------


def test_unresolved_entry_modules_reports_an_unimportable_m_entry():
    assert loader.unresolved_entry_modules(["-m", "no.such.module.anywhere"]) == [
        "no.such.module.anywhere",
    ]


def test_unresolved_entry_modules_is_empty_for_an_importable_one():
    assert loader.unresolved_entry_modules(
        ["-m", "workstation_agent.plugins.hello_world"],
    ) == []


@pytest.mark.parametrize("entry", [[], ["-m"], ["plugin.py"]])
def test_unresolved_entry_modules_ignores_entries_with_no_module(entry):
    assert loader.unresolved_entry_modules(entry) == []


def test_the_two_label_schemes_really_do_produce_different_messages(tmp_path):
    """Why the signer refuses rather than warns.

    A ``-m`` entry that resolves is labelled module-relative; one that does not
    falls back to plugin-dir-relative.  Same files, different signed message —
    so a signature produced under one scheme is invalid under the other, which
    is exactly what happened when a bundled plugin was signed from a worktree
    whose venv had the package installed from a different checkout.  The signer
    could not notice: its own verify step resolved the same wrong way.
    """
    copy = copy_plugin(_HELLO_WORLD_DIR, tmp_path)  # entry=[] -> directory scan
    dir_scan = [label for label, _ in loader._covered_files(copy.entry, copy.plugin_dir)]
    module = [
        label
        for label, _ in loader._covered_files(
            ["-m", "workstation_agent.plugins.hello_world"], copy.plugin_dir,
        )
    ]
    assert dir_scan != module
    assert all("/" not in label for label in dir_scan)
    assert all(label.startswith("workstation_agent.plugins.") for label in module)


def test_the_signer_refuses_when_it_cannot_import_the_entry_module(tmp_path):
    """The footgun, closed: refuse rather than write a signature valid nowhere."""
    # Loaded by path: `scripts/` is deliberately not a package (ruff's
    # per-file-ignores exempt it from INP001), so there is nothing to import
    # by name and a sys.path insert would only hide that from the type checker.
    import importlib.util

    script = Path(__file__).resolve().parents[3] / "scripts" / "sign_plugin.py"
    spec = importlib.util.spec_from_file_location("_sign_plugin_under_test", script)
    assert spec is not None
    assert spec.loader is not None
    signer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signer)

    copy = copy_plugin(_HELLO_WORLD_DIR, tmp_path)
    toml = copy.plugin_dir / "plugin.toml"
    toml.write_text(
        toml.read_text(encoding="utf-8").replace(
            'entry = ["-m", "workstation_agent.plugins.hello_world"]',
            'entry = ["-m", "no.such.module.anywhere"]',
        ),
        encoding="utf-8",
    )
    before = (copy.plugin_dir / "signature.sig").read_bytes()

    line = signer.sign_plugin(
        copy.plugin_dir, SigningKey.generate(), replace_sentinel=True,
    )
    assert line.startswith("FAIL"), line
    assert "cannot import no.such.module.anywhere" in line
    assert (copy.plugin_dir / "signature.sig").read_bytes() == before, (
        "a refused signing must not have written anything"
    )

    ok = signer.sign_plugin(
        copy.plugin_dir, SigningKey.generate(), replace_sentinel=True, allow_dir_scan=True,
    )
    assert ok.startswith("OK"), ok


# ---------------------------------------------------------------------------
# "What does this plugin declare" -- one function, running or not
# ---------------------------------------------------------------------------


def _declaring_manifest(tmp_path) -> loader.PluginManifest:
    return loader.PluginManifest(
        id="declarer",
        name="Declaring Plugin",
        version="2.0.0",
        runtime="python",
        entry=["-m", "declarer"],
        plugin_dir=tmp_path,
        signature_file=tmp_path / "signature.sig",
        declared_permissions=["tool:demo.echo", "args:demo.echo:read:text=opaque"],
        confirmable_conditions=["command_outside_allowlist"],
    )


def test_plugin_declaration_reports_the_signed_claims_verbatim(tmp_path):
    """The settings UI reads this for a plugin the host never started.

    A plugin that is switched off is skipped by ``MCPHost.start`` and so is
    absent from ``MCPHost.plugins()`` entirely. The page still has to be able to
    say what it declares -- and it has to be the *same* answer the host would
    give, which is why there is one function for the question rather than a
    second reader of the same signed file.
    """
    decl = loader.plugin_declaration(_declaring_manifest(tmp_path))

    assert decl.id == "declarer"
    assert decl.name == "Declaring Plugin"
    assert decl.version == "2.0.0"
    assert decl.declared_permissions == (
        "tool:demo.echo", "args:demo.echo:read:text=opaque",
    )
    assert decl.confirmable_conditions == ("command_outside_allowlist",)


def test_a_declaration_cannot_be_edited_by_whoever_is_shown_it(tmp_path):
    """It is a report about a signed document, not a working copy."""
    decl = loader.plugin_declaration(_declaring_manifest(tmp_path))

    with pytest.raises((AttributeError, TypeError)):
        decl.declared_permissions = ("tool:demo.anything",)  # type: ignore[misc]
    assert isinstance(decl.declared_permissions, tuple)


@pytest.mark.asyncio
async def test_the_host_answers_the_declaration_question_the_same_way(tmp_path):
    """``MCPHost.plugins`` and the UI must not read the manifest differently."""
    from workstation_agent.mcp_host.host import MCPHost, _PluginRuntime

    manifest = _declaring_manifest(tmp_path)
    host = MCPHost()
    host._runtimes[manifest.id] = _PluginRuntime(
        manifest=manifest,
        verify_result=loader.VerifyResult(status="valid"),
    )

    row = (await host.plugins())[0]
    decl = loader.plugin_declaration(manifest)

    assert row.id == decl.id
    assert row.name == decl.name
    assert row.version == decl.version
    assert tuple(row.declared_permissions) == decl.declared_permissions
    assert tuple(row.confirmable_conditions) == decl.confirmable_conditions
