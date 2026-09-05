"""Unit tests for workstation_agent.mcp_host.loader."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
from pathlib import Path

from nacl.signing import SigningKey

import workstation_agent.security.signature as _sig
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

    manifest_dict = loader._manifest_dict(m)
    msg = _sig.canonical_json(manifest_dict) + b"\n"
    signed = signing_key.sign(msg)

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

    manifest_dict = loader._manifest_dict(m)
    msg = _sig.canonical_json(manifest_dict) + b"\n"
    signed = signing_key1.sign(msg)
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


def _sign_hello_world_bundle(pubkey_bytes: bytes, signing_key: SigningKey) -> None:
    """Re-sign the bundled hello_world plugin with *signing_key* and register pubkey."""
    manifests = loader._discover_bundled()
    hw = next(m for m in manifests if m.id == "hello_world")
    manifest_dict = loader._manifest_dict(hw)
    manifest_bytes = _sig.canonical_json(manifest_dict)
    entry_paths = loader._entry_file_paths(hw.entry, hw.plugin_dir)
    entry_hash_parts = [
        hashlib.sha256(p.read_bytes()).digest() for p in entry_paths
    ]
    message = manifest_bytes + b"\n" + b"".join(entry_hash_parts)
    signed = signing_key.sign(message)
    hw.signature_file.write_bytes(signed.signature)
    if pubkey_bytes not in loader.TRUSTED_PUBKEYS:
        loader.TRUSTED_PUBKEYS.append(pubkey_bytes)


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
    manifest_dict = loader._manifest_dict(m)
    manifest_bytes = _sig.canonical_json(manifest_dict)
    entry_paths = loader._entry_file_paths(m.entry, m.plugin_dir)
    entry_hash_parts = [hashlib.sha256(p.read_bytes()).digest() for p in entry_paths]
    message = manifest_bytes + b"\n" + b"".join(entry_hash_parts)
    signed = signing_key.sign(message)
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


def test_entry_file_hashing_includes_module_files():
    """Tampering with __main__.py of a signed plugin flips verify → 'invalid'."""
    signing_key = SigningKey.generate()
    pubkey = bytes(signing_key.verify_key)

    original_sig = (_HELLO_WORLD_DIR / "signature.sig").read_bytes()
    main_path = _HELLO_WORLD_DIR / "__main__.py"
    original_main = main_path.read_bytes()
    try:
        # Sign the plugin fresh with the test key.
        _sign_hello_world_bundle(pubkey, signing_key)

        # Sanity check: unmodified plugin verifies.
        hw = next(m for m in loader._discover_bundled() if m.id == "hello_world")
        good = loader.verify(hw, [pubkey], allow_unsigned=False)
        assert good.status == "valid", good.reason

        # Tamper: change one byte in __main__.py.
        main_path.write_bytes(original_main + b"\n# tampered\n")

        tampered = loader.verify(hw, [pubkey], allow_unsigned=False)
        assert tampered.status == "invalid", (
            f"expected invalid after __main__.py tamper, got {tampered.status}"
        )
    finally:
        main_path.write_bytes(original_main)
        (_HELLO_WORLD_DIR / "signature.sig").write_bytes(original_sig)
        with contextlib.suppress(ValueError):
            loader.TRUSTED_PUBKEYS.remove(pubkey)


def test_entry_file_hashing_covers_package_init_and_main():
    """Tampering with __init__.py of a signed plugin flips verify → 'invalid'."""
    signing_key = SigningKey.generate()
    pubkey = bytes(signing_key.verify_key)

    original_sig = (_HELLO_WORLD_DIR / "signature.sig").read_bytes()
    init_path = _HELLO_WORLD_DIR / "__init__.py"
    original_init = init_path.read_bytes()
    try:
        _sign_hello_world_bundle(pubkey, signing_key)

        hw = next(m for m in loader._discover_bundled() if m.id == "hello_world")
        good = loader.verify(hw, [pubkey], allow_unsigned=False)
        assert good.status == "valid", good.reason

        # Tamper: change one byte in __init__.py.
        init_path.write_bytes(original_init + b"\n# tampered\n")

        tampered = loader.verify(hw, [pubkey], allow_unsigned=False)
        assert tampered.status == "invalid", (
            f"expected invalid after __init__.py tamper, got {tampered.status}"
        )
    finally:
        init_path.write_bytes(original_init)
        (_HELLO_WORLD_DIR / "signature.sig").write_bytes(original_sig)
        with contextlib.suppress(ValueError):
            loader.TRUSTED_PUBKEYS.remove(pubkey)


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
