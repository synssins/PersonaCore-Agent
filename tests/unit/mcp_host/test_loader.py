"""Unit tests for workstation_agent.mcp_host.loader."""
# ruff: noqa: ANN201, S101, SLF001, ANN202

from __future__ import annotations

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
