"""pytest session fixture: generate an Ed25519 keypair, sign hello_world, patch loader.

Usage in tests::

    from tests.fakes.gen_test_keypair import signed_hello_world_keypair

    def test_something(signed_hello_world_keypair):
        pubkey, privkey = signed_hello_world_keypair
        ...

The fixture:

1. Generates a fresh Ed25519 keypair via PyNaCl.
2. Computes the correct message (canonical-JSON manifest + SHA-256 of entry
   files) for the hello_world canary plugin.
3. Writes a real 64-byte signature into the hello_world ``signature.sig`` file.
4. Appends the test public key to ``workstation_agent.mcp_host.loader.TRUSTED_PUBKEYS``.
5. Yields ``(public_key_bytes, signing_key)`` to the test.
6. On teardown: removes the test key from TRUSTED_PUBKEYS and restores the
   original sentinel ``b"UNSIGNED"`` in ``signature.sig``.
"""
# ruff: noqa: ANN201, SLF001

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import workstation_agent.mcp_host.loader as _loader
import workstation_agent.security.signature as _sig

_HELLO_WORLD_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "workstation_agent"
    / "plugins"
    / "hello_world"
)
_SIG_FILE = _HELLO_WORLD_DIR / "signature.sig"


def _build_message(manifest_dict: dict, plugin_dir: Path, entry: list[str]) -> bytes:
    """Reproduce the exact message that loader.verify() checks."""
    manifest_bytes = _sig.canonical_json(manifest_dict)
    entry_hash_parts: list[bytes] = []
    for entry_item in entry:
        candidate = Path(entry_item)
        if not candidate.is_absolute():
            candidate = plugin_dir / entry_item
        if candidate.is_file():
            h = hashlib.sha256(candidate.read_bytes()).digest()
            entry_hash_parts.append(h)
    return manifest_bytes + b"\n" + b"".join(entry_hash_parts)


@pytest.fixture(scope="session")
def signed_hello_world_keypair():
    """Session-scoped fixture that signs hello_world with a fresh Ed25519 key.

    Yields:
        Tuple of (public_key_bytes: bytes, signing_key: nacl.signing.SigningKey).
    """
    manifest_list = _loader._discover_bundled()
    hello_manifest = next((m for m in manifest_list if m.id == "hello_world"), None)

    signing_key = SigningKey.generate()
    pubkey_bytes = bytes(signing_key.verify_key)

    if hello_manifest is not None:
        manifest_dict = _loader._manifest_dict(hello_manifest)
        message = _build_message(manifest_dict, hello_manifest.plugin_dir, hello_manifest.entry)
    else:
        manifest_dict = {
            "id": "hello_world",
            "name": "Hello World",
            "version": "0.1.0",
            "runtime": "python",
            "entry": ["-m", "workstation_agent.plugins.hello_world"],
            "declared_permissions": [],
            "confirmable_conditions": [],
            "compat": {"min_host_version": "0.1.0"},
        }
        message = _build_message(manifest_dict, _HELLO_WORLD_DIR, [])

    signed = signing_key.sign(message)
    signature = signed.signature

    original_sig = _SIG_FILE.read_bytes() if _SIG_FILE.exists() else b"UNSIGNED"
    _SIG_FILE.write_bytes(signature)

    _loader.TRUSTED_PUBKEYS.append(pubkey_bytes)

    yield pubkey_bytes, signing_key

    _SIG_FILE.write_bytes(original_sig)
    with contextlib.suppress(ValueError):
        _loader.TRUSTED_PUBKEYS.remove(pubkey_bytes)


@pytest.fixture(scope="session")
def test_signing_key():
    """Return a fresh Ed25519 signing key (not registered with the loader)."""
    return SigningKey.generate()
