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

from __future__ import annotations

import contextlib
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import workstation_agent.mcp_host.loader as _loader

_HELLO_WORLD_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "workstation_agent"
    / "plugins"
    / "hello_world"
)
_SIG_FILE = _HELLO_WORLD_DIR / "signature.sig"


def _hello_world_manifest() -> _loader.PluginManifest:
    """The bundled hello_world manifest, or an equivalent built from scratch.

    The fallback exists for the case where bundled discovery finds nothing (a
    stripped install); it must describe the same plugin so the signature the
    fixture writes is one the loader would accept.
    """
    discovered = next(
        (m for m in _loader._discover_bundled() if m.id == "hello_world"), None,
    )
    if discovered is not None:
        return discovered
    return _loader.PluginManifest(
        id="hello_world",
        name="Hello World",
        version="0.1.0",
        runtime="python",
        entry=["-m", "workstation_agent.plugins.hello_world"],
        plugin_dir=_HELLO_WORLD_DIR,
        signature_file=_SIG_FILE,
        compat={"min_host_version": "0.1.0"},
    )


def _build_message(manifest: _loader.PluginManifest) -> bytes:
    """Reproduce the exact message that loader.verify() checks.

    Delegates wholesale to :func:`loader.signing_message` rather than
    reassembling the format here.  Reimplementing it is how this fixture went
    stale the last two times the message changed — first when file hashing
    gained newline normalisation, then when each digest gained its path binding
    and the scheme tag.  There is one definition of the message and this is not
    a second copy of it.
    """
    return _loader.signing_message(manifest)


@pytest.fixture(scope="session")
def signed_hello_world_keypair():
    """Session-scoped fixture that signs hello_world with a fresh Ed25519 key.

    Yields:
        Tuple of (public_key_bytes: bytes, signing_key: nacl.signing.SigningKey).
    """
    signing_key = SigningKey.generate()
    pubkey_bytes = bytes(signing_key.verify_key)

    signed = signing_key.sign(_build_message(_hello_world_manifest()))
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
