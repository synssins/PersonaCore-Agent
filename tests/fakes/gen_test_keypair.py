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
3. Writes a real 64-byte signature into a **copy** of the hello_world plugin
   under ``tmp_path``; the tracked canary keeps its ``UNSIGNED`` sentinel.
4. Appends the test public key to ``workstation_agent.mcp_host.loader.TRUSTED_PUBKEYS``.
5. Yields ``(public_key_bytes, signing_key)`` to the test.
6. On teardown: removes the test key from TRUSTED_PUBKEYS.

Nothing in this module writes to the source tree.  See
:func:`signed_hello_world_keypair` for why that matters.
"""

from __future__ import annotations

import contextlib
import shutil
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


def copy_plugin(source_dir: Path, dest_parent: Path) -> _loader.PluginManifest:
    """Copy a bundled plugin into *dest_parent* and return a manifest for the copy.

    The copy's manifest carries an **empty** ``entry``.  That is deliberate and
    it is the only way this works: ``loader._covered_files`` resolves a
    ``-m <module>`` entry through ``importlib.util.find_spec``, which finds the
    *installed* package, not the copy — so a copy signed under the real entry
    would have its signature computed over the original's files and the whole
    exercise would be a no-op.  With no ``-m`` argument the resolver falls back
    to scanning ``plugin_dir``, which is the copy.  ``host._resolve_entry``
    treats an empty entry as ``-m workstation_agent.plugins.<id>`` anyway, so a
    copy is still spawnable.
    """
    dest = dest_parent / source_dir.name
    shutil.copytree(source_dir, dest, ignore=shutil.ignore_patterns("__pycache__"))
    manifest = _loader._parse_toml(dest / "plugin.toml", source="bundled")
    if manifest is None:  # pragma: no cover - the bundled manifest always parses
        msg = f"could not parse the copied manifest at {dest}"
        raise RuntimeError(msg)
    manifest.entry = []
    return manifest


def sign_plugin_copy(
    manifest: _loader.PluginManifest,
    signing_key: SigningKey,
) -> bytes:
    """Write a real signature for *manifest* and return the public key."""
    manifest.signature_file.write_bytes(signing_key.sign(_build_message(manifest)).signature)
    return bytes(signing_key.verify_key)


@pytest.fixture(scope="session")
def signed_hello_world_keypair(tmp_path_factory):
    """A fresh Ed25519 keypair that really has signed a real plugin.

    **It signs a COPY.**  This fixture used to write a 64-byte signature into
    the tracked ``src/workstation_agent/plugins/hello_world/signature.sig``,
    which is committed as the 8-byte ``UNSIGNED`` sentinel, and restore it on
    teardown.  Three things were wrong with that:

    * teardown does not run when the session is killed — a timeout, a ``^C``,
      a crash — so a developer's working tree was left with a modified tracked
      file, and ``git status`` showed a plugin signature edited by a test run;
    * the "original" it restored was whatever it read at setup, so a run that
      started from an already-corrupted file cemented the corruption;
    * it is **session-scoped**, so from the first test that requested it until
      the end of the run the ``hello_world`` canary verified ``valid`` instead
      of ``unsigned``, quietly changing what every later test saw. Once, with
      leftover state from an interrupted run, it verified ``invalid`` and the
      plugin was quarantined instead — which is the kind of state that makes an
      unrelated failure look like a code bug.

    The canary is now left exactly as committed.  Consumers want two things —
    a trusted public key registered with the loader, and the assurance that it
    corresponds to a signature the loader really accepts — and both are
    provided by signing a throwaway copy under ``tmp_path``.

    Yields:
        Tuple of (public_key_bytes: bytes, signing_key: nacl.signing.SigningKey).
    """
    signing_key = SigningKey.generate()
    copy = copy_plugin(_HELLO_WORLD_DIR, tmp_path_factory.mktemp("signed-plugin"))
    pubkey_bytes = sign_plugin_copy(copy, signing_key)

    # The signature is real, and proving so here means a consumer that only
    # registers the key is not quietly relying on something untested.
    result = _loader.verify(copy, [pubkey_bytes], allow_unsigned=False)
    if result.status != "valid":  # pragma: no cover - a broken fixture, not a test
        msg = f"the fixture's own signature did not verify: {result.status} {result.reason}"
        raise RuntimeError(msg)

    _loader.TRUSTED_PUBKEYS.append(pubkey_bytes)
    try:
        yield pubkey_bytes, signing_key
    finally:
        with contextlib.suppress(ValueError):
            _loader.TRUSTED_PUBKEYS.remove(pubkey_bytes)


@pytest.fixture(scope="session")
def test_signing_key():
    """Return a fresh Ed25519 signing key (not registered with the loader)."""
    return SigningKey.generate()
