"""Thin wrapper over ``security.signature.verify``.

Kept as its own module so callers can dependency-inject a fake verifier
during tests without monkey-patching the ``security`` package.
"""

from __future__ import annotations

from workstation_agent.security import signature as _sig


def verify(manifest_bytes: bytes, sig_bytes: bytes, pubkey: bytes) -> bool:
    """Verify an Ed25519 signature over the raw manifest bytes.

    Args:
        manifest_bytes: exact bytes as transmitted (do not re-serialise).
        sig_bytes: 64-byte Ed25519 signature.
        pubkey: 32-byte Ed25519 public key.

    Returns:
        ``True`` on success, ``False`` on any failure (never raises).
    """
    return _sig.verify(pubkey, manifest_bytes, sig_bytes)
