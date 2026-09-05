"""Cross-platform fake DPAPI for testing — XOR-based, not cryptographically secure."""

from __future__ import annotations

_XOR_KEY = b"fake-dpapi-xor-key-for-tests-only"


def _xor(data: bytes) -> bytes:
    """XOR *data* with the repeating fake key."""
    key = _XOR_KEY
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def protect(plaintext: bytes, *, entropy: bytes | None = None) -> bytes:
    """Fake-encrypt: XOR plaintext with a fixed key."""
    _ = entropy
    return _xor(plaintext)


def unprotect(blob: bytes, *, entropy: bytes | None = None) -> bytes:
    """Fake-decrypt: XOR is its own inverse."""
    _ = entropy
    return _xor(blob)
