"""Tests for security.dpapi — Windows-only DPAPI round-trips."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="DPAPI is Windows-only",
)


def test_protect_unprotect_roundtrip() -> None:
    """Encrypt then decrypt a small blob returns the original plaintext."""
    from workstation_agent.security.dpapi import protect, unprotect

    plaintext = b"super secret value 12345"
    blob = protect(plaintext)
    assert isinstance(blob, bytes)
    assert blob != plaintext

    result = unprotect(blob)
    assert result == plaintext


def test_protect_with_entropy() -> None:
    """Entropy-bound blobs can be decrypted with the same entropy."""
    from workstation_agent.security.dpapi import protect, unprotect

    plaintext = b"entropy-bound secret"
    entropy = b"my-entropy-seed"
    blob = protect(plaintext, entropy=entropy)
    result = unprotect(blob, entropy=entropy)
    assert result == plaintext


def test_unprotect_garbage_raises_dpapi_error() -> None:
    """Decrypting garbage raises DpapiError (not a generic exception)."""
    from workstation_agent.security.dpapi import DpapiError, unprotect

    with pytest.raises(DpapiError):
        unprotect(b"\x00" * 64)


def test_dpapi_error_no_data_leak() -> None:
    """DpapiError message does not include the blob content."""
    from workstation_agent.security.dpapi import DpapiError, unprotect

    garbage = b"\xde\xad\xbe\xef" * 8
    with pytest.raises(DpapiError) as exc_info:
        unprotect(garbage)
    msg = exc_info.value.args[0]
    assert "\xde\xad" not in msg
    assert "plaintext" not in msg.lower()


def test_protect_failure_raises_dpapi_error() -> None:
    """If CryptProtectData raises, DpapiError is raised with an error code."""
    import win32crypt

    from workstation_agent.security.dpapi import DpapiError, protect

    with (
        patch.object(win32crypt, "CryptProtectData", side_effect=OSError("fail")),
        pytest.raises(DpapiError, match="CryptProtectData failed"),
    ):
        protect(b"data")
