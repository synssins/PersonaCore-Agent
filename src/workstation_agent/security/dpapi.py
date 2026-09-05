"""DPAPI encryption/decryption wrappers (Windows-only) and key redaction."""

from __future__ import annotations

import re
import sys


class DpapiError(Exception):
    """Raised when DPAPI protect/unprotect fails.

    Never includes plaintext or ciphertext in the message.
    """


if sys.platform == "win32":
    import win32crypt  # type: ignore[import]

_PLATFORM_MSG = "DPAPI is only available on Windows"
_PROTECT_FAIL = "CryptProtectData failed with code "
_UNPROTECT_FAIL = "CryptUnprotectData failed with code "


def protect(plaintext: bytes, *, entropy: bytes | None = None) -> bytes:
    """Encrypt *plaintext* with DPAPI CurrentUser scope.

    Args:
        plaintext: Raw bytes to protect.
        entropy: Optional entropy blob for extra binding.

    Returns:
        DPAPI-encoded ciphertext blob.

    Raises:
        DpapiError: On non-Windows or encryption failure.
    """
    if sys.platform != "win32":
        raise DpapiError(_PLATFORM_MSG)
    try:
        return win32crypt.CryptProtectData(  # type: ignore[no-any-return]
            plaintext,
            None,
            entropy,
            None,
            None,
            0,
        )
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "winerror", None)
        msg = _PROTECT_FAIL + str(code)
        raise DpapiError(msg) from None


def unprotect(blob: bytes, *, entropy: bytes | None = None) -> bytes:
    """Decrypt a DPAPI blob produced by :func:`protect`.

    Args:
        blob: DPAPI ciphertext blob.
        entropy: Optional entropy blob; must match the one used during protect.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        DpapiError: If decryption fails. Error code is included; no data leaked.
    """
    if sys.platform != "win32":
        raise DpapiError(_PLATFORM_MSG)
    try:
        _desc, plaintext = win32crypt.CryptUnprotectData(blob, entropy)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "winerror", None)
        msg = _UNPROTECT_FAIL + str(code)
        raise DpapiError(msg) from None
    else:
        return plaintext  # type: ignore[no-any-return]


# Regex for OpenAI-style API keys: sk- followed by 20+ alphanumeric/_/- chars
_OPENAI_KEY_RE = re.compile(r"sk-[A-Za-z0-9_-]{20,}")
# Regex for standalone 40+ char base64-ish blobs (letters, digits, +/=)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def redact_key(text: str) -> str:
    """Strip API keys and large base64 blobs from *text* for safe logging.

    Replaces any ``sk-<20+chars>`` (OpenAI-style) key and any 40+ character
    base64 blob with ``[REDACTED]``.

    Args:
        text: Arbitrary string, e.g. a log message.

    Returns:
        The text with sensitive tokens replaced by ``[REDACTED]``.
    """
    # OpenAI-style keys first (more specific pattern)
    text = _OPENAI_KEY_RE.sub("[REDACTED]", text)
    # Then large base64-ish blobs
    return _BASE64_BLOB_RE.sub("[REDACTED]", text)
