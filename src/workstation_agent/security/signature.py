# ruff: noqa: ANN401, TRY300
"""Ed25519 signature verification and canonical JSON serialisation."""

from __future__ import annotations

import json
import math
import os
from typing import Any

from nacl.signing import VerifyKey


def verify(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 *sig* over *message* using *pubkey*.

    Args:
        pubkey: 32-byte Ed25519 public key (raw, not base64).
        message: Signed message bytes.
        sig: 64-byte Ed25519 signature.

    Returns:
        ``True`` if the signature is valid, ``False`` for any failure
        (bad sig, wrong length, malformed key) — never raises.
    """
    try:
        vk = VerifyKey(pubkey)
        vk.verify(message, sig)
        return True
    except Exception:  # noqa: BLE001
        return False


def _no_nan_inf(obj: Any) -> Any:
    """Recursive check that no float is NaN or Infinity."""
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            msg = "canonical_json: NaN and Infinity are not allowed"
            raise ValueError(msg)
    elif isinstance(obj, dict):
        return {k: _no_nan_inf(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_no_nan_inf(v) for v in obj]
    return obj


def canonical_json(obj: Any) -> bytes:
    """Serialise *obj* to deterministic JSON bytes.

    Rules enforced (SPEC-06 Go updater will byte-compare against this):

    * Keys sorted recursively.
    * No whitespace between tokens (``separators=(',', ':')``)
    * UTF-8 encoded, ``ensure_ascii=False``.
    * No trailing newline.
    * NaN / Infinity raise :class:`ValueError` (not valid JSON).

    Args:
        obj: JSON-serialisable Python object.

    Returns:
        Deterministic UTF-8 bytes.
    """
    checked = _no_nan_inf(obj)
    return json.dumps(
        checked,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def load_public_key(env_var: str = "PC_AGENT_SIGNING_PUBKEY") -> bytes | None:
    """Load the Ed25519 public key from an environment variable.

    Used for build-time bake-in. Returns ``None`` in test/dev mode when
    the variable is not set.

    Args:
        env_var: Name of the environment variable holding the hex-encoded
                 public key.

    Returns:
        32-byte raw public key, or ``None`` if *env_var* is unset.
    """
    raw = os.environ.get(env_var)
    if raw is None:
        return None
    return bytes.fromhex(raw.strip())
