"""Tests for security.signature — verify, canonical_json, load_public_key."""

from __future__ import annotations

import json

import pytest
from nacl.signing import SigningKey

from workstation_agent.security.signature import (
    canonical_json,
    load_public_key,
    verify,
)


def test_verify_valid_signature() -> None:
    """Round-trip: sign then verify returns True."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    message = b"hello PersonaCore"
    signed = sk.sign(message)
    sig = signed.signature

    assert verify(vk.encode(), message, sig) is True


def test_verify_flipped_byte() -> None:
    """A single bit-flip in the signature returns False."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    message = b"hello PersonaCore"
    signed = sk.sign(message)
    sig = bytearray(signed.signature)
    sig[0] ^= 0xFF
    assert verify(vk.encode(), message, bytes(sig)) is False


def test_verify_wrong_message() -> None:
    """Different message with same sig returns False."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    signed = sk.sign(b"original")
    assert verify(vk.encode(), b"tampered", signed.signature) is False


def test_verify_malformed_sig_returns_false() -> None:
    """A short/malformed sig must not raise — just return False."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    assert verify(vk.encode(), b"data", b"\x00" * 10) is False


def test_verify_malformed_pubkey_returns_false() -> None:
    """A wrong-length pubkey must not raise — just return False."""
    assert verify(b"\x00" * 5, b"data", b"\x00" * 64) is False


def test_verify_empty_sig_returns_false() -> None:
    """Empty signature returns False without raising."""
    sk = SigningKey.generate()
    assert verify(sk.verify_key.encode(), b"data", b"") is False


def test_canonical_json_sorted_keys() -> None:
    """Keys must be sorted recursively."""
    data = {"z": 1, "a": 2, "m": {"q": 3, "b": 4}}
    result = canonical_json(data)
    parsed = json.loads(result)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert list(parsed["m"].keys()) == sorted(parsed["m"].keys())


def test_canonical_json_no_whitespace() -> None:
    """Output must use compact separators, no spaces."""
    result = canonical_json({"a": 1, "b": [1, 2, 3]})
    assert b" " not in result


def test_canonical_json_utf8() -> None:
    """Output is UTF-8 bytes, not ASCII-escaped."""
    result = canonical_json({"emoji": "\U0001f600"})
    assert isinstance(result, bytes)
    assert "\U0001f600".encode("utf-8") in result
    assert b"\\u" not in result


def test_canonical_json_deterministic() -> None:
    """Same input always produces same output."""
    data = {"b": [3, 1, 2], "a": {"y": True, "x": False}}
    assert canonical_json(data) == canonical_json(data)


def test_canonical_json_rejects_nan() -> None:
    """NaN raises ValueError."""
    with pytest.raises(ValueError, match="NaN"):
        canonical_json({"x": float("nan")})


def test_canonical_json_rejects_inf() -> None:
    """Infinity raises ValueError."""
    with pytest.raises(ValueError, match="NaN"):
        canonical_json({"x": float("inf")})


def test_canonical_json_nested_nan_raises() -> None:
    """NaN nested in a list raises ValueError."""
    with pytest.raises(ValueError, match="NaN"):
        canonical_json([1, float("nan"), 3])


def test_load_public_key_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when env var is absent."""
    monkeypatch.delenv("PC_AGENT_SIGNING_PUBKEY", raising=False)
    assert load_public_key() is None


def test_load_public_key_returns_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns decoded bytes when env var is set."""
    key_hex = "a0" * 32
    monkeypatch.setenv("PC_AGENT_SIGNING_PUBKEY", key_hex)
    result = load_public_key()
    assert result == bytes.fromhex(key_hex)


def test_load_public_key_custom_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepts a custom env var name."""
    key_hex = "b1" * 32
    monkeypatch.setenv("MY_CUSTOM_VAR", key_hex)
    result = load_public_key("MY_CUSTOM_VAR")
    assert result == bytes.fromhex(key_hex)
