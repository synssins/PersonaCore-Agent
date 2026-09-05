"""Tests for security.dpapi.redact_key — log sanitisation."""

from __future__ import annotations

from workstation_agent.security.dpapi import redact_key


def test_openai_key_basic() -> None:
    """An OpenAI-style key is replaced with [REDACTED]."""
    key = "sk-" + "a" * 32
    assert redact_key(key) == "[REDACTED]"


def test_openai_key_embedded_in_log_line() -> None:
    """Key embedded in a log line is still redacted."""
    key = "sk-" + "B9z_-" * 5
    line = f"Using API key: {key} for model gpt-4"
    result = redact_key(line)
    assert "[REDACTED]" in result
    assert key not in result


def test_multiple_keys_in_one_string() -> None:
    """Multiple keys in the same string are all redacted."""
    k1 = "sk-" + "x" * 24
    k2 = "sk-" + "y" * 30
    text = f"key1={k1} key2={k2}"
    result = redact_key(text)
    assert result.count("[REDACTED]") >= 2
    assert k1 not in result
    assert k2 not in result


def test_base64_blob_redacted() -> None:
    """A 40+ char base64 blob is redacted."""
    blob = "A" * 44
    result = redact_key(blob)
    assert "[REDACTED]" in result
    assert blob not in result


def test_short_key_not_redacted() -> None:
    """A key with fewer than 20 chars after sk- is left alone (if total < 40)."""
    short = "sk-abc123short"
    result = redact_key(short)
    assert short in result


def test_normal_text_unchanged() -> None:
    """Ordinary text without secrets passes through unchanged."""
    text = "Starting agent on port 8053"
    assert redact_key(text) == text


def test_openai_key_at_boundaries() -> None:
    """Key at start or end of string is redacted."""
    key = "sk-" + "Z" * 20
    assert redact_key(key + " trailing text").startswith("[REDACTED]")
    assert redact_key("leading text " + key).endswith("[REDACTED]")


def test_sk_prefix_too_short_not_matched() -> None:
    """sk- with only 19 chars after is not matched as an API key (total 22 < 40)."""
    text = "sk-" + "a" * 19
    assert "sk-" + "a" * 19 in redact_key(text)
