"""DPAPI helpers: encryption, decryption, and log-safe key redaction.

Real DPAPI calls are deferred to SPEC-02. This module provides the
``redact_key`` helper used by the LLM client to keep secrets out of logs.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

_REDACT_KEEP = 4


def redact_key(value: str) -> str:
    """Return a redacted representation of *value* safe for log lines.

    Shows only the first 4 characters followed by ``...[REDACTED]``.
    If *value* is shorter than 5 characters the entire string is masked.
    """
    if len(value) <= _REDACT_KEEP:
        return "[REDACTED]"
    return value[:_REDACT_KEEP] + "...[REDACTED]"
