"""Default system prompt and helpers for the LLM subsystem.

The config field ``config.llm.system_prompt`` is intentionally not read here
yet — SPEC-02's ``LlmConfig`` schema does not currently carry that field.

# TODO(orchestrator-integrate): read config.llm.system_prompt when SPEC-02
#   config schema is extended to include ``system_prompt: str | None``.
#   At that point, ``effective_system_prompt(config)`` should prefer the
#   configured value over the default below.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

_DEFAULT = (
    "You are a Windows workstation assistant. "
    "You have access to local tools via MCP. "
    "Prefer concise answers. "
    "Confirm destructive actions before running them. "
    "Speak naturally when your reply will be read aloud."
)


def default_system_prompt() -> str:
    """Return the built-in default system prompt."""
    return _DEFAULT


def effective_system_prompt(configured: str | None = None) -> str:
    """Return *configured* if provided, otherwise the built-in default."""
    if configured:
        return configured
    return _DEFAULT
