"""Tests for config.schema — Pydantic model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from workstation_agent.config.schema import (
    AgentConfig,
    LlmConfig,
    PluginsConfig,
    SessionConfig,
    WyomingConfig,
    default,
)


def test_default_is_valid() -> None:
    """default() returns a fully-populated, valid AgentConfig."""
    cfg = default()
    assert isinstance(cfg, AgentConfig)
    assert str(cfg.llm.base_url).startswith("http://192.168.1.150:8053")
    assert cfg.wyoming.host == "192.168.1.150"
    assert cfg.wyoming.port == 10300
    assert "hey_jarvis" in cfg.wake.model_names
    assert cfg.ptt.hotkey == "ctrl+alt+space"
    assert cfg.session.mode == "sticky"
    assert cfg.session.sticky_seconds == 30
    assert cfg.update.github_repo == "synssins/PersonaCore-Agent"


def test_invalid_url_raises() -> None:
    """An invalid base_url raises ValidationError."""
    with pytest.raises(ValidationError):
        LlmConfig(base_url="not-a-url")  # type: ignore[arg-type]


def test_unknown_session_mode_raises() -> None:
    """An unsupported session mode raises ValidationError."""
    with pytest.raises(ValidationError):
        SessionConfig(mode="turbo")  # type: ignore[arg-type]


def test_sticky_seconds_must_be_positive() -> None:
    """sticky_seconds <= 0 raises ValidationError."""
    with pytest.raises(ValidationError):
        SessionConfig(mode="sticky", sticky_seconds=0)

    with pytest.raises(ValidationError):
        SessionConfig(mode="sticky", sticky_seconds=-5)


def test_port_out_of_range_raises() -> None:
    """Wyoming port outside 1-65535 raises ValidationError."""
    with pytest.raises(ValidationError):
        WyomingConfig(port=0)

    with pytest.raises(ValidationError):
        WyomingConfig(port=70000)


def test_valid_session_modes() -> None:
    """All three session modes are accepted."""
    for mode in ("single_shot", "sticky", "persistent"):
        s = SessionConfig(mode=mode)  # type: ignore[arg-type]
        assert s.mode == mode


def test_timeout_must_be_positive() -> None:
    """LlmConfig.timeout_seconds must be > 0."""
    with pytest.raises(ValidationError):
        LlmConfig(timeout_seconds=0)


def test_agent_config_round_trip() -> None:
    """AgentConfig can be serialised and re-validated."""
    cfg = default()
    data = cfg.model_dump(mode="json")
    restored = AgentConfig.model_validate(data)
    assert restored.wyoming.port == cfg.wyoming.port
    assert restored.session.mode == cfg.session.mode


def test_allow_unsigned_defaults_to_false() -> None:
    """``plugins.allow_unsigned`` must never default to ``True``.

    This is the Ed25519 signature bypass: a plugin that fails verification
    is spawned anyway when it is on. It has a UI toggle
    (``/plugins`` — see ``plugins_routes.py``) that requires deliberate
    confirmation to turn on and persists frictionlessly when turned back
    off, but nothing about that toggle stops the *default* from silently
    becoming unsafe if someone edits this schema later. Guard it explicitly:
    a fresh install, an unconfigured ``PluginsConfig()``, and a bare
    ``AgentConfig()`` must all start with signature verification enabled.
    """
    assert PluginsConfig().allow_unsigned is False
    assert AgentConfig().plugins.allow_unsigned is False
    assert default().plugins.allow_unsigned is False
