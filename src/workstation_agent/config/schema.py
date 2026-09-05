"""Pydantic v2 configuration schema for PersonaCore-Agent."""

from __future__ import annotations

from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


class LlmConfig(BaseModel):
    """LLM backend configuration."""

    base_url: AnyHttpUrl = AnyHttpUrl("http://192.168.1.150:8053/v1")
    model: str = "gpt-4o"
    api_key_ref: str = ""
    """Name of the DPAPI blob on disk; never the raw key."""
    timeout_seconds: int = Field(default=60, gt=0)
    streaming: bool = True


class WyomingConfig(BaseModel):
    """Wyoming protocol (ASR/TTS) connection settings."""

    host: str = "192.168.1.150"
    port: int = Field(default=10300, ge=1, le=65535)
    tts_voice: str = "en-us-amy-low"
    asr_model: str = "tiny-int8"


class WakeConfig(BaseModel):
    """Wake-word detection configuration."""

    enabled: bool = True
    model_names: list[str] = Field(default_factory=lambda: ["hey_jarvis"])
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    mic_device: str | None = None


class PttConfig(BaseModel):
    """Push-to-talk configuration."""

    enabled: bool = True
    hotkey: str = "ctrl+alt+space"


class SessionConfig(BaseModel):
    """Conversation session mode."""

    mode: Literal["single_shot", "sticky", "persistent"] = "sticky"
    sticky_seconds: int = Field(default=30, gt=0)


class UpdateConfig(BaseModel):
    """Auto-update configuration."""

    enabled: bool = True
    poll_interval_hours: int = Field(default=24, gt=0)
    channel: str = "stable"
    github_repo: str = "synssins/PersonaCore-Agent"


class NotificationsConfig(BaseModel):
    """Notification settings."""

    toast_enabled: bool = True
    voice_announce_updates_enabled: bool = True
    voice_announce_confirmations_enabled: bool = True


class UIConfig(BaseModel):
    """UI / window behaviour settings."""

    webview_close_to_tray: bool = True
    systray_show_startup_notification: bool = True


class PluginConfig(BaseModel):
    """Per-plugin enable flag and granted permissions."""

    enabled: bool = True
    granted_permissions: list[str] = Field(default_factory=list)


class PluginsConfig(BaseModel):
    """Plugin loader configuration."""

    allow_unsigned: bool = False
    per_plugin: dict[str, PluginConfig] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    """Root configuration model for PersonaCore-Agent."""

    llm: LlmConfig = Field(default_factory=LlmConfig)
    wyoming: WyomingConfig = Field(default_factory=WyomingConfig)
    wake: WakeConfig = Field(default_factory=WakeConfig)
    ptt: PttConfig = Field(default_factory=PttConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    update: UpdateConfig = Field(default_factory=UpdateConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)

    @field_validator("session", mode="before")
    @classmethod
    def _validate_session(cls, v: object) -> object:
        """Pass through; Pydantic validates the nested model."""
        return v


def default() -> AgentConfig:
    """Return a sensible default :class:`AgentConfig`.

    All values match the documented defaults in SPEC-02:
    Wyoming on 192.168.1.150:10300, sticky sessions, etc.

    Returns:
        A fully-populated default configuration instance.
    """
    return AgentConfig()
