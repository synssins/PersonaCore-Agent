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
    system_prompt: str | None = None
    """User-customised system prompt.

    None means use the built-in default from
    ``llm.system_prompt.default_system_prompt()``.
    """


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


class AudioConfig(BaseModel):
    """Audio input/output device selection.

    Values are the human-readable device names returned by
    ``sounddevice.query_devices()``. ``None`` means "use OS default".
    """

    input_device: str | None = None
    output_device: str | None = None


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


class NetworkMcpConfig(BaseModel):
    """The LAN-facing MCP endpoint PersonaCore connects to (contract §1-§3).

    Off by default. Turning it on puts this workstation's capability families on
    the network, so it is an explicit operator decision, not a default.
    """

    enabled: bool = False
    """Serve the endpoint. Default off: the operator opts in."""

    bind_host: str = "127.0.0.1"
    """The interface to bind.

    Contract §3: **never 0.0.0.0 by default**. This goes further and refuses a
    wildcard outright — see :meth:`_reject_wildcard_bind`. The default is
    loopback, which is useless to PersonaCore on purpose: the operator has to
    name the interface they mean, and naming it is the moment they decide to
    expose the machine.
    """

    port: int = Field(default=8765, ge=0, le=65535)
    """The port to bind. 0 lets the OS pick an ephemeral port (tests use this)."""

    max_connections: int = Field(default=16, ge=1, le=1024)
    """Concurrent in-flight requests, including long-lived SSE streams."""

    max_request_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    """Post-authentication request-body ceiling.

    An unauthenticated peer's body is never read at all, so this bounds only
    already-authenticated requests. ~17x the largest legitimate payload (§5.3
    caps results at 60,000 characters). Raise it only if a real ``files_write``
    needs more.
    """

    max_json_depth: int = Field(default=64, ge=4, le=512)
    """JSON nesting ceiling. Deeper bodies are rejected before the parser runs."""

    body_read_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    """Seconds a client gets to finish streaming a body. Bounds slow-loris sends."""

    keep_alive_seconds: float = Field(default=5.0, gt=0, le=300)
    """Idle keep-alive timeout for an established connection."""

    graceful_shutdown_seconds: int = Field(default=3, ge=1, le=60)
    """Seconds to let in-flight requests finish when stopping the endpoint."""

    max_sessions: int = Field(default=8, ge=1, le=1024)
    """Concurrent MCP sessions the SDK will track."""

    session_idle_seconds: float = Field(default=300.0, gt=0)
    """Idle MCP session lifetime before the SDK reclaims it."""

    @field_validator("bind_host")
    @classmethod
    def _reject_wildcard_bind(cls, v: str) -> str:
        """Refuse a wildcard bind (contract §3: an operator-chosen interface).

        ``0.0.0.0``, ``::``, ``*`` and empty all mean "every interface this
        machine has, including ones the operator has not thought about". The
        brief forbids that as a default; refusing it as a *value* is the safer
        reading, and costs an operator who really wants every interface only the
        effort of naming the one they mean.
        """
        host = v.strip()
        if host.lower() in {"", "0.0.0.0", "::", "[::]", "*", "0", "::0"}:  # noqa: S104
            msg = (
                "network_mcp.bind_host must name one interface (a LAN IP or a "
                f"hostname); {v!r} binds every interface on this machine"
            )
            raise ValueError(msg)
        return host


class AgentConfig(BaseModel):
    """Root configuration model for PersonaCore-Agent."""

    llm: LlmConfig = Field(default_factory=LlmConfig)
    wyoming: WyomingConfig = Field(default_factory=WyomingConfig)
    wake: WakeConfig = Field(default_factory=WakeConfig)
    audio: AudioConfig = Field(default_factory=AudioConfig)
    ptt: PttConfig = Field(default_factory=PttConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    update: UpdateConfig = Field(default_factory=UpdateConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    network_mcp: NetworkMcpConfig = Field(default_factory=NetworkMcpConfig)

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
