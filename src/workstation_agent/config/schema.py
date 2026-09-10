"""Pydantic v2 configuration schema for PersonaCore-Agent."""

from __future__ import annotations

import ipaddress
from typing import Final, Literal

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


class AdbConfig(BaseModel):
    """Where this workstation's ``adb`` binary lives.

    The ``adb`` capability family resolves its binary in this order: this
    setting, then ``PATH``, then the usual Android SDK install locations. The
    plugin runs in a separate low-integrity process and reads ``[adb]
    binary_path`` straight out of ``config.toml`` with ``tomllib`` rather than
    importing this package (see ``plugins/adb/__init__.py``); this entry exists
    so the settings UI has somewhere to write that key, and so the operator
    never has to open the TOML file to set it.

    Empty means "not configured -- search ``PATH`` and the SDK locations".
    It is deliberately ``str`` and not ``str | None``: ``config.store`` skips
    ``None`` values when merging into the TOML document, so a ``None`` would
    leave a previously-written ``binary_path`` sitting in the file forever and
    an operator who cleared the field in the UI would find the old path still
    in force. An empty string is written, and the plugin already treats a
    blank value as unset.
    """

    binary_path: str = ""

    @field_validator("binary_path")
    @classmethod
    def _strip(cls, v: str) -> str:
        """Trim surrounding whitespace and the quotes a Windows copy-path adds.

        "Copy as path" in Explorer yields ``"C:\\...\\adb.exe"`` -- quotes
        included -- and pasting that into the settings field is the single most
        likely way this value arrives malformed. Stripping them here means the
        UI, the CLI and a hand-edited file all get the same treatment.
        """
        return v.strip().strip('"')


class PttConfig(BaseModel):
    """Push-to-talk configuration."""

    enabled: bool = True
    hotkey: str = "ctrl+alt+space"


class SessionConfig(BaseModel):
    """Conversation session mode."""

    mode: Literal["single_shot", "sticky", "persistent"] = "sticky"
    sticky_seconds: int = Field(default=30, gt=0)


class UpdateConfig(BaseModel):
    """Update-check configuration.

    ``channel`` stays a plain ``str`` rather than a ``Literal``: this file is
    read at startup, and a config carrying a channel this build does not know
    must not stop the Agent from booting. It is validated where it is *used*
    instead — the About page only offers the three valid values, ``POST
    /config`` refuses anything else, and a value that somehow got in by hand
    is reported to the owner as a failed check rather than silently treated as
    ``stable``. See :mod:`workstation_agent.updater_client.channels`.
    """

    enabled: bool = True
    poll_interval_hours: int = Field(default=24, gt=0)
    channel: str = "stable"
    github_repo: str = "synssins/PersonaCore-Agent"

    #: Install a found update without asking. Off, and off is the design:
    #: the updater's job is to say a build exists. An agent that moved itself
    #: from alpha.14 to alpha.17 in the middle of a diagnosis would make the
    #: defect being diagnosed much harder to pin down, which is exactly how
    #: several of this project's real defects were found. The owner opts in.
    auto_install: bool = False


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


#: Contract §7's default confirmation policy, in the contract's own
#: underscore ``family_verb`` spelling.  The gate
#: (``mcp_host.permissions.evaluate_detailed``) and ``MCPHost.invoke`` work in
#: the dotted ``family.verb`` form the plugin manifests declare; the mapping
#: between the two lives entirely in
#: :func:`workstation_agent.confirm.underscore_to_dotted`, never here — this
#: module only stores what the operator typed.  ``jobs_*`` is the one
#: family-wildcard entry: it is expanded to ``jobs.*`` at evaluation time and
#: matches every tool in the ``jobs`` family.
DEFAULT_NEVER_PROMPT_TOOLS: Final[tuple[str, ...]] = (
    "workstation_status",
    "devices_list",
    "jobs_*",
    "adb_devices",
    "adb_pull",
    "adb_logcat",
    "serial_ports",
    "serial_read",
    "serial_close",
    "files_list",
    "files_read",
)

DEFAULT_ALWAYS_PROMPT_TOOLS: Final[tuple[str, ...]] = (
    "shell_run",
    "adb_shell",
    "adb_push",
    "adb_install",
    "files_write",
    "serial_open",
    "serial_write",
)


class ConfirmationPolicyConfig(BaseModel):
    """Operator-editable confirmation policy (contract §7).

    Tool names here are §7's underscore ``family_verb`` form (``files_read``,
    ``jobs_*``) — the same spelling the contract and the settings UI use.
    :func:`workstation_agent.confirm.underscore_to_dotted` converts to the
    gate's dotted form at the point of use; a name that does not convert to
    anything real simply matches nothing, which fails toward prompting (the
    safe direction), never away from it.

    ``never_prompt`` and ``always_prompt`` are meant to be mutually exclusive
    per tool — the settings UI moves a tool from one to the other rather than
    adding it to both — but if a tool is ever listed in both,
    :meth:`workstation_agent.confirm.PromptPolicy.classify` resolves it to
    ``"always"``: the safe failure direction is more confirmation, not less.

    ``remember_for_session`` is a third, independent list: tools for which an
    explicit Allow is remembered for the rest of the calling session, so a
    burst of calls (contract §7: "a burst of serial writes asks once") only
    prompts the first time. Off by default for every tool — the operator
    opts a tool in explicitly. It is never persisted as *state* (only this
    *setting* is); the actual remembered approvals live only in
    :class:`workstation_agent.confirm.PromptPolicy`'s in-memory session map,
    keyed by ``(session_id, tool)``, which is why they can never leak across
    sessions and never survive an Agent restart (§5.5: sessions die with the
    Agent).
    """

    never_prompt: list[str] = Field(default_factory=lambda: list(DEFAULT_NEVER_PROMPT_TOOLS))
    always_prompt: list[str] = Field(default_factory=lambda: list(DEFAULT_ALWAYS_PROMPT_TOOLS))
    remember_for_session: list[str] = Field(default_factory=list)


#: Every spelling of "listen on everything". Refused as a *value*, not merely
#: as a default — see :meth:`NetworkMcpConfig._reject_wildcard_bind`.
_WILDCARD_BINDS: Final[frozenset[str]] = frozenset({
    "", "0.0.0.0", "::", "[::]", "*", "0", "::0",  # noqa: S104
})


def _is_unspecified_address(host: str) -> bool:
    """True if *host* parses as "every interface", in any spelling.

    The literal set above catches what an operator types. This catches what an
    operator pastes: ``0:0:0:0:0:0:0:0``, ``::0.0.0.0``, ``[::]%0`` and — the
    one that looks least like a wildcard — ``::ffff:0.0.0.0``, whose
    ``is_unspecified`` is ``False`` because it is not ``::``, and which binds
    every IPv4 interface on the machine regardless.

    Names are not addresses and cannot be judged here at all; the resolved
    address is checked immediately before ``bind()``, in
    :func:`~workstation_agent.network_mcp.listeners._bind_one`. This is the
    early, legible half of that rule, so an operator who pastes one is told at
    the moment they save rather than by a bind failure afterwards.
    """
    bare = host.strip().strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return False
    if ip.is_unspecified:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_unspecified)


def _reject_wildcard(value: str, *, sentence: str) -> str:
    """Return *value* stripped, or raise if it is any spelling of a wildcard.

    One implementation, shared by the single preferred address and by every
    entry of the additional set, so selecting three addresses can never become
    a back door to the thing naming one address is refused for. *sentence* is
    the field-specific opening clause; the rest of the message — and therefore
    the sentence the UI shows the operator — is identical either way.
    """
    host = value.strip()
    if host.lower() in _WILDCARD_BINDS or _is_unspecified_address(host):
        msg = f"{sentence}; {value!r} binds every interface on this machine"
        raise ValueError(msg)
    return host


def _host_key(host: str) -> str:
    """A comparison key for de-duplicating bind addresses.

    Addresses are compared *as addresses*, so ``::1`` and ``0:0:0:0:0:0:0:1``
    and ``[::1]`` are one entry rather than three sockets fighting over one
    port; names are compared case-insensitively, because DNS is.
    """
    cleaned = host.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return cleaned.lower()


class NetworkMcpConfig(BaseModel):
    """The LAN-facing MCP endpoint PersonaCore connects to (contract §1-§3).

    Off by default. Turning it on puts this workstation's capability families on
    the network, so it is an explicit operator decision, not a default.

    The endpoint binds a **chosen set** of addresses — a machine that bridges
    two networks has to answer on both — expressed as one preferred address
    (:attr:`bind_host`) plus :attr:`additional_bind_hosts`. That shape rather
    than a single list because exactly one of them has to be *the* address: the
    registration carries one ``url``, and the core reads one ``url``. See
    :attr:`bind_hosts` for the resolved set.

    Choosing three addresses is emphatically not the same as choosing "all", and
    the wildcard refusal below applies to every entry of the set.
    """

    enabled: bool = False
    """Serve the endpoint. Default off: the operator opts in."""

    bind_host: str = "127.0.0.1"
    """The **preferred** interface to bind — the one the registration names.

    Contract §3: **never 0.0.0.0 by default**. This goes further and refuses a
    wildcard outright — see :meth:`_reject_wildcard_bind`. The default is
    loopback, which is useless to PersonaCore on purpose: the operator has to
    name the interface they mean, and naming it is the moment they decide to
    expose the machine.
    """

    additional_bind_hosts: list[str] = Field(default_factory=list, max_length=32)
    """Further interfaces to bind, beyond :attr:`bind_host`.

    Empty by default, so an existing configuration keeps binding exactly the one
    address it always did. Every entry is held to the same wildcard refusal as
    :attr:`bind_host` — see :meth:`_reject_wildcard_binds` — because the point
    of the set is that the operator picks which addresses, not that they get a
    longer way to spell "every interface this machine has".
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

    @property
    def bind_hosts(self) -> tuple[str, ...]:
        """The complete set of addresses to bind, preferred one first.

        De-duplicated by :func:`_host_key`, so an operator who selects both
        ``::1`` and ``[::1]`` gets one socket rather than a bind failure on the
        second. Never empty: :attr:`bind_host` cannot validate as empty.

        A property rather than a field on purpose — there is no second place to
        keep in step, nothing to drift, and ``config.bind_host = "10.0.0.5"``
        (which pydantic allows: this model does not set ``validate_assignment``)
        cannot leave a stale set behind it.
        """
        ordered: list[str] = []
        seen: set[str] = set()
        for raw in (self.bind_host, *self.additional_bind_hosts):
            host = raw.strip()
            key = _host_key(host)
            if not host or key in seen:
                continue
            seen.add(key)
            ordered.append(host)
        return tuple(ordered)

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
        return _reject_wildcard(
            v,
            sentence=(
                "network_mcp.bind_host must name one interface (a LAN IP or a hostname)"
            ),
        )

    @field_validator("additional_bind_hosts")
    @classmethod
    def _reject_wildcard_binds(cls, v: list[str]) -> list[str]:
        """Hold every additional address to the same refusal as the first.

        Without this, ``additional_bind_hosts = ["0.0.0.0"]`` would be the
        wildcard bind the field above refuses, reached by a different door.
        """
        return [
            _reject_wildcard(
                entry,
                sentence=(
                    "network_mcp.additional_bind_hosts must name one interface each "
                    "(a LAN IP or a hostname)"
                ),
            )
            for entry in v
        ]


class AgentConfig(BaseModel):
    """Root configuration model for PersonaCore-Agent."""

    llm: LlmConfig = Field(default_factory=LlmConfig)
    wyoming: WyomingConfig = Field(default_factory=WyomingConfig)
    wake: WakeConfig = Field(default_factory=WakeConfig)
    audio: AudioConfig = Field(default_factory=AudioConfig)
    adb: AdbConfig = Field(default_factory=AdbConfig)
    ptt: PttConfig = Field(default_factory=PttConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    update: UpdateConfig = Field(default_factory=UpdateConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    network_mcp: NetworkMcpConfig = Field(default_factory=NetworkMcpConfig)
    confirmation: ConfirmationPolicyConfig = Field(default_factory=ConfirmationPolicyConfig)

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
