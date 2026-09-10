"""MCPHost facade: discover, verify, spawn, invoke, audit, and stop plugins.

This is the single object that the rest of the agent (SPEC-05, SPEC-07, SPEC-08)
imports.  It implements the :class:`workstation_agent.protocols.MCPHost` Protocol
plus the ``start`` / ``stop`` lifecycle methods added by SPEC-03B.

Typical lifecycle::

    host = MCPHost()
    await host.start(config, confirm_cb=my_confirm)
    result = await host.invoke("hello_world.echo", {"text": "hi"})
    await host.stop()
"""
# ruff: noqa: ANN401, BLE001

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from workstation_agent.config.schema import AgentConfig

from workstation_agent.confirm import PromptPolicy
from workstation_agent.mcp_host.audit import AuditEvent
from workstation_agent.mcp_host.audit import log as audit_log
from workstation_agent.mcp_host.loader import (
    TRUSTED_PUBKEYS,
    PluginManifest,
    VerifyResult,
    discover,
    verify,
)
from workstation_agent.mcp_host.mcp_client import MCPStdioClient
from workstation_agent.mcp_host.permissions import SessionContext, evaluate_detailed
from workstation_agent.mcp_host.supervisor import PluginSupervisor, ResourceLimits, SubprocessHandle
from workstation_agent.mcp_host.watchdog import HeartbeatWatchdog

log = logging.getLogger(__name__)

__all__ = [
    "MAX_RESULT_CHARS",
    "ConfirmationRequestImpl",
    "MCPHost",
    "PluginInfoImpl",
    "SessionContext",
    "ToolDescriptorImpl",
    "ToolResultImpl",
    "strip_special_tokens",
]


# ---------------------------------------------------------------------------
# §5.6 — special-token stripping for untrusted content
# ---------------------------------------------------------------------------

#: Anything shaped like a self-hosted chat template's angle-pipe token:
#: ``<|im_start|>``, ``<|im_end|>``, ``<|eot_id|>``, ``<|start_header_id|>``,
#: ``<|endoftext|>``, ``<|python_tag|>`` … "and their kin" (§5.6).  Matching
#: the *shape* rather than a fixed list is deliberate — the list of models
#: and their tokens grows, and this code must not need editing each time.
#: ``<`` and ``>`` are excluded from the body so a nested construction
#: cannot make one token's body swallow another's opening delimiter.
_ANGLE_PIPE_TOKEN = re.compile(r"<\|[^<>|]{0,64}\|>")

#: The bracket-and-tag forms: Llama-2 / Mistral instruction markers and the
#: SentencePiece sentence delimiters.
_BRACKET_TOKEN = re.compile(
    r"\[/?INST\]|\[/?SYS\]|<</?SYS>>|</?s>|<\|?/?im_(?:start|end)\|?>",
    re.IGNORECASE,
)

_STRIP_PASSES = 8

#: §5.3 — text results are capped by the Agent at 60,000 characters.
MAX_RESULT_CHARS = 60_000

#: What replaces content the stripper could not finish cleaning.  A refusal,
#: not a best effort: see :func:`strip_special_tokens`.
_UNSTRIPPABLE = (
    "[withheld: this output nests chat-template special tokens more deeply than "
    "the Agent unwinds, so it could not be made safe to display]"
)


def strip_special_tokens(text: str) -> str:
    """Remove chat-template special tokens from untrusted content (§5.6).

    Applied **to a fixed point**, not in a single pass.  A single pass is
    defeated by nesting: ``<|im_<|im_start|>start|>`` contains
    ``<|im_start|>``, and removing the inner one leaves a freshly-assembled
    ``<|im_start|>`` behind.  Repeating until the text stops changing (with
    a hard bound, so a pathological input cannot spin here) removes the
    reassembled token too.

    **Exhausting the pass budget is a refusal, not a partial result.**  The
    loop is bounded because each pass only deletes, so an unbounded version
    terminates but takes O(n) passes over an O(n) string — a 60,000-character
    adversarial input would spin here, trading a silent failure for a CPU
    denial of service that nobody needs (no legitimate content nests these
    eight deep).  Returning the partially-stripped text on exhaustion, though,
    makes "I could not finish" indistinguishable from "there was nothing to
    strip", and the caller cannot tell the difference.  So the budget is kept
    and the result is *checked*: if tokens genuinely survive after the last
    allowed pass, the content is withheld and a warning is logged.  Text that
    reached a fixed point on the last allowed pass is clean and is returned
    normally — exhaustion alone is not the failure, surviving tokens are.
    """
    if not text:
        return text
    current = text
    for _ in range(_STRIP_PASSES):
        stripped = _BRACKET_TOKEN.sub("", _ANGLE_PIPE_TOKEN.sub("", current))
        if stripped == current:
            return current
        current = stripped
    if _ANGLE_PIPE_TOKEN.search(current) or _BRACKET_TOKEN.search(current):
        log.warning(
            "special-token stripping did not converge in %d passes; withholding content",
            _STRIP_PASSES,
        )
        return _UNSTRIPPABLE
    return current


#: §5.3's trailing marker, as a template.  The rendered marker counts toward
#: the cap it announces — see :func:`_truncate_to`.
_CAP_MARKER = "[... {n} more characters; use jobs_output to page ...]"


def _truncate_to(text: str, limit: int) -> str:
    """Truncate *text* so the result — marker included — is at most *limit*.

    The marker's length depends on the number it reports, which depends on
    where the cut lands, which depends on the marker's length.  Sizing the
    marker for the worst case (``n`` = the whole length) breaks that circle in
    a single pass and makes ``len(result) <= limit`` provable rather than
    approximate: the real ``n`` is never larger than the worst case, so the
    real marker is never longer than the one budgeted for.
    """
    if len(text) <= limit:
        return text
    worst = _CAP_MARKER.format(n=len(text))
    if limit <= len(worst):
        # No room for text and marker both.  The marker is the more useful of
        # the two — it says the content was cut — but it must still fit.
        return worst[:limit]
    keep = limit - len(worst)
    return text[:keep] + _CAP_MARKER.format(n=len(text) - keep)


def _cap_text(text: str) -> str:
    """Apply §5.3's 60,000-character cap, **marker included**.

    The marker counts toward the cap.  Slicing to 60,000 and *then* appending
    a ~70-character marker used to yield a 60,070-character result — over the
    cap it claims to enforce, and over the cap this function's own caller
    re-applies, which cut the marker in half and appended a second one
    reporting a nonsense remainder.  Landing at or under 60,000 makes a
    second application of this cap a no-op.
    """
    return _truncate_to(text, MAX_RESULT_CHARS)


#: Anything path-shaped.  The drive-letter alternative deliberately does not
#: require a following *separator* — ``C:secret.txt`` is the drive-relative
#: form and leaks just as much as ``C:\secret.txt`` — but it does require at
#: least one following non-space character.  Without that it also matched the
#: bare ``adb:`` or ``Authorization:`` that begins many plugin messages,
#: turning "adb: failed to install" into "ad<path> failed to install" and,
#: worse, destroying the credential keyword before :data:`_CREDENTIAL_KV`
#: could key on it.  A drive-relative path never has a space after the colon;
#: a prose label always does.
_ABS_PATH = re.compile(r"(?:[A-Za-z]:[^\s'\"]+|\\\\[^\s'\"]*|(?<![\w.])/[^\s'\"]*)")

_REASON_LIMIT = 300

_REDACTED = "[redacted]"

#: ``key: value`` / ``key=value`` where the key names a credential.  The value
#: pattern is "the rest of the line", not ``\S+`` — with ``\S+`` a line like
#: ``Authorization: Bearer eyJhbGci….verysecret`` matched only the word
#: ``Bearer`` and left the token itself sitting in the output.  A credential
#: key means everything after it on that line is the credential.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(authorization|auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|bearer|api[-_]?key|apikey|secret|password|passwd|pwd|"
    r"session[-_]?id|cookie|set-cookie|x-api-key)\b\s*[:=]\s*.+",
)

#: A bare ``Bearer <token>`` anywhere in the line.
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")

#: A long run of credential-shaped characters with no spaces.  Deliberately
#: long (40) so ordinary text — package names, class names, hashes of a dozen
#: characters — survives, while a 32-byte token rendered as hex (64 chars) or
#: base64 (43 chars) does not.
_LONG_OPAQUE = re.compile(r"(?<![\w./-])[A-Za-z0-9._~+/=-]{40,}(?![\w./-])")


def sanitise_reason(text: str) -> str:
    """Make an arbitrary error message safe to hand back as a §5.2 ``reason``.

    §5.2: "The Agent never returns a stack trace, an absolute path outside a
    declared root, **or the token**."  An exception message from a plugin is
    untrusted content like any other, so all three are removed rather than
    hoped for: only the first line survives (a traceback is multi-line),
    anything credential-shaped is replaced, anything path-shaped is replaced,
    and the result is bounded.

    Credentials are scrubbed **before** paths.  Otherwise the path pattern
    consumes the ``Authorization:`` keyword and leaves the credential pattern
    nothing to key on.  Nothing leaks by going in this order: a credential
    value that happens to contain a path is replaced wholesale.
    """
    first_line = str(text).splitlines()[0] if text else ""
    redacted = _CREDENTIAL_KV.sub(lambda m: f"{m.group(1)}={_REDACTED}", first_line)
    redacted = _BEARER.sub(f"Bearer {_REDACTED}", redacted)
    redacted = _LONG_OPAQUE.sub(_REDACTED, redacted)
    redacted = _ABS_PATH.sub("<path>", redacted)
    redacted = strip_special_tokens(redacted)
    if len(redacted) > _REASON_LIMIT:
        # The ellipsis counts, exactly as the cap marker does in _truncate_to.
        redacted = redacted[: _REASON_LIMIT - 1] + "…"
    return redacted or "the tool failed without a message"


@dataclass
class ToolDescriptorImpl:
    """Concrete :class:`workstation_agent.protocols.ToolDescriptor`."""

    name: str
    description: str
    input_schema: dict[str, Any]
    plugin_id: str


@dataclass
class ToolResultImpl:
    """Concrete :class:`workstation_agent.protocols.ToolResult`, §5.2-shaped.

    ``content`` is what the core receives and fences as untrusted data.  The
    §5.2 envelope keys are mirrored onto the dataclass so a caller can gate
    on them without re-parsing the text:

    * ``ok`` — false for every non-success outcome.
    * ``code`` — one of §5.2's codes when ``ok`` is false, else ``None``.
    * ``reason`` — one plain-English sentence when ``ok`` is false.

    ``is_error`` is the MCP-level flag and is **not** a synonym for ``not
    ok``.  §7: "A refused or unconfirmed call is a normal result (§5.2), not
    an error" — the persona is meant to read the reason and say it plainly,
    not report a tool crash.  So ``denied`` and ``unconfirmed`` carry
    ``ok=False`` with ``is_error=False``, while ``error``/``not_found``
    (something actually went wrong) carry both.
    """

    content: list[dict[str, Any]]
    is_error: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    code: str | None = None
    reason: str | None = None


#: §5.2 codes.  ``unknown_job``/``unknown_session`` belong to the families
#: (§5.4, §5.5) and are produced by B6/B8, not by the gate.
CODE_DENIED = "denied"
CODE_UNCONFIRMED = "unconfirmed"
CODE_NOT_FOUND = "not_found"
CODE_TIMEOUT = "timeout"
CODE_ERROR = "error"


def _envelope_text(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Render a §5.2 envelope as the single text content block."""
    return [{"type": "text", "text": json.dumps(payload, separators=(",", ": "))}]


def failure_result(code: str, reason: str, *, is_error: bool) -> ToolResultImpl:
    """Build a §5.2 failure envelope.

    The reason is sanitised on the way in rather than at each call site, so
    a future caller cannot forget and leak a path or a traceback.
    """
    clean = sanitise_reason(reason)
    payload: dict[str, Any] = {"ok": False, "code": code, "reason": clean}
    return ToolResultImpl(
        content=_envelope_text(payload),
        is_error=is_error,
        raw=dict(payload),
        ok=False,
        code=code,
        reason=clean,
    )


def _strip_json_values(value: Any) -> Any:
    """Apply §5.6 stripping to every string inside a decoded JSON structure."""
    if isinstance(value, str):
        return strip_special_tokens(value)
    if isinstance(value, dict):
        return {k: _strip_json_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_json_values(v) for v in value]
    return value


def _conform_text_block(block: dict[str, Any], *, ok: bool) -> dict[str, Any]:
    """Strip special tokens, guarantee ``ok``, and cap one text block.

    **Stripping happens per JSON value, not over the serialised text**, and
    that is a correctness requirement rather than a tidiness one.

    :data:`_ANGLE_PIPE_TOKEN` is the one pattern with a wildcard body
    (``<\\|[^<>|]{0,64}\\|>``).  Run against a *rendered* envelope it can match
    **across two fields**: a family that returns
    ``{"stdout": "tail <|im_", "stderr": "x|> head"}`` renders to a string in
    which the match spans the ``","stderr": "`` between them, and substituting
    it away deletes the JSON structure — leaving text that is no longer an
    envelope at all.  Any family whose output an attacker can influence could
    reach this deliberately; ``shell_run`` controls both streams, and
    ``adb_logcat`` carries whatever the device logged.

    Decoding first makes the splice impossible: each string is cleaned in
    isolation, the structure is rebuilt by ``json.dumps`` rather than being
    edited as text, and a value the stripper could not finish is withheld on
    its own instead of taking the envelope with it.  Plain (non-JSON) text has
    no structure to damage, so it is stripped as one piece exactly as before.

    §5.2: "where structure matters a JSON object rendered as text ... Every
    family's result object carries ``ok``".  A family that renders a JSON
    object without ``ok`` is a defect; rather than passing it through, fill it
    in.
    """
    raw_text = str(block.get("text", ""))

    parsed: Any = None
    if raw_text.lstrip().startswith("{"):
        try:
            parsed = json.loads(raw_text)
        except (json.JSONDecodeError, RecursionError):
            parsed = None

    if isinstance(parsed, dict):
        cleaned = _strip_json_values(parsed)
        if "ok" not in cleaned:
            cleaned = {"ok": ok, **cleaned}
        text = json.dumps(cleaned, separators=(",", ": "))
    else:
        text = strip_special_tokens(raw_text)

    return {**block, "type": "text", "text": _cap_text(text)}


def conform_result(raw: dict[str, Any]) -> ToolResultImpl:
    """Turn a plugin's raw MCP result into a §5.2-conformant result.

    Applies §5.6 stripping and §5.3's cap to every text block, guarantees the
    ``ok`` key on structured results, and refuses to forward binary: §5.3
    says binary never travels in v1, so a non-text content block is replaced
    by the error §5.3 prescribes instead of being passed through in the hope
    that nothing downstream looks at it.
    """
    is_error = bool(raw.get("isError", False))
    blocks = raw.get("content")
    if not isinstance(blocks, list):
        blocks = []

    out: list[dict[str, Any]] = []
    binary_kinds: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            out.append({"type": "text", "text": _cap_text(strip_special_tokens(str(block)))})
            continue
        if block.get("type") == "text":
            out.append(_conform_text_block(block, ok=not is_error))
            continue
        binary_kinds.append(str(block.get("type", "unknown")))

    if binary_kinds:
        kinds = ", ".join(sorted(set(binary_kinds)))
        return failure_result(
            CODE_ERROR,
            f"the tool returned {kinds} content; binary transfer is not available yet",
            is_error=True,
        )

    return ToolResultImpl(
        content=out,
        is_error=is_error,
        raw=raw,
        ok=not is_error,
        code=CODE_ERROR if is_error else None,
        reason=None,
    )


@dataclass
class ConfirmationRequestImpl:
    """Concrete :class:`workstation_agent.protocols.ConfirmationRequest`.

    ``correlation_id`` is minted by the host for every prompt and echoed by
    the confirm adapter, so the prompt, its outcome and the audit rows that
    follow can be tied together after the fact.
    """

    plugin_id: str
    tool_id: str
    args: dict[str, Any]
    condition: str = ""
    correlation_id: str = ""


@dataclass
class PluginInfoImpl:
    """Concrete :class:`workstation_agent.protocols.PluginInfo`."""

    id: str
    name: str
    version: str
    status: str
    signature_status: str
    granted_permissions: list[str]
    resource_limits: dict[str, Any]
    integrity: str
    pid: int | None = None
    #: The plugin's *signed* ``declared_permissions``, verbatim from
    #: ``plugin.toml``.  Carried here so the settings UI can show the owner what
    #: this plugin can ever be allowed to do, and can bound what it offers him
    #: by it.  Without this the UI would have to guess -- and a grant screen
    #: that offers a permission the manifest never declared is a checkbox that
    #: always denies.
    declared_permissions: list[str] = field(default_factory=list)
    #: The conditions the manifest declares *confirmable*.  A hard guard the
    #: plugin does not name here always denies and can never be approved at the
    #: prompt; the UI reads this to tell the two apart rather than presenting
    #: an unliftable guard as something a click could change.
    confirmable_conditions: list[str] = field(default_factory=list)


@dataclass
class _PluginRuntime:
    """Internal plugin runtime record."""

    manifest: PluginManifest
    verify_result: VerifyResult
    handle: SubprocessHandle | None = None
    client: MCPStdioClient | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    granted_permissions: set[str] = field(default_factory=set)
    status: str = "stopped"


class MCPHost:
    """Facade implementing the MCPHost Protocol (SPEC-03B)."""

    def __init__(self) -> None:
        self._runtimes: dict[str, _PluginRuntime] = {}
        self._supervisor = PluginSupervisor()
        self._watchdog: HeartbeatWatchdog | None = None
        self._confirm_cb: Callable[[ConfirmationRequestImpl], Awaitable[bool]] | None = None
        self._tts_speak: Any | None = None
        self._config: AgentConfig | None = None
        self._lock = asyncio.Lock()
        #: Contract §7's operator-editable confirmation policy (B3).  Reads
        #: ``self._config`` lazily on every query, so a setting saved through
        #: the UI (via :meth:`set_config`) takes effect on the very next
        #: ``invoke`` — see ``workstation_agent.confirm.PromptPolicy``.
        self._prompt_policy = PromptPolicy(config_provider=lambda: self._config)

    async def start(
        self,
        config: AgentConfig,
        confirm_cb: Callable[[ConfirmationRequestImpl], Awaitable[bool]] | None = None,
        tts_speak: Any | None = None,
    ) -> None:
        """Discover, verify, and spawn every enabled plugin.

        ``confirm_cb`` is the awaitable confirmation primitive (see
        :mod:`workstation_agent.confirm`).  When it is ``None`` every
        confirmable condition is denied — the host never falls through to
        an implicit allow.

        ``tts_speak`` is the voice channel for confirmation prompts.  The
        prompt is presented by ``confirm_cb`` — toast and spoken line have
        to share one timeout and one answer — so the host hands the voice
        to the callback via its ``attach_voice`` hook rather than speaking
        over it.
        """
        self._config = config
        self._confirm_cb = confirm_cb
        self._tts_speak = tts_speak
        self._attach_voice()
        # §7 "remember for this session" must not survive an Agent restart
        # (§5.5: sessions die with the Agent) -- every (re)start drops
        # whatever the prompt policy had remembered.
        self._prompt_policy.reset()

        manifests = discover()
        allow_unsigned = config.plugins.allow_unsigned

        for manifest in manifests:
            per = config.plugins.per_plugin.get(manifest.id)
            enabled = per.enabled if per is not None else True
            if not enabled:
                log.info("plugin %s disabled by config; skipping", manifest.id)
                continue

            vresult = verify(manifest, TRUSTED_PUBKEYS, allow_unsigned=allow_unsigned)
            log.info("plugin=%s verify_status=%s", manifest.id, vresult.status)

            granted: set[str] = set(per.granted_permissions) if per else set()

            runtime = _PluginRuntime(
                manifest=manifest,
                verify_result=vresult,
                granted_permissions=granted,
            )

            if vresult.status in {"quarantined", "invalid"}:
                runtime.status = "quarantined"
                self._runtimes[manifest.id] = runtime
                audit_log(AuditEvent(
                    event="plugin_quarantined",
                    plugin_id=manifest.id,
                    detail=vresult.reason,
                ))
                continue

            try:
                await self._spawn(runtime)
            except Exception:
                log.exception("failed to spawn plugin=%s", manifest.id)
                runtime.status = "stopped"
                self._runtimes[manifest.id] = runtime
                continue

            self._runtimes[manifest.id] = runtime

        self._watchdog = HeartbeatWatchdog(
            self._supervisor,
            interval=10.0,
            heartbeat_timeout=30.0,
            ping_timeout=5.0,
            on_plugin_died=self._on_plugin_died,
        )
        await self._watchdog.start()
        audit_log(AuditEvent(event="host_started"))

    def set_config(self, config: AgentConfig) -> None:
        """Push an updated config into the running host without a restart.

        The settings UI calls this after saving a §7 confirmation-policy
        change (never/always-prompt lists, "remember for this session") so
        the new lists apply to the very next ``invoke`` call. Unlike
        :meth:`start`, this does **not** reset remembered session approvals
        or touch running plugins -- only a real restart does that (§5.5:
        sessions die with the Agent, not with a settings save).

        It **does** re-read each running plugin's granted permissions, because
        ``start`` snapshots them into the runtime record and the gate reads the
        snapshot, not the config.  Without this refresh the owner grants a
        permission on the Plugins page, the page shows it granted, and the very
        next tool call is still denied until the Agent restarts -- the page
        telling him something the gate does not agree with, which is the whole
        defect P25 exists to close.  A grant is applied here exactly as
        ``start`` would apply it: whatever ``per_plugin[id].granted_permissions``
        now says, and nothing else.  Revoking is the same operation in the other
        direction and takes effect just as immediately.
        """
        self._config = config
        for plugin_id, runtime in self._runtimes.items():
            per = config.plugins.per_plugin.get(plugin_id)
            runtime.granted_permissions = set(per.granted_permissions) if per else set()

    async def _spawn(self, runtime: _PluginRuntime) -> None:
        """Spawn the subprocess, connect the client, collect tools."""
        manifest = runtime.manifest
        entry = _resolve_entry(manifest)

        limits = ResourceLimits()
        handle = self._supervisor.spawn(
            entry_cmd=entry,
            cwd=manifest.plugin_dir,
            plugin_id=manifest.id,
            resource_limits=limits,
        )

        client = MCPStdioClient()
        await client.connect(handle.stdin, handle.stdout)

        try:
            await client.initialize()
        except Exception:
            log.exception("initialize failed for plugin=%s", manifest.id)
            await client.close()
            await self._supervisor.terminate(handle)
            raise

        try:
            tools = await client.tools_list()
        except Exception:
            tools = []

        runtime.handle = handle
        runtime.client = client
        runtime.tools = tools
        runtime.status = "running"

        if self._watchdog is not None:
            self._watchdog.register(handle, client)

        audit_log(AuditEvent(
            event="plugin_started",
            plugin_id=manifest.id,
            detail=f"pid={handle.pid} integrity={handle.integrity} tools={len(tools)}",
        ))

    async def _on_plugin_died(self, handle: SubprocessHandle, reason: str) -> None:
        """Called by the watchdog when a plugin stops responding."""
        plugin_id = handle.plugin_id
        runtime = self._runtimes.get(plugin_id)
        if runtime is None:
            return
        runtime.status = "stopped"
        runtime.handle = None
        runtime.client = None
        audit_log(AuditEvent(
            event="plugin_died",
            plugin_id=plugin_id,
            detail=reason,
        ))

    async def stop(self) -> None:
        """Gracefully shut down every plugin and the watchdog."""
        if self._watchdog is not None:
            await self._watchdog.stop()
            self._watchdog = None

        async with self._lock:
            for runtime in list(self._runtimes.values()):
                if runtime.handle is None or runtime.handle.closed:
                    continue
                client = runtime.client
                # Capture client in closure; default-arg trick avoids late-binding
                _captured_client: MCPStdioClient | None = client

                async def _make_shutdown(c: MCPStdioClient | None) -> None:
                    if c is not None:
                        await c.shutdown()

                async def _shutdown_fn(
                    _c: MCPStdioClient | None = _captured_client,
                ) -> None:
                    await _make_shutdown(_c)

                try:
                    await self._supervisor.terminate(
                        runtime.handle,
                        shutdown_fn=_shutdown_fn,  # type: ignore[arg-type]
                    )
                except Exception:
                    log.exception("terminate failed for plugin=%s", runtime.manifest.id)

                if client is not None:
                    with contextlib.suppress(Exception):
                        await client.close()

                runtime.status = "stopped"
                runtime.handle = None
                runtime.client = None

        audit_log(AuditEvent(event="host_stopped"))

    async def tools(self) -> list[ToolDescriptorImpl]:
        """Return the combined tool inventory across all running plugins."""
        result: list[ToolDescriptorImpl] = []
        for runtime in self._runtimes.values():
            if runtime.status != "running":
                continue
            result.extend(
                ToolDescriptorImpl(
                    name=tool_dict.get("name", ""),
                    description=tool_dict.get("description", ""),
                    input_schema=tool_dict.get("inputSchema", {}),
                    plugin_id=runtime.manifest.id,
                )
                for tool_dict in runtime.tools
            )
        return result

    async def invoke(
        self,
        tool_id: str,
        args: dict[str, Any],
        *,
        session: SessionContext | None = None,
    ) -> ToolResultImpl:
        """Resolve *tool_id* to a plugin, evaluate permissions, dispatch, audit.

        Always returns a §5.2-conformant :class:`ToolResultImpl`; a refusal is
        a result, not an exception.  §7 is explicit about this — "A refused or
        unconfirmed call is a normal result (§5.2), not an error: the persona
        says plainly that nobody confirmed it on the workstation" — and §11
        item 6 requires the refusal to reach the operator *in plain English*,
        which it cannot do if every transport has to remember to catch a
        ``PermissionError`` and translate it back into prose.  Making the
        envelope the return value means a transport that simply serialises
        the result is compliant by default rather than by diligence.

        ``asyncio.CancelledError`` is the one thing that still propagates: it
        is shutdown, not a tool outcome.

        ``session`` identifies the transport connection the call arrived on
        (§5.7's audit row, and the key B3's "remember for this session" will
        need).  It is optional so in-process callers need not invent one.
        """
        started = time.perf_counter()
        session_id = session.session_id if session is not None else None
        request_id = session.request_id if session is not None else None

        def _elapsed_ms() -> float:
            return round((time.perf_counter() - started) * 1000.0, 3)

        def _audit(event: str, decision: str, code: str | None, **kw: Any) -> None:
            audit_log(AuditEvent(
                event=event,
                plugin_id=kw.pop("plugin_id", None),
                tool_id=tool_id,
                args=args,
                decision=decision,
                code=code,
                duration_ms=_elapsed_ms(),
                request_id=request_id,
                session_id=session_id,
                **kw,
            ))

        runtime = self._resolve_tool(tool_id)
        if runtime is None:
            _audit("tool_not_found", "deny", CODE_NOT_FOUND, result="error")
            return failure_result(
                CODE_NOT_FOUND,
                f"There is no tool called {tool_id!r} running on this workstation.",
                is_error=True,
            )

        plugin_id = runtime.manifest.id
        outcome = evaluate_detailed(
            runtime.manifest,
            tool_id,
            args,
            runtime.granted_permissions,
            session=session,
        )

        if outcome.decision == "deny":
            _audit(
                "tool_denied",
                "deny",
                CODE_DENIED,
                plugin_id=plugin_id,
                result="denied",
                detail=outcome.rule,
            )
            return failure_result(CODE_DENIED, outcome.reason, is_error=False)

        # ---- §7 confirmation policy (B3) -----------------------------
        #
        # The gate above has already resolved "deny" (returned) or one of
        # "confirm" / "allow".  The operator's never-prompt / always-prompt
        # lists only ever act on those two: they can suppress a prompt the
        # gate asked for ("confirm" + never-prompt, or an already-remembered
        # tool+session), or add one the gate did not ask for ("allow" +
        # always-prompt).  There is no branch here that reaches a "deny" --
        # pre-approval cannot widen one because it is never consulted for one.
        correlation_id: str | None = None
        policy_class = self._prompt_policy.classify(tool_id)
        wants_prompt = (
            policy_class != "never" if outcome.decision == "confirm" else policy_class == "always"
        )

        if wants_prompt:
            if self._prompt_policy.is_remembered(session_id, tool_id):
                _audit(
                    "tool_confirmed",
                    "confirm_remembered",
                    None,
                    plugin_id=plugin_id,
                    detail=outcome.rule or "policy_always_prompt",
                )
            else:
                confirmed, correlation_id = await self._do_confirm(
                    runtime, tool_id, args, condition=outcome.condition,
                )
                if not confirmed:
                    _audit(
                        "tool_denied",
                        "confirm_rejected",
                        CODE_UNCONFIRMED,
                        plugin_id=plugin_id,
                        result="unconfirmed",
                        correlation_id=correlation_id,
                        detail=outcome.rule,
                    )
                    return failure_result(
                        CODE_UNCONFIRMED,
                        f"Nobody confirmed {tool_id} on the workstation, so it was not run.",
                        is_error=False,
                    )
                self._prompt_policy.remember(session_id, tool_id)
                _audit(
                    "tool_confirmed",
                    "confirm_allowed",
                    None,
                    plugin_id=plugin_id,
                    correlation_id=correlation_id,
                    detail=outcome.rule,
                )
        elif outcome.decision == "confirm":
            # policy_class == "never": the gate wanted a prompt but the
            # operator's never-prompt list pre-approves this tool.  Logged
            # distinctly from a plain "allow" so the audit trail shows the
            # prompt was suppressed by policy, not that none was ever due.
            _audit(
                "tool_confirmed",
                "confirm_preapproved",
                None,
                plugin_id=plugin_id,
                detail=outcome.rule,
            )

        if runtime.client is None:  # pragma: no cover — invariant
            _audit(
                "tool_error",
                outcome.decision,
                CODE_ERROR,
                plugin_id=plugin_id,
                result="error",
                correlation_id=correlation_id,
            )
            return failure_result(
                CODE_ERROR,
                f"The plugin {plugin_id!r} is not connected, so {tool_id} could not run.",
                is_error=True,
            )

        result, dispatch_failed = await _call_plugin(runtime.client, tool_id, args)

        _audit(
            "tool_error" if dispatch_failed else "tool_invoke",
            outcome.decision,
            result.code,
            plugin_id=plugin_id,
            result="ok" if result.ok else "error",
            correlation_id=correlation_id,
        )

        return result

    def _resolve_tool(self, tool_id: str) -> _PluginRuntime | None:
        """Find the running plugin that owns *tool_id*."""
        for runtime in self._runtimes.values():
            if runtime.status != "running":
                continue
            for tool_dict in runtime.tools:
                if tool_dict.get("name") == tool_id:
                    return runtime
        return None

    def _attach_voice(self) -> None:
        """Hand ``tts_speak`` to the confirm callback if it accepts one.

        Presentation lives in one place (the confirm adapter) so the toast
        and the spoken line share a single timeout and a single answer.
        A callback without the hook simply does not get a voice; that is
        never an error and never changes a decision.
        """
        cb = self._confirm_cb
        if cb is None or self._tts_speak is None:
            return
        attach = getattr(cb, "attach_voice", None)
        if not callable(attach):
            log.debug("confirm callback has no attach_voice hook; prompts stay silent")
            return
        try:
            attach(self._tts_speak)
        except Exception:
            log.exception("failed to attach voice to confirm callback")

    async def _do_confirm(
        self,
        runtime: _PluginRuntime,
        tool_id: str,
        args: dict[str, Any],
        *,
        condition: str = "",
    ) -> tuple[bool, str]:
        """Present a confirmation prompt.  Returns ``(allowed, correlation_id)``.

        **Fail-closed.**  No confirm callback, a callback that raises, or a
        callback that returns anything other than ``True`` all deny.  The
        only path to ``True`` is an explicit affirmative answer.
        """
        correlation_id = uuid.uuid4().hex
        req = ConfirmationRequestImpl(
            plugin_id=runtime.manifest.id,
            tool_id=tool_id,
            args=args,
            condition=condition,
            correlation_id=correlation_id,
        )

        cb = self._confirm_cb
        if cb is None:
            log.warning(
                "confirm[%s]: no confirmation callback wired — denying %s",
                correlation_id,
                tool_id,
            )
            return False, correlation_id

        try:
            answer = await cb(req)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception(
                "confirm[%s]: confirmation callback raised — denying %s",
                correlation_id,
                tool_id,
            )
            return False, correlation_id

        return answer is True, correlation_id

    async def plugins(self) -> list[PluginInfoImpl]:
        """Return status for every known plugin."""
        result: list[PluginInfoImpl] = []
        for runtime in self._runtimes.values():
            handle = runtime.handle
            result.append(PluginInfoImpl(
                id=runtime.manifest.id,
                name=runtime.manifest.name,
                version=runtime.manifest.version,
                status=runtime.status,
                signature_status=runtime.verify_result.status,
                granted_permissions=list(runtime.granted_permissions),
                resource_limits=(
                    {
                        "max_memory_mb": handle.resource_limits.max_memory_mb,
                        "max_job_memory_mb": handle.resource_limits.max_job_memory_mb,
                        "max_active_processes": handle.resource_limits.max_active_processes,
                    }
                    if handle is not None
                    else {}
                ),
                integrity=handle.integrity if handle is not None else "unknown",
                pid=handle.pid if handle is not None else None,
                declared_permissions=list(runtime.manifest.declared_permissions),
                confirmable_conditions=list(runtime.manifest.confirmable_conditions),
            ))
        return result

    async def reload(self, plugin_id: str) -> None:
        """Terminate and respawn *plugin_id*."""
        async with self._lock:
            runtime = self._runtimes.get(plugin_id)
            if runtime is None:
                msg = f"plugin {plugin_id!r} not found"
                raise KeyError(msg)

            if runtime.handle is not None and not runtime.handle.closed:
                if self._watchdog is not None:
                    self._watchdog.unregister(runtime.handle)
                client = runtime.client

                async def _shutdown() -> None:
                    if client is not None:
                        await client.shutdown()

                await self._supervisor.terminate(runtime.handle, shutdown_fn=_shutdown)
                if client is not None:
                    with contextlib.suppress(Exception):
                        await client.close()

            runtime.handle = None
            runtime.client = None
            runtime.tools = []
            runtime.status = "reload_pending"

            audit_log(AuditEvent(event="plugin_reload", plugin_id=plugin_id))

            if self._config is not None:
                allow_unsigned = self._config.plugins.allow_unsigned
                runtime.verify_result = verify(
                    runtime.manifest, TRUSTED_PUBKEYS, allow_unsigned=allow_unsigned,
                )

            if runtime.verify_result.status in {"quarantined", "invalid"}:
                runtime.status = "quarantined"
                return

            try:
                await self._spawn(runtime)
            except Exception:
                log.exception("reload spawn failed for plugin=%s", plugin_id)
                runtime.status = "stopped"


async def _call_plugin(
    client: MCPStdioClient,
    tool_id: str,
    args: dict[str, Any],
) -> tuple[ToolResultImpl, bool]:
    """Dispatch to the plugin and shape the outcome as §5.2.

    Returns ``(result, dispatch_failed)``.  ``dispatch_failed`` distinguishes
    "the call itself blew up" from "the tool ran and reported a problem", so
    the audit row says which — a plugin returning ``isError`` is a
    ``tool_invoke``, an exception out of the transport is a ``tool_error``.

    ``asyncio.CancelledError`` propagates: that is shutdown, not a tool
    outcome, and swallowing it into an ``error`` envelope would leave a
    cancelled task looking like a completed one.
    """
    try:
        raw = await client.tools_call(tool_id, args)
    except asyncio.CancelledError:
        raise
    except TimeoutError as exc:
        return failure_result(
            CODE_TIMEOUT, f"{tool_id} ran out of time: {exc}", is_error=True,
        ), True
    except Exception as exc:
        log.exception("tool %s raised", tool_id)
        return failure_result(
            CODE_ERROR, f"{tool_id} failed: {exc}", is_error=True,
        ), True
    return conform_result(raw if isinstance(raw, dict) else {}), False


def _resolve_entry(manifest: PluginManifest) -> list[str]:
    """Convert a manifest entry list to an absolute spawn command."""
    if not manifest.entry:
        return [sys.executable, "-u", "-m", f"workstation_agent.plugins.{manifest.id}"]

    first = manifest.entry[0]
    if first in ("-m", "-u") or not Path(first).is_absolute():
        return [sys.executable, "-u", *manifest.entry]

    return list(manifest.entry)
