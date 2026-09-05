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
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from workstation_agent.config.schema import AgentConfig

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
from workstation_agent.mcp_host.permissions import evaluate
from workstation_agent.mcp_host.supervisor import PluginSupervisor, ResourceLimits, SubprocessHandle
from workstation_agent.mcp_host.watchdog import HeartbeatWatchdog

log = logging.getLogger(__name__)


@dataclass
class ToolDescriptorImpl:
    """Concrete :class:`workstation_agent.protocols.ToolDescriptor`."""

    name: str
    description: str
    input_schema: dict[str, Any]
    plugin_id: str


@dataclass
class ToolResultImpl:
    """Concrete :class:`workstation_agent.protocols.ToolResult`."""

    content: list[dict[str, Any]]
    is_error: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfirmationRequestImpl:
    """Concrete :class:`workstation_agent.protocols.ConfirmationRequest`."""

    plugin_id: str
    tool_id: str
    args: dict[str, Any]
    condition: str = ""


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

    async def start(
        self,
        config: AgentConfig,
        confirm_cb: Callable[[ConfirmationRequestImpl], Awaitable[bool]] | None = None,
        tts_speak: Any | None = None,
    ) -> None:
        """Discover, verify, and spawn every enabled plugin."""
        self._config = config
        self._confirm_cb = confirm_cb
        self._tts_speak = tts_speak

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

    async def invoke(self, tool_id: str, args: dict[str, Any]) -> ToolResultImpl:
        """Resolve *tool_id* to a plugin, evaluate permissions, dispatch, audit."""
        runtime = self._resolve_tool(tool_id)
        if runtime is None:
            msg = f"no running plugin owns tool {tool_id!r}"
            raise KeyError(msg)

        decision = evaluate(
            runtime.manifest,
            tool_id,
            args,
            runtime.granted_permissions,
        )

        if decision == "deny":
            audit_log(AuditEvent(
                event="tool_denied",
                plugin_id=runtime.manifest.id,
                tool_id=tool_id,
                args=args,
                decision="deny",
            ))
            msg = f"tool {tool_id!r} denied by permissions model"
            raise PermissionError(msg)

        if decision == "confirm":
            confirmed = await self._do_confirm(runtime, tool_id, args)
            if not confirmed:
                audit_log(AuditEvent(
                    event="tool_denied",
                    plugin_id=runtime.manifest.id,
                    tool_id=tool_id,
                    args=args,
                    decision="confirm_rejected",
                ))
                msg = f"tool {tool_id!r} rejected by user confirmation"
                raise PermissionError(msg)

        if runtime.client is None:  # pragma: no cover — invariant
            msg = f"plugin {runtime.manifest.id!r} has no client"
            raise RuntimeError(msg)
        try:
            raw = await runtime.client.tools_call(tool_id, args)
        except Exception:
            audit_log(AuditEvent(
                event="tool_error",
                plugin_id=runtime.manifest.id,
                tool_id=tool_id,
                args=args,
                decision=decision,
            ))
            raise

        result = ToolResultImpl(
            content=raw.get("content", []),
            is_error=bool(raw.get("isError", False)),
            raw=raw,
        )

        audit_log(AuditEvent(
            event="tool_invoke",
            plugin_id=runtime.manifest.id,
            tool_id=tool_id,
            args=args,
            result="ok" if not result.is_error else "error",
            decision=decision,
        ))

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

    async def _do_confirm(
        self,
        runtime: _PluginRuntime,
        tool_id: str,
        args: dict[str, Any],
    ) -> bool:
        """Present a confirmation prompt to the user."""
        req = ConfirmationRequestImpl(
            plugin_id=runtime.manifest.id,
            tool_id=tool_id,
            args=args,
        )

        if self._tts_speak is not None:
            with contextlib.suppress(Exception):
                msg = f"Plugin {runtime.manifest.name} wants to call {tool_id}. Allow?"
                await self._tts_speak.speak(msg)

        if self._confirm_cb is not None:
            return await self._confirm_cb(req)
        return False

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


def _resolve_entry(manifest: PluginManifest) -> list[str]:
    """Convert a manifest entry list to an absolute spawn command."""
    if not manifest.entry:
        return [sys.executable, "-u", "-m", f"workstation_agent.plugins.{manifest.id}"]

    first = manifest.entry[0]
    if first in ("-m", "-u") or not Path(first).is_absolute():
        return [sys.executable, "-u", *manifest.entry]

    return list(manifest.entry)
