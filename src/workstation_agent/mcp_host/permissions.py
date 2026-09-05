"""Runtime permissions evaluation for MCP plugin tool calls.

Every tool invocation passes through :func:`evaluate` before being dispatched.
The decision is one of:

* ``"allow"``   — the call is within all declared permissions and no
                  confirmable condition is triggered.
* ``"deny"``    — the call violates a hard constraint (tool not in granted
                  permissions, path outside declared scope, unknown condition).
* ``"confirm"`` — the call is allowed in principle but a confirmable condition
                  is triggered; the host must present a user prompt.

Built-in condition checkers are registered in :data:`CONDITION_CHECKERS`.  Each
checker receives ``(manifest, tool, args)`` and returns ``True`` when the
condition is met (i.e. the call *would* violate the guard).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .loader import PluginManifest

log = logging.getLogger(__name__)

PermissionDecision = Literal["allow", "deny", "confirm"]

_ConditionChecker = Callable[["PluginManifest", str, dict[str, Any]], bool]

_HARD_GUARDS = ("outside_declared_paths", "command_outside_allowlist", "domain_outside_allowlist")


def _outside_declared_paths(
    manifest: PluginManifest,
    tool: str,  # noqa: ARG001
    args: dict[str, Any],
) -> bool:
    """Return True if any path-like argument is outside declared allowed paths."""
    allowed_paths = [p[5:] for p in manifest.declared_permissions if p.startswith("path:")]

    if not allowed_paths:
        return False

    for val in args.values():
        if not isinstance(val, str):
            continue
        if "/" not in val and "\\" not in val:
            continue
        normalised = val.replace("\\", "/")
        if not any(normalised.startswith(ap.replace("\\", "/")) for ap in allowed_paths):
            log.debug("path argument %r outside declared paths %s", val, allowed_paths)
            return True
    return False


def _command_outside_allowlist(
    manifest: PluginManifest,
    tool: str,  # noqa: ARG001
    args: dict[str, Any],
) -> bool:
    """Return True if a command argument is not in the declared command allowlist."""
    cmd_patterns = [p[4:] for p in manifest.declared_permissions if p.startswith("cmd:")]

    if not cmd_patterns:
        return False

    for key in ("command", "cmd", "shell", "executable"):
        val = args.get(key)
        if val is None or not isinstance(val, str):
            continue
        if not any(re.fullmatch(pat, val) for pat in cmd_patterns):
            log.debug("command %r not in allowlist %s", val, cmd_patterns)
            return True
    return False


def _domain_outside_allowlist(
    manifest: PluginManifest,
    tool: str,  # noqa: ARG001
    args: dict[str, Any],
) -> bool:
    """Return True if a URL/domain argument is not in the declared domain allowlist."""
    domain_patterns = [p[7:] for p in manifest.declared_permissions if p.startswith("domain:")]

    if not domain_patterns:
        return False

    for key in ("url", "domain", "host", "endpoint"):
        val = args.get(key)
        if val is None or not isinstance(val, str):
            continue
        domain = val.split("//")[-1].split("/")[0].split(":")[0]
        if not any(re.fullmatch(pat.replace("*", ".*"), domain) for pat in domain_patterns):
            log.debug("domain %r not in allowlist %s", domain, domain_patterns)
            return True
    return False


CONDITION_CHECKERS: dict[str, _ConditionChecker] = {
    "outside_declared_paths": _outside_declared_paths,
    "command_outside_allowlist": _command_outside_allowlist,
    "domain_outside_allowlist": _domain_outside_allowlist,
}


def evaluate(
    plugin: PluginManifest,
    tool: str,
    args: dict[str, Any],
    granted: set[str],
) -> PermissionDecision:
    """Evaluate whether *plugin* may call *tool* with *args*.

    Args:
        plugin: The manifest of the plugin making the call.
        tool: Fully-qualified tool name (e.g. ``hello_world.echo``).
        args: Arguments passed to the tool.
        granted: Set of permission strings that have been explicitly granted to
                 this plugin by the user (from config or prior confirmation).

    Returns:
        ``"allow"``, ``"deny"``, or ``"confirm"``.
    """
    if plugin.declared_permissions:
        tool_perm = f"tool:{tool}"
        if tool_perm not in granted and "*" not in granted:
            declared_tool_perms = {
                p
                for p in plugin.declared_permissions
                if p.startswith("tool:") or p == "*"
            }
            if (
                declared_tool_perms
                and tool_perm not in declared_tool_perms
                and "*" not in declared_tool_perms
            ):
                log.warning(
                    "deny: tool=%s not in declared_permissions for plugin=%s",
                    tool,
                    plugin.id,
                )
                return "deny"

    for condition_name in plugin.confirmable_conditions:
        checker = CONDITION_CHECKERS.get(condition_name)
        if checker is None:
            log.warning(
                "unknown confirmable_condition=%r for plugin=%s; denying",
                condition_name,
                plugin.id,
            )
            return "deny"
        if checker(plugin, tool, args):
            log.debug(
                "condition=%s triggered for plugin=%s tool=%s; requesting confirm",
                condition_name,
                plugin.id,
                tool,
            )
            return "confirm"

    for guard_name in _HARD_GUARDS:
        if guard_name in plugin.confirmable_conditions:
            continue
        checker = CONDITION_CHECKERS[guard_name]
        if checker(plugin, tool, args):
            log.warning(
                "deny (hard guard): %s triggered for plugin=%s tool=%s",
                guard_name,
                plugin.id,
                tool,
            )
            return "deny"

    return "allow"
