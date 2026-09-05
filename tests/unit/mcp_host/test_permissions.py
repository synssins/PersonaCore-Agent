"""Unit tests for workstation_agent.mcp_host.permissions."""
# ruff: noqa: ANN201, S101, S108

from __future__ import annotations

from pathlib import Path

from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import (
    CONDITION_CHECKERS,
    evaluate,
)


def _manifest(
    plugin_id: str = "test_plugin",
    declared_permissions: list[str] | None = None,
    confirmable_conditions: list[str] | None = None,
) -> PluginManifest:
    return PluginManifest(
        id=plugin_id,
        name="Test Plugin",
        version="0.0.1",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=declared_permissions or [],
        confirmable_conditions=confirmable_conditions or [],
    )


def test_evaluate_allow_no_permissions():
    """No declared permissions → allow everything."""
    m = _manifest()
    decision = evaluate(m, "some.tool", {"x": 1}, granted=set())
    assert decision == "allow"


def test_evaluate_allow_granted_wildcard():
    """Wildcard '*' in granted set → allow."""
    m = _manifest(declared_permissions=["tool:some.tool"])
    decision = evaluate(m, "some.tool", {}, granted={"*"})
    assert decision == "allow"


def test_evaluate_allow_declared_and_granted():
    """Tool is in declared_permissions and granted → allow."""
    m = _manifest(declared_permissions=["tool:do_thing"])
    decision = evaluate(m, "do_thing", {}, granted={"tool:do_thing"})
    assert decision == "allow"


def test_evaluate_allow_with_safe_args():
    """Call with safe args and no confirmable conditions → allow."""
    m = _manifest(declared_permissions=["tool:safe_tool"])
    decision = evaluate(m, "safe_tool", {"text": "hello"}, granted={"tool:safe_tool"})
    assert decision == "allow"


def test_evaluate_deny_tool_not_in_declared():
    """Tool not in declared_permissions (and no wildcard) → deny."""
    m = _manifest(declared_permissions=["tool:allowed_tool"])
    decision = evaluate(m, "forbidden_tool", {}, granted=set())
    assert decision == "deny"


def test_evaluate_deny_unknown_condition():
    """Unknown confirmable_condition → deny + WARN."""
    m = _manifest(confirmable_conditions=["nonexistent_check"])
    decision = evaluate(m, "any.tool", {}, granted=set())
    assert decision == "deny"


def test_evaluate_deny_path_outside_declared():
    """Path argument outside declared paths → deny (hard guard)."""
    m = _manifest(declared_permissions=["path:/safe/"])
    args = {"path": "/unsafe/evil/file.txt"}
    decision = evaluate(m, "file.read", args, granted=set())
    assert decision == "deny"


def test_evaluate_deny_command_outside_allowlist():
    """Command argument not matching declared cmd patterns → deny (hard guard)."""
    m = _manifest(declared_permissions=["cmd:ls"])
    args = {"command": "rm"}
    decision = evaluate(m, "shell.run", args, granted=set())
    assert decision == "deny"


def test_evaluate_deny_domain_outside_allowlist():
    """Domain argument not in declared domain allowlist → deny (hard guard)."""
    m = _manifest(declared_permissions=["domain:safe.example.com"])
    args = {"url": "https://evil.com/payload"}
    decision = evaluate(m, "browser.open", args, granted=set())
    assert decision == "deny"


def test_evaluate_confirm_path_condition():
    """'outside_declared_paths' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=["path:/safe/"],
        confirmable_conditions=["outside_declared_paths"],
    )
    args = {"path": "/unsafe/file.txt"}
    decision = evaluate(m, "file.write", args, granted=set())
    assert decision == "confirm"


def test_evaluate_confirm_command_condition():
    """'command_outside_allowlist' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=["cmd:git"],
        confirmable_conditions=["command_outside_allowlist"],
    )
    args = {"command": "curl"}
    decision = evaluate(m, "shell.exec", args, granted=set())
    assert decision == "confirm"


def test_evaluate_confirm_domain_condition():
    """'domain_outside_allowlist' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=["domain:trusted.org"],
        confirmable_conditions=["domain_outside_allowlist"],
    )
    args = {"url": "https://unknown.io/api"}
    decision = evaluate(m, "http.get", args, granted=set())
    assert decision == "confirm"


def test_evaluate_confirm_not_triggered_stays_allow():
    """Confirmable condition present but NOT triggered → allow."""
    m = _manifest(
        declared_permissions=["path:/safe/"],
        confirmable_conditions=["outside_declared_paths"],
    )
    args = {"path": "/safe/data.txt"}
    decision = evaluate(m, "file.read", args, granted=set())
    assert decision == "allow"


def test_outside_declared_paths_no_restriction():
    """No 'path:' permissions → checker returns False (not applicable)."""
    m = _manifest(declared_permissions=[])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert not checker(m, "tool", {"path": "/any/path"})


def test_outside_declared_paths_inside():
    """Path within declared scope → checker returns False."""
    m = _manifest(declared_permissions=["path:/home/user/docs/"])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert not checker(m, "tool", {"path": "/home/user/docs/file.txt"})


def test_outside_declared_paths_outside():
    """Path outside declared scope → checker returns True."""
    m = _manifest(declared_permissions=["path:/home/user/docs/"])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert checker(m, "tool", {"path": "/tmp/evil.sh"})


def test_command_outside_allowlist_no_restriction():
    """No 'cmd:' permissions → checker returns False."""
    m = _manifest(declared_permissions=[])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert not checker(m, "tool", {"command": "anything"})


def test_command_inside_allowlist():
    """Command matches declared pattern → checker returns False."""
    m = _manifest(declared_permissions=["cmd:git"])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert not checker(m, "tool", {"command": "git"})


def test_command_outside_allowlist():
    """Command does not match declared pattern → checker returns True."""
    m = _manifest(declared_permissions=["cmd:git"])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert checker(m, "tool", {"command": "curl"})


def test_domain_outside_allowlist_no_restriction():
    """No 'domain:' permissions → checker returns False."""
    m = _manifest(declared_permissions=[])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert not checker(m, "tool", {"url": "https://anywhere.com"})


def test_domain_inside_allowlist():
    """Domain matches declared pattern → checker returns False."""
    m = _manifest(declared_permissions=["domain:api.example.com"])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert not checker(m, "tool", {"url": "https://api.example.com/v1"})


def test_domain_outside_allowlist():
    """Domain does not match declared pattern → checker returns True."""
    m = _manifest(declared_permissions=["domain:api.example.com"])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert checker(m, "tool", {"url": "https://evil.io/steal"})
