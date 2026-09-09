"""Unit tests for workstation_agent.mcp_host.permissions.

Every test here is the one that was here before B2b, with one mechanical
change: a manifest that wants a call examined rather than refused outright now
has to say what its tool's arguments are.  That is default-deny on absence,
and it is asserted directly by ``test_a_tool_with_no_declaration_is_refused``
and by the extra row on the permission table at the bottom.
"""
# ruff: noqa: S108

from __future__ import annotations

from pathlib import Path

import pytest

from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import (
    CONDITION_CHECKERS,
    evaluate,
    evaluate_detailed,
)

#: The declaration the direct-checker tests below need.  ``tool`` is the
#: fictional tool they all call; each argument name they use is classified
#: explicitly, because an argument nothing classifies refuses the call.
_TOOL_ARGS = (
    "args:tool:action:path=ws_path,command=ws_command,url=web_target,"
    "text=opaque,count=opaque,selector=opaque"
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


def test_evaluate_deny_no_permissions():
    """No declared permissions → deny (security default)."""
    m = _manifest()
    decision = evaluate(m, "some.tool", {"x": 1}, granted=set())
    assert decision == "deny"


def test_evaluate_allow_granted_wildcard():
    """Wildcard '*' in granted set → allow."""
    m = _manifest(declared_permissions=["tool:some.tool", "args:some.tool:action"])
    decision = evaluate(m, "some.tool", {}, granted={"*"})
    assert decision == "allow"


def test_evaluate_allow_declared_and_granted():
    """Tool is in declared_permissions and granted → allow."""
    m = _manifest(declared_permissions=["tool:do_thing", "args:do_thing:action"])
    decision = evaluate(m, "do_thing", {}, granted={"tool:do_thing"})
    assert decision == "allow"


def test_evaluate_allow_with_safe_args():
    """Call with safe args and no confirmable conditions → allow."""
    m = _manifest(
        declared_permissions=["tool:safe_tool", "args:safe_tool:action:text=opaque"],
    )
    decision = evaluate(m, "safe_tool", {"text": "hello"}, granted={"tool:safe_tool"})
    assert decision == "allow"


def test_evaluate_deny_tool_not_in_declared():
    """Tool not in declared_permissions (and no wildcard) → deny."""
    m = _manifest(declared_permissions=["tool:allowed_tool"])
    decision = evaluate(m, "forbidden_tool", {}, granted=set())
    assert decision == "deny"


def test_evaluate_deny_unknown_condition():
    """Unknown confirmable_condition → deny + WARN.

    The manifest must have a valid declared+granted pair *and* an argument
    declaration, so neither the tool-permission gate nor the declaration gate
    denies first; the unknown-condition path is what we're exercising here.
    """
    m = _manifest(
        declared_permissions=["tool:any.tool", "args:any.tool:action"],
        confirmable_conditions=["nonexistent_check"],
    )
    outcome = evaluate_detailed(m, "any.tool", {}, granted={"tool:any.tool"})
    assert outcome.decision == "deny"
    assert outcome.rule == "unknown_condition"


def test_evaluate_deny_path_outside_declared():
    """Path argument outside declared paths → deny (hard guard)."""
    m = _manifest(
        declared_permissions=[
            "tool:file.read", "path:/safe/", "args:file.read:action:!path=ws_path",
        ],
    )
    args = {"path": "/unsafe/evil/file.txt"}
    decision = evaluate(m, "file.read", args, granted={"tool:file.read"})
    assert decision == "deny"


def test_evaluate_deny_command_outside_allowlist():
    """Command argument not matching declared cmd patterns → deny (hard guard)."""
    m = _manifest(
        declared_permissions=[
            "tool:shell.run", "cmd:ls", "args:shell.run:action:!command=ws_command",
        ],
    )
    args = {"command": "rm"}
    decision = evaluate(m, "shell.run", args, granted={"tool:shell.run"})
    assert decision == "deny"


def test_evaluate_deny_domain_outside_allowlist():
    """Domain argument not in declared domain allowlist → deny (hard guard)."""
    m = _manifest(
        declared_permissions=[
            "tool:browser.open",
            "domain:safe.example.com",
            "args:browser.open:action:!url=web_target",
        ],
    )
    args = {"url": "https://evil.com/payload"}
    decision = evaluate(m, "browser.open", args, granted={"tool:browser.open"})
    assert decision == "deny"


def test_evaluate_confirm_path_condition():
    """'outside_declared_paths' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=[
            "tool:file.write", "path:/safe/", "args:file.write:action:!path=ws_path",
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    args = {"path": "/unsafe/file.txt"}
    decision = evaluate(m, "file.write", args, granted={"tool:file.write"})
    assert decision == "confirm"


def test_evaluate_confirm_command_condition():
    """'command_outside_allowlist' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=[
            "tool:shell.exec", "cmd:git", "args:shell.exec:action:!command=ws_command",
        ],
        confirmable_conditions=["command_outside_allowlist"],
    )
    args = {"command": "curl"}
    decision = evaluate(m, "shell.exec", args, granted={"tool:shell.exec"})
    assert decision == "confirm"


def test_evaluate_confirm_domain_condition():
    """'domain_outside_allowlist' as confirmable_condition → confirm when triggered."""
    m = _manifest(
        declared_permissions=[
            "tool:http.get", "domain:trusted.org", "args:http.get:action:!url=web_target",
        ],
        confirmable_conditions=["domain_outside_allowlist"],
    )
    args = {"url": "https://unknown.io/api"}
    decision = evaluate(m, "http.get", args, granted={"tool:http.get"})
    assert decision == "confirm"


def test_evaluate_confirm_not_triggered_stays_allow():
    """Confirmable condition present but NOT triggered → allow."""
    m = _manifest(
        declared_permissions=[
            "tool:file.read", "path:/safe/", "args:file.read:action:!path=ws_path",
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    args = {"path": "/safe/data.txt"}
    decision = evaluate(m, "file.read", args, granted={"tool:file.read"})
    assert decision == "allow"


# ---------------------------------------------------------------------------
# Default-deny on absence — the property the declaration layer exists for
# ---------------------------------------------------------------------------


def test_a_tool_with_no_declaration_is_refused():
    """Declared, granted, harmless arguments — and still refused.

    If absence meant "allow", the declaration would be an opt-in bypass: any
    plugin could escape every check below simply by declaring nothing, which
    is strictly worse than the heuristic it replaces.
    """
    m = _manifest(declared_permissions=["tool:undeclared_tool"])
    outcome = evaluate_detailed(
        m, "undeclared_tool", {"text": "hello"}, granted={"tool:undeclared_tool"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_an_argument_the_declaration_omits_is_refused():
    """A complete-looking declaration with one argument left out still refuses.

    The finer-grained half of the same rule: a plugin must not be able to hide
    an argument by omitting it from an otherwise honest declaration.
    """
    m = _manifest(
        declared_permissions=["tool:t", "path:/safe/", "args:t:action:!path=ws_path"],
    )
    outcome = evaluate_detailed(
        m, "t", {"path": "/safe/a", "extra": "/unsafe/b"}, granted={"tool:t"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_argument"


def test_a_missing_required_argument_is_refused():
    """``!`` is the declared successor to the ``requires_path`` table."""
    m = _manifest(
        declared_permissions=["tool:t", "path:/safe/", "args:t:action:!path=ws_path"],
    )
    outcome = evaluate_detailed(m, "t", {}, granted={"tool:t"})
    assert outcome.decision == "deny"
    assert outcome.rule == "missing_required_argument"


def test_the_wildcard_tool_permission_is_not_a_wildcard_declaration():
    """``*`` grants tool identity.  It does not stand in for the declaration.

    Letting it would put the opt-in bypass back under a different spelling.
    """
    m = _manifest(declared_permissions=["*"])
    outcome = evaluate_detailed(m, "anything.at.all", {}, granted={"*"})
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_a_declaration_cannot_arrive_from_anywhere_but_declared_permissions():
    """The anchor, asserted: nothing outside the signed field is consulted.

    A plugin's self-reported MCP ``inputSchema`` lives on the manifest object
    nowhere, and ``compat`` is the only other free-form field a plugin.toml
    carries.  Putting a declaration there must have no effect whatever — a
    third party that could declare from an unsigned or self-reported source
    would simply announce that its ``path`` argument is none of the gate's
    business and walk out of confinement.
    """
    m = _manifest(declared_permissions=["tool:t"])
    m.compat = {"args:t:action:!path=ws_path": True, "declared_permissions": [
        "args:t:action:!path=ws_path",
    ]}
    outcome = evaluate_detailed(m, "t", {"path": "/safe/a"}, granted={"tool:t"})
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_outside_declared_paths_no_declared_root_denies_every_path():
    """No 'path:' permission → NO path access, not unrestricted path access.

    This test previously asserted the opposite ("not applicable"), which is
    precisely the fail-open the rework fixes: a plugin granted
    ``tool:filesystem.read`` while declaring no root could read anywhere,
    because "no roots" meant "no restriction to violate" and the call fell
    through both loops to ``return "allow"``.
    """
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert checker(m, "tool", {"path": "/any/path"})


def test_outside_declared_paths_with_no_declaration_at_all_denies():
    """A checker called directly fails closed too, not just ``evaluate``."""
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert checker(_manifest(declared_permissions=[]), "tool", {"path": "/any/path"})
    assert checker(_manifest(declared_permissions=[]), "tool", {"text": "hello"})


def test_outside_declared_paths_no_root_and_no_path_argument_is_fine():
    """The rule bites on path *arguments*; a call with none is not a violation."""
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert not checker(m, "tool", {"text": "hello", "count": 3})


def test_path_star_is_the_explicit_everywhere_declaration():
    """``path:/`` (or ``path:*``) is how a plugin opts out of confinement.

    Auditable in the manifest, unlike the previous behaviour where saying
    nothing at all achieved the same thing silently.
    """
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    for root in ("path:/", "path:*"):
        m = _manifest(declared_permissions=[root, _TOOL_ARGS])
        assert not checker(m, "tool", {"path": "/any"})


def test_outside_declared_paths_inside():
    """Path within declared scope → checker returns False."""
    m = _manifest(declared_permissions=["path:/home/user/docs/", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert not checker(m, "tool", {"path": "/home/user/docs/file.txt"})


def test_outside_declared_paths_outside():
    """Path outside declared scope → checker returns True."""
    m = _manifest(declared_permissions=["path:/home/user/docs/", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["outside_declared_paths"]
    assert checker(m, "tool", {"path": "/tmp/evil.sh"})


def test_command_no_declared_allowlist_denies_every_command():
    """No 'cmd:' permission → NO command access (was: unrestricted)."""
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert checker(m, "tool", {"command": "anything"})


def test_command_no_allowlist_and_no_command_argument_is_fine():
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert not checker(m, "tool", {"text": "hello"})


def test_command_inside_allowlist():
    """Command matches declared pattern → checker returns False."""
    m = _manifest(declared_permissions=["cmd:git", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert not checker(m, "tool", {"command": "git"})


def test_command_outside_allowlist():
    """Command does not match declared pattern → checker returns True."""
    m = _manifest(declared_permissions=["cmd:git", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["command_outside_allowlist"]
    assert checker(m, "tool", {"command": "curl"})


def test_domain_no_declared_allowlist_denies_every_domain():
    """No 'domain:' permission → NO network access (was: unrestricted).

    The shipped ``browser`` manifest is exactly this shape: it declares
    ``domain_outside_allowlist`` as confirmable but lists no ``domain:``
    permission, so every navigation now prompts rather than sailing through.
    """
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert checker(m, "tool", {"url": "https://anywhere.com"})


def test_domain_no_allowlist_and_no_url_argument_is_fine():
    m = _manifest(declared_permissions=[_TOOL_ARGS])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert not checker(m, "tool", {"selector": "#main"})


def test_domain_inside_allowlist():
    """Domain matches declared pattern → checker returns False."""
    m = _manifest(declared_permissions=["domain:api.example.com", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert not checker(m, "tool", {"url": "https://api.example.com/v1"})


def test_domain_outside_allowlist():
    """Domain does not match declared pattern → checker returns True."""
    m = _manifest(declared_permissions=["domain:api.example.com", _TOOL_ARGS])
    checker = CONDITION_CHECKERS["domain_outside_allowlist"]
    assert checker(m, "tool", {"url": "https://evil.io/steal"})


# ---------------------------------------------------------------------------
# 4x2 permission decision table:
#     declared_permissions ∈ {[], ["path:/x"], ["tool:target_tool"], ["tool:other_tool"]}
#     granted              ∈ {set(), {"tool:target_tool"}}
# Only (declared=["tool:target_tool"], granted={"tool:target_tool"}) may allow.
# All other combinations must deny.  Each row exercises a distinct code path
# (including both former bypass paths: no declared_permissions, and
# declared_permissions containing no tool-scoped entries).
#
# Every manifest below also carries the argument declaration, so the table
# tests the identity gate rather than tripping over the declaration gate.
# The row that proves the declaration gate is required *as well* is
# test_the_declaration_gate_binds_even_in_the_permissive_cell, below.
# ---------------------------------------------------------------------------
_TARGET_ARGS = "args:target_tool:action"


@pytest.mark.parametrize(
    ("declared_permissions", "granted", "expected"),
    [
        # (1) No declared perms + no grant     → deny (bypass #1 path)
        ([],                        set(),                  "deny"),
        # (2) No declared perms + grant        → deny (bypass #1 path)
        ([],                        {"tool:target_tool"},   "deny"),
        # (3) Only path perm + no grant        → deny (bypass #2 path)
        (["path:/x"],               set(),                  "deny"),
        # (4) Only path perm + grant           → deny (bypass #2 path)
        (["path:/x"],               {"tool:target_tool"},   "deny"),
        # (5) Declared target tool + no grant  → deny (declared, not granted)
        (["tool:target_tool"],      set(),                  "deny"),
        # (6) Declared target tool + grant     → ALLOW (only permissive cell)
        (["tool:target_tool"],      {"tool:target_tool"},   "allow"),
        # (7) Declared OTHER tool + no grant   → deny (not declared, not granted)
        (["tool:other_tool"],       set(),                  "deny"),
        # (8) Declared OTHER tool + grant      → deny (not declared)
        (["tool:other_tool"],       {"tool:target_tool"},   "deny"),
    ],
)
def test_evaluate_permission_table(declared_permissions, granted, expected):
    """Table-driven proof that only (declared AND granted) tool perms yield allow."""
    m = _manifest(declared_permissions=[*declared_permissions, _TARGET_ARGS])
    decision = evaluate(m, "target_tool", {}, granted=set(granted))
    assert decision == expected, (
        f"declared={declared_permissions}, granted={granted}: "
        f"expected {expected}, got {decision}"
    )


def test_the_declaration_gate_binds_even_in_the_permissive_cell():
    """Row 6 without the ``args:`` line: declared, granted, and still refused.

    Proves the two gates are independent — passing the identity gate buys
    nothing if the plugin has not said what the tool's arguments are.
    """
    m = _manifest(declared_permissions=["tool:target_tool"])
    outcome = evaluate_detailed(m, "target_tool", {}, granted={"tool:target_tool"})
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"
