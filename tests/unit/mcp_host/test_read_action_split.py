"""The read/action split, the §5.2 envelope, §5.6 stripping and session plumbing.

The centrepiece is the read/action split (contract §11 item 6): a read whose
path falls outside the plugin's declared roots must come back ``denied``, and
must never be put to the operator as a prompt.

The failure mode these tests exist to catch is not "it prompted".  It is that
the obvious fix — making ``_outside_declared_paths`` return ``False`` for
reads — skips the confirmable-condition branch *and* the hard-guard loop
(which deliberately skips any guard the plugin declares as confirmable, and
``filesystem`` declares ``outside_declared_paths``) and falls through to
``evaluate``'s trailing ``return "allow"``.  That converts a prompt into a
**silent out-of-roots read**.

A test that only asserts "no prompt appeared" passes for that regression as
happily as for the correct fix, so every test below asserts the decision
positively as ``deny`` *and* asserts it is not ``allow``.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest.mock import AsyncMock

import pytest

import workstation_agent.mcp_host.audit as audit_mod
from workstation_agent.mcp_host import host as host_mod
from workstation_agent.mcp_host.host import (
    MAX_RESULT_CHARS,
    MCPHost,
    conform_result,
    failure_result,
    sanitise_reason,
    strip_special_tokens,
)
from workstation_agent.mcp_host.loader import PluginManifest, VerifyResult
from workstation_agent.mcp_host.permissions import (
    UNINSPECTABLE,
    SessionContext,
    classify,
    evaluate,
    evaluate_detailed,
    is_absolute_path,
    normalise_path,
    safe_name,
    tool_declaration,
    url_host,
)

#: The argument declaration the real ``filesystem`` plugin.toml carries, plus
#: the handful of extra argument names the tests below exercise.  Under
#: default-deny-on-absence an argument nobody declared refuses the call, so a
#: fixture that wants to prove something *other* than "undeclared refuses"
#: has to say what its arguments are — exactly as a real manifest does.
_FS_ARGS = [
    (
        "args:filesystem.read:read:!path=ws_path,encoding=opaque,payload=opaque,"
        "n=opaque,flag=opaque,ratio=opaque,opt=opaque"
    ),
    # `path` and `paths` are both optional on `list` here because the tests
    # exercise both spellings; the shipped manifest declares `!path`.
    "args:filesystem.list:read:path=ws_path,paths=ws_path",
    # `content` is optional here and required in the shipped manifest: these
    # tests call `write` with only a path, to exercise the *path* rules
    # without the required-argument rule firing first.
    "args:filesystem.write:action:!path=ws_path,content=opaque",
    "args:filesystem.delete:action:!path=ws_path",
]


def _fs_manifest(
    *,
    plugin_id: str = "filesystem",
    confirmable: list[str] | None = None,
) -> PluginManifest:
    """A manifest shaped exactly like the real ``filesystem`` plugin.toml."""
    return PluginManifest(
        id=plugin_id,
        name="Filesystem",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:filesystem.list",
            "tool:filesystem.read",
            "tool:filesystem.write",
            "tool:filesystem.delete",
            "path:/roots/documents",
            *_FS_ARGS,
        ],
        confirmable_conditions=(
            ["outside_declared_paths"] if confirmable is None else confirmable
        ),
    )


_GRANTED = {
    "tool:filesystem.list",
    "tool:filesystem.read",
    "tool:filesystem.write",
    "tool:filesystem.delete",
}


def _plugin_with(plugin_id: str, declared: list[str]) -> PluginManifest:
    """A bare manifest carrying exactly *declared*.

    Every declaration in these tests comes through ``declared_permissions``,
    which is the field ``loader._manifest_dict`` covers with the plugin
    signature.  There is deliberately no way to hand :func:`evaluate` a
    declaration from anywhere else.
    """
    return PluginManifest(
        id=plugin_id,
        name=plugin_id,
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=list(declared),
        confirmable_conditions=[],
    )


# ---------------------------------------------------------------------------
# The split itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["filesystem.read", "filesystem.list"])
def test_read_outside_roots_is_denied_not_allowed(tool: str) -> None:
    """A read outside the roots denies — and is emphatically not allowed."""
    m = _fs_manifest()
    decision = evaluate(m, tool, {"path": "/elsewhere/secret.txt"}, _GRANTED)

    assert decision == "deny"
    # Asserted separately: this is the assertion the catastrophic fix fails.
    assert decision != "allow"
    # …and it must not merely have stopped confirming.
    assert decision != "confirm"


@pytest.mark.parametrize("tool", ["filesystem.read", "filesystem.list"])
def test_read_outside_roots_carries_the_read_rule(tool: str) -> None:
    """The denial is attributed to the read/action split, not to a hard guard.

    Pins *which* rule fired.  If the short-circuit were removed and the hard
    guard happened to deny for some other reason, the decision would still
    read "deny" while the intended rule had quietly stopped existing.
    """
    outcome = evaluate_detailed(_fs_manifest(), tool, {"path": "/elsewhere/x"}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.rule == "read_outside_declared_paths"
    assert outcome.condition == ""


def test_read_inside_roots_is_allowed() -> None:
    """The split only bites outside the roots; inside, a read is ordinary."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"path": "/roots/documents/a.txt"}, _GRANTED,
    )
    assert outcome.decision == "allow"


def test_write_outside_roots_still_confirms() -> None:
    """The action half of the split is unchanged: writes go to the operator."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.write", {"path": "/elsewhere/x.txt"}, _GRANTED,
    )
    assert outcome.decision == "confirm"
    assert outcome.condition == "outside_declared_paths"


def test_delete_outside_roots_still_confirms() -> None:
    """Any unrecognised verb is an action; an action outside the roots prompts."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.delete", {"path": "/elsewhere/x.txt"}, _GRANTED,
    )
    assert outcome.decision == "confirm"


def test_read_outside_roots_denies_even_without_a_confirmable_condition() -> None:
    """A plugin that does not declare the condition still denies out-of-roots reads.

    Here the hard guard would also deny, so this pins that the two mechanisms
    agree rather than one masking the other's absence.
    """
    m = _fs_manifest(confirmable=[])
    assert evaluate(m, "filesystem.read", {"path": "/elsewhere/x"}, _GRANTED) == "deny"


def test_read_denial_precedes_the_confirm_branch() -> None:
    """The split short-circuits BEFORE the confirmable-condition loop.

    A plugin declaring an *unknown* condition denies with rule
    ``unknown_condition`` — unless the read/action split got there first.
    Asserting the rule proves the ordering, which is what stops the read from
    ever reaching a prompt.
    """
    m = _fs_manifest(confirmable=["outside_declared_paths", "no_such_condition"])
    outcome = evaluate_detailed(m, "filesystem.read", {"path": "/elsewhere/x"}, _GRANTED)
    assert outcome.rule == "read_outside_declared_paths"


def test_read_of_an_ungranted_tool_still_denies_on_identity_first() -> None:
    """The identity gate keeps precedence; the split does not weaken it."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"path": "/roots/documents/a"}, granted=set(),
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "tool_not_granted"


# ---------------------------------------------------------------------------
# Traversal — the deny must not be walk-around-able
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/roots/documents/../../elsewhere/secret.txt",
        r"\roots\documents\..\..\elsewhere\secret.txt",
        "/roots/documents/./../../elsewhere/secret.txt",
        "/roots/documents//..//..//elsewhere",
        "/roots/documentsevil/secret.txt",  # prefix, but not a path segment
    ],
)
def test_traversal_and_prefix_tricks_are_still_outside(path: str) -> None:
    """``..``, redundant separators and segment-prefix collisions do not escape.

    Without lexical ``..`` resolution the first four start with the declared
    root as a *string* and slip through a naive prefix test; without
    segment-boundary matching the last one does.  Each would make the deny
    above decorative.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": path}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.rule == "read_outside_declared_paths"


def test_declared_root_env_var_is_expanded(monkeypatch) -> None:
    """A root written as ``path:%USERPROFILE%\\Documents`` matches a real path.

    The shipped manifests declare their roots with an unexpanded environment
    variable while arguments arrive expanded, so without expansion the two
    never match and *every* path is "outside the roots".
    """
    monkeypatch.setenv("PCTESTHOME", r"C:\Users\tester")
    m = PluginManifest(
        id="filesystem",
        name="Filesystem",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:filesystem.read", r"path:%PCTESTHOME%\Documents", *_FS_ARGS,
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    granted = {"tool:filesystem.read"}

    inside = evaluate(m, "filesystem.read", {"path": r"C:\Users\tester\Documents\a.txt"}, granted)
    assert inside == "allow"

    outside = evaluate(m, "filesystem.read", {"path": r"C:\Users\tester\Desktop\a.txt"}, granted)
    assert outside == "deny"


def test_case_insensitive_on_windows_paths(monkeypatch) -> None:
    """Windows paths are case-insensitive; the root comparison must be too."""
    monkeypatch.setenv("PCTESTHOME", r"C:\Users\tester")
    m = PluginManifest(
        id="filesystem",
        name="Filesystem",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:filesystem.read", r"path:%PCTESTHOME%\Documents", *_FS_ARGS,
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    decision = evaluate(
        m, "filesystem.read", {"path": r"c:\users\TESTER\DOCUMENTS\a.txt"},
        {"tool:filesystem.read"},
    )
    assert decision == "allow"


def test_path_argument_without_a_separator_is_still_checked() -> None:
    """``{"path": "secret.txt"}`` is a path even though it has no separator.

    The original checker skipped any value without ``/`` or ``\\``, so a bare
    relative filename was never compared against the roots at all.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": "secret.txt"}, _GRANTED)
    assert outcome.decision == "deny"


def test_non_path_arguments_are_not_mistaken_for_paths() -> None:
    """Widening the check must not turn every string into a path.

    ``encoding`` has no separator and is not a path-shaped key, so it must
    not push an otherwise-legitimate in-roots read into a denial.
    """
    outcome = evaluate_detailed(
        _fs_manifest(),
        "filesystem.read",
        {"path": "/roots/documents/a.txt", "encoding": "utf-8"},
        _GRANTED,
    )
    assert outcome.decision == "allow"


def test_paths_nested_in_a_list_are_checked() -> None:
    """A list of paths is checked element-wise, not skipped for not being a str."""
    outcome = evaluate_detailed(
        _fs_manifest(),
        "filesystem.list",
        {"paths": ["/roots/documents/a", "/elsewhere/b"]},
        _GRANTED,
    )
    assert outcome.decision == "deny"


# ---------------------------------------------------------------------------
# Rework finding 1: an empty allowlist must fail CLOSED
#
# Every test here asserts `deny` AND asserts `!= "allow"`.  The hole being
# fixed produced `allow`, and a test that only checked "it did not prompt"
# would have passed against it.
# ---------------------------------------------------------------------------


def _no_roots_manifest(plugin_id: str = "filesystem") -> PluginManifest:
    """A plugin granted a filesystem tool that declares no ``path:`` root."""
    return PluginManifest(
        id=plugin_id,
        name="Filesystem",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:filesystem.read", "tool:filesystem.write", *_FS_ARGS,
        ],
        confirmable_conditions=["outside_declared_paths"],
    )


def test_read_with_no_declared_root_is_denied_not_allowed() -> None:
    """The worst of the five: no roots meant unrestricted reads."""
    granted = {"tool:filesystem.read"}
    outcome = evaluate_detailed(
        _no_roots_manifest(), "filesystem.read",
        {"path": r"C:\Windows\System32\config\SAM"}, granted,
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"
    assert outcome.decision != "confirm", "the fix must not become a prompt on a read"
    assert outcome.rule == "read_outside_declared_paths"


def test_write_with_no_declared_root_is_not_allowed() -> None:
    """The action half fails closed too — to a prompt, since the plugin
    declares the condition as confirmable."""
    outcome = evaluate_detailed(
        _no_roots_manifest(), "filesystem.write",
        {"path": r"C:\Windows\evil.txt"}, {"tool:filesystem.write"},
    )
    assert outcome.decision != "allow"
    assert outcome.decision == "confirm"


def test_write_with_no_declared_root_and_no_confirmable_condition_denies() -> None:
    """With no confirmable condition declared, the hard guard denies."""
    m = _no_roots_manifest()
    m.confirmable_conditions = []
    outcome = evaluate_detailed(
        m, "filesystem.write", {"path": r"C:\Windows\evil.txt"}, {"tool:filesystem.write"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_call_with_no_path_argument_is_unaffected() -> None:
    """The rule bites on path arguments, not on every call.

    Without this, "no roots means deny" would break every plugin that has no
    business with the filesystem at all.
    """
    m = PluginManifest(
        id="hello_world", name="Hello", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:hello_world.echo",
            "args:hello_world.echo:read:!text=opaque",
        ],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "hello_world.echo", {"text": "ping"}, {"tool:hello_world.echo"},
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize("root", ["path:/", "path:*"])
def test_explicit_everywhere_declaration_still_allows(root: str) -> None:
    """``path:/`` is the auditable opt-out that replaces the silent one."""
    m = _no_roots_manifest()
    m.declared_permissions = [*m.declared_permissions, root]
    outcome = evaluate_detailed(
        m, "filesystem.read", {"path": r"C:\Windows\x"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "allow"


def test_free_text_arguments_are_not_turned_into_path_violations() -> None:
    """The empty-allowlist fix must not make ordinary tools unusable.

    ``powershell.run`` is gated by its ``cmd:`` allowlist, not by ``path:``.
    Treating any value containing a separator as a path argument would deny
    every command mentioning a directory — an over-inclusion with no
    per-argument whitelist to escape it.
    """
    m = PluginManifest(
        id="powershell", name="PowerShell", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:powershell.run",
            "cmd:*",
            "args:powershell.run:action:!command=ws_command",
        ],
        confirmable_conditions=["command_outside_allowlist"],
    )
    outcome = evaluate_detailed(
        m, "powershell.run", {"command": r"dir C:\Windows"}, {"tool:powershell.run"},
    )
    assert outcome.decision == "allow"


# ---------------------------------------------------------------------------
# Cycle-2 finding 1: the empty-allowlist denial sat BEHIND the extractor
#
# The denial added last cycle was evadable by reshaping the argument: a value
# the extractor does not classify yields no candidates, and the
# empty-candidates short-circuit returned False before the empty-roots
# denial could run.  It is now decided on the TOOL (`requires_path`), because
# for a tool whose signature always carries a path, "no path detected" is a
# scanner failure rather than a call without paths.
# ---------------------------------------------------------------------------


def test_path_tool_with_empty_allowlist_denies_when_extraction_finds_nothing() -> None:
    """THE hole: no roots, and an argument that yields no path candidate.

    Under the heuristic, ``payload`` was not a path-ish key and ``notes``
    carried no separator, drive letter or colon, so the extractor returned
    ``[]`` and the empty-candidates short-circuit returned ``False`` right
    there, never reaching the empty-allowlist denial.

    The declaration closes it a rung higher up: ``payload`` is declared
    ``opaque`` (so it genuinely produces no path candidate, exactly as
    before), and ``filesystem.read`` declares ``!path``, so the call is
    refused for the argument it did *not* carry rather than for the one it
    did.  "No path was found" can no longer resolve to "carry on".
    """
    args = {"payload": "notes"}
    classified = classify(_no_roots_manifest(), "filesystem.read", args)
    assert classified.paths == (), "precondition: this argument yields no path candidate"
    assert classified.undeclared == (), "precondition: it is declared, just not a path"
    assert classified.missing == ("path",)

    outcome = evaluate_detailed(
        _no_roots_manifest(), "filesystem.read", args, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"
    assert outcome.decision != "confirm"


def test_path_tool_with_empty_allowlist_denies_on_completely_empty_args() -> None:
    """Not even an argument to reshape: the tool's signature is enough."""
    outcome = evaluate_detailed(
        _no_roots_manifest(), "filesystem.read", {}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_path_tool_with_roots_denies_when_extraction_finds_nothing() -> None:
    """The same scanner-failure reasoning with roots present.

    One step beyond the reported finding, and the same hole: "not shown to be
    inside the roots" must not resolve to "allowed".  No legitimate call to a
    path-required tool omits its path.
    """
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"payload": "notes"}, _GRANTED,
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_swapping_the_checks_would_have_broken_this_and_does_not() -> None:
    """The fix must NOT be "deny whenever a plugin declares no root".

    ``hello_world`` declares no ``path:`` root and has no business with the
    filesystem.  Swapping the two checks — the obvious fix — denies this.
    """
    m = PluginManifest(
        id="hello_world", name="Hello", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:hello_world.echo",
            "args:hello_world.echo:read:!text=opaque",
        ],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "hello_world.echo", {"text": "ping"}, {"tool:hello_world.echo"},
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize(
    "tool",
    ["filesystem.read", "filesystem.list", "filesystem.write", "filesystem.delete",
     "files_read", "files_list", "files_write", "adb_push", "adb_install"],
)
def test_path_required_classification(tool: str) -> None:
    """The successor to ``requires_path``: it is declared, not guessed.

    ``requires_path`` was a hand-maintained set of tool names plus two
    name-prefix rules (``filesystem.``, ``files_``), so a third-party plugin
    shipping a tool called ``files_read`` inherited the classification and a
    first-party family that spelled its verb differently did not.  The same
    property is now one ``!`` in the tool's own signed manifest.
    """
    plugin = "adb" if tool.startswith("adb_") else "files"
    m = _plugin_with(plugin, [f"tool:{tool}", f"args:{tool}:action:!path=ws_path"])
    decl = tool_declaration(m, tool)
    assert decl is not None
    assert "path" in decl.required


@pytest.mark.parametrize(
    "tool",
    # shell_run's `cwd` is OPTIONAL, so a shell_run with no cwd is a normal
    # call with genuinely no path; adb_pull's device_path is on the phone.
    ["shell_run", "adb_pull", "adb_shell", "adb_devices", "serial_read",
     "hello_world.echo", "clipboard.get", "workstation_status"],
)
def test_tools_without_a_mandatory_path_are_not_reclassified(tool: str) -> None:
    """An optional or foreign path argument is not a required workstation one."""
    m = _plugin_with(
        "x", [f"tool:{tool}", f"args:{tool}:action:cwd=ws_path,device_path=foreign"],
    )
    decl = tool_declaration(m, tool)
    assert decl is not None
    assert decl.required == frozenset()


@pytest.mark.parametrize("tool", ["", "  ", None, 123, object(), ["filesystem.read"]])
def test_a_malformed_tool_id_has_no_declaration(tool: object) -> None:
    """A tool id is not assumed to be a well-formed string — and no
    declaration means refused, never waved through."""
    assert tool_declaration(_fs_manifest(), tool) is None


def test_shell_run_without_a_cwd_is_not_denied_by_the_path_rule() -> None:
    """The optional-vs-mandatory distinction, asserted end to end."""
    m = PluginManifest(
        id="shell", name="Shell", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:shell_run",
            "cmd:*",
            "path:/roots/documents",
            # §6: shell_run's cwd is OPTIONAL, and the declaration says so by
            # not marking it required.  That is the whole of the old
            # `_PATH_REQUIRED_TOOLS` exception list, stated where it belongs.
            "args:shell_run:action:!command=ws_command,cwd=ws_path,wait_s=opaque",
        ],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(m, "shell_run", {"command": "whoami"}, {"tool:shell_run"})
    assert outcome.decision == "allow"


# ---------------------------------------------------------------------------
# Cycle-3 finding 1: a path that normalises to empty bypassed confinement
#
# ".", "./." and "foo/.." all resolve to their own base, so normalise_path
# returned "" and the comparison loop hit `continue` — found nothing, denied
# nothing.  It slipped past the cycle-2 fix specifically: `requires_path` was
# satisfied because the extractor DID find a candidate; it evaporated during
# normalisation instead.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [".", "./.", "foo/..", "./", ".\\", r"foo\..", "a/b/../..", "./a/..", "  .  "],
)
def test_a_path_that_normalises_away_is_denied_not_skipped(path: str) -> None:
    """``filesystem.read {"path": "."}`` read the agent's working directory."""
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": path}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"
    assert outcome.decision != "confirm"


def test_the_candidate_exists_so_the_required_rule_cannot_catch_it() -> None:
    """Precondition: this is a *normalisation* failure, not a classification one.

    Pins why the required-argument rule does not cover this case — the
    argument is present and does produce a candidate, so nothing upstream of
    the comparison layer objects.  ``.`` normalises to the empty string, and
    the comparison layer is what has to refuse it.  This is the clearest
    demonstration in the file that declaring what an argument *is* does
    nothing about what it *resolves to*.
    """
    classified = classify(_fs_manifest(), "filesystem.read", {"path": "."})
    assert classified.paths == (".",)
    assert classified.missing == ()
    assert normalise_path(".") == ""


@pytest.mark.parametrize(
    "path",
    ["notes.txt", "docs/notes.txt", "..", "../secret", "C:secret.txt", "a/../b"],
)
def test_relative_paths_are_refused_rather_than_interpreted(path: str) -> None:
    """A relative path has no meaning at this gate.

    Resolving one needs a base directory, and the only one available is the
    agent's cwd — which is exactly why ``Path.resolve()`` is refused.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": path}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_absolute_paths_are_still_allowed_inside_the_roots() -> None:
    """The refusal must not swallow the ordinary case."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"path": "/roots/documents/a.txt"}, _GRANTED,
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/roots/documents", True),
        ("//server/share", True),
        ("c:/users/me", True),
        ("c:secret.txt", False),   # drive-RELATIVE
        ("notes.txt", False),
        ("", False),
        ("..", False),
    ],
)
def test_is_absolute_path(path: str, *, expected: bool) -> None:
    assert is_absolute_path(path) is expected


def test_a_relative_declared_root_is_ignored() -> None:
    """A relative root would confine against the agent's launch directory."""
    m = PluginManifest(
        id="filesystem", name="Filesystem", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:filesystem.read", "path:docs", *_FS_ARGS],
        confirmable_conditions=["outside_declared_paths"],
    )
    # The root is dropped, so the plugin has no usable root at all and the
    # empty-allowlist rule applies.
    outcome = evaluate_detailed(
        m, "filesystem.read", {"path": "docs/notes.txt"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Cycle-3 finding 2: adb_pull denied because the extractor is tool-blind
#
# `device_path` names a file on the phone.  `/sdcard/DCIM/x.jpg` has a
# leading separator, so it was extracted as a path and compared against
# Windows roots it can never be inside — denying every legitimate adb_pull.
# ---------------------------------------------------------------------------


#: What the adb family's arguments are.  §6: "adb_push, adb_install and
#: files_* take workstation paths", which says by implication that the rest of
#: the family does not — a phone path or a phone command can never be inside a
#: Windows root, and comparing it to one denies every legitimate call.
#:
#: Under the heuristic this lived in a hard-coded table in permissions.py
#: keyed on ``(manifest.id, tool-name prefix)``.  It is now the plugin's own
#: signed statement about its own arguments, which is both narrower (nothing
#: is inherited by anything) and auditable by whoever grants the plugin.
_ADB_ARGS = [
    "args:adb_pull:read:serial=opaque,!device_path=foreign,remote_path=foreign",
    "args:adb_push:action:serial=opaque,!workstation_path=ws_path,!device_path=foreign",
    "args:adb_install:action:serial=opaque,!workstation_path=ws_path",
    "args:adb_shell:action:serial=opaque,!command=foreign",
    "args:adb_logcat:read:serial=opaque,seconds=opaque,filter=foreign",
]


def _adb_manifest() -> PluginManifest:
    return PluginManifest(
        id="adb", name="ADB", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:adb_pull", "tool:adb_push", "tool:adb_install",
            "tool:adb_shell", "tool:adb_logcat",
            "path:/roots/documents",
            *_ADB_ARGS,
        ],
        confirmable_conditions=["outside_declared_paths"],
    )


_ADB_GRANTED = {
    "tool:adb_pull", "tool:adb_push", "tool:adb_install",
    "tool:adb_shell", "tool:adb_logcat",
}


def test_a_plausible_adb_pull_succeeds() -> None:
    """The regression the finding names: every legitimate adb_pull failed."""
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_pull",
        {"serial": "R58M1234", "device_path": "/sdcard/DCIM/Camera/IMG_0001.jpg"},
        _ADB_GRANTED,
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("adb_shell", {"serial": "R58M1234", "command": "/system/bin/ls /sdcard"}),
        ("adb_logcat", {"serial": "R58M1234", "seconds": 5, "filter": "*:E"}),
        ("adb_pull", {"device_path": "/data/local/tmp/out.txt"}),
    ],
)
def test_other_device_side_adb_arguments_are_not_judged_against_workstation_roots(
    tool: str, args: dict,
) -> None:
    """§6: only adb_push, adb_install and files_* take workstation paths."""
    outcome = evaluate_detailed(_adb_manifest(), tool, args, _ADB_GRANTED)
    assert outcome.decision == "allow"


def test_adb_push_of_an_out_of_roots_source_still_denies() -> None:
    """The half that must keep being checked: push reads FROM the workstation.

    Otherwise adb_push would copy any file on the machine onto a device —
    which is exactly what §6 says it must not (`a path outside is denied for
    push and install exactly as for files_read`).
    """
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_push",
        {"serial": "R58M1234",
         "workstation_path": r"C:\Windows\System32\config\SAM",
         "device_path": "/sdcard/loot.bin"},
        _ADB_GRANTED,
    )
    assert outcome.decision != "allow"


def test_adb_push_of_an_in_roots_source_is_permitted() -> None:
    """Confinement, not prohibition."""
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_push",
        {"serial": "R58M1234",
         "workstation_path": "/roots/documents/firmware.bin",
         "device_path": "/sdcard/firmware.bin"},
        _ADB_GRANTED,
    )
    assert outcome.decision == "allow"


def test_adb_install_of_an_out_of_roots_apk_still_denies() -> None:
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_install",
        {"serial": "R58M1234", "workstation_path": r"C:\Windows\evil.apk"},
        _ADB_GRANTED,
    )
    assert outcome.decision != "allow"


def test_adb_push_with_only_a_device_path_denies_rather_than_sailing_through() -> None:
    """Exemption removes an argument from ROOT COMPARISON, not from scrutiny.

    Every argument here is exempt, so extraction finds nothing — and
    ``adb_push`` is path-required, so "no workstation path was produced"
    denies.  This is the test that proves fixing finding 2 did not loosen
    finding 1.
    """
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_push", {"device_path": "/sdcard/x"}, _ADB_GRANTED,
    )
    assert outcome.decision != "allow"


def test_the_exemption_is_scoped_to_the_foreign_family() -> None:
    """``device_path`` is only foreign under adb_; it is not a magic key name.

    If the exemption were keyed on the argument name alone, renaming an
    argument would be enough to escape root confinement entirely.
    """
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read",
        {"device_path": r"C:\Windows\System32\config\SAM"}, _GRANTED,
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_an_unrecognised_adb_argument_is_still_checked() -> None:
    """The exemption lists device-side names, not "everything except known".

    A family that spelled its workstation argument some other way must not
    escape confinement; an unknown name stays checked, so the failure mode is
    a visible over-denial rather than a silent bypass.
    """
    outcome = evaluate_detailed(
        _adb_manifest(), "adb_push",
        {"some_new_arg": r"C:\Windows\System32\config\SAM"}, _ADB_GRANTED,
    )
    assert outcome.decision != "allow"


@pytest.mark.parametrize(
    ("plugin_id", "tool", "expected"),
    [
        ("adb", "adb_pull", {"device_path": "foreign", "remote_path": "foreign",
                             "serial": "opaque"}),
        ("adb", "adb_shell", {"command": "foreign", "serial": "opaque"}),
        ("adb", "adb_push", {"workstation_path": "ws_path", "device_path": "foreign",
                             "serial": "opaque"}),
    ],
)
def test_foreign_argument_classification(plugin_id: str, tool: str, expected: dict) -> None:
    """Classification comes from the manifest, argument by argument.

    Replaces the ``foreign_args`` table test.  What that test proved — that
    ``device_path`` is foreign under adb and ``workstation_path`` is not —
    is proved here from the declaration instead of from a hard-coded
    ``(plugin id, tool prefix)`` tuple.
    """
    m = _plugin_with(plugin_id, [f"tool:{tool}", *_ADB_ARGS])
    decl = tool_declaration(m, tool)
    assert decl is not None
    assert dict(decl.arguments) == expected


@pytest.mark.parametrize(
    ("plugin_id", "tool"),
    [
        # Right plugin, wrong family of tool.
        ("adb", "filesystem.read"),
        ("serial", "adb_devices"),
        # Right-looking tool, wrong plugin — the cycle-4 hole.
        ("adblock", "adb_run"),
        ("thirdparty", "adb_something"),
        ("adb", ""),
    ],
)
def test_a_tool_the_manifest_does_not_name_has_no_declaration(
    plugin_id: str, tool: str,
) -> None:
    """No entry, no classification — and no classification means refused."""
    m = _plugin_with(plugin_id, [f"tool:{tool}", *_ADB_ARGS])
    assert tool_declaration(m, tool) is None


# ---------------------------------------------------------------------------
# Cycle-4 finding 2: the exemption was inheritable by any plugin
#
# It is now inheritable by nothing at all.  The exemption used to key off the
# tool NAME — caller-supplied — and cycle 4 narrowed that to (manifest.id,
# tool-name prefix).  Under the declaration nothing is keyed on a name at
# all: an argument is exempt because the plugin's own signed manifest says
# that argument is foreign, and a plugin that says nothing gets nothing.
# ---------------------------------------------------------------------------


def test_a_third_party_plugin_cannot_inherit_the_adb_exemption() -> None:
    """A plugin shipping ``adb_run`` must not get ``command`` waved through.

    Its manifest declares ``command`` a workstation command (or nothing at
    all), so it is judged against a ``cmd:`` allowlist it does not have.
    Naming a tool ``adb_*`` buys it exactly nothing.
    """
    m = _plugin_with(
        "adblock",
        ["tool:adb_run", "args:adb_run:action:!command=ws_command"],
    )
    outcome = evaluate_detailed(
        m, "adb_run", {"command": "powershell -enc ..."}, {"tool:adb_run"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_an_undeclared_lookalike_tool_is_refused_outright() -> None:
    """…and a plugin that declares nothing about ``adb_run`` gets refused.

    The heuristic's failure here was silent: ``adb_run`` matched the ``adb_``
    prefix and its ``command`` was skipped.  Saying nothing now costs the
    call, which is the only direction "we do not know what this is" may fail
    in.
    """
    m = _plugin_with("adblock", ["tool:adb_run"])
    outcome = evaluate_detailed(
        m, "adb_run", {"command": "powershell -enc ..."}, {"tool:adb_run"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_the_real_adb_plugin_keeps_its_exemption() -> None:
    """…while the plugin that actually declares the exemption still works."""
    m = _plugin_with("adb", ["tool:adb_shell", *_ADB_ARGS])
    outcome = evaluate_detailed(
        m, "adb_shell", {"serial": "R1", "command": "getprop ro.product.model"},
        {"tool:adb_shell"},
    )
    assert outcome.decision == "allow"


def test_a_third_party_plugin_cannot_inherit_the_serial_exemption() -> None:
    m = _plugin_with(
        "notserial",
        ["tool:serial_send", "args:serial_send:action:!text=ws_path"],
    )
    outcome = evaluate_detailed(
        m, "serial_send", {"text": r"C:\Windows\System32\config\SAM"}, {"tool:serial_send"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Cycle-4 finding 3: command and domain checkers saw only top-level keys
# ---------------------------------------------------------------------------


def _cmd_manifest(patterns: list[str]) -> PluginManifest:
    return PluginManifest(
        id="powershell", name="PowerShell", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:powershell.run",
            "args:powershell.run:action:!command=ws_command,intent=opaque",
            *patterns,
        ],
        confirmable_conditions=[],
    )


@pytest.mark.parametrize(
    "args",
    [
        {"config": {"cmd": "curl evil.com"}},
        {"config": {"nested": {"command": "curl evil.com"}}},
        {"steps": [{"command": "curl evil.com"}]},
        {"steps": [[{"executable": "curl"}]]},
    ],
)
def test_a_nested_command_is_still_checked(args: dict) -> None:
    """``args.get("command")`` saw nothing, so both checkers returned allow.

    Still refused, for a stronger reason than recursion: contract §5.1 says
    arguments are flat, so ``config`` and ``steps`` are not shapes any
    declaration names — and an argument nothing declares refuses the call.
    A command cannot hide one level down because there is no "down".
    """
    outcome = evaluate_detailed(
        _cmd_manifest(["cmd:git"]), "powershell.run", args, {"tool:powershell.run"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_declared_allowed_command_is_still_allowed() -> None:
    """Refusing the nested shape must not deny what the allowlist permits.

    CHANGED OUTCOME.  This used to assert ``{"config": {"command": "git"}}``
    is allowed, which was the "recursing must not over-deny" half of the
    cycle-4 fix.  With classification declared rather than recursive there is
    no recursion to over-deny with, and the nested spelling is refused as an
    undeclared argument — asserted immediately below, so the pair still pins
    both directions.
    """
    outcome = evaluate_detailed(
        _cmd_manifest(["cmd:git"]), "powershell.run",
        {"command": "git"}, {"tool:powershell.run"},
    )
    assert outcome.decision == "allow"


def test_the_nested_spelling_is_refused_as_undeclared() -> None:
    """The other half: nesting is not a shape a declaration can name."""
    outcome = evaluate_detailed(
        _cmd_manifest(["cmd:git"]), "powershell.run",
        {"config": {"command": "git"}}, {"tool:powershell.run"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_argument"


def _dom_manifest(patterns: list[str]) -> PluginManifest:
    return PluginManifest(
        id="browser", name="Browser", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:browser.open",
            "args:browser.open:action:!url=web_target",
            *patterns,
        ],
        confirmable_conditions=[],
    )


@pytest.mark.parametrize(
    "args",
    [
        {"config": {"url": "https://evil.com/x"}},
        {"targets": [{"endpoint": "https://evil.com"}]},
        {"a": {"b": {"host": "evil.com"}}},
    ],
)
def test_a_nested_url_is_still_checked(args: dict) -> None:
    outcome = evaluate_detailed(
        _dom_manifest(["domain:safe.example.com"]), "browser.open", args,
        {"tool:browser.open"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_declared_allowed_url_is_still_allowed() -> None:
    """CHANGED OUTCOME, for the same reason as the command case above: the
    nested spelling is now refused, and the declared one still works."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:safe.example.com"]), "browser.open",
        {"url": "https://safe.example.com/x"}, {"tool:browser.open"},
    )
    assert outcome.decision == "allow"


def test_a_command_buried_below_the_recursion_bound_denies() -> None:
    """No recursion bound left to bury anything below.

    The heuristic walked arbitrary structures and had to decide what
    exceeding its own bound meant; ``payload`` is simply not an argument
    ``powershell.run`` declares, so the depth of what is inside it never
    comes up.
    """
    deep: object = {"command": "curl evil.com"}
    for _ in range(12):
        deep = {"nested": deep}
    outcome = evaluate_detailed(
        _cmd_manifest(["cmd:*"]), "powershell.run", {"payload": deep},  # type: ignore[dict-item]
        {"tool:powershell.run"},
    )
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Cycle-4 finding 1: URL userinfo and friends
# ---------------------------------------------------------------------------


def test_userinfo_cannot_smuggle_a_host_past_the_allowlist() -> None:
    """``http://allowed.com:password@evil.com/`` connects to evil.com.

    The old split expression returned ``allowed.com`` — the *username* — and
    passed an allowlist of exactly that.
    """
    outcome = evaluate_detailed(
        _dom_manifest(["domain:allowed.com"]), "browser.open",
        {"url": "http://allowed.com:password@evil.com/"}, {"tool:browser.open"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


@pytest.mark.parametrize(
    "url",
    [
        "http://allowed.com@evil.com/",
        "https://allowed.com:@evil.com/",
        "https://user:pass@evil.com/",
        "https://allowed.com%40evil.com@evil.com/",
    ],
)
def test_any_userinfo_section_is_refused_outright(url: str) -> None:
    """Refused rather than interpreted: deciding "which half is the host"
    is the bug itself."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:allowed.com"]), "browser.open",
        {"url": url}, {"tool:browser.open"},
    )
    assert outcome.decision != "allow"


def test_url_host_extracts_what_a_client_would_connect_to() -> None:
    assert url_host("http://allowed.com:password@evil.com/") == UNINSPECTABLE
    assert url_host("https://evil.com/path") == "evil.com"
    assert url_host("evil.com") == "evil.com"
    assert url_host("evil.com:8080") == "evil.com"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://EVIL.COM/x", "evil.com"),          # uppercase
        ("https://evil.com./x", "evil.com"),         # trailing dot
        ("https://evil.com.../x", "evil.com"),       # several
        ("http://[::1]:8080/x", "::1"),              # bracketed IPv6
        ("[::1]", "::1"),
        ("https://127.0.0.1:443/x", "127.0.0.1"),
    ],
)
def test_url_host_normalises_the_confusions(value: str, expected: str) -> None:
    assert url_host(value) == expected


def test_case_and_trailing_dot_cannot_evade_the_allowlist() -> None:
    """Each of these is the same host as the allowlisted one…"""
    m = _dom_manifest(["domain:safe.example.com"])
    for url in ("https://SAFE.EXAMPLE.COM/x", "https://safe.example.com./x"):
        outcome = evaluate_detailed(m, "browser.open", {"url": url}, {"tool:browser.open"})
        assert outcome.decision == "allow", url


def test_an_idn_homograph_does_not_match_its_ascii_lookalike() -> None:
    """A Cyrillic lookalike encodes to a different punycode label than ASCII."""
    homograph = "https://\u0430llowed.com/x"  # U+0430, not ASCII a
    outcome = evaluate_detailed(
        _dom_manifest(["domain:allowed.com"]), "browser.open",
        {"url": homograph}, {"tool:browser.open"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_value_that_is_not_a_url_at_all_is_refused() -> None:
    outcome = evaluate_detailed(
        _dom_manifest(["domain:*"]), "browser.open",
        {"url": "   "}, {"tool:browser.open"},
    )
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Cycle-5 finding: the wildcard translation did not escape literal dots
#
# `pat.replace("*", ".*")` left every literal dot as a regex `.`, so
# `domain:*.example.com` became `.*.example.com` and matched a lookalike
# domain across the dot boundary.
# ---------------------------------------------------------------------------


def test_a_lookalike_domain_does_not_match_a_subdomain_wildcard() -> None:
    """THE bypass: `evil-example.com` against `domain:*.example.com`.

    `.*` took "evil" and the unescaped dot took "-", so a subdomain
    restriction was defeated by registering a lookalike.
    """
    outcome = evaluate_detailed(
        _dom_manifest(["domain:*.example.com"]), "browser.open",
        {"url": "https://evil-example.com/x"}, {"tool:browser.open"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


@pytest.mark.parametrize(
    "host",
    ["evil-example.com", "evilXexample.com", "evil.example.com.evil.net",
     "example.com.evil.net"],
)
def test_the_dot_boundary_is_literal(host: str) -> None:
    """Every dot in a pattern can now only ever mean a dot."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:*.example.com"]), "browser.open",
        {"url": f"https://{host}/x"}, {"tool:browser.open"},
    )
    assert outcome.decision != "allow", host


def test_a_legitimate_subdomain_still_matches() -> None:
    """Escaping must not break the pattern's actual purpose."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:*.example.com"]), "browser.open",
        {"url": "https://api.example.com/v1"}, {"tool:browser.open"},
    )
    assert outcome.decision == "allow"


def test_the_wildcard_spans_exactly_one_label() -> None:
    """Chosen semantics: `*` is one label, as in a TLS wildcard certificate.

    `*.example.com` therefore covers `api.example.com` but not
    `a.b.example.com` — the more restrictive of the two readings, and the
    one a manifest author is most likely to mean.
    """
    m = _dom_manifest(["domain:*.example.com"])
    deep = evaluate_detailed(
        m, "browser.open", {"url": "https://a.b.example.com/x"}, {"tool:browser.open"},
    )
    assert deep.decision != "allow"


def test_the_wildcard_does_not_cover_the_apex() -> None:
    """`*.example.com` does not match `example.com`, same as TLS."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:*.example.com"]), "browser.open",
        {"url": "https://example.com/x"}, {"tool:browser.open"},
    )
    assert outcome.decision != "allow"


def test_a_literal_dot_in_a_domain_pattern_is_a_literal_dot() -> None:
    """Without escaping, `domain:api.example.com` matched `apiXexample.com`."""
    outcome = evaluate_detailed(
        _dom_manifest(["domain:api.example.com"]), "browser.open",
        {"url": "https://apiXexample.com/x"}, {"tool:browser.open"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_the_bare_star_still_means_anywhere() -> None:
    """`domain:*` is the explicit "anywhere" declaration and must survive.

    Single-label semantics would otherwise make a bare `*` match no host
    containing a dot, i.e. no real host at all.
    """
    m = _dom_manifest(["domain:*"])
    for url in ("https://anything.example.com/x", "https://evil.com/", "http://a.b.c.d/"):
        outcome = evaluate_detailed(m, "browser.open", {"url": url}, {"tool:browser.open"})
        assert outcome.decision == "allow", url


def test_command_and_domain_patterns_are_one_language_now() -> None:
    r"""CHANGED OUTCOME — the cmd:/domain: language split, resolved.

    ``cmd:`` used to be a raw regex and ``domain:`` a glob, in the same
    manifest, with nothing marking which was which.  Both are globs now,
    both go through the same escaper, and ``re:`` is the explicit escape
    hatch in either class.

    Consequences asserted here rather than left implicit:

    * ``cmd:git.exe`` is a literal and no longer matches ``gitXexe``.  Under
      the old semantics it did, which is the footgun the previous docstring
      documented and told authors to work around with ``cmd:git\.exe``.
    * ``cmd:.*`` now means "a literal dot, then anything" — so a manifest
      written for the old regex semantics *tightens*, and the shipped
      ``powershell`` manifest is changed to ``cmd:*`` in the same commit.
    * ``cmd:*`` and ``domain:*`` both mean "anything", which they did not
      before.
    """
    # A dot in an untagged pattern is a literal dot, in both classes.
    m = _cmd_manifest(["cmd:git.exe"])
    assert evaluate(
        m, "powershell.run", {"command": "git.exe"}, {"tool:powershell.run"},
    ) == "allow"
    assert evaluate(
        m, "powershell.run", {"command": "gitXexe"}, {"tool:powershell.run"},
    ) == "deny"

    # The old regex spelling fails CLOSED rather than opening up.
    assert evaluate(
        _cmd_manifest(["cmd:.*"]), "powershell.run",
        {"command": "anything at all"}, {"tool:powershell.run"},
    ) == "deny"

    # The bare star is "anything" in both classes.
    assert evaluate(
        _cmd_manifest(["cmd:*"]), "powershell.run",
        {"command": "anything at all"}, {"tool:powershell.run"},
    ) == "allow"


def test_the_regex_escape_hatch_is_spelled_out() -> None:
    """``re:`` selects a regex explicitly, in both allowlist classes."""
    m = _cmd_manifest([r"cmd:re:git\.(exe|cmd)"])
    for command, expected in (("git.exe", "allow"), ("git.cmd", "allow"),
                              ("gitXexe", "deny"), ("git.bat", "deny")):
        assert evaluate(
            m, "powershell.run", {"command": command}, {"tool:powershell.run"},
        ) == expected, command

    d = _dom_manifest([r"domain:re:(api|cdn)\.example\.com"])
    for url, expected in (("https://api.example.com/x", "allow"),
                          ("https://cdn.example.com/x", "allow"),
                          ("https://evil.example.com/x", "deny"),
                          ("https://apiXexample.com/x", "deny")):
        assert evaluate(
            d, "browser.open", {"url": url}, {"tool:browser.open"},
        ) == expected, url


def test_the_shared_escaper_protects_the_command_class_too() -> None:
    """The escaping fix now covers ``cmd:`` as well as ``domain:``.

    ``domain:*.example.com`` once admitted ``evil-example.com`` because the
    translation left literal dots unescaped.  ``cmd:`` never had that bug
    only because it never translated — the moment it acquired a wildcard it
    would have.  One translator means the fix is already there.
    """
    m = _cmd_manifest(["cmd:git *"])
    assert evaluate(
        m, "powershell.run", {"command": "git status"}, {"tool:powershell.run"},
    ) == "allow"
    assert evaluate(
        m, "powershell.run", {"command": "gitXstatus"}, {"tool:powershell.run"},
    ) == "deny"
    assert evaluate(
        m, "powershell.run", {"command": "notgit status"}, {"tool:powershell.run"},
    ) == "deny"


def test_command_allowlist_is_anchored_at_both_ends() -> None:
    """`cmd:git` must not match `git; rm -rf /` — re.fullmatch, not search."""
    m = _cmd_manifest(["cmd:git"])
    assert evaluate(
        m, "powershell.run", {"command": "git; rm -rf /"}, {"tool:powershell.run"},
    ) == "deny"
    assert evaluate(
        m, "powershell.run", {"command": "notgit"}, {"tool:powershell.run"},
    ) == "deny"


# ---------------------------------------------------------------------------
# Cycle-4 finding 4: an exempt key pruned its whole subtree
# ---------------------------------------------------------------------------


def test_a_structure_under_an_exempt_key_does_not_hide_a_workstation_path() -> None:
    """``remote_path={"local_target": "C:/…/SAM"}`` skipped the whole subtree.

    The exemption means "this *string* names something in a foreign
    namespace".  A structure under an exempt key is not a foreign path, it is
    unclassifiable — and unclassifiable resolves to a denial.
    """
    m = PluginManifest(
        id="adb", name="ADB", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:adb_pull", "path:/roots/documents", *_ADB_ARGS],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "adb_pull",
        {"remote_path": {"local_target": r"C:\Windows\System32\config\SAM"}},
        {"tool:adb_pull"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


@pytest.mark.parametrize(
    "value",
    [
        {"local_target": "C:/Windows/x"},
        ["C:/Windows/x"],
        [{"nested": "C:/Windows/x"}],
    ],
)
def test_only_scalars_are_exempt(value: object) -> None:
    m = PluginManifest(
        id="adb", name="ADB", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:adb_pull", "path:/roots/documents", *_ADB_ARGS],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "adb_pull", {"device_path": value}, {"tool:adb_pull"},  # type: ignore[dict-item]
    )
    assert outcome.decision != "allow"


def test_a_scalar_under_an_exempt_key_is_still_exempt() -> None:
    """The narrowing must not undo cycle 3: a plain device path still works."""
    m = PluginManifest(
        id="adb", name="ADB", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:adb_pull", "path:/roots/documents", *_ADB_ARGS],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "adb_pull", {"device_path": "/sdcard/DCIM/x.jpg"}, {"tool:adb_pull"},
    )
    assert outcome.decision == "allow"


def test_a_structure_under_an_exempt_command_key_is_also_refused() -> None:
    """The same narrowing in the command checker."""
    m = PluginManifest(
        id="adb", name="ADB", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:adb_shell", "cmd:*", *_ADB_ARGS],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "adb_shell", {"command": {"inner": "whoami"}}, {"tool:adb_shell"},
    )
    assert outcome.decision != "allow"


def test_serial_write_payload_is_not_a_workstation_path() -> None:
    """Pre-emptive: B8 would otherwise hit finding 2 the first time it wrote
    a payload beginning with a separator."""
    m = PluginManifest(
        id="serial", name="Serial", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:serial_write",
            # §6: a serial payload is not a workstation path.  Declared by
            # the serial plugin about its own arguments, rather than
            # pre-emptively hard-coded in the gate on B8's behalf.
            "args:serial_write:action:!session_id=opaque,text=foreign,hex=foreign",
        ],
        confirmable_conditions=[],
    )
    outcome = evaluate_detailed(
        m, "serial_write", {"session_id": "s1", "text": "/status\r\n"},
        {"tool:serial_write"},
    )
    assert outcome.decision == "allow"


# ---------------------------------------------------------------------------
# Cycle-2 finding 2: UNC paths conflated with local absolute paths
# ---------------------------------------------------------------------------


def _unc_manifest(root: str) -> PluginManifest:
    return PluginManifest(
        id="filesystem", name="Filesystem", version="0.1.0", runtime="python", entry=[],
        plugin_dir=Path(), signature_file=Path("signature.sig"),
        declared_permissions=["tool:filesystem.read", f"path:{root}", *_FS_ARGS],
        confirmable_conditions=["outside_declared_paths"],
    )


def test_unc_is_not_the_same_path_as_a_local_absolute_path() -> None:
    r"""``\\server\share`` collapsed to ``/server/share`` — the local path.

    A plugin granted ``path:\server`` therefore reached arbitrary network
    shares.  Plain UNC is neither ``\\?\`` nor ``\\.\``, so the
    device-namespace rule never saw it.
    """
    assert normalise_path(r"\\server\share\x") != normalise_path(r"\server\share\x")
    assert normalise_path(r"\\server\share\x") == "//server/share/x"
    assert normalise_path(r"\server\share\x") == "/server/share/x"


def test_a_local_root_does_not_admit_a_unc_path() -> None:
    outcome = evaluate_detailed(
        _unc_manifest(r"\server"), "filesystem.read",
        {"path": r"\\server\share\secret.txt"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_the_universal_root_does_not_admit_a_unc_path() -> None:
    """``path:/`` grants the whole workstation, not the whole network."""
    outcome = evaluate_detailed(
        _unc_manifest("/"), "filesystem.read",
        {"path": r"\\server\share\secret.txt"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_unc_root_does_not_admit_a_local_path() -> None:
    """The exclusion runs both ways."""
    outcome = evaluate_detailed(
        _unc_manifest(r"\\server\share"), "filesystem.read",
        {"path": r"C:\Windows\x"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_matching_unc_root_admits_its_own_share() -> None:
    """Confinement, not prohibition: a declared share still works."""
    outcome = evaluate_detailed(
        _unc_manifest(r"\\server\share"), "filesystem.read",
        {"path": r"\\server\share\reports\q1.txt"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize(
    "path",
    [r"\\server\other\secret.txt", r"\\evil\share\secret.txt",
     r"\\server\share\..\other\secret.txt", r"\\server\sharedrive\secret.txt"],
)
def test_a_unc_root_confines_to_its_own_host_and_share(path: str) -> None:
    """A different share, a different host, traversal out, and a segment-prefix."""
    outcome = evaluate_detailed(
        _unc_manifest(r"\\server\share"), "filesystem.read",
        {"path": path}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_a_unc_root_naming_only_a_host_is_ignored() -> None:
    r"""``path:\\server`` would grant every share on that machine."""
    outcome = evaluate_detailed(
        _unc_manifest(r"\\server"), "filesystem.read",
        {"path": r"\\server\share\secret.txt"}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Cycle-2 finding 3: the sentinel was admitted by the universal root
# ---------------------------------------------------------------------------


def test_universal_root_does_not_admit_uninspectable_arguments() -> None:
    """``path:/`` means "every path", not "things that are not paths at all".

    ``_is_within``'s ``root == "/"`` fast path returned True for the
    sentinel, so the explicit everywhere-declaration handed back exactly the
    arguments the sentinel exists to refuse.
    """

    class Opaque:
        pass

    outcome = evaluate_detailed(
        _unc_manifest("/"), "filesystem.read",
        {"path": Opaque()}, {"tool:filesystem.read"},  # type: ignore[dict-item]
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


@pytest.mark.parametrize(
    "path",
    [r"\\?\C:\Windows\x", r"\\.\PhysicalDrive0",
     r"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows"],
)
def test_universal_root_does_not_admit_device_namespace_paths(path: str) -> None:
    """Same fast path, same contradiction: ``path:/`` is not raw device access."""
    outcome = evaluate_detailed(
        _unc_manifest("/"), "filesystem.read",
        {"path": path}, {"tool:filesystem.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_universal_root_still_admits_ordinary_local_paths() -> None:
    """The refusals must not turn ``path:/`` into a deny-everything root."""
    for path in (r"C:\Windows\System32\x", "/anywhere/at/all", r"C:\Users\me\a.txt"):
        outcome = evaluate_detailed(
            _unc_manifest("/"), "filesystem.read",
            {"path": path}, {"tool:filesystem.read"},
        )
        assert outcome.decision == "allow", path


def test_is_within_refuses_the_sentinel_against_every_root() -> None:
    """Unit-level: no root value whatsoever contains the sentinel."""
    from workstation_agent.mcp_host.permissions import UNINSPECTABLE, _is_within

    for root in ("/", "//server/share", "c:/users/me", "/roots/documents"):
        assert _is_within(UNINSPECTABLE, root) is False


# ---------------------------------------------------------------------------
# Rework finding 2: trailing spaces and dots defeat the `..` comparison
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/roots/documents/.. /elsewhere/secret.txt",
        "/roots/documents/.../elsewhere/secret.txt",
        "/roots/documents/.. /.. /elsewhere",
        "/roots/documents/... /elsewhere",
        "/roots/documents/.. ./elsewhere",
        r"\roots\documents\.. \elsewhere\secret.txt",
        r"\roots\documents\...\elsewhere\secret.txt",
        "/roots/documents/.. \\elsewhere\\secret.txt",
        r"C:\roots\documents\.. \Windows",
    ],
)
def test_windows_trailing_padding_does_not_defeat_parent_resolution(path: str) -> None:
    """Win32 strips trailing dots and spaces; `seg == ".."` did not.

    Each of these arrives with a segment like ``".. "`` or ``"..."`` that a
    strict equality test reads as an ordinary directory name, concluding the
    path stays inside the root while the OS walks out of it.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": path}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_trailing_padding_on_ordinary_segments_still_matches_the_root() -> None:
    """The same stripping keeps in-roots paths working, not just out ones.

    Win32 resolves ``/roots/documents /a.txt`` to ``/roots/documents/a.txt``.
    """
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"path": "/roots/documents /a.txt"}, _GRANTED,
    )
    assert outcome.decision == "allow"


@pytest.mark.parametrize(
    "path",
    [
        r"\\?\C:\roots\documents\..\..\Windows",
        r"\\?\C:\roots\documents\a.txt",
        r"\\.\PhysicalDrive0",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows",
        "//?/C:/roots/documents/a.txt",
    ],
)
def test_device_namespace_paths_are_outside_every_root(path: str) -> None:
    """``\\\\?\\`` and ``\\\\.\\`` are not normalised by Win32 at all.

    ``..`` is passed through literally and trailing padding is not stripped,
    so neither rule modelled here applies to them.  Rather than maintain two
    contradictory models, they are treated as outside every declared root —
    including the second case, which *would* be inside if it were an
    ordinary path.  A device-namespace path is never a legitimate root.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": path}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Rework finding 3: paths that carry no separator
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value"),
    [
        # Drive-relative: resolves against that drive's current directory.
        ("path", "C:secret.txt"),
        ("blob", "C:secret.txt"),          # unambiguous shape, any key
        ("blob", r"C:..\Windows\x"),
        # Alternate data stream, under a key not in the exact-name list.
        ("file_to_read", "secret.txt:Zone.Identifier"),
        # A bare filename resolved against an out-of-roots cwd, under a key
        # the original list did not contain.
        ("file_to_read", "secret.txt"),
        ("target_directory", "elsewhere"),
        ("dest_folder", "elsewhere"),
        ("output_filename", "notes.txt"),
    ],
)
def test_separatorless_paths_are_still_checked(key: str, value: str) -> None:
    """None of these contains ``/`` or ``\\``, and the key list missed most."""
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {key: value}, _GRANTED)
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_urls_are_not_mistaken_for_paths() -> None:
    """``http://`` is the domain allowlist's business, not the path guard's.

    The heuristic decided this by inspecting the value: a colon one character
    in was a drive letter, a longer scheme was a URI, and ``file://`` was
    special-cased back to being a path.  Three shape rules to answer a
    question the manifest can simply state.

    Asserted here as a routing property, which is what it always was: a
    ``web_target`` never reaches the path guard and a ``ws_path`` never
    reaches the domain guard, whatever either value happens to look like.
    """
    m = _plugin_with(
        "mixed",
        [
            "tool:mixed.go",
            "path:/roots/documents",
            "domain:example.com",
            "args:mixed.go:action:url=web_target,path=ws_path",
        ],
    )
    classified = classify(
        m, "mixed.go",
        {"url": "https://example.com/x", "path": "file:///C:/Windows/x"},
    )
    assert classified.domains == ("https://example.com/x",)
    assert classified.paths == ("file:///C:/Windows/x",)
    # …and a URL-shaped value under a path argument is still confined,
    # rather than escaping the path guard for looking like a URL.
    assert evaluate(m, "mixed.go", {"path": "https://example.com/x"}, {"tool:mixed.go"}) == "deny"


# ---------------------------------------------------------------------------
# Rework finding 4: bytes and PathLike arguments
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        Path(r"C:\Windows\System32\config\SAM"),
        PurePosixPath("/elsewhere/secret.txt"),
        PureWindowsPath(r"C:\Windows\x"),
        b"/elsewhere/secret.txt",
        bytearray(b"/elsewhere/secret.txt"),
        rb"C:\Windows\System32",
    ],
)
def test_bytes_and_pathlike_arguments_are_checked(value: object) -> None:
    """These were invisible to every check and resolved to a silent allow.

    Unreachable over JSON transport, but ``invoke`` is called in-process too.
    """
    outcome = evaluate_detailed(_fs_manifest(), "filesystem.read", {"path": value}, _GRANTED)  # type: ignore[dict-item]
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_an_in_roots_pathlike_is_still_allowed() -> None:
    """Handling PathLike must not mean denying it wholesale."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read",
        {"path": PurePosixPath("/roots/documents/a.txt")}, _GRANTED,  # type: ignore[dict-item]
    )
    assert outcome.decision == "allow"


def test_an_argument_of_an_unknown_type_denies_rather_than_disappearing() -> None:
    """An unrecognised type must not read as "there were no paths"."""

    class Opaque:
        pass

    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"path": Opaque()}, _GRANTED,  # type: ignore[dict-item]
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


def test_ordinary_scalars_are_not_treated_as_paths() -> None:
    """ints, floats, bools and None are not paths and must not deny."""
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read",
        {"path": "/roots/documents/a", "n": 3, "flag": True, "ratio": 1.5, "opt": None},
        _GRANTED,
    )
    assert outcome.decision == "allow"


def test_a_path_buried_below_the_recursion_bound_denies() -> None:
    """Exceeding the inspection bound is a violation, not a truncation."""
    deep: object = "/elsewhere/secret.txt"
    for _ in range(12):
        deep = {"nested": deep}
    outcome = evaluate_detailed(
        _fs_manifest(), "filesystem.read", {"payload": deep}, _GRANTED,  # type: ignore[dict-item]
    )
    assert outcome.decision == "deny"
    assert outcome.decision != "allow"


# ---------------------------------------------------------------------------
# Rework finding 5: the tool name is caller-controlled and was echoed back
# ---------------------------------------------------------------------------


def test_a_path_shaped_tool_name_is_not_echoed_into_the_reason() -> None:
    """§5.2 forbids returning an absolute path; the refusal itself leaked one."""
    hostile = r"C:/Windows/System32/config/SAM"
    outcome = evaluate_detailed(_fs_manifest(), hostile, {}, granted=set())

    assert outcome.decision == "deny"
    assert "C:" not in outcome.reason
    assert "SAM" not in outcome.reason
    assert "/" not in outcome.reason
    assert "\\" not in outcome.reason


def test_a_drive_relative_tool_name_is_not_echoed_either() -> None:
    """``C:secret.txt`` has no separator and slipped the first path pattern."""
    outcome = evaluate_detailed(_fs_manifest(), "C:secret.txt", {}, granted=set())
    assert "C:" not in outcome.reason


@pytest.mark.asyncio
@pytest.mark.usefixtures("isolated_audit_db")
async def test_a_hostile_tool_name_does_not_leak_through_invoke() -> None:
    """End to end: the envelope the caller actually receives carries no path."""
    h = MCPHost()
    result = await h.invoke(r"C:\Windows\System32\config\SAM", {})
    assert result.ok is False
    assert result.reason is not None
    assert "C:" not in result.reason
    assert "SAM" not in result.reason


def test_safe_name_bounds_an_absurd_tool_name() -> None:
    """A caller-supplied name is bounded as well as scrubbed."""
    assert len(safe_name("x" * 5000)) <= 64
    assert safe_name("///") == "the requested tool"
    assert safe_name(None) == "None"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    ["filesystem.read", "filesystem.list", "files_read", "files_list",
     "serial_read", "jobs_output", "workstation_status", "FILESYSTEM.READ"],
)
def test_known_reads_classify_as_reads(tool: str) -> None:
    """The read/action mode is declared, and the tool id is case-folded.

    ``is_read_only_tool`` inferred this from the last segment of the tool
    name against a verb allowlist, so ``filesystem.list_recent`` decomposed
    to ``recent`` and a family that spelled a read ``fetch`` was silently an
    action.  Declared instead; the fallback is unchanged in direction, since
    the absence of a declaration refuses the call outright.
    """
    m = _plugin_with("x", [f"tool:{tool}", f"args:{tool}:read"])
    decl = tool_declaration(m, tool)
    assert decl is not None
    assert decl.read_only is True


@pytest.mark.parametrize(
    "tool",
    ["filesystem.write", "filesystem.delete", "files_write", "shell_run",
     "serial_write", "adb_push", "clipboard.set", "desktop.click",
     "filesystem.list_recent"],
)
def test_actions_and_unknowns_classify_as_actions(tool: str) -> None:
    """An ``action`` mode is an action; nothing is inferred from the verb."""
    m = _plugin_with("x", [f"tool:{tool}", f"args:{tool}:action"])
    decl = tool_declaration(m, tool)
    assert decl is not None
    assert decl.read_only is False


@pytest.mark.parametrize("mode", ["", "  ", "reads", "READ ONLY", "maybe", "*"])
def test_an_unrecognised_mode_discards_the_declaration(mode: str) -> None:
    """A malformed declaration is dropped, not partially honoured.

    Dropping it means the tool has no declaration, which means the call is
    refused: a typo in a manifest costs a visible over-denial rather than a
    tool whose mode quietly defaulted to something.
    """
    m = _plugin_with("x", ["tool:t", f"args:t:{mode}:!path=ws_path"])
    assert tool_declaration(m, "t") is None
    assert evaluate(m, "t", {"path": "/x"}, {"tool:t"}) == "deny"


def test_normalise_path_is_lexical_not_filesystem_backed() -> None:
    """Normalisation never consults the filesystem or the process cwd."""
    assert normalise_path("/A/B/../C/") == "/a/c"
    assert normalise_path(r"C:\A\.\B") == "c:/a/b"
    assert normalise_path("/../..") == "/"


# ---------------------------------------------------------------------------
# Malformed manifests must not raise out of the evaluator
# ---------------------------------------------------------------------------


def test_a_malformed_allowlist_regex_denies_rather_than_raising() -> None:
    """An unparseable ``cmd:`` pattern is data, not code: fail closed."""
    m = PluginManifest(
        id="powershell",
        name="PowerShell",
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=[
            "tool:powershell.run",
            "args:powershell.run:action:!command=ws_command",
            # Marked `re:`, so it really does reach re.compile and really is
            # unparseable.  An UNTAGGED `cmd:[unclosed` is now a glob, which
            # is escaped and matches the literal text — no longer a way to
            # exercise this path.
            "cmd:re:[unclosed",
        ],
        confirmable_conditions=[],
    )
    decision = evaluate(m, "powershell.run", {"command": "whoami"}, {"tool:powershell.run"})
    assert decision == "deny"


# ---------------------------------------------------------------------------
# §5.6 special-token stripping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    ["<|im_start|>", "<|im_end|>", "<|eot_id|>", "<|start_header_id|>",
     "<|end_header_id|>", "<|endoftext|>", "<|python_tag|>", "<|eom_id|>",
     "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>", "<s>", "</s>"],
)
def test_special_tokens_are_stripped(token: str) -> None:
    assert strip_special_tokens(f"before{token}after") == "beforeafter"


def test_unknown_angle_pipe_tokens_are_stripped_too() -> None:
    """§5.6 says "and their kin": the shape is matched, not a fixed list."""
    assert strip_special_tokens("a<|some_future_model_token|>b") == "ab"


def test_nested_token_construction_is_stripped_to_a_fixed_point() -> None:
    """A single pass is defeated by nesting; this is the reason for looping.

    Removing the inner ``<|im_start|>`` from ``<|im_<|im_start|>start|>``
    leaves a freshly-assembled ``<|im_start|>`` behind.
    """
    assert strip_special_tokens("<|im_<|im_start|>start|>") == ""
    assert strip_special_tokens("[IN[INST]ST]") == ""


def test_stripping_leaves_ordinary_text_alone() -> None:
    assert strip_special_tokens("a < b and c | d > e") == "a < b and c | d > e"
    assert strip_special_tokens("") == ""


def test_stripping_is_applied_to_tool_output() -> None:
    """The strip is wired into the result path, not merely available."""
    result = conform_result(
        {"content": [{"type": "text", "text": "hello<|im_end|>world"}], "isError": False},
    )
    assert result.content[0]["text"] == "helloworld"


# ---------------------------------------------------------------------------
# §5.2 envelope
# ---------------------------------------------------------------------------


def test_failure_envelope_has_the_contract_keys() -> None:
    r = failure_result("denied", "Nope.", is_error=False)
    payload = json.loads(r.content[0]["text"])
    assert payload == {"ok": False, "code": "denied", "reason": "Nope."}
    assert r.ok is False
    assert r.code == "denied"


def test_structured_results_gain_the_ok_key() -> None:
    """§5.2: every structured result carries ``ok``."""
    r = conform_result(
        {"content": [{"type": "text", "text": '{"status": "ready"}'}], "isError": False},
    )
    payload = json.loads(r.content[0]["text"])
    assert payload["ok"] is True
    assert payload["status"] == "ready"


def test_a_result_that_already_declares_ok_is_not_overwritten() -> None:
    r = conform_result(
        {"content": [{"type": "text", "text": '{"ok": false, "code": "not_found"}'}],
         "isError": False},
    )
    payload = json.loads(r.content[0]["text"])
    assert payload["ok"] is False


def test_plain_text_results_stay_plain_text() -> None:
    """§5.2 allows plain text; it must not be forced into a JSON object."""
    r = conform_result({"content": [{"type": "text", "text": "ping"}], "isError": False})
    assert r.content[0]["text"] == "ping"


def test_binary_content_never_travels() -> None:
    """§5.3: binary never travels in v1."""
    r = conform_result(
        {"content": [{"type": "image", "data": "AAAA"}], "isError": False},
    )
    assert r.ok is False
    assert r.code == "error"
    assert "binary transfer is not available yet" in (r.reason or "")


def test_oversized_text_is_capped_with_the_stated_marker() -> None:
    """§5.3's 60,000-character cap, marker included, never overshoots it.

    The marker's own length depends on the number it reports, which depends
    on where the cut lands.  ``conform_result`` sizes the marker for the
    worst case up front, so the rendered result — text plus marker — never
    exceeds the cap it announces (previously it landed ~70 characters over).
    """
    r = conform_result(
        {"content": [{"type": "text", "text": "x" * (MAX_RESULT_CHARS + 10)}],
         "isError": False},
    )
    text = r.content[0]["text"]
    assert len(text) <= MAX_RESULT_CHARS
    assert "more characters; use jobs_output to page ..." in text
    assert text.startswith("x")
    assert not text.startswith("x" * MAX_RESULT_CHARS), (
        "the marker must eat into the 60,000-character budget, not sit past it"
    )


@pytest.mark.parametrize("length", [0, 1, MAX_RESULT_CHARS - 1, MAX_RESULT_CHARS,
                                     MAX_RESULT_CHARS + 1, MAX_RESULT_CHARS + 70, 200_000])
def test_cap_text_never_overshoots_the_cap(length: int) -> None:
    """Mutation target for defect 1: reinstating the naive slice-then-append
    overshoots the cap for any length past it.
    """
    assert len(host_mod._cap_text("y" * length)) <= MAX_RESULT_CHARS


def test_a_capped_result_is_a_no_op_under_a_second_capping() -> None:
    """Landing at or under the cap means re-applying the cap changes nothing.

    This is why defect 1 mattered beyond arithmetic: a plugin that capped its
    own output to something over 60,000 would have that marker cut in half by
    a second application of this same function, appending a second, nonsense
    marker.
    """
    capped = host_mod._cap_text("y" * 200_000)
    assert host_mod._cap_text(capped) == capped


def test_reason_never_carries_a_stack_trace_or_a_path() -> None:
    """§5.2: never a stack trace, never an absolute path outside a root."""
    raw = (
        'failed to open C:\\Users\\tester\\secret.txt\n'
        "Traceback (most recent call last):\n"
        '  File "/opt/agent/host.py", line 3, in go\n'
    )
    clean = sanitise_reason(raw)
    assert "\n" not in clean
    assert "Traceback" not in clean
    assert "C:\\Users" not in clean
    assert "secret.txt" not in clean
    assert "<path>" in clean


def test_reason_is_never_over_the_stated_limit() -> None:
    """Mutation target for defect 3: the ellipsis must count toward the cap.

    A naive ``text[:300] + "…"`` lands at 301 characters — one over the limit
    it is meant to enforce.
    """
    clean = sanitise_reason("word " * 1000)
    assert len(clean) == host_mod._REASON_LIMIT
    assert clean.endswith("…")


def test_a_short_reason_is_left_alone() -> None:
    assert sanitise_reason("short message") == "short message"


def test_reason_scrubs_a_bearer_token() -> None:
    """Mutation target for defect 4: §5.2 forbids returning "the token"."""
    leaky = 'adb: failed running curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef"'
    clean = sanitise_reason(leaky)
    assert "eyJhbGciOiJIUzI1NiJ9.abcdef" not in clean
    assert "adb" in clean, "the adb: prefix must survive, not be eaten as a path"


def test_reason_scrubs_a_credential_key_value_pair() -> None:
    clean = sanitise_reason("login failed: password=hunter2fortyTwoWithExtraCharacters")
    assert "hunter2" not in clean


def test_reason_scrubs_a_long_opaque_token_with_no_keyword() -> None:
    token = "a" * 45
    clean = sanitise_reason(f"upload failed: {token}")
    assert token not in clean


def test_credentials_are_scrubbed_before_paths_so_the_keyword_survives() -> None:
    """Ordering matters: the path pattern must not consume ``Authorization:``
    before the credential pattern gets a chance to key on it.
    """
    leaky = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
    clean = sanitise_reason(leaky)
    assert "eyJhbGciOiJIUzI1NiJ9" not in clean
    assert "[redacted]" in clean


def test_the_path_pattern_does_not_eat_a_bare_prefix_like_adb_colon() -> None:
    """Mutation target: the drive-letter alternative needs a non-space tail.

    Without it, ``[A-Za-z]:`` with a zero-length tail matches the bare
    ``adb:`` that begins many device-tool messages, turning "adb: failed to
    install app.apk" into "ad<path> failed to install app.apk" — not the
    plain English §11 item 6 requires.
    """
    clean = sanitise_reason("adb: failed to install app.apk")
    assert "<path>" not in clean
    assert clean == "adb: failed to install app.apk"


def test_a_drive_relative_path_is_still_caught() -> None:
    """The fix narrows the match; it must not stop catching real paths."""
    clean = sanitise_reason("cannot read C:secrets.txt")
    assert "<path>" in clean
    assert "secrets.txt" not in clean


def test_strip_special_tokens_withholds_content_that_never_converges() -> None:
    """Mutation target for defect 2: exhaustion must be a refusal.

    Forty levels of nesting outlast the 8-pass budget, so the naive
    implementation returns partially-stripped text that still contains a
    special token. The fix must detect that and withhold instead.
    """
    deep = "<|im_" * 40 + "start" + "|>" * 40
    out = strip_special_tokens(deep)
    assert out == host_mod._UNSTRIPPABLE
    assert not host_mod._ANGLE_PIPE_TOKEN.search(out)


def test_strip_special_tokens_still_returns_normally_when_it_converges_in_time() -> None:
    """Exhaustion alone is not the failure; surviving tokens are.

    Text that needs exactly the pass budget must come back stripped, not
    withheld, or the refusal fires on legitimate content.
    """
    nested = "<|im_" * 4 + "start" + "|>" * 4
    out = strip_special_tokens(nested)
    assert out != host_mod._UNSTRIPPABLE
    assert not host_mod._ANGLE_PIPE_TOKEN.search(out)


# ---------------------------------------------------------------------------
# Session plumbing (what B3 builds on)
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_audit_db(tmp_path):
    audit_mod.set_db_path(tmp_path / "audit.db")
    yield tmp_path / "audit.db"
    audit_mod.reset_connection()


def test_evaluate_accepts_a_session_without_changing_its_verdict() -> None:
    """B2 plumbs the identity; it does not yet let it change a decision.

    (B3 adds the remembering on top.  Pinning "same verdict with and without"
    now means a later change that lets a session id *loosen* a decision has
    to break this test deliberately rather than by accident.)"""
    session = SessionContext(session_id="sess-42", transport="named_pipe", request_id="7")
    args = {"path": "/elsewhere/x"}
    without = evaluate_detailed(_fs_manifest(), "filesystem.read", args, _GRANTED)
    with_session = evaluate_detailed(
        _fs_manifest(), "filesystem.read", args, _GRANTED, session=session,
    )
    assert without.decision == with_session.decision == "deny"


@pytest.mark.asyncio
async def test_invoke_plumbs_the_session_into_evaluate_and_the_audit_row(
    isolated_audit_db, monkeypatch,
) -> None:
    """End to end: transport session id → evaluator → §5.7 audit row."""
    seen: list[SessionContext | None] = []
    real = host_mod.evaluate_detailed

    def _spy(*args, **kwargs):
        seen.append(kwargs.get("session"))
        return real(*args, **kwargs)

    monkeypatch.setattr(host_mod, "evaluate_detailed", _spy)

    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    manifest = _fs_manifest(plugin_id="sess_plugin")
    manifest.declared_permissions = [
        "tool:sess_plugin.read",
        "path:/roots/documents",
        "args:sess_plugin.read:read:!path=ws_path",
    ]
    runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "sess_plugin.read"}],
        granted_permissions={"tool:sess_plugin.read"},
        client=client,
    )

    h = MCPHost()
    h._runtimes["sess_plugin"] = runtime

    session = SessionContext(session_id="sess-42", transport="named_pipe", request_id="7")
    result = await h.invoke("sess_plugin.read", {"path": "/roots/documents/a"}, session=session)

    assert result.ok is True
    assert len(seen) == 1
    assert seen[0] is session

    rows = audit_mod.query(audit_mod.AuditQuery(session_id="sess-42"), db_path=isolated_audit_db)
    assert len(rows) == 1
    assert rows[0].request_id == "7"
    assert rows[0].duration_ms is not None


@pytest.mark.asyncio
async def test_invoke_without_a_session_still_works(isolated_audit_db) -> None:
    """In-process callers need not invent a session id."""
    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    manifest = _fs_manifest(plugin_id="nosess")
    manifest.declared_permissions = [
        "tool:nosess.read",
        "path:/roots/documents",
        "args:nosess.read:read:!path=ws_path",
    ]
    runtime = host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": "nosess.read"}],
        granted_permissions={"tool:nosess.read"},
        client=client,
    )
    h = MCPHost()
    h._runtimes["nosess"] = runtime

    result = await h.invoke("nosess.read", {"path": "/roots/documents/a"})
    assert result.ok is True

    rows = audit_mod.query(audit_mod.AuditQuery(event="tool_invoke"), db_path=isolated_audit_db)
    assert rows[0].session_id is None
    assert rows[0].duration_ms is not None
