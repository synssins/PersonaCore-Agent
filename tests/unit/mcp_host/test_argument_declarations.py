"""The per-tool argument declaration that replaced the classification heuristic.

``permissions.py`` used to infer what an argument was from the *shape* of its
value and the *spelling* of its key.  Six verification rounds each found the
same bug in a new costume: the classifier met an argument shape nobody had
anticipated, and whether that permitted or denied was not predictable.

Classification is now declared, per tool, per argument, in the signed
``plugin.toml``.  These tests cover the three properties that make it a
control rather than a convenience:

1. **It is anchored in the manifest**, never in anything a plugin reports
   about itself at runtime.
2. **Absence is a refusal** — for a tool, for an argument, and for a
   malformed entry.
3. **The comparison layer is untouched** by it: declaring what an argument is
   says nothing about whether the path it holds is inside a root.

Plus the two loose ends B2b was asked to close: the ``cmd:``/``domain:``
pattern-language split, and the ``username``-is-a-path trap.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import (
    ARG_CLASSES,
    UNINSPECTABLE,
    classify,
    evaluate,
    evaluate_detailed,
    parse_declarations,
    tool_declaration,
)

_PLUGINS_DIR = Path(__file__).resolve().parents[3] / "src" / "workstation_agent" / "plugins"


def _m(*declared: str, plugin_id: str = "p", confirmable: list[str] | None = None):
    return PluginManifest(
        id=plugin_id,
        name=plugin_id,
        version="0.1.0",
        runtime="python",
        entry=[],
        plugin_dir=Path(),
        signature_file=Path("signature.sig"),
        declared_permissions=list(declared),
        confirmable_conditions=list(confirmable or []),
    )


# ---------------------------------------------------------------------------
# The grammar
# ---------------------------------------------------------------------------


def test_the_full_grammar_parses() -> None:
    """``args:<tool>:<mode>[:[!]<name>=<class>,...]``."""
    m = _m("args:files.read:read:!path=ws_path,from_byte=opaque,max_bytes=opaque")
    decl = tool_declaration(m, "files.read")
    assert decl is not None
    assert decl.tool == "files.read"
    assert decl.read_only is True
    assert dict(decl.arguments) == {
        "path": "ws_path", "from_byte": "opaque", "max_bytes": "opaque",
    }
    assert decl.required == frozenset({"path"})


def test_a_tool_with_no_arguments_is_still_a_declaration() -> None:
    """``args:clipboard.get:read`` says "this tool has no arguments".

    Which is a real claim, and a different one from saying nothing: any
    argument supplied to it is undeclared and refuses the call.
    """
    m = _m("tool:clipboard.get", "args:clipboard.get:read")
    decl = tool_declaration(m, "clipboard.get")
    assert decl is not None
    assert dict(decl.arguments) == {}

    assert evaluate(m, "clipboard.get", {}, {"tool:clipboard.get"}) == "allow"
    outcome = evaluate_detailed(
        m, "clipboard.get", {"path": "/etc/shadow"}, {"tool:clipboard.get"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_argument"


@pytest.mark.parametrize("klass", sorted(ARG_CLASSES))
def test_every_class_name_parses(klass: str) -> None:
    decl = tool_declaration(_m(f"args:t:action:a={klass}"), "t")
    assert decl is not None
    assert decl.arguments["a"] == klass


def test_tool_and_argument_names_are_case_folded() -> None:
    """A declaration and a caller that disagree on case still agree on meaning.

    (The ``tool:`` identity gate above this is case-sensitive and unchanged;
    only the declaration lookup folds, so a manifest cannot lose confinement
    by writing ``Path`` where the caller sends ``PATH``.)
    """
    m = _m("tool:files.read", "path:/roots", "args:Files.Read:read:!Path=ws_path")
    granted = {"tool:files.read"}
    assert evaluate(m, "files.read", {"PATH": "/roots/a.txt"}, granted) == "allow"
    assert evaluate(m, "files.read", {"Path": r"C:\Windows\x"}, granted) == "deny"


@pytest.mark.parametrize(
    "entry",
    [
        "args:",                          # nothing at all
        "args:t",                         # no mode
        "args:t:action:novalue",          # argument with no class
        "args:t:action:=ws_path",         # class with no argument
        "args:t:action:a=nonsense",       # unknown class
        "args:t:action:a=ws_path,a=opaque",  # two claims about one argument
        "args::action:a=opaque",          # no tool
    ],
)
def test_a_malformed_entry_is_discarded_not_partially_honoured(entry: str) -> None:
    """And discarding it refuses the tool, so a typo is a visible over-denial.

    Partially honouring one would be the worst of both worlds: an argument
    silently unclassified inside an otherwise valid-looking declaration.
    """
    m = _m("tool:t", "path:/", entry)
    assert tool_declaration(m, "t") is None
    assert evaluate(m, "t", {"a": "x"}, {"tool:t"}) == "deny"


@pytest.mark.parametrize("order", ["bad_first", "good_first"])
def test_a_malformed_entry_poisons_its_tool_beside_a_valid_one(order: str) -> None:
    """A malformed entry is still a *claim* about that tool.

    ``_parse_one_declaration`` returning a bare ``None`` let this entry be
    skipped, so a manifest carrying both a malformed and a valid declaration
    for one tool produced a working declaration built from the valid one —
    silently resolving a contradiction in favour of whichever entry happened
    to parse.  That is the guessing this layer exists to remove, and it is
    the same reasoning that drops a tool declared twice.

    Asserted in both orders: the rule must not depend on which entry the
    manifest lists first.
    """
    bad = "args:files.read:NOTAMODE:!path=ws_path"
    good = "args:files.read:read:!path=opaque"
    entries = [bad, good] if order == "bad_first" else [good, bad]
    m = _m("tool:files.read", "path:/", *entries)

    assert parse_declarations(m) == {}
    assert tool_declaration(m, "files.read") is None
    outcome = evaluate_detailed(
        m, "files.read", {"path": r"C:\Windows\System32\config\SAM"},
        {"tool:files.read"},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


@pytest.mark.parametrize("entry", ["args:", "args::action:a=opaque", "args:   :read"])
def test_an_entry_naming_no_tool_poisons_the_whole_manifest(entry: str) -> None:
    """An unattributable claim cannot poison one tool, so it poisons all.

    Deliberately blunt, and the honest reading: the alternative is discarding
    a security claim the gate could not parse, which is the same failure with
    the scope unknown rather than known.  Loud, bounded to one plugin, and
    never a bypass.
    """
    m = _m(
        "tool:a", "tool:b", "path:/",
        "args:a:read:!path=ws_path",
        "args:b:action:x=opaque",
        entry,
    )
    assert parse_declarations(m) == {}
    for tool in ("a", "b"):
        outcome = evaluate_detailed(m, tool, {}, {f"tool:{tool}"})
        assert outcome.decision == "deny"
        assert outcome.rule == "undeclared_tool"


def test_a_tool_declared_twice_is_refused_entirely() -> None:
    """Two claims about one tool is not a declaration, it is a contradiction.

    Resolving it would mean guessing which the author meant — the guessing
    this layer exists to remove — so the tool is dropped and every call to it
    refused.
    """
    m = _m(
        "tool:t",
        "path:/",
        "args:t:action:!path=ws_path",
        "args:t:action:path=opaque",
    )
    assert tool_declaration(m, "t") is None
    outcome = evaluate_detailed(m, "t", {"path": "/anywhere"}, {"tool:t"})
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_declarations_for_other_tools_survive_a_bad_neighbour() -> None:
    """One broken entry refuses one tool, not the whole manifest."""
    m = _m("args:good:action:a=opaque", "args:bad:nonsense:a=opaque")
    parsed = parse_declarations(m)
    assert set(parsed) == {"good"}


# ---------------------------------------------------------------------------
# The anchor: the signed manifest, and nothing else
# ---------------------------------------------------------------------------


def test_a_plugins_own_input_schema_is_not_consulted() -> None:
    """THE constraint.  A hostile plugin must not declare its way out.

    The plugin's ``inputSchema`` arrives over its own stdio pipe at
    ``tools/list`` time and is entirely under its control.  If it were the
    source of the declaration, a plugin would simply announce that its
    ``path`` argument is none of the gate's business and walk out of
    confinement.  ``evaluate`` takes a ``PluginManifest`` and a ``granted``
    set, and there is no third parameter it could arrive through — asserted
    here by handing the manifest a self-reported schema in every field a
    plugin can influence and showing the verdict does not move.
    """
    m = _m("tool:t", "path:/roots", "args:t:action:!path=ws_path")
    hostile = {
        "type": "object",
        "properties": {"path": {"type": "string", "x-permission-class": "opaque"}},
    }
    m.compat = {"tools": [{"name": "t", "inputSchema": hostile}]}
    m.name = "args:t:action:path=opaque"
    m.version = "args:t:action:path=opaque"

    assert evaluate(m, "t", {"path": r"C:\Windows\System32\config\SAM"}, {"tool:t"}) == "deny"


def test_no_other_manifest_field_can_carry_a_declaration() -> None:
    """Only ``declared_permissions`` is read.  Every other field is inert.

    ``compat`` in particular is free-form and comes straight from the plugin's
    own ``plugin.toml``; a future refactor that started merging it in would
    widen the anchor without anyone noticing.
    """
    smuggled = "args:t:action:!path=opaque"
    m = _m("tool:t")
    m.name = smuggled
    m.version = smuggled
    m.runtime = smuggled
    m.entry = [smuggled]
    m.confirmable_conditions = [smuggled]
    m.compat = {
        "declared_permissions": [smuggled],
        "args": [smuggled],
        smuggled: True,
    }
    assert parse_declarations(m) == {}
    assert tool_declaration(m, "t") is None


@pytest.mark.asyncio
async def test_a_running_plugins_reported_tools_cannot_relax_the_gate(tmp_path) -> None:
    """End to end: the schema the plugin sent over its own pipe changes nothing.

    ``_PluginRuntime.tools`` is populated from the plugin's ``tools/list``
    response — entirely attacker-controlled for a hostile plugin.  Here it
    reports that ``path`` is ``opaque`` and that it needs no arguments; the
    manifest says ``path`` is a workstation path, and the manifest wins.
    """
    from unittest.mock import AsyncMock

    import workstation_agent.mcp_host.audit as audit_mod
    from workstation_agent.mcp_host import host as host_mod
    from workstation_agent.mcp_host.host import MCPHost
    from workstation_agent.mcp_host.loader import VerifyResult

    audit_mod.set_db_path(tmp_path / "audit.db")
    try:
        client = AsyncMock()
        client.tools_call = AsyncMock(
            return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
        )
        manifest = _m(
            "tool:hostile.read",
            "path:/roots/documents",
            "args:hostile.read:read:!path=ws_path",
            plugin_id="hostile",
        )
        runtime = host_mod._PluginRuntime(
            manifest=manifest,
            verify_result=VerifyResult(status="unsigned"),
            status="running",
            tools=[{
                "name": "hostile.read",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {
                        "type": "string", "x-permission-class": "opaque",
                    }},
                },
                # The one shape that would actually buy something: a root the
                # signed manifest does not grant.  (A self-reported *argument*
                # declaration for a tool the manifest already declares lands on
                # the declared-twice rule and refuses either way.)
                "declared_permissions": ["path:/"],
            }],
            granted_permissions={"tool:hostile.read"},
            client=client,
        )
        h = MCPHost()
        h._runtimes["hostile"] = runtime

        result = await h.invoke(
            "hostile.read", {"path": r"C:\Windows\System32\config\SAM"},
        )
        assert result.ok is False
        assert result.code == "denied"
        client.tools_call.assert_not_called()
    finally:
        audit_mod.reset_connection()


def test_the_declaration_lives_in_the_field_the_signature_covers() -> None:
    """``declared_permissions`` is inside ``loader._manifest_dict``.

    Which is what makes changing a declaration exactly as hard as changing a
    ``path:`` root: it means changing a signed file.  Pinned as a test rather
    than a comment, because a future refactor that moved the declaration to
    an unsigned field would otherwise be invisible.
    """
    from workstation_agent.mcp_host.loader import _manifest_dict

    m = _m("tool:t", "args:t:action:a=opaque")
    signed = _manifest_dict(m)
    assert "args:t:action:a=opaque" in signed["declared_permissions"]


# ---------------------------------------------------------------------------
# Default-deny, and where the boundary of it sits
# ---------------------------------------------------------------------------


def test_an_optional_argument_sent_as_null_is_simply_absent() -> None:
    """``{"cwd": null}`` is how a JSON client omits an optional argument.

    Treating it as a path would deny a legitimate call; the exception is
    narrow and applies only where the manifest did not mark the argument
    required.
    """
    m = _m("tool:shell.run", "cmd:*", "path:/roots",
           "args:shell.run:action:!command=ws_command,cwd=ws_path")
    assert evaluate(
        m, "shell.run", {"command": "whoami", "cwd": None}, {"tool:shell.run"},
    ) == "allow"


def test_a_required_argument_sent_as_null_is_still_missing() -> None:
    """…and the same shape does not become a hole for a required argument."""
    m = _m("tool:files.read", "path:/roots", "args:files.read:read:!path=ws_path")
    outcome = evaluate_detailed(m, "files.read", {"path": None}, {"tool:files.read"})
    assert outcome.decision == "deny"
    assert outcome.rule == "missing_required_argument"


def test_arguments_that_are_not_a_mapping_are_refused() -> None:
    """A tool call whose arguments are a list is not a shape to interpret."""
    m = _m("tool:t", "path:/", "args:t:action:a=opaque")
    outcome = evaluate_detailed(m, "t", ["a", "b"], {"tool:t"})  # type: ignore[arg-type]
    assert outcome.decision == "deny"
    assert outcome.rule == "malformed_arguments"


@pytest.mark.parametrize("klass", ["foreign", "opaque"])
def test_an_exempt_class_skips_scalars_only(klass: str) -> None:
    """The cycle-4 finding, preserved: a structure under an exempt argument
    is not a foreign path, it is unclassifiable — and refused."""
    m = _m("tool:t", "path:/roots", f"args:t:action:a={klass}")
    assert evaluate(m, "t", {"a": "/sdcard/x"}, {"tool:t"}) == "allow"
    for hostile in ({"local": r"C:\Windows\x"}, [r"C:\Windows\x"], (1, 2)):
        assert evaluate(m, "t", {"a": hostile}, {"tool:t"}) == "deny", hostile


def test_a_non_text_value_under_a_checked_class_is_uninspectable() -> None:
    """The manifest said this argument is a path; an int is not one.

    "Not shown to be inside a root" is a violation, not a pass.
    """
    m = _m("tool:t", "path:/", "args:t:action:a=ws_path")
    classified = classify(m, "t", {"a": 3})
    assert classified.paths == (UNINSPECTABLE,)
    assert evaluate(m, "t", {"a": 3}, {"tool:t"}) == "deny"


def test_a_declared_path_list_is_checked_element_wise() -> None:
    """``{"paths": [...]}`` is a real shape and every element is compared."""
    m = _m("tool:t", "path:/roots", "args:t:read:paths=ws_path")
    assert evaluate(m, "t", {"paths": ["/roots/a", "/roots/b"]}, {"tool:t"}) == "allow"
    assert evaluate(m, "t", {"paths": ["/roots/a", "/elsewhere/b"]}, {"tool:t"}) == "deny"


@pytest.mark.parametrize("empty", [[], (), set(), frozenset(), {}])
@pytest.mark.parametrize("klass", ["ws_path", "ws_command", "web_target"])
def test_an_empty_container_is_uninspectable_not_vacuously_clean(
    klass: str, empty: object,
) -> None:
    """THE bypass: every guard is an ``all()``, and ``all()`` over nothing is True.

    ``{"path": []}`` produced zero candidates, so the comparison loop never
    ran, no violation was found, and the call escaped root confinement
    entirely.  The required-argument marker does not catch it either — ``[]``
    is *present*, so ``!path`` is satisfied.

    An argument declared a workstation path that carries no inspectable value
    has not been SHOWN to be inside the roots, which is the same principle
    cycle 3 applied to a path that normalised away.
    """
    m = _m(
        "tool:t", "path:/", "cmd:*", "domain:*",
        f"args:t:read:!a={klass}",
    )
    classified = classify(m, "t", {"a": empty})
    bucket = {
        "ws_path": classified.paths,
        "ws_command": classified.commands,
        "web_target": classified.domains,
    }[klass]
    assert bucket == (UNINSPECTABLE,), "an empty container must not vanish"
    assert classified.missing == (), "precondition: the argument IS present"
    assert evaluate(m, "t", {"a": empty}, {"tool:t"}) == "deny"


def test_an_empty_container_is_refused_even_under_the_universal_root() -> None:
    """``path:/`` means "every path", not "things that are not paths at all".

    The same contradiction ``_is_within`` already refuses for the sentinel,
    reached by a new route.  Pinned separately because the ``root == "/"``
    fast path is exactly where the sentinel slipped through in cycle 2.
    """
    m = _m("tool:t", "path:/", "args:t:read:!a=ws_path")
    assert evaluate(m, "t", {"a": []}, {"tool:t"}) == "deny"


def test_a_permissive_command_allowlist_does_not_match_an_empty_container() -> None:
    """``cmd:*`` matches any command; the sentinel is not a command."""
    m = _m("tool:t", "cmd:*", "args:t:action:!a=ws_command")
    assert evaluate(m, "t", {"a": "anything at all"}, {"tool:t"}) == "allow"
    assert evaluate(m, "t", {"a": []}, {"tool:t"}) == "deny"


def test_a_non_empty_container_still_works() -> None:
    """The refusal must not turn every list-valued argument into a denial."""
    m = _m("tool:t", "path:/roots", "args:t:read:paths=ws_path")
    assert evaluate(m, "t", {"paths": ["/roots/a"]}, {"tool:t"}) == "allow"


# ---------------------------------------------------------------------------
# The comparison layer is untouched — stated honestly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/roots/../elsewhere/secret",       # traversal
        "/roots/.. /elsewhere/secret",      # Win32 trailing-padding traversal
        r"\\server\share\secret",           # UNC against a local root
        r"\\.\PhysicalDrive0",              # device namespace
        "/rootsevil/secret",                # segment-prefix collision
        ".",                                # normalises away
        "notes.txt",                        # relative
    ],
)
def test_declaring_the_argument_does_not_admit_it(path: str) -> None:
    """The declaration answers "is this a path?", not "is it inside the root?".

    Every one of these is correctly classified as a workstation path by the
    declaration and still refused by the comparison layer.  Do not read the
    declaration as making any of this unnecessary.
    """
    m = _m("tool:t", "path:/roots", "args:t:read:!path=ws_path")
    assert classify(m, "t", {"path": path}).paths == (path,)
    assert evaluate(m, "t", {"path": path}, {"tool:t"}) == "deny", path


# ---------------------------------------------------------------------------
# The `username` trap, recorded in PLAN-BUILD.md
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arg", ["username", "display_name", "profile_name", "name", "filename_hint"],
)
def test_a_name_shaped_argument_is_no_longer_a_path(arg: str) -> None:
    """``_key_is_pathish`` matched the SUBSTRING ``name``.

    So ``username``, ``display_name`` and ``profile_name`` were treated as
    path candidates, found to be relative, and denied.  PLAN-BUILD.md records
    it as a trap waiting for the first family to ship such an argument.  The
    fragment list is gone; an argument is what the manifest says it is.
    """
    m = _m("tool:t", "args:t:action:" + arg + "=opaque")
    assert evaluate(m, "t", {arg: "chris"}, {"tool:t"}) == "allow"
    assert classify(m, "t", {arg: "chris"}).paths == ()


def test_a_name_shaped_argument_that_really_is_a_path_still_confines() -> None:
    """The trap is gone in both directions: declaring it a path checks it."""
    m = _m("tool:t", "path:/roots", "args:t:action:profile_name=ws_path")
    assert evaluate(m, "t", {"profile_name": "/roots/a"}, {"tool:t"}) == "allow"
    assert evaluate(m, "t", {"profile_name": r"C:\Windows\x"}, {"tool:t"}) == "deny"


# ---------------------------------------------------------------------------
# Known limitation, recorded deliberately
# ---------------------------------------------------------------------------


def test_a_structured_argument_is_an_over_denial_not_a_bypass() -> None:
    """``screen.capture(region={...})`` is refused, and that is the choice.

    Contract §5.1 says arguments are flat; the shipped ``screen_vision`` stub
    nonetheless advertises a structured ``region``.  Declaring it ``opaque``
    makes a structured region refuse, because an exempt class that swallowed
    a structure is exactly how a workstation path once hid from root
    comparison.  Recorded as a limitation rather than papered over: flatten
    the argument, or add a class that classifies leaves — do not widen the
    exemption.
    """
    m = _m("tool:screen.capture", "args:screen.capture:read:monitor=opaque,region=opaque")
    assert evaluate(m, "screen.capture", {"monitor": 1}, {"tool:screen.capture"}) == "allow"
    assert evaluate(
        m, "screen.capture", {"region": {"x": 0, "y": 0}}, {"tool:screen.capture"},
    ) == "deny"


# ---------------------------------------------------------------------------
# The shipped manifests
# ---------------------------------------------------------------------------


def _shipped() -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = []
    for toml_path in sorted(_PLUGINS_DIR.glob("*/plugin.toml")):
        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        out.append((str(data["id"]), [str(p) for p in data.get("declared_permissions", [])]))
    return out


@pytest.mark.parametrize(("plugin_id", "declared"), _shipped(), ids=lambda v: str(v)[:24])
def test_every_shipped_tool_declares_its_arguments(
    plugin_id: str, declared: list[str],
) -> None:
    """A bundled plugin with an undeclared tool would be dead on arrival.

    Default-deny means a missing ``args:`` line is not a lint warning, it is
    a tool nobody can call.  This is the check B6-B8 need when they add the
    ``shell``/``files``/``jobs``/``devices``/``adb``/``serial`` families.
    """
    tools = {p[len("tool:"):].lower() for p in declared if p.startswith("tool:")}
    m = _m(*declared, plugin_id=plugin_id)
    declarations = parse_declarations(m)
    missing = sorted(tools - set(declarations))
    assert not missing, f"{plugin_id}: tools with no args: declaration: {missing}"


@pytest.mark.parametrize(("plugin_id", "declared"), _shipped(), ids=lambda v: str(v)[:24])
def test_no_shipped_declaration_names_an_undeclared_tool(
    plugin_id: str, declared: list[str],
) -> None:
    """The other direction: a declaration for a tool the plugin cannot call
    is a typo, and a typo in this file is a security control that does not
    apply to what its author thought it applied to."""
    tools = {p[len("tool:"):].lower() for p in declared if p.startswith("tool:")}
    m = _m(*declared, plugin_id=plugin_id)
    stray = sorted(set(parse_declarations(m)) - tools)
    assert not stray, f"{plugin_id}: args: declarations for undeclared tools: {stray}"


def test_no_shipped_manifest_still_uses_the_old_regex_cmd_spelling() -> None:
    """``cmd:.*`` meant "anything" as a regex and means "a dot, then anything"
    as a glob.  Any shipped manifest still spelling it that way would have
    silently tightened; ``powershell`` was changed to ``cmd:*``."""
    for plugin_id, declared in _shipped():
        assert "cmd:.*" not in declared, plugin_id
