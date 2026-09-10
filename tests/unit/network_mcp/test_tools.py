"""The static families-only allowlist: contract §2 names and what may not leak."""
# ruff: noqa: N812
# `T` is the tool table under test; every assertion reads T.<thing>.

from __future__ import annotations

import json

import pytest

from workstation_agent.network_mcp import tools as T

# Contract §6's v1 families and tools, transcribed independently of the module
# under test so a typo in one is not silently agreed with by the other.
CONTRACT_V1_TOOLS = {
    "workstation_status",
    "devices_list",
    "shell_run",
    "files_list", "files_read", "files_write",
    "jobs_wait", "jobs_output", "jobs_list", "jobs_kill",
    "adb_devices", "adb_shell", "adb_push", "adb_pull", "adb_install", "adb_logcat",
    "serial_ports", "serial_open", "serial_write", "serial_read", "serial_close",
}

# Every tool the Agent exposes locally that must NEVER reach the LAN: the
# agent.* internals plus the families contract §10 defers to v2/v3.
MUST_NOT_BE_SERVED_PREFIXES = (
    "agent", "agent_",
    "screen", "screen_",
    "clipboard", "clipboard_",
    "desktop", "desktop_",
    "browser", "browser_",
    "powershell", "powershell_",
    "filesystem", "filesystem_",
    "claude_code", "hello_world",
)


def test_served_set_is_exactly_contract_section_6():
    assert set(T.served_tool_names()) == CONTRACT_V1_TOOLS


def test_no_contract_violations_in_the_table():
    assert T.validate_tool_names() == []


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_every_name_matches_the_manifest_pattern_after_translation(tool):
    """Contract §2: ``^[a-z][a-z0-9-]{1,63}$`` after ``_`` -> ``-``, no dots."""
    assert "." not in tool.name
    assert T.TOOL_NAME_PATTERN.match(tool.manifest_name), tool.manifest_name
    assert len(tool.manifest_name) <= 64


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_internal_name_is_family_dot_verb(tool):
    """The Agent's internal id is ``family.verb``; the wire name is ``family_verb``."""
    family, _, verb = tool.internal_name.partition(".")
    assert family == tool.family
    assert verb
    assert tool.name == f"{family}_{verb}"


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_every_argument_has_a_description(tool):
    """§5.1: arguments are a flat object and every argument has a description."""
    schema = tool.input_schema
    assert schema["type"] == "object"
    for name, prop in schema["properties"].items():
        assert prop.get("description"), f"{tool.name}.{name} has no description"
        assert prop.get("type") != "object", f"{tool.name}.{name} is not flat"
    for required in schema.get("required", []):
        assert required in schema["properties"]


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_boolean_arguments_default_to_the_safe_value(tool):
    """§5.1: booleans default to the safe value."""
    for name, prop in tool.input_schema["properties"].items():
        if prop.get("type") == "boolean":
            assert prop.get("default") is False, f"{tool.name}.{name} defaults to true"


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_every_tool_is_declared_safe(tool):
    """Contract §4: the core cannot prompt, so the Agent is the gate."""
    assert tool.risk == "safe"


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_json_schema_round_trips(tool):
    """B5 writes these into the registration; they must round-trip."""
    schema = tool.json_schema()
    assert json.loads(json.dumps(schema)) == schema


@pytest.mark.parametrize("forbidden", MUST_NOT_BE_SERVED_PREFIXES)
def test_internal_and_deferred_families_are_never_served(forbidden):
    for name in T.served_tool_names():
        assert not name.startswith(forbidden), f"{name!r} must not be on the LAN"
    for tool in T.SERVED_TOOLS:
        assert not tool.internal_name.startswith(forbidden + ".")


def test_served_families_are_exactly_the_contract_families():
    assert set(T.SERVED_FAMILIES) == {
        "workstation", "devices", "shell", "files", "jobs", "adb", "serial",
    }


def test_names_are_unique_and_the_index_agrees_with_the_table():
    names = T.served_tool_names()
    assert len(names) == len(set(names))
    assert set(T.SERVED_TOOLS_BY_NAME) == set(names)
    assert all(T.SERVED_TOOLS_BY_NAME[n].name == n for n in names)


# ---------------------------------------------------------------------------
# Immutability. Each of these asserts the mutation RAISES, not merely that the
# module does not perform it: the threat is other in-process code, so "we did
# not do it" is not the property that matters.
# ---------------------------------------------------------------------------


def test_the_table_is_immutable():
    """The served set must not be mutable at runtime — that is the whole point."""
    assert isinstance(T.SERVED_TOOLS, tuple)
    with pytest.raises((AttributeError, TypeError)):
        T.SERVED_TOOLS[0].name = "hacked"  # type: ignore[misc]
    with pytest.raises(TypeError):
        T.SERVED_TOOLS[0] = T.SERVED_TOOLS[1]  # type: ignore[index]


def test_the_name_index_cannot_have_a_tool_added_to_it():
    """The served-set/registration drift this would cause is terminal on the core.

    ``_invoke`` resolves through this index while B5 exports from the frozen
    tuple, so a writeable index would put a tool on the LAN that the manifest
    never mentions.
    """
    smuggled = T.ServedTool(
        name="agent_speak",
        internal_name="agent.speak",
        family="agent",
        description="not for the LAN",
        input_schema={},
    )
    with pytest.raises(TypeError):
        T.SERVED_TOOLS_BY_NAME["agent_speak"] = smuggled  # type: ignore[index]
    with pytest.raises(TypeError):
        del T.SERVED_TOOLS_BY_NAME["files_read"]  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        T.SERVED_TOOLS_BY_NAME.clear()  # type: ignore[attr-defined]
    assert "agent_speak" not in T.SERVED_TOOLS_BY_NAME
    assert set(T.SERVED_TOOLS_BY_NAME) == set(T.served_tool_names())


@pytest.mark.parametrize("tool", T.SERVED_TOOLS, ids=lambda t: t.name)
def test_a_served_schema_cannot_be_edited_in_place(tool):
    with pytest.raises(TypeError):
        tool.input_schema["type"] = "hacked"  # type: ignore[index]
    for prop in tool.input_schema["properties"].values():
        with pytest.raises(TypeError):
            prop["description"] = "hacked"
    if "required" in tool.input_schema:
        assert isinstance(tool.input_schema["required"], tuple)
        with pytest.raises(TypeError):
            tool.input_schema["required"][0] = "hacked"  # type: ignore[index]


@pytest.mark.parametrize(
    "fragment",
    [T._PATH, T._WAIT_S, T._JOB_ID, T._SESSION_ID, T._ADB_SERIAL],
)
def test_the_shared_property_fragments_cannot_be_edited(fragment):
    """One of these appears in four tools; editing it would rewrite all four."""
    with pytest.raises(TypeError):
        fragment["description"] = "hacked"


def test_editing_one_tools_schema_copy_cannot_reach_another_tool():
    """The classic shared-reference bug, asserted directly."""
    runner = T.SERVED_TOOLS_BY_NAME["shell_run"]
    waiter = T.SERVED_TOOLS_BY_NAME["jobs_wait"]
    assert runner.input_schema["properties"]["wait_s"]["maximum"] == 25
    assert waiter.input_schema["properties"]["wait_s"]["maximum"] == 25

    copy = runner.json_schema()
    copy["properties"]["wait_s"]["maximum"] = 9999
    assert runner.input_schema["properties"]["wait_s"]["maximum"] == 25
    assert waiter.input_schema["properties"]["wait_s"]["maximum"] == 25
    assert runner.json_schema()["properties"]["wait_s"]["maximum"] == 25


def test_json_schema_hands_out_a_new_object_every_call():
    tool = T.SERVED_TOOLS[0]
    assert tool.json_schema() is not tool.json_schema()
    assert tool.json_schema() == tool.json_schema()


# ---------------------------------------------------------------------------
# The §2 name rules, and the guard that enforces them
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("files-read\n", id="trailing-newline"),
        pytest.param("files-read\r\n", id="trailing-crlf"),
        pytest.param("\nfiles-read", id="leading-newline"),
        pytest.param("files-read\nrm -rf", id="embedded-newline"),
    ],
)
def test_the_name_pattern_rejects_newlines(name):
    """``$`` also matches before a trailing newline; ``\\Z`` does not.

    A name that passes our regex and fails the core's is a terminal load failure
    (contract §2), so the two must not disagree about what "end of string" means.
    """
    assert T.TOOL_NAME_PATTERN.match(name) is None


@pytest.mark.parametrize(
    "name",
    ["files-read", "ab", "a" + "b" * 63, "workstation-status", "adb-logcat"],
)
def test_the_name_pattern_accepts_legal_names(name):
    assert T.TOOL_NAME_PATTERN.match(name) is not None


@pytest.mark.parametrize(
    "name",
    ["a", "Files-read", "files_read", "1files", "files.read", "files read", "a" * 65, ""],
)
def test_the_name_pattern_rejects_illegal_names(name):
    assert T.TOOL_NAME_PATTERN.match(name) is None


def _problems_with(*extra: T.ServedTool) -> list[str]:
    """Run the validator over the real table plus *extra*."""
    original = T.SERVED_TOOLS
    try:
        T.SERVED_TOOLS = (*original, *extra)  # type: ignore[misc]
        return T.validate_tool_names()
    finally:
        T.SERVED_TOOLS = original  # type: ignore[misc]


def test_validate_tool_names_actually_detects_a_violation():
    """A guard that cannot fail is not a guard."""
    bad = T.ServedTool(
        name="Bad.Name",
        internal_name="wrong",
        family="other",
        description="x",
        input_schema={},
        risk="restricted",
    )
    problems = _problems_with(bad)
    assert any("dot" in p for p in problems)
    assert any("does not match" in p for p in problems)
    assert any("family.verb" in p for p in problems)
    assert any("risk" in p for p in problems)


def test_a_mistranslated_name_is_caught():
    """``name`` and ``internal_name`` are written separately; they can disagree.

    Everything else about this entry is legal: the name matches §2's pattern, the
    internal name is a well-formed ``family.verb`` whose family matches, and the
    risk is ``safe``. Only the translation is wrong — which would route one
    tool's calls to another tool's implementation.
    """
    mistranslated = T.ServedTool(
        name="custom_name",
        internal_name="custom.other",
        family="custom",
        description="x",
        input_schema={},
    )
    problems = _problems_with(mistranslated)
    assert any("is not the §2 translation" in p for p in problems), problems
    assert any("custom_other" in p for p in problems), problems


def test_a_name_that_only_collides_after_translation_is_caught():
    """``my_tool`` and ``my-tool`` are distinct wire names, one manifest name."""
    underscore = T.ServedTool(
        name="mine_tool", internal_name="mine.tool", family="mine",
        description="x", input_schema={},
    )
    hyphen = T.ServedTool(
        name="mine-tool", internal_name="mine.tool", family="mine",
        description="x", input_schema={},
    )
    assert underscore.name != hyphen.name
    assert underscore.manifest_name == hyphen.manifest_name

    problems = _problems_with(underscore, hyphen)
    assert any("duplicate manifest name" in p for p in problems), problems


def test_a_duplicate_wire_name_is_still_caught():
    twin = T.SERVED_TOOLS[0]
    assert any("duplicate served name" in p for p in _problems_with(twin))


def test_a_trailing_newline_in_a_name_is_caught_by_the_validator():
    sneaky = T.ServedTool(
        name="mine_tool\n", internal_name="mine.tool\n", family="mine",
        description="x", input_schema={},
    )
    assert any("does not match" in p for p in _problems_with(sneaky))


# ---------------------------------------------------------------------------
# The two spellings, and which direction may be computed
# ---------------------------------------------------------------------------


def test_wire_name_is_the_translation_the_table_uses():
    """One spelling of contract §2's translation, checked against the table.

    ``validate_tool_names`` compares every entry's hand-written wire name to
    this function, so if the two ever disagree the endpoint refuses to bind.
    This asserts the same property directly, so a failure names the cause.
    """
    for tool in T.SERVED_TOOLS:
        assert T.wire_name(tool.internal_name) == tool.name


def test_wire_name_leaves_a_name_with_no_dot_alone():
    assert T.wire_name("shell_run") == "shell_run"
    assert T.wire_name("") == ""


def test_tool_family_splits_on_the_first_dot_only():
    assert T.tool_family("shell.run") == "shell"
    assert T.tool_family("jobs.output") == "jobs"
    # A name with no dot is a family of one, not a family of nothing.
    assert T.tool_family("hello_world") == "hello_world"


def test_tool_family_agrees_with_the_table():
    for tool in T.SERVED_TOOLS:
        assert T.tool_family(tool.internal_name) == tool.family


def test_internal_name_for_wire_round_trips_every_served_tool():
    for tool in T.SERVED_TOOLS:
        assert T.internal_name_for_wire(tool.name) == tool.internal_name


def test_internal_name_for_wire_refuses_to_guess():
    """``_`` to ``.`` is not invertible, so an unknown name is not rewritten.

    A guess here would filter, or route, for a tool that does not exist --
    silently, which is the failure mode the explicit table exists to prevent.
    """
    assert T.internal_name_for_wire("hello_world_echo") is None
    assert T.internal_name_for_wire("not_a_tool") is None
    assert T.internal_name_for_wire("") is None


def test_internal_name_for_wire_tolerates_surrounding_space():
    """It reads what an operator typed into a box, not a machine-made string."""
    assert T.internal_name_for_wire("  shell_run  ") == "shell.run"
