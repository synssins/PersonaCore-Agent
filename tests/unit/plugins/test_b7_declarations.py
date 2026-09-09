"""B7's signed argument declarations, and the two mutations that pin them.

The `foreign` / `ws_path` split is the whole game for the ``adb`` family, and
it breaks in both directions:

* declare a **phone** path ``ws_path`` and every legitimate call is compared
  against a Windows root, never matches, and is denied;
* declare a **workstation** path ``foreign`` and ``adb_push`` is exempted from
  root confinement, which is precisely the hole §6 names ("otherwise
  ``adb_push`` would read any file on the workstation onto a device").

Both mutations are performed here, on the real shipped manifest, and both must
fail loudly.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest

from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import (
    classify,
    evaluate_detailed,
    parse_declarations,
)

_PLUGINS_DIR = Path(__file__).resolve().parents[3] / "src" / "workstation_agent" / "plugins"

# A phone path and a phone command.  Neither is a location or a program on
# this workstation, and treating them as though they were is the bug.
PHONE_PATH = "/sdcard/DCIM/Camera/IMG_0001.jpg"
PHONE_COMMAND = "getprop ro.product.model"

IN_ROOTS = os.path.expandvars(r"%USERPROFILE%\Downloads\app.apk")
OUT_OF_ROOTS = os.path.expandvars(r"%USERPROFILE%\.ssh\id_rsa")


def _load(plugin_id: str, *, mutate=None) -> PluginManifest:
    """Load a shipped manifest, optionally rewriting its declarations."""
    data = tomllib.loads(
        (_PLUGINS_DIR / plugin_id / "plugin.toml").read_text(encoding="utf-8"),
    )
    declared = [str(p) for p in data["declared_permissions"]]
    if mutate is not None:
        declared = [mutate(p) for p in declared]
    return PluginManifest(
        id=str(data["id"]),
        name=str(data.get("name", plugin_id)),
        version=str(data.get("version", "0.1.0")),
        runtime="python",
        entry=[],
        plugin_dir=_PLUGINS_DIR / plugin_id,
        signature_file=_PLUGINS_DIR / plugin_id / "signature.sig",
        declared_permissions=declared,
        confirmable_conditions=[str(c) for c in data.get("confirmable_conditions", [])],
    )


def _granted(manifest: PluginManifest) -> set[str]:
    return {p for p in manifest.declared_permissions if p.startswith("tool:")}


def _decide(manifest: PluginManifest, tool: str, args: dict):
    return evaluate_detailed(manifest, tool, args, _granted(manifest))


@pytest.fixture
def adb_manifest() -> PluginManifest:
    return _load("adb")


@pytest.fixture
def devices_manifest() -> PluginManifest:
    return _load("devices")


# ---------------------------------------------------------------------------
# The names are dotted
# ---------------------------------------------------------------------------


def test_every_adb_tool_is_declared_under_its_dotted_name(adb_manifest):
    """``host.invoke`` is given ``tool.internal_name`` on every path that exists.

    Under default-deny the underscore spelling declares a tool that does not
    exist and leaves the real one undeclared — a tool nobody can call.
    """
    declarations = parse_declarations(adb_manifest)
    assert set(declarations) == {
        "adb.devices", "adb.shell", "adb.push", "adb.pull", "adb.install", "adb.logcat",
    }


def test_no_underscore_spelling_survives_in_either_manifest():
    for plugin_id in ("adb", "devices"):
        manifest = _load(plugin_id)
        for perm in manifest.declared_permissions:
            if perm.startswith("args:"):
                claimed = perm[len("args:"):].split(":", 1)[0]
                assert "." in claimed, f"{plugin_id}: {perm!r} is not a dotted tool name"
                assert "_" not in claimed.split(".")[0], f"{plugin_id}: {perm!r}"


def test_the_declared_names_match_what_the_endpoint_actually_dispatches():
    """The served set is the authority on the spelling, not this file."""
    from workstation_agent.network_mcp.tools import SERVED_TOOLS

    served = {t.internal_name for t in SERVED_TOOLS if t.family in {"adb", "devices"}}
    declared = set(parse_declarations(_load("adb"))) | set(parse_declarations(_load("devices")))
    assert declared == served


def test_the_plugins_advertise_the_same_dotted_names_they_declare():
    """A manifest declaring ``adb.pull`` while the plugin advertises something
    else produces a tool the host cannot resolve."""
    from workstation_agent.plugins.adb import __main__ as adb_main
    from workstation_agent.plugins.devices import __main__ as devices_main

    assert {t["name"] for t in adb_main.TOOLS} == set(parse_declarations(_load("adb")))
    assert {t["name"] for t in devices_main.TOOLS} == set(parse_declarations(_load("devices")))


# ---------------------------------------------------------------------------
# The split, stated
# ---------------------------------------------------------------------------


def test_a_phone_path_is_foreign_and_a_workstation_path_is_not(adb_manifest):
    push = parse_declarations(adb_manifest)["adb.push"]
    assert push.arguments["device_path"] == "foreign"
    assert push.arguments["workstation_path"] == "ws_path"
    assert {"device_path", "workstation_path"} <= push.required


def test_a_phone_command_is_foreign_not_ws_command(adb_manifest):
    """``ws_command`` would compare it against this workstation's ``cmd:``
    allowlist, which the family does not have and should not have — the
    command runs on the phone."""
    shell = parse_declarations(adb_manifest)["adb.shell"]
    assert shell.arguments["command"] == "foreign"
    assert not any(p.startswith("cmd:") for p in adb_manifest.declared_permissions)


def test_a_device_serial_is_opaque_because_it_is_an_identifier(adb_manifest):
    """``foreign`` and ``opaque`` are identical in mechanism and differ only in
    what they tell the audit reader.  A serial names no location and no
    program, so it is the same kind of thing as a job id."""
    for tool in ("adb.shell", "adb.push", "adb.pull", "adb.install", "adb.logcat"):
        assert parse_declarations(adb_manifest)[tool].arguments["serial"] == "opaque"


def test_the_read_action_modes_follow_section_7s_two_lists(adb_manifest, devices_manifest):
    decls = parse_declarations(adb_manifest) | parse_declarations(devices_manifest)
    never_prompt = {"devices.list", "adb.devices", "adb.pull", "adb.logcat"}
    always_prompt = {"adb.shell", "adb.push", "adb.install"}
    for tool in never_prompt:
        assert decls[tool].read_only is True, tool
    for tool in always_prompt:
        assert decls[tool].read_only is False, tool


def test_the_adb_manifest_declares_no_confirmable_conditions_today(adb_manifest):
    """§6 says an out-of-roots push is ``denied``, exactly as for
    ``files_read``.

    ``evaluate_detailed``'s hard-guard loop skips any guard the plugin lists as
    a confirmable condition, so listing ``outside_declared_paths`` here would
    convert that refusal into a prompt somebody could approve.

    This records today's state. The invariant that must hold *forever* is the
    next test, which is narrower and does not have to be edited to add a
    legitimate future guard.
    """
    assert adb_manifest.confirmable_conditions == []


@pytest.mark.parametrize("plugin_id", ["adb", "devices"])
def test_no_hard_guard_is_ever_listed_as_confirmable(plugin_id):
    """The invariant, stated so a future guard cannot reopen the downgrade.

    ``confirmable_conditions`` is plugin-wide, not per-tool, so the obvious
    way to add (say) a dangerous-device-command prompt to ``adb_shell`` is to
    append to this list — and if the name appended happens to be one of
    ``_HARD_GUARDS``, the hard-guard loop starts skipping it for *every* tool
    in the family and §6's ``denied`` silently becomes an approvable prompt.

    A new guard whose name is **not** in ``_HARD_GUARDS`` is safe to list here
    and works correctly: the confirm loop runs over every declared condition,
    while the skip only applies to the three hard guards.  So the rule is not
    "never add a confirmable condition", it is "never add one that is also a
    hard guard" — which is what this asserts.
    """
    from workstation_agent.mcp_host.permissions import _HARD_GUARDS

    manifest = _load(plugin_id)
    overlap = set(manifest.confirmable_conditions) & set(_HARD_GUARDS)
    assert not overlap, (
        f"{plugin_id} lists hard guard(s) {sorted(overlap)} as confirmable, which "
        f"downgrades a §6 denial into a prompt"
    )


# ---------------------------------------------------------------------------
# The split, enforced
# ---------------------------------------------------------------------------


def test_a_legitimate_phone_pull_is_allowed(adb_manifest):
    outcome = _decide(adb_manifest, "adb.pull", {"device_path": PHONE_PATH})
    assert outcome.decision == "allow", outcome.reason


def test_a_legitimate_phone_command_is_allowed(adb_manifest):
    outcome = _decide(adb_manifest, "adb.shell", {"command": PHONE_COMMAND})
    assert outcome.decision == "allow", outcome.reason


def test_getprop_reaches_the_family_at_all(adb_manifest):
    """§11 item 2 runs through here; if the gate refused it, nothing else in
    that criterion could ever pass."""
    outcome = _decide(
        adb_manifest,
        "adb.shell",
        {"serial": "R58N12ABCDE", "command": "getprop ro.product.model", "wait_s": 20},
    )
    assert outcome.decision == "allow", outcome.reason


def test_a_push_from_inside_the_roots_is_allowed(adb_manifest):
    outcome = _decide(
        adb_manifest,
        "adb.push",
        {"workstation_path": IN_ROOTS, "device_path": "/sdcard/app.apk"},
    )
    assert outcome.decision == "allow", outcome.reason


def test_a_push_from_outside_the_roots_is_denied_not_prompted(adb_manifest):
    """§6: "a path outside is denied for push and install exactly as for
    files_read.  Otherwise adb_push would read any file on the workstation
    onto a device." """
    outcome = _decide(
        adb_manifest,
        "adb.push",
        {"workstation_path": OUT_OF_ROOTS, "device_path": "/sdcard/id_rsa"},
    )
    assert outcome.decision == "deny", outcome.reason
    assert outcome.decision != "confirm"
    assert outcome.decision != "allow"


def test_an_install_from_outside_the_roots_is_denied(adb_manifest):
    outcome = _decide(adb_manifest, "adb.install", {"workstation_path": OUT_OF_ROOTS})
    assert outcome.decision == "deny"


@pytest.mark.parametrize(
    "path",
    [
        os.path.expandvars(r"%USERPROFILE%\Downloads\..\.ssh\id_rsa"),
        r"C:\Windows\System32\config\SAM",
        "Downloads/app.apk",
        ".",
        "",
    ],
)
def test_traversal_and_relative_pushes_are_refused(adb_manifest, path):
    """Declaring the argument correctly does not admit it; the comparison layer
    still runs afterwards."""
    outcome = _decide(
        adb_manifest, "adb.push", {"workstation_path": path, "device_path": "/sdcard/x"},
    )
    assert outcome.decision == "deny", path


# ---------------------------------------------------------------------------
# MUTATION 1 — a phone path declared ws_path breaks legitimate calls
# ---------------------------------------------------------------------------


def _phone_path_as_ws_path(perm: str) -> str:
    if perm.startswith(("args:adb.pull:", "args:adb.push:")):
        return perm.replace("device_path=foreign", "device_path=ws_path")
    return perm


def test_mutation_declaring_a_phone_path_ws_path_breaks_every_legitimate_pull():
    """The bug found twice during the gate work, reproduced deliberately.

    ``/sdcard/DCIM/…`` is compared against ``%USERPROFILE%\\Downloads``, never
    matches, and denies a call that should plainly succeed.
    """
    healthy = _load("adb")
    mutated = _load("adb", mutate=_phone_path_as_ws_path)

    assert _decide(healthy, "adb.pull", {"device_path": PHONE_PATH}).decision == "allow"
    assert _decide(mutated, "adb.pull", {"device_path": PHONE_PATH}).decision == "deny"


def test_mutation_declaring_a_phone_path_ws_path_also_breaks_push():
    mutated = _load("adb", mutate=_phone_path_as_ws_path)
    outcome = _decide(
        mutated, "adb.push", {"workstation_path": IN_ROOTS, "device_path": "/sdcard/app.apk"},
    )
    assert outcome.decision == "deny", "a push that should work is now refused"


def test_mutation_the_phone_path_really_did_change_class():
    """Guards the mutation itself: a rewrite that silently matched nothing
    would make the two tests above pass for the wrong reason."""
    mutated = _load("adb", mutate=_phone_path_as_ws_path)
    assert parse_declarations(mutated)["adb.pull"].arguments["device_path"] == "ws_path"
    classified = classify(mutated, "adb.pull", {"device_path": PHONE_PATH})
    assert PHONE_PATH in classified.paths


# ---------------------------------------------------------------------------
# MUTATION 2 — a workstation path declared foreign stops being confined
# ---------------------------------------------------------------------------


def _ws_path_as_foreign(perm: str) -> str:
    return perm.replace("workstation_path=ws_path", "workstation_path=foreign")


def test_mutation_declaring_the_push_source_foreign_stops_denying_the_hole_section_6_names():
    """The other direction, and the dangerous one.

    Exempting ``workstation_path`` from root comparison lets ``adb_push`` copy
    any file on the workstation onto a phone.
    """
    healthy = _load("adb")
    mutated = _load("adb", mutate=_ws_path_as_foreign)

    args = {"workstation_path": OUT_OF_ROOTS, "device_path": "/sdcard/id_rsa"}
    assert _decide(healthy, "adb.push", args).decision == "deny"
    assert _decide(mutated, "adb.push", args).decision == "allow", (
        "the mutation must visibly remove the confinement, or this test proves nothing"
    )


def test_mutation_declaring_the_install_source_foreign_stops_denying():
    mutated = _load("adb", mutate=_ws_path_as_foreign)
    assert _decide(
        mutated, "adb.install", {"workstation_path": OUT_OF_ROOTS},
    ).decision == "allow"


def test_mutation_the_workstation_path_really_did_change_class():
    mutated = _load("adb", mutate=_ws_path_as_foreign)
    assert parse_declarations(mutated)["adb.push"].arguments["workstation_path"] == "foreign"
    classified = classify(mutated, "adb.push", {"workstation_path": OUT_OF_ROOTS,
                                                "device_path": "/sdcard/x"})
    assert not classified.paths, "an exempt argument reaches no root comparison"


# ---------------------------------------------------------------------------
# MUTATION 3 — removing the declaration entirely
# ---------------------------------------------------------------------------


def test_mutation_a_tool_with_its_declaration_removed_becomes_uncallable():
    """Default-deny on absence: the declaration is not documentation."""
    def drop_pull(perm: str) -> str:
        return "" if perm.startswith("args:adb.pull:") else perm

    mutated = _load("adb", mutate=drop_pull)
    outcome = _decide(mutated, "adb.pull", {"device_path": PHONE_PATH})
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_tool"


def test_mutation_listing_outside_declared_paths_as_confirmable_downgrades_a_denial():
    """Why the manifest declares no confirmable conditions.

    The hard-guard loop skips any guard listed as confirmable, so this turns
    §6's ``denied`` into a prompt.
    """
    manifest = _load("adb")
    manifest.confirmable_conditions.append("outside_declared_paths")
    outcome = _decide(
        manifest, "adb.push", {"workstation_path": OUT_OF_ROOTS, "device_path": "/sdcard/x"},
    )
    assert outcome.decision == "confirm", (
        "if this is still deny, the comment in plugin.toml is wrong about why"
    )


# ---------------------------------------------------------------------------
# Default-deny on absence, for the arguments this family actually has
# ---------------------------------------------------------------------------


def test_an_undeclared_argument_refuses_the_call(adb_manifest):
    outcome = _decide(
        adb_manifest, "adb.shell", {"command": PHONE_COMMAND, "run_as_root": True},
    )
    assert outcome.decision == "deny"
    assert outcome.rule == "undeclared_argument"


def test_a_missing_required_argument_refuses_the_call(adb_manifest):
    outcome = _decide(adb_manifest, "adb.push", {"workstation_path": IN_ROOTS})
    assert outcome.decision == "deny"
    assert outcome.rule == "missing_required_argument"


def test_devices_list_takes_no_arguments_and_says_so(devices_manifest):
    assert parse_declarations(devices_manifest)["devices.list"].arguments == {}
    assert _decide(devices_manifest, "devices.list", {}).decision == "allow"
    assert _decide(devices_manifest, "devices.list", {"path": "C:/"}).decision == "deny"


def test_a_structured_argument_is_refused_rather_than_pruned(adb_manifest):
    """An exempt class is scalar-only: a mapping under ``device_path`` is not a
    foreign path, it is something that cannot be classified, and skipping it
    once hid a workstation path from root comparison."""
    outcome = _decide(
        adb_manifest,
        "adb.push",
        {"workstation_path": {"nested": OUT_OF_ROOTS}, "device_path": "/sdcard/x"},
    )
    assert outcome.decision == "deny"


def test_an_empty_container_is_not_vacuously_inside_the_roots(adb_manifest):
    outcome = _decide(
        adb_manifest, "adb.push", {"workstation_path": [], "device_path": "/sdcard/x"},
    )
    assert outcome.decision == "deny"


# ---------------------------------------------------------------------------
# The manifests are well-formed as shipped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("plugin_id", ["adb", "devices"])
def test_the_shipped_manifest_parses_with_no_poisoned_tools(plugin_id):
    manifest = _load(plugin_id)
    tools = {p[len("tool:"):] for p in manifest.declared_permissions if p.startswith("tool:")}
    assert set(parse_declarations(manifest)) == tools


def test_the_adb_family_declares_roots_because_two_of_its_tools_need_them(adb_manifest):
    """``_outside_declared_paths`` denies a path argument on a plugin that
    declares no ``path:`` root — "no restriction to violate" was the bug it
    used to have."""
    roots = [p for p in adb_manifest.declared_permissions if p.startswith("path:")]
    assert roots


def test_the_devices_family_declares_no_roots_because_it_takes_no_paths(devices_manifest):
    assert not [p for p in devices_manifest.declared_permissions if p.startswith("path:")]
