"""The two defects P26 exists to close, asserted where they actually bite.

**Defect 1 -- the page named tools by a name he never sees.** He went looking
for ``shell_run``, the only name PersonaCore has ever shown him, and the page
listed ``shell.run``. He concluded the tool was missing. There is a second,
independent way the row can be absent: a plugin the host is not running never
enters ``MCPHost._runtimes``, so it was not on the page at all. Both are here.

**Defect 2 -- the interface made him click twenty-one times.** Family-level
grants are now the default interface and per-tool control moved behind
Advanced. The tests that matter assert on **the gate**, never on the page's
wording: a page that says a family is allowed while
:func:`~workstation_agent.mcp_host.permissions.evaluate` still says ``deny`` is
the same lie in a larger font.

The gate itself is deliberately unchanged, and this file proves it two ways:
:func:`test_the_gate_has_no_family_wildcard` shows a family is not a concept the
gate knows, and :func:`test_a_family_grant_writes_explicit_entries_only` shows
the UI expands one click into N exact ``tool:`` entries rather than storing a
prefix that would silently cover whatever the plugin adds next.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from tests.unit.ui.conftest import (
    FakeConfigStore,
    FakeMCPHost,
    FakePluginInfo,
    make_client,
)
from workstation_agent.config.schema import AgentConfig, PluginConfig
from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import evaluate
from workstation_agent.ui.backend.routers import audit_routes, plugins_routes

if TYPE_CHECKING:
    from pathlib import Path

PLUGIN_ID = "shell_files_jobs"

#: The real plugin's shape, trimmed: three families, eight tools, the dotted
#: internal spelling the manifest actually uses.
DECLARED = [
    "tool:shell.run",
    "tool:files.list",
    "tool:files.read",
    "tool:files.write",
    "tool:jobs.wait",
    "tool:jobs.output",
    "tool:jobs.list",
    "tool:jobs.kill",
    "args:shell.run:action:!command=ws_command",
    "args:files.list:read:!path=ws_path",
    "args:files.read:read:!path=ws_path",
    "args:files.write:action:!path=ws_path,!content=opaque",
    "args:jobs.wait:read:!job_id=opaque",
    "args:jobs.output:read:!job_id=opaque",
    "args:jobs.list:read",
    "args:jobs.kill:action:!job_id=opaque",
]

JOBS_TOOLS = ("jobs.wait", "jobs.output", "jobs.list", "jobs.kill")
JOBS_PERMS = {f"tool:{t}" for t in JOBS_TOOLS}

#: Arguments that satisfy each jobs tool's own ``args:`` declaration.
#:
#: ``jobs.list`` declares *no* arguments, and the declaration gate refuses a
#: call carrying one it does not name -- so passing ``job_id`` to it would be
#: denied for a reason that has nothing to do with the identity grant this file
#: is testing. Keeping these honest is what makes an ``allow`` here mean "the
#: family grant reached the gate" rather than "the arguments happened to fit".
JOBS_ARGS: dict[str, dict[str, str]] = {
    "jobs.wait": {"job_id": "j-1"},
    "jobs.output": {"job_id": "j-1"},
    "jobs.list": {},
    "jobs.kill": {"job_id": "j-1"},
}


def _manifest(tmp_path: Path, plugin_id: str = PLUGIN_ID) -> PluginManifest:
    return PluginManifest(
        id=plugin_id,
        name="Shell, Files and Jobs",
        version="0.1.0",
        runtime="python",
        entry=["python", "-m", plugin_id],
        plugin_dir=tmp_path,
        signature_file=tmp_path / "plugin.sig",
        declared_permissions=list(DECLARED),
        confirmable_conditions=["command_outside_allowlist"],
    )


def _fixture(tmp_path: Path, cfg: AgentConfig | None = None):
    store = FakeConfigStore(cfg or AgentConfig())
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(
            id=PLUGIN_ID,
            name="Shell, Files and Jobs",
            declared_permissions=list(DECLARED),
            confirmable_conditions=["command_outside_allowlist"],
        ),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)
    return client, store, host


def _granted(store: FakeConfigStore, plugin_id: str = PLUGIN_ID) -> set[str]:
    """Exactly what ``MCPHost.start`` hands the gate, read back from config."""
    entry = store.load().plugins.per_plugin.get(plugin_id)
    return set(entry.granted_permissions) if entry is not None else set()


def _form_action(page: str, fragment: str) -> str:
    """The page's own form action containing *fragment*, or fail loudly.

    Taken from the rendered HTML rather than typed into this file: the whole
    class of defect being fixed is a control the page does not actually carry,
    and a test that posts to a URL it invented would pass against a page with no
    buttons on it at all.
    """
    actions = re.findall(r'<form[^>]*action="([^"]+)"', page)
    matches = [a for a in actions if fragment in a]
    assert matches, f"no form action containing {fragment!r}; found: {actions}"
    return matches[0]


def _without_page_notes(page: str) -> str:
    """*page* minus the explanatory notes, which mention names of their own.

    The notes have to name ``shell_run`` to explain the two spellings, so a
    naive substring search would pass against a page whose rows were still
    dotted only -- the exact defect, undetected. Every assertion about what the
    page *lists* runs against this.
    """
    for note in (
        plugins_routes.NAME_SPELLING_NOTE,
        plugins_routes.FAMILY_SCOPE_NOTE,
    ):
        page = page.replace(note, "")
    return page


# ---------------------------------------------------------------------------
# Defect 1: the name he searches for is the name on the page
# ---------------------------------------------------------------------------


def test_searching_the_page_for_the_name_he_is_shown_finds_it(tmp_path):
    """``shell_run`` is the only name he has ever been given. It must be there."""
    client, _store, _host = _fixture(tmp_path)

    listed = _without_page_notes(client.get("/plugins").text)

    assert "shell_run" in listed
    for wire in ("files_write", "jobs_kill", "files_read"):
        assert wire in listed, f"{wire} is not on the page"


def test_the_internal_name_is_shown_as_well_but_does_not_lead(tmp_path):
    """The dotted name appears in refusals and the audit log, so it stays."""
    client, _store, _host = _fixture(tmp_path)

    listed = _without_page_notes(client.get("/plugins").text)

    assert "shell.run" in listed
    # ...and it is not the only spelling of it, which was the defect.
    assert "shell_run" in listed


def test_a_disabled_plugin_still_appears_with_its_tools_and_the_reason(
    tmp_path, monkeypatch,
):
    """The second, independent cause: not running means not in ``_runtimes``.

    A page that silently omits a tool he can watch being refused elsewhere is
    broken whatever the reason. It must say *why* the row cannot be changed
    rather than leaving him to conclude the tool does not exist.
    """
    monkeypatch.setattr(
        plugins_routes, "discover", lambda: [_manifest(tmp_path)],
    )
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(enabled=False)
    store = FakeConfigStore(cfg)
    # The host is running nothing -- exactly what a disabled plugin looks like.
    client = make_client(
        config_store=store, mcp_host=FakeMCPHost(plugins_list=[]), tmp_path=tmp_path,
    )

    page = client.get("/plugins").text
    listed = _without_page_notes(page)

    assert "shell_run" in listed, "a disabled plugin's tools are missing entirely"
    assert plugins_routes.DISABLED_PLUGIN_NOTE in page
    # It says what to do about it, and offers the control that does it.
    assert f"/plugins/{PLUGIN_ID}/enable" in page
    # And it does not pretend anything can be allowed while it is off.
    assert f"/plugins/{PLUGIN_ID}/grant/" not in page
    assert f"/plugins/{PLUGIN_ID}/grant-family/" not in page


def test_an_enabled_plugin_the_host_is_not_running_says_that_instead(
    tmp_path, monkeypatch,
):
    """Switched on but not started is a different sentence from switched off."""
    monkeypatch.setattr(
        plugins_routes, "discover", lambda: [_manifest(tmp_path)],
    )
    client = make_client(
        config_store=FakeConfigStore(AgentConfig()),
        mcp_host=FakeMCPHost(plugins_list=[]),
        tmp_path=tmp_path,
    )

    page = client.get("/plugins").text

    assert plugins_routes.NOT_RUNNING_PLUGIN_NOTE in page
    assert plugins_routes.DISABLED_PLUGIN_NOTE not in page
    assert "shell_run" in _without_page_notes(page)


def test_a_running_plugin_is_not_listed_twice(tmp_path, monkeypatch):
    """Discovery fills in the gaps; it does not duplicate what is running."""
    monkeypatch.setattr(
        plugins_routes, "discover", lambda: [_manifest(tmp_path)],
    )
    client, _store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text

    assert page.count(f'id="plugin-{PLUGIN_ID}"') == 1
    assert plugins_routes.DISABLED_PLUGIN_NOTE not in page
    assert plugins_routes.NOT_RUNNING_PLUGIN_NOTE not in page


# ---------------------------------------------------------------------------
# Defect 2: one click per intention, asserted at the gate
# ---------------------------------------------------------------------------


def test_one_family_click_allows_every_tool_in_it_at_the_gate(tmp_path):
    """The whole point. One click, four tools, checked on ``evaluate``."""
    client, store, _host = _fixture(tmp_path)
    manifest = _manifest(tmp_path)

    for tool, args in JOBS_ARGS.items():
        assert evaluate(manifest, tool, args, _granted(store)) == "deny"

    page = client.get("/plugins").text
    action = _form_action(page, f"/{PLUGIN_ID}/grant-family/jobs")
    resp = client.post(action, follow_redirects=False)
    assert resp.status_code == 303

    for tool, args in JOBS_ARGS.items():
        assert evaluate(manifest, tool, args, _granted(store)) == "allow", (
            f"{tool} is still denied after allowing its family"
        )
    # And it allowed *that* family, not everything.
    assert evaluate(manifest, "files.write", {"path": "x", "content": "y"},
                    _granted(store)) == "deny"


def test_a_family_grant_writes_explicit_entries_only(tmp_path):
    """No prefix, no wildcard: exactly the tools declared today.

    A ``tool:jobs.*`` entry would be the tidier implementation and the wrong
    change -- it would silently cover whatever a future version of the plugin
    adds to the family, which is a change to enforcement made for a
    presentation problem.
    """
    client, store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text
    client.post(_form_action(page, f"/{PLUGIN_ID}/grant-family/jobs"),
                follow_redirects=False)

    assert _granted(store) == JOBS_PERMS
    assert "tool:jobs.*" not in _granted(store)
    assert "tool:jobs" not in _granted(store)
    assert "*" not in _granted(store)


def test_the_gate_has_no_family_wildcard(tmp_path):
    """Confirming the claim this subtask rests on rather than trusting it.

    ``_check_tool_permission`` matches ``tool:<exact>`` or ``*``. If a prefix
    form existed, the UI's expansion would be unnecessary -- and a page built on
    a belief about the gate that the gate does not share is how the last build
    got here.
    """
    manifest = _manifest(tmp_path)

    for pretend_family_grant in ("tool:jobs.*", "tool:jobs", "tool:jobs_*", "jobs"):
        assert evaluate(
            manifest, "jobs.wait", {"job_id": "j-1"}, {pretend_family_grant},
        ) == "deny", f"{pretend_family_grant!r} unexpectedly allows a whole family"

    # The exact entry, and only it, allows the call.
    assert evaluate(manifest, "jobs.wait", {"job_id": "j-1"},
                    {"tool:jobs.wait"}) == "allow"


def test_stopping_a_family_returns_every_tool_in_it_to_denied(tmp_path):
    """A control that only switches on is not a control."""
    client, store, _host = _fixture(tmp_path)
    manifest = _manifest(tmp_path)

    page = client.get("/plugins").text
    client.post(_form_action(page, f"/{PLUGIN_ID}/grant-family/jobs"),
                follow_redirects=False)
    assert evaluate(manifest, "jobs.kill", {"job_id": "j-1"},
                    _granted(store)) == "allow"

    page = client.get("/plugins").text
    resp = client.post(_form_action(page, f"/{PLUGIN_ID}/revoke-family/jobs"),
                       follow_redirects=False)
    assert resp.status_code == 303

    assert _granted(store) == set()
    for tool, args in JOBS_ARGS.items():
        assert evaluate(manifest, tool, args, _granted(store)) == "deny"


def test_stopping_a_family_also_clears_a_stale_grant_in_it(tmp_path):
    """Revoke is unbounded by the declaration, family-wide as well as per tool."""
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=["tool:jobs.wait", "tool:jobs.tool_it_no_longer_declares"],
    )
    client, store, _host = _fixture(tmp_path, cfg)

    page = client.get("/plugins").text
    client.post(_form_action(page, f"/{PLUGIN_ID}/revoke-family/jobs"),
                follow_redirects=False)

    assert _granted(store) == set()


def test_a_partly_allowed_family_reads_as_partly_allowed(tmp_path):
    """Three of five on is neither off nor on, and it must say which."""
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=["tool:jobs.wait", "tool:jobs.list"],
    )
    client, _store, _host = _fixture(tmp_path, cfg)

    page = client.get("/plugins").text

    assert "Partly allowed" in page
    assert "2 of 4" in page
    # It says *which*, rather than leaving him to open Advanced to find out.
    jobs_row = page[page.index("jobs_*"):]
    jobs_row = jobs_row[:jobs_row.index("</tr>")]
    assert "jobs_wait" in jobs_row
    assert "jobs_kill" in jobs_row
    # Both directions are offered from a partly-on family.
    assert f"/{PLUGIN_ID}/grant-family/jobs" in page
    assert f"/{PLUGIN_ID}/revoke-family/jobs" in page


def test_a_fully_allowed_family_reads_as_allowed_and_offers_no_second_grant(tmp_path):
    """Nothing left to allow, so there is no button claiming otherwise."""
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=sorted(JOBS_PERMS),
    )
    client, _store, _host = _fixture(tmp_path, cfg)

    page = client.get("/plugins").text
    jobs_row = page[page.index("jobs_*"):]
    jobs_row = jobs_row[:jobs_row.index("</tr>")]

    assert "all 4" in jobs_row
    assert "Partly allowed" not in jobs_row
    assert "grant-family/jobs" not in jobs_row
    assert "revoke-family/jobs" in jobs_row


def test_an_untouched_family_reads_as_not_allowed(tmp_path):
    """Default-deny, said plainly, with only the one button that applies."""
    client, _store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text
    jobs_row = page[page.index("jobs_*"):]
    jobs_row = jobs_row[:jobs_row.index("</tr>")]

    assert "Not allowed" in jobs_row
    assert "grant-family/jobs" in jobs_row
    assert "revoke-family/jobs" not in jobs_row


def test_a_family_toggle_asks_no_confirmation(tmp_path):
    """He has said what he thinks of being protected from himself.

    The signature-verification toggle answers its first POST with a 200 and a
    second form. A family toggle must not: one click, done, 303.
    """
    client, store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text
    action = _form_action(page, f"/{PLUGIN_ID}/grant-family/files")
    resp = client.post(action, follow_redirects=False)

    assert resp.status_code == 303
    assert _granted(store) == {"tool:files.list", "tool:files.read", "tool:files.write"}
    # No client-side nag either.
    assert "onsubmit" not in _form_action_element(page, "grant-family/files")


def _form_action_element(page: str, fragment: str) -> str:
    """The whole opening ``<form>`` tag whose action contains *fragment*."""
    match = re.search(r"<form[^>]*action=\"[^\"]*" + re.escape(fragment) + r"[^\"]*\"[^>]*>",
                      page)
    assert match, f"no form element for {fragment!r}"
    return match.group(0)


def test_a_family_grant_reaches_the_running_host(tmp_path):
    """Otherwise the click is still a lie until the Agent restarts."""
    client, _store, host = _fixture(tmp_path)

    page = client.get("/plugins").text
    client.post(_form_action(page, f"/{PLUGIN_ID}/grant-family/jobs"),
                follow_redirects=False)

    assert host.configs_set, "the family grant was not pushed to the running host"
    pushed = host.configs_set[-1].plugins.per_plugin[PLUGIN_ID].granted_permissions
    assert set(pushed) == JOBS_PERMS


def test_a_family_the_manifest_does_not_declare_is_refused(tmp_path):
    """A button that reports success while doing nothing is the same old lie."""
    client, store, _host = _fixture(tmp_path)

    resp = client.post(f"/plugins/{PLUGIN_ID}/grant-family/registry",
                       follow_redirects=False)

    assert resp.status_code == 400
    assert "does not declare" in resp.text
    assert _granted(store) == set()


def test_a_family_grant_to_an_unknown_plugin_is_refused(tmp_path):
    client, store, _host = _fixture(tmp_path)

    resp = client.post("/plugins/no_such_plugin/grant-family/jobs",
                       follow_redirects=False)

    assert resp.status_code == 400
    assert store.load().plugins.per_plugin.get("no_such_plugin") is None


def test_family_grant_from_another_origin_is_refused(tmp_path):
    """Nobody else gets to allow a whole family on his behalf."""
    client, store, _host = _fixture(tmp_path)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/grant-family/jobs",
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )

    assert resp.status_code == 403
    assert _granted(store) == set()


def test_family_revoke_from_another_origin_is_refused(tmp_path):
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=sorted(JOBS_PERMS),
    )
    client, store, _host = _fixture(tmp_path, cfg)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/revoke-family/jobs",
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )

    assert resp.status_code == 403
    assert _granted(store) == JOBS_PERMS


# ---------------------------------------------------------------------------
# Advanced: reachable, not the default, and unchanged in what it offers
# ---------------------------------------------------------------------------


def test_advanced_is_reachable_and_is_not_the_default_view(tmp_path):
    client, _store, _host = _fixture(tmp_path)

    default = client.get("/plugins").text
    assert "<details>" in default, "the per-tool view is not reachable"
    assert "<details open>" not in default, "the per-tool view is the default"

    opened = client.get("/plugins?advanced=1").text
    assert "<details open>" in opened


def test_advanced_keeps_every_per_tool_control(tmp_path):
    """Nothing the last build gave the per-tool rows is lost behind the toggle."""
    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=["tool:files.read", "tool:files.gone"],
    )
    client, _store, _host = _fixture(tmp_path, cfg)

    page = client.get("/plugins?advanced=1").text

    # One row per declared tool, each individually grantable or revokable.
    assert f"/{PLUGIN_ID}/grant/tool%3Ashell.run" in page
    assert f"/{PLUGIN_ID}/revoke/tool%3Afiles.read" in page
    # Hard guards, still statements of fact rather than controls.
    assert "outside the folders" in page
    assert "grant/outside_declared_paths" not in page
    # A stale grant, still removable, and now shown under both spellings.
    assert "files_gone" in page
    assert "tool:files.gone" in page
    assert "no effect" in page.lower()


def test_a_per_tool_click_returns_him_to_the_advanced_view(tmp_path):
    """Collapsing what he opened on every click is the same complaint, smaller."""
    client, _store, _host = _fixture(tmp_path)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/grant/tool%3Ashell.run",
        data={"advanced": "1"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/plugins?advanced=1")


def test_a_family_click_returns_him_to_the_family_view(tmp_path):
    client, _store, _host = _fixture(tmp_path)

    resp = client.post(f"/plugins/{PLUGIN_ID}/grant-family/jobs",
                       follow_redirects=False)

    assert resp.headers["location"] == "/plugins"


def test_the_page_says_a_later_tool_is_not_covered_by_an_earlier_click(tmp_path):
    """A new capability deserves new consent -- said, not left to be discovered."""
    client, _store, _host = _fixture(tmp_path)

    assert plugins_routes.FAMILY_SCOPE_NOTE in client.get("/plugins").text


def test_a_family_grant_does_not_cover_a_tool_added_later(tmp_path):
    """The behaviour the sentence promises, checked at the gate.

    The plugin gains ``jobs.purge`` in a later version. The click he made before
    that must not carry over to it.
    """
    client, store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text
    client.post(_form_action(page, f"/{PLUGIN_ID}/grant-family/jobs"),
                follow_redirects=False)

    updated = _manifest(tmp_path)
    updated.declared_permissions = [
        *DECLARED, "tool:jobs.purge", "args:jobs.purge:action:!job_id=opaque",
    ]

    assert evaluate(updated, "jobs.purge", {"job_id": "j-1"},
                    _granted(store)) == "deny"
    assert evaluate(updated, "jobs.wait", {"job_id": "j-1"},
                    _granted(store)) == "allow"


# ---------------------------------------------------------------------------
# The same naming fault, on the other page that names tools at him
# ---------------------------------------------------------------------------


class _Row:
    """One audit record, shaped like the reader's rows."""

    def __init__(self, **kw: str) -> None:
        self.ts = kw.get("ts", "2026-09-10T00:00:00+00:00")
        self.event = kw.get("event", "tool_call")
        self.plugin_id = kw.get("plugin_id", PLUGIN_ID)
        self.tool_id = kw.get("tool_id", "shell.run")
        self.decision = kw.get("decision", "allow")
        self.result = kw.get("result", "ok")
        self.detail = kw.get("detail", "")


class _CapturingAuditReader:
    """A reader that records the query it was handed and returns fixed rows."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows
        self.queries: list[Any] = []

    def __call__(self, query: object) -> list[Any]:
        self.queries.append(query)
        return self._rows


def test_the_audit_page_names_the_tool_the_way_he_knows_it(tmp_path):
    """He reads the audit log to find out what happened, under which name?"""
    reader = _CapturingAuditReader([_Row(tool_id="files.write")])
    client = make_client(audit_reader=reader, tmp_path=tmp_path)

    page = client.get("/audit").text

    assert "files_write" in page
    # The dotted id stays: it is what the row actually stores and what a
    # refusal quotes back at him.
    assert "files.write" in page


def test_the_audit_filter_accepts_the_name_on_the_page(tmp_path):
    """Typing the only name he has been shown must not come back empty."""
    reader = _CapturingAuditReader([_Row()])
    client = make_client(audit_reader=reader, tmp_path=tmp_path)

    resp = client.get("/audit", params={"tool_id": "shell_run"})

    assert resp.status_code == 200
    assert reader.queries, "the audit reader was never called"
    assert reader.queries[-1].tool_id == "shell.run"
    # And it says so, rather than quietly searching for something else.
    assert audit_routes.TOOL_FILTER_TRANSLATED_NOTE.format(
        wire="shell_run", internal="shell.run",
    ) in resp.text
    # The box still shows what he typed.
    assert 'value="shell_run"' in resp.text


def test_the_audit_filter_still_accepts_the_internal_name(tmp_path):
    """The dotted spelling is what the log stores; it must keep working."""
    reader = _CapturingAuditReader([_Row()])
    client = make_client(audit_reader=reader, tmp_path=tmp_path)

    client.get("/audit", params={"tool_id": "shell.run"})

    assert reader.queries[-1].tool_id == "shell.run"


def test_an_unknown_tool_name_is_passed_through_untranslated(tmp_path):
    """No guessing: ``_`` to ``.`` is not invertible, so an unknown name is not
    rewritten into one that does not exist."""
    reader = _CapturingAuditReader([])
    client = make_client(audit_reader=reader, tmp_path=tmp_path)

    client.get("/audit", params={"tool_id": "hello_world_echo"})

    assert reader.queries[-1].tool_id == "hello_world_echo"
