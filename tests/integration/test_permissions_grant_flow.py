"""The owner's actual situation, end to end: deny -> grant in the UI -> allow.

The Agent enrols, offers its tools, and every call is denied, because
``granted_permissions`` starts empty and until P25 nothing on any page could
put anything in it.  This file is the proof that the loop now closes, and it
asserts on **the gate's decision**, never on the page's wording: a page that
says "granted" while :func:`permissions.evaluate` still says ``deny`` is the
exact class of lie that produced the defect.

The one thing taken from the page is the form's ``action`` -- the grant is
posted to the URL the rendered page actually carries, so a page wired to a
route that does not exist (or to a different one) fails here rather than in
front of the owner.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from tests.unit.ui.conftest import (
    FakeConfigStore,
    FakeMCPHost,
    FakePluginInfo,
    make_client,
)
from workstation_agent.config.schema import AgentConfig, PluginConfig
from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import evaluate, evaluate_detailed

if TYPE_CHECKING:
    from pathlib import Path

PLUGIN_ID = "demo"
TOOL = "demo.echo"
TOOL_PERM = f"tool:{TOOL}"

#: What the signed manifest declares.  Both halves are needed for a call to
#: succeed: the ``tool:`` entry satisfies the identity gate, the ``args:``
#: entry satisfies the declaration gate.
DECLARED = [
    TOOL_PERM,
    "tool:demo.write",
    f"args:{TOOL}:read:text=opaque",
    "args:demo.write:action:text=opaque",
]


def _manifest(tmp_path: Path) -> PluginManifest:
    return PluginManifest(
        id=PLUGIN_ID,
        name="Demo Plugin",
        version="1.0.0",
        runtime="python",
        entry=["python", "-m", "demo"],
        plugin_dir=tmp_path,
        signature_file=tmp_path / "plugin.sig",
        declared_permissions=list(DECLARED),
        confirmable_conditions=[],
    )


def _granted(store: FakeConfigStore) -> set[str]:
    """Exactly what ``MCPHost.start`` hands the gate, read back from config."""
    cfg = store.load()
    entry = cfg.plugins.per_plugin.get(PLUGIN_ID)
    return set(entry.granted_permissions) if entry is not None else set()


def _fixture(tmp_path: Path):
    store = FakeConfigStore(AgentConfig())
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(
            id=PLUGIN_ID,
            name="Demo Plugin",
            declared_permissions=list(DECLARED),
        ),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)
    return client, store, host


def _form_action(page: str, verb: str, perm: str) -> str:
    """The action of the page's own *verb* form for *perm*, or fail loudly.

    Searching the rendered HTML rather than hard-coding the URL is deliberate:
    the defect being fixed was a route with no caller, and a test that posts to
    a URL it made up itself would pass just as happily against a page with no
    buttons on it at all.
    """
    actions = re.findall(r'<form[^>]*action="([^"]+)"', page)
    wanted = [a for a in actions if f"/{PLUGIN_ID}/{verb}/" in a]
    assert wanted, (
        f"the plugins page carries no {verb} form for {PLUGIN_ID}; "
        f"forms found: {actions}"
    )
    encoded = perm.replace(":", "%3A")
    matches = [a for a in wanted if a.endswith((encoded, perm))]
    assert matches, f"no {verb} form for {perm!r}; {verb} forms found: {wanted}"
    return matches[0]


# ---------------------------------------------------------------------------
# The whole point of the subtask
# ---------------------------------------------------------------------------


def test_deny_then_grant_through_the_ui_then_allow(tmp_path):
    """Nothing granted -> denied.  Grant via a form post -> the same call allowed."""
    client, store, _host = _fixture(tmp_path)
    manifest = _manifest(tmp_path)
    args = {"text": "hello"}

    # 1. The owner's situation this morning: enrolled, tools offered, denied.
    assert _granted(store) == set()
    before = evaluate_detailed(manifest, TOOL, args, _granted(store))
    assert before.decision == "deny"
    assert before.rule == "tool_not_granted"

    # 2. He opens Plugins and clicks Allow.  The URL comes from the page.
    page = client.get("/plugins")
    assert page.status_code == 200
    action = _form_action(page.text, "grant", TOOL_PERM)

    granted_resp = client.post(action, follow_redirects=False)
    assert granted_resp.status_code == 303

    # 3. The same call, re-evaluated against what the config now holds.
    assert _granted(store) == {TOOL_PERM}
    assert evaluate(manifest, TOOL, args, _granted(store)) == "allow"


def test_revoke_through_the_ui_returns_the_call_to_denied(tmp_path):
    """A grant he cannot take back is not a control."""
    client, store, _host = _fixture(tmp_path)
    manifest = _manifest(tmp_path)
    args = {"text": "hello"}

    page = client.get("/plugins")
    client.post(_form_action(page.text, "grant", TOOL_PERM), follow_redirects=False)
    assert evaluate(manifest, TOOL, args, _granted(store)) == "allow"

    page = client.get("/plugins")
    revoke = _form_action(page.text, "revoke", TOOL_PERM)
    resp = client.post(revoke, follow_redirects=False)
    assert resp.status_code == 303

    assert _granted(store) == set()
    assert evaluate(manifest, TOOL, args, _granted(store)) == "deny"


def test_grant_and_revoke_are_idempotent(tmp_path):
    """Clicking twice does the same thing as clicking once, in both directions."""
    client, store, _host = _fixture(tmp_path)

    page = client.get("/plugins")
    grant = _form_action(page.text, "grant", TOOL_PERM)
    client.post(grant, follow_redirects=False)
    client.post(grant, follow_redirects=False)
    entry = store.load().plugins.per_plugin[PLUGIN_ID]
    assert entry.granted_permissions.count(TOOL_PERM) == 1

    page = client.get("/plugins")
    revoke = _form_action(page.text, "revoke", TOOL_PERM)
    assert client.post(revoke, follow_redirects=False).status_code == 303
    assert client.post(revoke, follow_redirects=False).status_code == 303
    assert _granted(store) == set()


# ---------------------------------------------------------------------------
# The bound: a grant the signed manifest never declared
# ---------------------------------------------------------------------------


def test_undeclared_permission_cannot_be_granted_even_when_named(tmp_path):
    """The route refuses a permission the plugin never declared.

    The page never offers this one -- but the route is the control, not the
    page, and a request that names it directly must not be able to write a
    grant that the gate would refuse forever anyway.
    """
    client, store, _host = _fixture(tmp_path)
    manifest = _manifest(tmp_path)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/grant/tool%3Ademo.wipe_disk",
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "declare" in resp.text.lower()

    assert _granted(store) == set()
    assert evaluate(manifest, "demo.wipe_disk", {}, _granted(store)) == "deny"


def test_undeclared_wildcard_cannot_be_granted(tmp_path):
    """``*`` is only grantable when the manifest itself declares ``*``."""
    client, store, _host = _fixture(tmp_path)

    resp = client.post(f"/plugins/{PLUGIN_ID}/grant/%2A", follow_redirects=False)
    assert resp.status_code == 400
    assert _granted(store) == set()


def test_grant_to_an_unknown_plugin_is_refused(tmp_path):
    """No manifest means no declaration to bound the grant by, so: no."""
    client, store, _host = _fixture(tmp_path)

    resp = client.post(
        "/plugins/no_such_plugin/grant/tool%3Ano_such_plugin.echo",
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert store.load().plugins.per_plugin.get("no_such_plugin") is None


def test_revoke_is_not_bounded_by_the_declaration(tmp_path):
    """A stale grant -- declared once, not any more -- must still be removable.

    Bounding revoke the way grant is bounded would strand exactly the grants
    the owner most wants gone.
    """
    client, store, _host = _fixture(tmp_path)
    cfg = store.load()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=["tool:demo.tool_it_no_longer_declares"],
    )
    store.save(cfg)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/revoke/tool%3Ademo.tool_it_no_longer_declares",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert _granted(store) == set()


# ---------------------------------------------------------------------------
# The page answers its three questions
# ---------------------------------------------------------------------------


def test_page_shows_declared_granted_and_denied(tmp_path):
    """Per plugin: what it can ask for, what it is allowed, what happens otherwise."""
    client, _store, _host = _fixture(tmp_path)

    page = client.get("/plugins").text
    # What it can ask for -- both declared tools, whether granted or not.
    assert TOOL in page
    assert "demo.write" in page
    # What is currently allowed -- nothing yet, and the page says so.
    assert "Not allowed" in page
    # A tool the manifest never declared is not offered as a control.
    assert "wipe_disk" not in page

    client.post(f"/plugins/{PLUGIN_ID}/grant/tool%3A{TOOL}", follow_redirects=False)
    page = client.get("/plugins").text
    assert "Allowed" in page


def test_page_does_not_offer_a_grant_the_manifest_omits(tmp_path):
    """The failure mode that got us here: a checkbox that will always deny."""
    store = FakeConfigStore(AgentConfig())
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(id=PLUGIN_ID, declared_permissions=[]),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)

    page = client.get("/plugins").text
    assert f"/{PLUGIN_ID}/grant/" not in page
    assert "declares no tools" in page.lower() or "nothing it can be allowed" in page.lower()


def test_wildcard_is_not_presented_as_allow_everything(tmp_path):
    """``*`` grants tool identity only; a control that lies about that is worse
    than no control."""
    store = FakeConfigStore(AgentConfig())
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(
            id=PLUGIN_ID,
            declared_permissions=["*", f"args:{TOOL}:read:text=opaque"],
        ),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)

    page = client.get("/plugins").text
    assert "identity" in page.lower()
    assert "allow everything" not in page.lower()


def test_hard_guards_are_shown_but_not_grantable(tmp_path):
    """A guard that always denies must not look like something a click can lift."""
    store = FakeConfigStore(AgentConfig())
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(
            id=PLUGIN_ID,
            declared_permissions=list(DECLARED),
            confirmable_conditions=[],
        ),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)

    page = client.get("/plugins").text
    assert "outside the folders" in page
    assert "grant/outside_declared_paths" not in page
    assert "revoke/outside_declared_paths" not in page


def test_stale_grant_is_shown_as_having_no_effect(tmp_path):
    """A grant for something no longer declared is inert; say so, and offer revoke."""
    store = FakeConfigStore(AgentConfig())
    cfg = store.load()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(
        granted_permissions=["tool:demo.gone"],
    )
    store.save(cfg)
    host = FakeMCPHost(plugins_list=[
        FakePluginInfo(id=PLUGIN_ID, declared_permissions=list(DECLARED)),
    ])
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)

    page = client.get("/plugins").text
    assert "demo.gone" in page
    assert "no effect" in page.lower()
    assert "/revoke/tool%3Ademo.gone" in page or "/revoke/tool:demo.gone" in page


# ---------------------------------------------------------------------------
# CSRF -- the grant is a real same-origin form post, and only that
# ---------------------------------------------------------------------------


def test_grant_from_another_origin_is_refused(tmp_path):
    """A page in the owner's browser must not be able to grant on his behalf."""
    client, store, _host = _fixture(tmp_path)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/grant/tool%3A{TOOL}",
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert _granted(store) == set()


def test_revoke_from_another_origin_is_refused(tmp_path):
    """Same on the way back: nobody else gets to take his permissions away."""
    client, store, _host = _fixture(tmp_path)
    client.post(f"/plugins/{PLUGIN_ID}/grant/tool%3A{TOOL}", follow_redirects=False)

    resp = client.post(
        f"/plugins/{PLUGIN_ID}/revoke/tool%3A{TOOL}",
        headers={"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert _granted(store) == {TOOL_PERM}


# ---------------------------------------------------------------------------
# A grant has to reach the running host, or the click is still a lie
# ---------------------------------------------------------------------------


def test_grant_is_pushed_to_the_running_host(tmp_path):
    """The UI pushes the saved config so the next call sees it, not the next restart."""
    client, _store, host = _fixture(tmp_path)

    client.post(f"/plugins/{PLUGIN_ID}/grant/tool%3A{TOOL}", follow_redirects=False)

    assert host.configs_set, "the grant was not pushed to the running host"
    pushed = host.configs_set[-1]
    assert TOOL_PERM in pushed.plugins.per_plugin[PLUGIN_ID].granted_permissions


@pytest.mark.asyncio
async def test_set_config_refreshes_a_running_plugins_grants(tmp_path):
    """``MCPHost.set_config`` re-reads the grants, so a UI grant takes effect now.

    Without this the owner clicks Allow, the page shows Allowed, and the very
    next tool call is still denied until the Agent restarts -- which is the
    same defect wearing a different hat.
    """
    from workstation_agent.mcp_host.host import MCPHost, _PluginRuntime
    from workstation_agent.mcp_host.loader import VerifyResult

    host = MCPHost()
    runtime = _PluginRuntime(
        manifest=_manifest(tmp_path),
        verify_result=VerifyResult(status="valid"),
        granted_permissions=set(),
        status="running",
    )
    host._runtimes[PLUGIN_ID] = runtime

    cfg = AgentConfig()
    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(granted_permissions=[TOOL_PERM])
    host.set_config(cfg)

    assert runtime.granted_permissions == {TOOL_PERM}

    cfg.plugins.per_plugin[PLUGIN_ID] = PluginConfig(granted_permissions=[])
    host.set_config(cfg)
    assert runtime.granted_permissions == set()
