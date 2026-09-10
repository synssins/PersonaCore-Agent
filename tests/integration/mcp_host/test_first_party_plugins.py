"""Integration test: verify all six first-party plugin stubs load and work.

Tests:
1. MCPHost.start() discovers and loads all six plugins.
2. Each plugin's tools appear in MCPHost.tools() output with correct schemas.
3. Invoking any tool returns the not_implemented payload.
4. Signature verification passes for all six (using first-party keypair).
"""
# ruff: noqa: E402, ARG001

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
# Add the worktree src directory FIRST to prioritize it over the main install
_WORKTREE_SRC = _REPO_ROOT / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import workstation_agent.mcp_host.audit as audit_mod
import workstation_agent.mcp_host.loader as loader_mod
from workstation_agent.config.schema import AgentConfig
from workstation_agent.mcp_host.host import MCPHost

# Load the first-party public key and add to TRUSTED_PUBKEYS
_pub_hex_path = _REPO_ROOT / "working" / "signing" / "first_party.pub.hex"
_first_party_pubkey_hex = _pub_hex_path.read_text().strip()
_first_party_pubkey = bytes.fromhex(_first_party_pubkey_hex)
loader_mod.TRUSTED_PUBKEYS.insert(0, _first_party_pubkey)


@pytest.fixture
def agent_config():
    """Minimal AgentConfig with allow_unsigned=True and all tool grants.

    Under the SPEC-03B default-deny permissions model, each tool must be
    granted in the user config for invocation to succeed.
    """
    from workstation_agent.config.schema import PluginConfig as _PluginCfg

    cfg = AgentConfig()
    # We have real signatures signed with first-party key

    # Grant all declared tools for all six plugins
    cfg.plugins.per_plugin["filesystem"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:filesystem.list",
            "tool:filesystem.read",
            "tool:filesystem.write",
            "tool:filesystem.delete",
        ],
    )
    cfg.plugins.per_plugin["powershell"] = _PluginCfg(
        enabled=True,
        granted_permissions=["tool:powershell.run"],
    )
    cfg.plugins.per_plugin["desktop_control"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:desktop.click",
            "tool:desktop.type",
            "tool:desktop.key",
            "tool:desktop.list_windows",
            "tool:desktop.focus_window",
        ],
    )
    cfg.plugins.per_plugin["browser"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:browser.open",
            "tool:browser.screenshot",
            "tool:browser.click",
            "tool:browser.type",
            "tool:browser.eval",
        ],
    )
    cfg.plugins.per_plugin["screen_vision"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:screen.capture",
            "tool:screen.capture_ocr",
            "tool:screen.list_monitors",
        ],
    )
    cfg.plugins.per_plugin["clipboard"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:clipboard.get",
            "tool:clipboard.set",
            "tool:clipboard.clear",
        ],
    )
    return cfg


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    """Each integration test gets its own audit DB."""
    db_path = tmp_path / "audit.db"
    audit_mod.set_db_path(db_path)
    yield db_path
    audit_mod.reset_connection()


@pytest.mark.asyncio
async def test_all_six_plugins_load(agent_config, isolated_audit_db):
    """All six plugins load and appear in MCPHost.plugins()."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        plugin_list = await host.plugins()
        plugin_ids = [p.id for p in plugin_list]

        expected_plugins = [
            "filesystem",
            "powershell",
            "desktop_control",
            "browser",
            "screen_vision",
            "clipboard",
        ]
        for pid in expected_plugins:
            assert pid in plugin_ids, f"{pid} not in plugins: {plugin_ids}"

        for p in plugin_list:
            if p.id in expected_plugins:
                assert p.status == "running", f"expected {p.id} running, got {p.status}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_filesystem_tools_list(agent_config, isolated_audit_db):
    """filesystem plugin exposes 4 tools with correct schemas."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        fs_tools = [t for t in tools if t.name.startswith("filesystem.")]
        assert len(fs_tools) == 4, f"expected 4 filesystem tools, got {len(fs_tools)}"

        expected = {"filesystem.list", "filesystem.read", "filesystem.write", "filesystem.delete"}
        actual = {t.name for t in fs_tools}
        assert actual == expected, f"filesystem tools mismatch: {actual}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_powershell_tools_list(agent_config, isolated_audit_db):
    """powershell plugin exposes 1 tool."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        ps_tools = [t for t in tools if t.name.startswith("powershell.")]
        assert len(ps_tools) == 1, f"expected 1 powershell tool, got {len(ps_tools)}"
        assert ps_tools[0].name == "powershell.run"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_desktop_control_tools_list(agent_config, isolated_audit_db):
    """desktop_control plugin exposes 5 tools."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        dc_tools = [t for t in tools if t.name.startswith("desktop.")]
        assert len(dc_tools) == 5, f"expected 5 desktop tools, got {len(dc_tools)}"

        expected = {
            "desktop.click",
            "desktop.type",
            "desktop.key",
            "desktop.list_windows",
            "desktop.focus_window",
        }
        actual = {t.name for t in dc_tools}
        assert actual == expected, f"desktop tools mismatch: {actual}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_browser_tools_list(agent_config, isolated_audit_db):
    """browser plugin exposes 5 tools."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        br_tools = [t for t in tools if t.name.startswith("browser.")]
        assert len(br_tools) == 5, f"expected 5 browser tools, got {len(br_tools)}"

        expected = {
            "browser.open",
            "browser.screenshot",
            "browser.click",
            "browser.type",
            "browser.eval",
        }
        actual = {t.name for t in br_tools}
        assert actual == expected, f"browser tools mismatch: {actual}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_screen_vision_tools_list(agent_config, isolated_audit_db):
    """screen_vision plugin exposes 3 tools."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        sv_tools = [t for t in tools if t.name.startswith("screen.")]
        assert len(sv_tools) == 3, f"expected 3 screen tools, got {len(sv_tools)}"

        expected = {"screen.capture", "screen.capture_ocr", "screen.list_monitors"}
        actual = {t.name for t in sv_tools}
        assert actual == expected, f"screen tools mismatch: {actual}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_clipboard_tools_list(agent_config, isolated_audit_db):
    """clipboard plugin exposes 3 tools."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)

    try:
        tools = await host.tools()
        cb_tools = [t for t in tools if t.name.startswith("clipboard.")]
        assert len(cb_tools) == 3, f"expected 3 clipboard tools, got {len(cb_tools)}"

        expected = {"clipboard.get", "clipboard.set", "clipboard.clear"}
        actual = {t.name for t in cb_tools}
        assert actual == expected, f"clipboard tools mismatch: {actual}"

    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_invoke_returns_not_implemented(agent_config, isolated_audit_db):
    """Invoking any tool returns not_implemented status."""
    host = MCPHost()

    # Auto-approve any runtime confirmation prompts so the stub-invocation
    # test doesn't have to shape args to fit each plugin's declared_paths /
    # command allowlist — we're testing the wire, not the guard rails.
    async def _auto_approve(_req) -> bool:
        return True

    await host.start(agent_config, confirm_cb=_auto_approve)

    try:
        # Test one tool from each plugin.  filesystem.read is given a path
        # INSIDE the plugin's declared roots: an out-of-roots read is denied
        # outright now (contract §11 item 6) and can no longer be waved
        # through by the auto-approver, which is asserted separately in
        # test_filesystem_read_outside_roots_is_denied below.
        test_cases = [
            ("filesystem.read", {"path": os.path.expandvars(
                r"%USERPROFILE%\Documents\probe.txt",
            )}),
            ("powershell.run", {"intent": "test", "command": "echo test"}),
            ("desktop.click", {"x": 100, "y": 100}),
            ("browser.open", {"url": "http://example.com"}),
            ("screen.capture", {}),
            ("clipboard.get", {}),
        ]

        for tool_name, args in test_cases:
            result = await host.invoke(tool_name, args)
            assert not result.is_error, f"{tool_name} returned error"

            # Extract the text content
            texts = [item["text"] for item in result.content if item.get("type") == "text"]
            assert len(texts) >= 1, f"{tool_name} returned no text"

            # Parse the JSON response
            response = json.loads(texts[0])
            assert (
                response["status"] == "not_implemented"
            ), f"{tool_name} status != not_implemented"
            valid_plugins = [
                "filesystem",
                "powershell",
                "desktop_control",
                "browser",
                "screen_vision",
                "clipboard",
            ]
            assert response["plugin"] in valid_plugins
            assert response["tool"] == tool_name

    finally:
        await host.stop()


# ---------------------------------------------------------------------------
# The read/action split, end to end through the real filesystem plugin
# (contract §11 item 6).  The unit-level proof lives in
# tests/unit/mcp_host/test_read_action_split.py; this asserts it holds with
# the real plugin.toml, the real signature check and a real subprocess.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filesystem_read_outside_roots_is_denied(agent_config, isolated_audit_db):
    """An out-of-roots read is DENIED, is not ALLOWED, and raises no prompt.

    Three separate assertions on purpose.  "No prompt appeared" passes both
    for the correct fix and for the catastrophic one (falling through to
    allow), so it cannot be the only thing checked; and "denied" is asserted
    positively rather than inferred from "not allowed".
    """
    prompts: list[object] = []

    async def _record_and_approve(req) -> bool:
        prompts.append(req)
        return True  # would approve — so a prompt means the read went through

    host = MCPHost()
    await host.start(agent_config, confirm_cb=_record_and_approve)
    try:
        result = await host.invoke("filesystem.read", {"path": r"C:\Windows\System32\config\SAM"})
    finally:
        await host.stop()

    # 1. It is denied.
    assert result.ok is False
    assert result.code == "denied"

    # 2. It is NOT allowed.  The catastrophic regression (a checker that
    #    returns False for reads, skipping the confirm AND the hard guard,
    #    falling through to `return "allow"`) produces a successful
    #    not_implemented payload here with ok=True and no code.
    assert result.code != "allow"
    assert result.ok is not True
    body = result.content[0]["text"]
    assert "not_implemented" not in body, "the tool ran: the read was allowed, not denied"

    # 3. No prompt was raised.  The brief forbids prompting for reads.
    assert prompts == [], "an out-of-roots read must never be put to the operator"

    # …and it says so in plain English without echoing the path back (§5.2
    # forbids returning an absolute path outside a declared root).
    assert result.reason
    assert "SAM" not in result.reason
    assert "C:" not in result.reason

    rows = audit_mod.query(
        audit_mod.AuditQuery(event="tool_denied"), db_path=isolated_audit_db,
    )
    assert any(r.tool_id == "filesystem.read" and r.code == "denied" for r in rows)


@pytest.mark.asyncio
async def test_filesystem_write_outside_roots_still_confirms(agent_config, isolated_audit_db):
    """An out-of-roots *write* still goes to the operator — the split is a split.

    If the read fix had been implemented by disabling the path condition
    wholesale, this would silently allow instead of prompting.
    """
    from workstation_agent.mcp_host.host import ConfirmationRequestImpl

    prompts: list[ConfirmationRequestImpl] = []

    async def _record_and_approve(req: ConfirmationRequestImpl) -> bool:
        prompts.append(req)
        return True

    host = MCPHost()
    await host.start(agent_config, confirm_cb=_record_and_approve)
    try:
        result = await host.invoke(
            "filesystem.write", {"path": r"C:\Windows\System32\evil.txt", "content": "x"},
        )
    finally:
        await host.stop()

    assert len(prompts) == 1, "an out-of-roots write must be put to the operator"
    assert prompts[0].tool_id == "filesystem.write"
    assert prompts[0].condition == "outside_declared_paths"
    assert result.ok is True  # the operator approved it
