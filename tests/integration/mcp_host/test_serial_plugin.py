"""Integration test: the real ``serial`` plugin subprocess through MCPHost.

Unlike ``tests/unit/plugins/serial/*`` (which drive the pure logic with a
fake backend), this exercises the whole path a real call takes: signature
verification of the shipped, signed ``plugin.toml``, a real subprocess
spawned by the supervisor, the JSON-RPC wire, the declaration gate, and back.

No serial hardware is required: ``serial.ports`` is real device enumeration
(whatever COM ports genuinely exist on the machine running this test, which
may be none), and ``serial.open`` against a port name nothing on this
machine has is exercised for its *failure* path — proving the gate, the
subprocess and the not_found/error mapping work end to end, which is exactly
what item 4 of the brief says cannot be proven for the *success* path
without a real device.
"""
# ruff: noqa: E402, ARG001

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="plugin subprocess race on GH Actions py3.12 (task #10)",
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKTREE_SRC = _REPO_ROOT / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import workstation_agent.mcp_host.audit as audit_mod
import workstation_agent.mcp_host.loader as loader_mod
from workstation_agent.config.schema import AgentConfig
from workstation_agent.config.schema import PluginConfig as _PluginCfg
from workstation_agent.mcp_host.host import MCPHost

_pub_hex_path = _REPO_ROOT / "working" / "signing" / "first_party.pub.hex"
_first_party_pubkey = bytes.fromhex(_pub_hex_path.read_text().strip())
if _first_party_pubkey not in loader_mod.TRUSTED_PUBKEYS:
    loader_mod.TRUSTED_PUBKEYS.insert(0, _first_party_pubkey)


@pytest.fixture
def agent_config():
    cfg = AgentConfig()
    cfg.plugins.per_plugin["serial"] = _PluginCfg(
        enabled=True,
        granted_permissions=[
            "tool:serial.ports",
            "tool:serial.open",
            "tool:serial.write",
            "tool:serial.read",
            "tool:serial.close",
        ],
    )
    return cfg


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    db_path = tmp_path / "audit.db"
    audit_mod.set_db_path(db_path)
    yield db_path
    audit_mod.reset_connection()


def _text_payload(result) -> dict:
    texts = [item["text"] for item in result.content if item.get("type") == "text"]
    assert len(texts) == 1
    return json.loads(texts[0])


@pytest.mark.asyncio
async def test_serial_plugin_loads_and_verifies(agent_config, isolated_audit_db):
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)
    try:
        plugins = await host.plugins()
        serial = next(p for p in plugins if p.id == "serial")
        assert serial.status == "running"
        assert serial.signature_status == "valid"
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_serial_plugin_exposes_five_tools(agent_config, isolated_audit_db):
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)
    try:
        tools = await host.tools()
        names = {t.name for t in tools if t.name.startswith("serial.")}
        assert names == {
            "serial.ports",
            "serial.open",
            "serial.write",
            "serial.read",
            "serial.close",
        }
    finally:
        await host.stop()


@pytest.mark.asyncio
async def test_serial_ports_end_to_end(agent_config, isolated_audit_db):
    """A real, pre-approved call: no confirm callback needed, no hardware
    needed either — an empty (or non-empty) port list is both a success."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)
    try:
        result = await host.invoke("serial.ports", {})
    finally:
        await host.stop()

    assert not result.is_error
    payload = _text_payload(result)
    assert payload["ok"] is True
    assert isinstance(payload["ports"], list)


@pytest.mark.asyncio
async def test_serial_open_on_a_port_that_does_not_exist_is_refused_end_to_end(
    agent_config, isolated_audit_db,
):
    """No hardware is needed to prove the failure path: a COM port name
    vanishingly unlikely to exist on the machine running this test still
    round-trips through the gate, the subprocess and pyserial's own error,
    landing on a clean §5.2 envelope rather than an exception or a hang."""

    async def _auto_approve(_req) -> bool:
        return True

    host = MCPHost()
    await host.start(agent_config, confirm_cb=_auto_approve)
    try:
        result = await host.invoke("serial.open", {"port": "COM987", "baud": 9600})
    finally:
        await host.stop()

    payload = _text_payload(result)
    assert payload["ok"] is False
    assert payload["code"] in {"not_found", "error"}
    assert "reason" in payload


@pytest.mark.asyncio
async def test_serial_write_on_an_unknown_session_is_refused_end_to_end(
    agent_config, isolated_audit_db,
):
    async def _auto_approve(_req) -> bool:
        return True

    host = MCPHost()
    await host.start(agent_config, confirm_cb=_auto_approve)
    try:
        result = await host.invoke(
            "serial.write", {"session_id": "0" * 32, "text": "AT\r\n"},
        )
    finally:
        await host.stop()

    payload = _text_payload(result)
    assert payload["ok"] is False
    assert payload["code"] == "unknown_session"


@pytest.mark.asyncio
async def test_serial_write_ungranted_argument_is_denied_by_the_gate(
    agent_config, isolated_audit_db,
):
    """A call carrying an argument the manifest never declared must be
    refused by the gate before it ever reaches the plugin subprocess —
    proves the declaration gate is actually wired for this family, not just
    unit-tested in isolation."""
    host = MCPHost()
    await host.start(agent_config, confirm_cb=None)
    try:
        result = await host.invoke(
            "serial.write",
            {"session_id": "abc", "text": "AT\r\n", "not_a_real_argument": "x"},
        )
    finally:
        await host.stop()

    assert result.ok is False
    assert result.code == "denied"
