"""Tests: GET/POST /config routes with fake config store."""

from __future__ import annotations

import pytest

from tests.unit.ui.conftest import FakeConfigStore, FakeMCPHost, make_client
from workstation_agent.config.schema import AgentConfig


def test_config_get_renders_form(tmp_path):
    """GET /config renders the config form with current values."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.get("/config")
    assert resp.status_code == 200
    assert "Configuration" in resp.text
    assert "llm_model" in resp.text or "Model" in resp.text


def test_config_post_saves_llm_model(tmp_path):
    """POST /config with valid data saves the LLM model."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/config",
        data={
            "llm_base_url": "http://192.168.1.150:8053/v1",
            "llm_model": "claude-3",
            "llm_timeout_seconds": "60",
            "llm_streaming": "true",
            "wyoming_host": "192.168.1.150",
            "wyoming_port": "10300",
            "wake_enabled": "true",
            "wake_threshold": "0.5",
            "session_mode": "sticky",
            "session_sticky_seconds": "30",
            "update_enabled": "true",
            "update_channel": "stable",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert store._cfg.llm.model == "claude-3"
    assert "saved" in resp.text.lower() or "Settings saved" in resp.text


def test_config_post_invalid_port_shows_error(tmp_path):
    """POST /config with invalid port renders inline error."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/config",
        data={
            "llm_base_url": "http://192.168.1.150:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "60",
            "llm_streaming": "true",
            "wyoming_host": "192.168.1.150",
            "wyoming_port": "99999",  # invalid
            "wake_enabled": "true",
            "wake_threshold": "0.5",
            "session_mode": "sticky",
            "session_sticky_seconds": "30",
            "update_enabled": "true",
            "update_channel": "stable",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "65535" in resp.text or "Port" in resp.text


def test_config_post_invalid_timeout_shows_error(tmp_path):
    """POST /config with timeout=0 renders inline error."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/config",
        data={
            "llm_base_url": "http://192.168.1.150:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "-1",
            "llm_streaming": "true",
            "wyoming_host": "192.168.1.150",
            "wyoming_port": "10300",
            "wake_enabled": "true",
            "wake_threshold": "0.5",
            "session_mode": "sticky",
            "session_sticky_seconds": "30",
            "update_enabled": "true",
            "update_channel": "stable",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "Timeout" in resp.text or "timeout" in resp.text


def test_config_post_invalid_session_mode(tmp_path):
    """POST /config with invalid session mode shows error."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/config",
        data={
            "llm_base_url": "http://192.168.1.150:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "60",
            "llm_streaming": "true",
            "wyoming_host": "192.168.1.150",
            "wyoming_port": "10300",
            "wake_enabled": "true",
            "wake_threshold": "0.5",
            "session_mode": "invalid_mode",
            "session_sticky_seconds": "30",
            "update_enabled": "true",
            "update_channel": "stable",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "session" in resp.text.lower() or "mode" in resp.text.lower()


def test_config_get_no_store_returns_200(tmp_path):
    """GET /config with no config store still renders (graceful)."""
    from tests.unit.ui.conftest import _LoopbackASGI, ui_test_client
    from workstation_agent.ui.backend.app import BackendContext, create_app
    ctx = BackendContext(config_store=None, log_dir=tmp_path / "logs")
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    c = ui_test_client(wrapped)
    resp = c.get("/config")
    assert resp.status_code == 200


def test_config_post_updates_wake_threshold(tmp_path):
    """POST /config changes wake threshold correctly."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/config",
        data={
            "llm_base_url": "http://192.168.1.150:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "60",
            "wyoming_host": "192.168.1.150",
            "wyoming_port": "10300",
            "wake_threshold": "0.8",
            "session_mode": "sticky",
            "session_sticky_seconds": "30",
            "update_channel": "stable",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert store._cfg.wake.threshold == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# Confirmation policy (§7) UI — B3
# ---------------------------------------------------------------------------


def test_config_get_lists_confirmation_tools(tmp_path):
    """GET /config shows every §7 default tool with its current radio choice."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.get("/config")
    assert resp.status_code == 200
    assert "files_read" in resp.text
    assert "shell_run" in resp.text
    assert 'name="policy_files_read"' in resp.text
    assert 'name="remember_shell_run"' in resp.text


def test_confirmation_policy_post_moves_tool_between_lists(tmp_path):
    """POST /config/confirmation moves a tool from always- to never-prompt."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    # shell_run starts on the always-prompt default; move it to never-prompt
    # and leave every other default tool where it started.
    data = {}
    for tool in store._cfg.confirmation.never_prompt:
        data[f"policy_{tool}"] = "never"
    for tool in store._cfg.confirmation.always_prompt:
        data[f"policy_{tool}"] = "always"
    data["policy_shell_run"] = "never"

    resp = client.post("/config/confirmation", data=data, follow_redirects=False)
    assert resp.status_code == 200
    assert "shell_run" in store._cfg.confirmation.never_prompt
    assert "shell_run" not in store._cfg.confirmation.always_prompt
    assert "saved" in resp.text.lower()


def test_confirmation_policy_post_sets_remember_flag(tmp_path):
    """A checked "remember" box lands in confirmation.remember_for_session."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    data = {f"policy_{t}": "always" for t in store._cfg.confirmation.always_prompt}
    data.update({f"policy_{t}": "never" for t in store._cfg.confirmation.never_prompt})
    data["remember_serial_write"] = "true"

    client.post("/config/confirmation", data=data, follow_redirects=False)
    assert store._cfg.confirmation.remember_for_session == ["serial_write"]


def test_confirmation_policy_post_pushes_to_running_host(tmp_path):
    """Saving the policy pushes the new config into MCPHost.set_config live."""
    store = FakeConfigStore()
    host = FakeMCPHost()
    client = make_client(config_store=store, mcp_host=host, tmp_path=tmp_path)

    data = {f"policy_{t}": "always" for t in store._cfg.confirmation.always_prompt}
    data.update({f"policy_{t}": "never" for t in store._cfg.confirmation.never_prompt})

    client.post("/config/confirmation", data=data, follow_redirects=False)

    assert len(host.configs_set) == 1
    assert host.configs_set[0] is store._cfg


def test_confirmation_policy_post_no_store_returns_200(tmp_path):
    """POST /config/confirmation with no config store still renders gracefully."""
    from tests.unit.ui.conftest import _LoopbackASGI, ui_test_client
    from workstation_agent.ui.backend.app import BackendContext, create_app

    ctx = BackendContext(config_store=None, log_dir=tmp_path / "logs")
    app = create_app(ctx)
    c = ui_test_client(_LoopbackASGI(app))
    resp = c.post("/config/confirmation", data={})
    assert resp.status_code == 200
    assert "Config store not available" in resp.text


def test_default_confirmation_policy_matches_contract_seven():
    """AgentConfig() ships exactly contract §7's default lists."""
    cfg = AgentConfig()
    assert set(cfg.confirmation.never_prompt) == {
        "workstation_status", "devices_list", "jobs_*", "adb_devices",
        "adb_pull", "adb_logcat", "serial_ports", "serial_read",
        "serial_close", "files_list", "files_read",
    }
    assert set(cfg.confirmation.always_prompt) == {
        "shell_run", "adb_shell", "adb_push", "adb_install", "files_write",
        "serial_open", "serial_write",
    }
    assert cfg.confirmation.remember_for_session == []
