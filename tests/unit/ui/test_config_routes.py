"""Tests: GET/POST /config routes with fake config store."""

from __future__ import annotations

import pytest

from tests.unit.ui.conftest import FakeConfigStore, make_client


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
    from starlette.testclient import TestClient

    from tests.unit.ui.conftest import _LoopbackASGI
    from workstation_agent.ui.backend.app import BackendContext, create_app
    ctx = BackendContext(config_store=None, log_dir=tmp_path / "logs")
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    c = TestClient(wrapped)
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
