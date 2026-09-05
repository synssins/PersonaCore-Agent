"""Tests: plugin enable/disable, grant, install, reload routes."""

from __future__ import annotations

import io

from tests.unit.ui.conftest import FakeConfigStore, FakeMCPHost, FakePluginInfo, make_client
from workstation_agent.config.schema import PluginConfig


def _client_with_plugin(tmp_path, plugin_id="test_plugin", **kwargs):
    store = FakeConfigStore()
    plugin = FakePluginInfo(id=plugin_id, **kwargs)
    host = FakeMCPHost(plugins_list=[plugin])
    return make_client(config_store=store, mcp_host=host, tmp_path=tmp_path), store, host


def test_plugins_list_renders(tmp_path):
    """GET /plugins renders the plugins list."""
    client, _store, _ = _client_with_plugin(tmp_path)
    resp = client.get("/plugins")
    assert resp.status_code == 200
    assert "Plugins" in resp.text
    assert "test_plugin" in resp.text


def test_plugin_enable_persists(tmp_path):
    """POST /plugins/{id}/enable writes enabled=True to config store."""
    client, store, _ = _client_with_plugin(tmp_path)
    # Pre-set to disabled
    store._cfg.plugins.per_plugin["test_plugin"] = PluginConfig(enabled=False)

    resp = client.post("/plugins/test_plugin/enable", follow_redirects=False)
    assert resp.status_code == 303
    assert store._cfg.plugins.per_plugin["test_plugin"].enabled is True


def test_plugin_disable_persists(tmp_path):
    """POST /plugins/{id}/disable writes enabled=False to config store."""
    client, store, _ = _client_with_plugin(tmp_path)

    resp = client.post("/plugins/test_plugin/disable", follow_redirects=False)
    assert resp.status_code == 303
    assert store._cfg.plugins.per_plugin["test_plugin"].enabled is False


def test_plugin_grant_permission(tmp_path):
    """POST /plugins/{id}/grant/{perm} adds perm to granted_permissions."""
    client, store, _ = _client_with_plugin(tmp_path)

    resp = client.post("/plugins/test_plugin/grant/filesystem:read", follow_redirects=False)
    assert resp.status_code == 303
    perms = store._cfg.plugins.per_plugin["test_plugin"].granted_permissions
    assert "filesystem:read" in perms


def test_plugin_grant_no_duplicate(tmp_path):
    """Granting an already-held permission doesn't duplicate it."""
    client, store, _ = _client_with_plugin(tmp_path)
    store._cfg.plugins.per_plugin["test_plugin"] = PluginConfig(
        granted_permissions=["filesystem:read"],
    )

    client.post("/plugins/test_plugin/grant/filesystem:read", follow_redirects=False)
    perms = store._cfg.plugins.per_plugin["test_plugin"].granted_permissions
    assert perms.count("filesystem:read") == 1


def test_plugin_install_file_requires_acknowledgment(tmp_path):
    """POST /plugins/install-file without acknowledged=true returns 400."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/install-file",
        files={"plugin_file": ("plugin.zip", io.BytesIO(b"fake zip"), "application/zip")},
        data={"acknowledged": "false"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "acknowledgment" in resp.text.lower() or "acknowledged" in resp.text.lower()


def test_plugin_install_file_with_acknowledgment(tmp_path):
    """POST /plugins/install-file with acknowledged=true succeeds."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/install-file",
        files={"plugin_file": ("plugin.zip", io.BytesIO(b"fake zip"), "application/zip")},
        data={"acknowledged": "true"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_plugin_install_file_allowed_unsigned(tmp_path):
    """POST /plugins/install-file without ack succeeds when allow_unsigned=True."""
    store = FakeConfigStore()
    store._cfg.plugins.allow_unsigned = True
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/install-file",
        files={"plugin_file": ("plugin.zip", io.BytesIO(b"fake zip"), "application/zip")},
        data={"acknowledged": "false"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_plugin_reload(tmp_path):
    """POST /plugins/{id}/reload calls mcp_host.reload()."""
    client, _store, host = _client_with_plugin(tmp_path)

    resp = client.post("/plugins/test_plugin/reload", follow_redirects=False)
    assert resp.status_code == 303
    assert "test_plugin" in host.reloaded


def test_plugin_install_registry_redirects(tmp_path):
    """POST /plugins/install-registry redirects back to /plugins."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/install-registry",
        data={"registry_url": "https://registry.example.com/plugin.json"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/plugins" in resp.headers["location"]
