"""Tests: plugin enable/disable, grant, install, reload routes."""

from __future__ import annotations

import io

import pytest

from tests.unit.ui.conftest import FakeConfigStore, FakeMCPHost, FakePluginInfo, make_client
from workstation_agent.config.schema import PluginConfig
from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.ui.backend.routers import plugins_routes


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


def _fake_manifest(
    tmp_path,
    plugin_id: str = "quarantined_plugin",
    name: str = "Quarantined Plugin",
) -> PluginManifest:
    """A manifest whose signature file does not exist.

    ``loader.verify`` returns ``quarantined`` (or ``unsigned`` if the caller's
    ``allow_unsigned`` is ``True``) for this without needing a real plugin
    tree -- the missing-signature-file branch is checked before any file is
    hashed. This lets tests exercise the *real* ``discover``/``verify``
    functions rather than mocking their output.
    """
    plugin_dir = tmp_path / plugin_id
    plugin_dir.mkdir(parents=True, exist_ok=True)
    return PluginManifest(
        id=plugin_id,
        name=name,
        version="1.0.0",
        runtime="python",
        entry=[],
        plugin_dir=plugin_dir,
        signature_file=plugin_dir / "signature.sig",
    )


def test_signature_verification_default_on_fresh_install(tmp_path):
    """A fresh install (default AgentConfig) shows verification ON."""
    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)

    resp = client.get("/plugins")
    assert resp.status_code == 200
    assert "ON" in resp.text
    assert "unsigned or tampered plugins are quarantined" in resp.text


def test_signature_verification_off_state_is_visually_distinct(tmp_path):
    """The OFF state uses the danger/error styling, not the safe one."""
    store = FakeConfigStore()
    store._cfg.plugins.allow_unsigned = True
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.get("/plugins")
    assert resp.status_code == 200
    assert "OFF" in resp.text
    assert 'class="error"' in resp.text


def test_signature_verification_page_uses_real_loader_state(tmp_path, monkeypatch):
    """The affected-plugins list comes from loader.discover/verify, not a hardcoded list."""
    manifest = _fake_manifest(tmp_path)
    monkeypatch.setattr(plugins_routes, "discover", lambda: [manifest])

    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)
    resp = client.get("/plugins")

    assert resp.status_code == 200
    assert "Quarantined Plugin (quarantined)" in resp.text


def test_signature_verification_reflects_unsigned_when_allowed(tmp_path, monkeypatch):
    """The same plugin shows as 'unsigned' rather than 'quarantined' once allowed."""
    manifest = _fake_manifest(tmp_path, plugin_id="p2", name="Formerly Quarantined")
    monkeypatch.setattr(plugins_routes, "discover", lambda: [manifest])

    store = FakeConfigStore()
    store._cfg.plugins.allow_unsigned = True
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.get("/plugins")
    assert resp.status_code == 200
    assert "Formerly Quarantined (unsigned)" in resp.text


def test_signature_verification_enable_persists_without_confirmation(tmp_path):
    """POST enable (return to the safe state) persists immediately, no confirm step."""
    store = FakeConfigStore()
    store._cfg.plugins.allow_unsigned = True
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post("/plugins/signature-verification/enable", follow_redirects=False)
    assert resp.status_code == 303
    assert store._cfg.plugins.allow_unsigned is False


def test_signature_verification_disable_requires_confirmation(tmp_path):
    """First POST without confirm=true does not persist and shows the consequence."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post("/plugins/signature-verification/disable", follow_redirects=False)

    assert resp.status_code == 200
    assert store._cfg.plugins.allow_unsigned is False
    text = resp.text.lower()
    assert "tampered" in text
    assert "shell commands" in text
    assert 'name="confirm" value="true"' in resp.text


def test_signature_verification_disable_confirmed_persists(tmp_path):
    """POST with confirm=true actually flips and persists the setting."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/signature-verification/disable",
        data={"confirm": "true"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert store._cfg.plugins.allow_unsigned is True


def test_signature_verification_confirmation_names_affected_plugins(tmp_path, monkeypatch):
    """The confirmation step names the real plugin(s) it would let run unverified."""
    manifest = _fake_manifest(tmp_path, plugin_id="p3", name="Affected Plugin")
    monkeypatch.setattr(plugins_routes, "discover", lambda: [manifest])

    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post("/plugins/signature-verification/disable", follow_redirects=False)

    assert resp.status_code == 200
    assert "Affected Plugin" in resp.text
    assert store._cfg.plugins.allow_unsigned is False


def test_signature_verification_page_states_restart_or_reload_needed(tmp_path):
    """The page tells the truth about when the change actually takes effect."""
    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)

    resp = client.get("/plugins")
    assert resp.status_code == 200
    text = resp.text.lower()
    assert "restart" in text
    assert "reload" in text


@pytest.mark.parametrize("truthy", ["true", "1", "yes", "on", "TRUE"])
def test_signature_verification_disable_accepts_truthy_confirm_values(tmp_path, truthy):
    """Confirm accepts the same truthy spellings the rest of this router uses."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/plugins/signature-verification/disable",
        data={"confirm": truthy},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert store._cfg.plugins.allow_unsigned is True


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
