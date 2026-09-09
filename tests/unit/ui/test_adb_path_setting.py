"""Subtask P7 -- the adb binary path, set from the settings page.

The adb capability family reads ``[adb] binary_path`` straight out of
``%APPDATA%\\WorkstationAgent\\config.toml`` with ``tomllib`` (it runs in a
separate low-integrity process and cannot import the config package). Until now
there was no schema entry and no field, so the only way to point the Agent at
an ``adb.exe`` was to open the TOML file by hand -- the exact thing the owner
said must never be required.

The plugin is deliberately not modified. These tests pin the two ends the UI
now owns: the value round-trips through the form, and it lands in
``config.toml`` under the key and section the plugin already reads.
"""

from __future__ import annotations

import tomllib

import pytest

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.config.schema import AdbConfig, AgentConfig


def _settings(**overrides):
    data = {
        "llm_base_url": "http://192.168.1.150:8053/v1",
        "llm_model": "gpt-4o",
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
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# The schema entry
# ---------------------------------------------------------------------------


def test_the_default_is_empty_meaning_search_path():
    assert AgentConfig().adb.binary_path == ""


def test_binary_path_is_a_string_not_an_optional():
    """``None`` would strand a cleared field.

    ``config.store._merge_into_toml`` skips ``None`` values, so a ``None``
    ``binary_path`` would leave a previously written path sitting in
    ``config.toml`` -- an operator who cleared the field in the UI would find
    the old path still in force, with nothing on screen to explain it.
    """
    assert AgentConfig.model_fields["adb"].annotation is AdbConfig
    assert AdbConfig.model_fields["binary_path"].annotation is str


@pytest.mark.parametrize(
    ("typed", "stored"),
    [
        (r"C:\tools\adb.exe", r"C:\tools\adb.exe"),
        (r'"C:\tools\adb.exe"', r"C:\tools\adb.exe"),  # Explorer "Copy as path"
        ("  C:\\tools\\adb.exe  ", r"C:\tools\adb.exe"),
        ("", ""),
    ],
)
def test_the_value_is_normalised_the_same_way_wherever_it_arrives(typed, stored):
    assert AdbConfig(binary_path=typed).binary_path == stored


# ---------------------------------------------------------------------------
# The UI round-trip
# ---------------------------------------------------------------------------


def test_the_adb_path_round_trips_through_the_settings_page(tmp_path):
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    adb = tmp_path / "platform-tools" / "adb.exe"
    adb.parent.mkdir(parents=True)
    adb.write_bytes(b"MZ")

    saved = client.post("/config", data=_settings(adb_binary_path=str(adb)))
    assert saved.status_code == 200
    assert store.load().adb.binary_path == str(adb)

    # ...and it comes back on the next page load, in the field the operator typed it into.
    reloaded = client.get("/config")
    assert str(adb) in reloaded.text
    assert 'name="adb_binary_path"' in reloaded.text


def test_clearing_the_field_clears_the_setting(tmp_path):
    cfg = AgentConfig()
    cfg.adb.binary_path = r"C:\old\adb.exe"
    store = FakeConfigStore(cfg)
    client = make_client(config_store=store, tmp_path=tmp_path)

    client.post("/config", data=_settings(adb_binary_path=""))

    assert store.load().adb.binary_path == ""


def test_a_quoted_path_is_saved_unquoted(tmp_path):
    """"Copy as path" in Explorer yields a quoted string.

    Saved verbatim, the plugin would look for a file whose name really does
    begin with a quote character and report that the configured adb is missing.
    """
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    client.post("/config", data=_settings(adb_binary_path=r'"C:\tools\adb.exe"'))

    assert store.load().adb.binary_path == r"C:\tools\adb.exe"


def test_a_path_that_does_not_exist_saves_but_says_so(tmp_path):
    """A warning, not a refusal.

    Pointing at an adb that is about to be installed is legitimate. But the
    plugin does *not* silently fall back to PATH for a configured path that is
    missing -- it raises -- so saying nothing would leave the adb tools broken
    with the reason buried in a plugin error message.
    """
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    missing = str(tmp_path / "nowhere" / "adb.exe")
    resp = client.post("/config", data=_settings(adb_binary_path=missing))

    assert store.load().adb.binary_path == missing  # saved anyway
    assert "no file at that adb path" in resp.text
    assert "Settings saved" in resp.text


def test_a_directory_is_treated_as_missing(tmp_path):
    """``is_file``, not ``exists``: the plugin runs the path as an executable."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post("/config", data=_settings(adb_binary_path=str(tmp_path)))

    assert "no file at that adb path" in resp.text


def test_a_real_path_saves_with_no_warning(tmp_path):
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)
    adb = tmp_path / "adb.exe"
    adb.write_bytes(b"MZ")

    resp = client.post("/config", data=_settings(adb_binary_path=str(adb)))

    assert "no file at that adb path" not in resp.text
    assert "Settings saved" in resp.text


def test_an_unreadable_path_is_reported_not_a_500(tmp_path, monkeypatch):
    """``is_file`` reaches the filesystem and can raise.

    A path on a disconnected share, or one the Agent cannot traverse, raises
    ``OSError`` rather than returning False. A settings page must not 500 over
    a field it was only trying to be helpful about.
    """
    from pathlib import Path

    def _boom(_self):
        msg = "the network path was not found"
        raise OSError(msg)

    monkeypatch.setattr(Path, "is_file", _boom)

    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)
    resp = client.post("/config", data=_settings(adb_binary_path=r"\\dead-server\sdk\adb.exe"))

    assert resp.status_code == 200
    assert "could not be checked" in resp.text
    assert store.load().adb.binary_path == r"\\dead-server\sdk\adb.exe"


# ---------------------------------------------------------------------------
# The end the plugin actually reads
# ---------------------------------------------------------------------------


def test_the_saved_path_lands_where_the_adb_plugin_looks_for_it(tmp_path, monkeypatch):
    """The whole point: the real config store must write `[adb] binary_path`.

    The plugin parses ``config.toml`` with ``tomllib`` and reads
    ``doc["adb"]["binary_path"]``. If the schema entry were named or nested
    differently, the UI would save happily and the plugin would keep using
    PATH -- the failure this subtask exists to prevent, in a form no UI test
    that stops at the fake store could see.
    """
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))
    from workstation_agent.config import store as real_store

    client = make_client(config_store=real_store, tmp_path=tmp_path)
    adb = tmp_path / "adb.exe"
    adb.write_bytes(b"MZ")

    client.post("/config", data=_settings(adb_binary_path=str(adb)))

    config_toml = real_store.paths()["config_file"]
    doc = tomllib.loads(config_toml.read_text(encoding="utf-8"))
    assert doc["adb"]["binary_path"] == str(adb)

    # And the plugin's own reader agrees -- called directly, not reimplemented.
    from workstation_agent.plugins.adb import _configured_adb_path

    assert _configured_adb_path() == str(adb)


def test_clearing_the_path_actually_removes_it_from_the_file(tmp_path, monkeypatch):
    """A cleared field must reach the plugin as "not configured".

    This is the case that would have gone wrong with ``str | None``: the store
    skips ``None`` when merging, so the stale key would survive and the plugin
    would go on refusing to run against an adb the operator had removed.
    """
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))
    from workstation_agent.config import store as real_store
    from workstation_agent.plugins.adb import _configured_adb_path

    client = make_client(config_store=real_store, tmp_path=tmp_path)
    adb = tmp_path / "adb.exe"
    adb.write_bytes(b"MZ")
    client.post("/config", data=_settings(adb_binary_path=str(adb)))
    assert _configured_adb_path() == str(adb)

    client.post("/config", data=_settings(adb_binary_path=""))

    assert _configured_adb_path() is None
