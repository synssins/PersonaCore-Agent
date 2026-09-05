"""Tests for workstation_agent.ui.systray.tray — SystemTray.

pystray is mocked: ``pystray.Icon`` is replaced with a spy so that
``run_detached()`` is a no-op and menu callbacks can be invoked directly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from workstation_agent.ui.systray.tray import SystemTray


@pytest.fixture
def mock_webview():
    return MagicMock()


@pytest.fixture
def mock_httpx(monkeypatch):
    """Replace httpx.post so no real HTTP calls are made."""
    mock_post = MagicMock()
    monkeypatch.setattr("workstation_agent.ui.systray.tray.httpx.post", mock_post)
    return mock_post


@pytest.fixture
def tray(mock_webview, mock_httpx):  # noqa: ARG001
    exit_calls: list[int] = []

    def _on_exit() -> None:
        exit_calls.append(1)

    st = SystemTray(
        webview_window=mock_webview,
        url_provider=lambda: "http://127.0.0.1:9999",
        on_exit=_on_exit,
        logs_dir="/logs",
        pending_plugin_count=lambda: 0,
    )
    # Store on tray so test_exit_calls_on_exit can inspect it
    object.__setattr__(st, "_exit_calls", exit_calls)
    return st


def test_build_menu_returns_menu(tray):
    import pystray

    menu = tray._build_menu()
    assert isinstance(menu, pystray.Menu)


def test_build_menu_badge_with_pending(mock_webview):
    st = SystemTray(
        webview_window=mock_webview,
        url_provider=lambda: "http://127.0.0.1:9999",
        pending_plugin_count=lambda: 3,
    )
    menu = st._build_menu()
    labels = [
        item.text
        for item in (menu.items or [])  # type: ignore[union-attr]
        if item is not None and hasattr(item, "text")
    ]
    reload_labels = [lbl for lbl in labels if "Reload" in str(lbl)]
    assert reload_labels, "Reload item not found"
    assert "3" in str(reload_labels[0])


def test_on_open_calls_webview(tray, mock_webview):
    tray._on_open(MagicMock(), MagicMock())
    mock_webview.open.assert_called_once_with("/dashboard")


def test_mute_toggle_changes_state(tray, mock_httpx):  # noqa: ARG001
    assert tray._muted is False
    tray._on_mute_toggle(MagicMock(), MagicMock())
    assert tray._muted is True
    tray._on_mute_toggle(MagicMock(), MagicMock())
    assert tray._muted is False


def test_mute_toggle_posts_config(tray, mock_httpx):
    tray._on_mute_toggle(MagicMock(), MagicMock())
    mock_httpx.assert_called_once()
    assert "/config" in mock_httpx.call_args[0][0]


def test_session_mode_action_updates_state(tray, mock_httpx):  # noqa: ARG001
    action = tray._make_session_mode_action("sticky")
    action(MagicMock(), MagicMock())
    assert tray._session_mode == "sticky"


def test_session_mode_action_posts_config(tray, mock_httpx):
    action = tray._make_session_mode_action("persistent")
    action(MagicMock(), MagicMock())
    mock_httpx.assert_called_once()
    assert "/config" in mock_httpx.call_args[0][0]


def test_reload_plugins_posts(tray, mock_httpx):
    tray._on_reload_plugins(MagicMock(), MagicMock())
    mock_httpx.assert_called_once()
    assert "/plugins/reload" in mock_httpx.call_args[0][0]


def test_reload_plugins_tolerates_http_error(tray, mock_httpx):
    mock_httpx.side_effect = Exception("network error")
    tray._on_reload_plugins(MagicMock(), MagicMock())  # must not raise


def test_check_updates_posts(tray, mock_httpx):
    tray._on_check_updates(MagicMock(), MagicMock())
    mock_httpx.assert_called_once()
    assert "/about/check-updates" in mock_httpx.call_args[0][0]


def test_open_config_opens_webview(tray, mock_webview):
    tray._on_open_config(MagicMock(), MagicMock())
    mock_webview.open.assert_called_once_with("/config")


def test_show_audit_log_opens_webview(tray, mock_webview):
    tray._on_show_audit_log(MagicMock(), MagicMock())
    mock_webview.open.assert_called_once_with("/audit-log")


def test_about_opens_webview(tray, mock_webview):
    tray._on_about(MagicMock(), MagicMock())
    mock_webview.open.assert_called_once_with("/about")


def test_show_logs_folder_calls_startfile(tray, monkeypatch):
    import os

    startfile_calls: list[str] = []
    monkeypatch.setattr(
        "workstation_agent.ui.systray.tray.os.startfile",
        startfile_calls.append,
    )
    tray._on_show_logs_folder(MagicMock(), MagicMock())
    assert len(startfile_calls) == 1
    assert os.path.normpath(startfile_calls[0]) == os.path.normpath("/logs")


def test_show_logs_folder_tolerates_error(tray, monkeypatch):
    def _raise(_p):
        msg = "no such dir"
        raise OSError(msg)

    monkeypatch.setattr("workstation_agent.ui.systray.tray.os.startfile", _raise)
    tray._on_show_logs_folder(MagicMock(), MagicMock())  # must not raise


def test_exit_calls_on_exit(tray):
    with patch.object(tray, "stop"):
        tray._on_exit_action(MagicMock(), MagicMock())
    assert tray._exit_calls == [1]


def test_run_detached_calls_icon_run_detached():
    with patch("workstation_agent.ui.systray.tray.pystray.Icon") as mock_icon_cls:
        mock_icon_instance = MagicMock()
        mock_icon_cls.return_value = mock_icon_instance
        st = SystemTray(url_provider=lambda: "http://127.0.0.1:9999")
        st.run_detached()
        mock_icon_instance.run_detached.assert_called_once()


def test_stop_calls_icon_stop():
    with patch("workstation_agent.ui.systray.tray.pystray.Icon") as mock_icon_cls:
        mock_icon_instance = MagicMock()
        mock_icon_cls.return_value = mock_icon_instance
        st = SystemTray(url_provider=lambda: "http://127.0.0.1:9999")
        st.run_detached()
        st.stop()
        mock_icon_instance.stop.assert_called_once()
        assert st._icon is None


def test_stop_when_no_icon_is_noop():
    st = SystemTray(url_provider=lambda: "http://127.0.0.1:9999")
    st.stop()  # must not raise


def test_default_url_provider_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    url = SystemTray._default_url_provider()
    assert "8765" in url


def test_default_url_provider_reads_file(tmp_path, monkeypatch):
    d = tmp_path / "WorkstationAgent"
    d.mkdir()
    (d / "ui-port").write_text("5432")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    url = SystemTray._default_url_provider()
    assert "5432" in url


def test_update_plugin_badge_refreshes_menu(mock_webview):
    with patch("workstation_agent.ui.systray.tray.pystray.Icon") as mock_icon_cls:
        mock_icon = MagicMock()
        mock_icon_cls.return_value = mock_icon
        st = SystemTray(
            webview_window=mock_webview,
            url_provider=lambda: "http://127.0.0.1:9999",
        )
        st.run_detached()
        st.update_plugin_badge()
        mock_icon.update_menu.assert_called_once()


def test_post_config_tolerates_http_error(tray, mock_httpx):
    mock_httpx.side_effect = Exception("timeout")
    tray._post_config({"key": "value"})  # must not raise
