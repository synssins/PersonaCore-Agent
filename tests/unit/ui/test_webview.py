"""Tests for workstation_agent.ui.webview.window — WebviewWindow.

WebView2 mock strategy
-----------------------
``webview`` (pywebview) is patched at the module level before the class
under test is imported:

* ``webview.create_window`` is replaced with a ``MagicMock`` that returns a
  fake window object (also a ``MagicMock``) exposing ``hide()``,
  ``show()``, ``load_url()``, and ``destroy()``.
* ``webview.start`` is replaced so it calls ``func(*args)`` immediately
  (draining the queue) rather than blocking on the Windows message loop.

This means no WebView2 / Edge process is launched in CI.
"""

from __future__ import annotations

from importlib import reload
from unittest.mock import MagicMock, patch


def _make_fake_window() -> MagicMock:
    w = MagicMock()
    w.hidden = False
    return w


def _make_fake_webview_module(fake_window: MagicMock) -> MagicMock:
    mod = MagicMock()
    mod.create_window.return_value = fake_window

    def _start(func=None, args=(), **_kwargs):
        if func is not None:
            func(*args)

    mod.start.side_effect = _start
    return mod


class TestWebviewWindowQueueing:
    def test_open_before_start_is_queued(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww.open("/dashboard")

            assert ww._pending_ops.qsize() == 1
            ww.start()

        fake_webview.create_window.assert_called_once()
        _, kwargs = fake_webview.create_window.call_args
        assert "/dashboard" in kwargs["url"]

    def test_open_after_start_navigates_existing_window(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww._window = fake_win
            ww.open("/settings")
            ww._process_queue()

        fake_webview.create_window.assert_not_called()
        fake_win.load_url.assert_called_once()
        assert "/settings" in fake_win.load_url.call_args[0][0]

    def test_close_hides_window(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww._window = fake_win
            ww.close()
            ww._process_queue()

        fake_win.hide.assert_called_once()

    def test_stop_destroys_window(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww._window = fake_win
            ww.stop()
            ww._process_queue()

        fake_win.destroy.assert_called_once()
        assert ww._window is None

    def test_multiple_ops_drained_in_order(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)
        call_order: list[str] = []

        def _create(*_args, **_kwargs):
            call_order.append("create")
            return fake_win

        fake_webview.create_window.side_effect = _create
        fake_win.load_url.side_effect = lambda url: call_order.append(f"load:{url}")

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww.open("/a")
            ww.open("/b")
            ww.start()

        assert call_order[0] == "create"
        assert "load" in call_order[1]
        assert "/b" in call_order[1]

    def test_configure_replaces_url_provider(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://old:1111")
            ww.configure(lambda: "http://new:2222")
            ww.open("/x")
            ww._process_queue()

        _, kwargs = fake_webview.create_window.call_args
        assert "new:2222" in kwargs["url"]

    def test_start_sets_started_and_stopped_events(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww.start()

        assert ww._started.is_set()
        assert ww._stopped.is_set()

    def test_default_url_provider_fallback(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("APPDATA", str(tmp_path))
        fake_webview = _make_fake_webview_module(_make_fake_window())

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow()
            url = ww._url_provider()

        assert "8765" in url

    def test_default_url_provider_reads_port_file(self, tmp_path, monkeypatch) -> None:
        port_dir = tmp_path / "WorkstationAgent"
        port_dir.mkdir()
        (port_dir / "ui-port").write_text("9876")
        monkeypatch.setenv("APPDATA", str(tmp_path))

        fake_webview = _make_fake_webview_module(_make_fake_window())

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow()
            url = ww._url_provider()

        assert "9876" in url

    def test_process_queue_handles_unknown_op(self) -> None:
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            ww._pending_ops.put(("unknown_op", None))
            ww._process_queue()  # should not raise
