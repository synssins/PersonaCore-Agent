"""Tests for workstation_agent.ui.webview.window — WebviewWindow.

WebView2 mock strategy
-----------------------
``webview`` (pywebview) is patched at the module level before the class
under test is imported:

* ``webview.create_window`` is replaced with a ``MagicMock`` that returns a
  fake window object (also a ``MagicMock``) exposing ``hide()``,
  ``show()``, ``load_url()``, and ``destroy()``.
* ``webview.start`` is replaced so it spawns ``func`` on a background thread
  and joins it with a bounded timeout.  This correctly exercises the
  periodic-drain loop (the worker runs until it receives a "stop" op or
  the join times out).

This means no WebView2 / Edge process is launched in CI.
"""

from __future__ import annotations

import threading
import time
from importlib import reload
from unittest.mock import MagicMock, patch


def _make_fake_window() -> MagicMock:
    w = MagicMock()
    w.hidden = False
    return w


def _make_fake_webview_module(fake_window: MagicMock) -> MagicMock:
    mod = MagicMock()
    mod.create_window.return_value = fake_window

    def start(func=None, args=(), **_kwargs):
        if func:
            thread = threading.Thread(target=func, args=args, daemon=True)
            thread.start()
            thread.join(timeout=2.0)  # bounded so tests don't hang forever

    mod.start.side_effect = start
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
            ww.stop()  # ensures worker exits after draining ops

            assert ww._pending_ops.qsize() == 2  # open + stop
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
            ww.stop()  # sentinel so the loop exits after processing
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
            ww.stop()  # sentinel so the loop exits
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
            ww.stop()  # ensures worker exits after draining both ops
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
            ww.stop()  # sentinel so the loop exits
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
            ww.stop()  # enqueue stop so worker exits promptly
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
            ww.stop()  # sentinel so the loop exits after the unknown op
            ww._process_queue()  # should not raise

    def test_multiple_ops_after_start(self) -> None:
        """Prove the periodic-drain loop handles ops that arrive AFTER start().

        Two ``open()`` calls are issued sequentially — the second arrives
        while the worker is already running.  Both must be processed and
        both ``load_url`` calls must be recorded.
        """
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)
        # track when the first open has been processed so we can safely issue
        # the second open on the worker thread
        first_open_done = threading.Event()

        original_load_url = fake_win.load_url

        def _load_url_side_effect(url: str) -> None:
            original_load_url(url)
            first_open_done.set()

        fake_win.load_url.side_effect = _load_url_side_effect

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")
            # Pre-create the window so both opens go through load_url
            ww._window = fake_win

            # First open is queued before start; will be processed by the worker.
            ww.open("/first")

            # Spawn a helper thread that waits for the first op to be processed
            # then enqueues a second open — simulating a caller from another thread.
            def _enqueue_second() -> None:
                first_open_done.wait(timeout=2.0)
                ww.open("/second")
                ww.stop()  # let the worker exit after the second open

            helper = threading.Thread(target=_enqueue_second, daemon=True)
            helper.start()

            ww.start()  # blocks until worker exits
            helper.join(timeout=3.0)

        load_calls = [call[0][0] for call in fake_win.load_url.call_args_list]
        assert any("/first" in url for url in load_calls), f"first not found in {load_calls}"
        assert any("/second" in url for url in load_calls), f"second not found in {load_calls}"

    def test_stop_exits_worker_promptly(self) -> None:
        """Prove the worker thread exits within 500 ms of a stop() call."""
        fake_win = _make_fake_window()
        fake_webview = _make_fake_webview_module(fake_win)

        with patch.dict("sys.modules", {"webview": fake_webview}):
            import workstation_agent.ui.webview.window as wm

            reload(wm)
            ww = wm.WebviewWindow(url_provider=lambda: "http://127.0.0.1:9999")

            worker_thread: list[threading.Thread] = []

            def _tracked_start(func=None, args=(), **_kwargs):
                if func:
                    t = threading.Thread(target=func, args=args, daemon=True)
                    worker_thread.append(t)
                    t.start()
                    t.join(timeout=2.0)

            fake_webview.start.side_effect = _tracked_start

            # Run start() on a background thread so this test thread can call stop()
            start_thread = threading.Thread(target=ww.start, daemon=True)
            start_thread.start()

            # Wait until the worker is actually running (started event is set)
            ww._started.wait(timeout=2.0)
            # Give the worker a moment to enter its blocking get()
            time.sleep(0.05)

            t0 = time.monotonic()
            ww.stop()

            assert len(worker_thread) > 0, "worker thread was never started"
            worker_thread[0].join(timeout=1.0)
            elapsed = time.monotonic() - t0

            assert not worker_thread[0].is_alive(), "worker thread did not exit after stop()"
            assert elapsed < 0.5, f"worker took {elapsed:.3f}s to exit — expected < 0.5s"

            start_thread.join(timeout=3.0)
