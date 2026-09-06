"""WebviewWindow — thin wrapper around pywebview for PersonaCore-Agent.

Threading model
---------------
``start()`` **MUST BE CALLED FROM THE MAIN THREAD**.  It calls
``webview.start(gui="edgechromium")``, which is a blocking main-thread call
that owns the Windows message loop for the lifetime of the process.

All other public methods (``open``, ``close``, ``stop``) are thread-safe.
They enqueue an operation onto ``_pending_ops`` (a ``queue.SimpleQueue``).
``_process_queue`` is registered with pywebview as a periodic callback and
drains that queue inside the main-thread message loop.

SPEC-10 is responsible for wiring the composition root so that asyncio runs
on a background thread and ``WebviewWindow.start()`` is called on ``main()``.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import TYPE_CHECKING, Any

import webview

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)


class WebviewWindow:
    """Manages a single pywebview / WebView2 window.

    Parameters
    ----------
    title:
        Window title string.
    url_provider:
        Callable that returns the base URL, e.g.
        ``"http://127.0.0.1:8765"``.  Called lazily so the port file can be
        read *after* the object is constructed.

    """

    def __init__(
        self,
        title: str = "PersonaCore Agent",
        url_provider: Callable[[], str] | None = None,
    ) -> None:
        """Initialise the window wrapper."""
        self._title = title
        self._url_provider: Callable[[], str] = url_provider or self._default_url_provider
        self._window: webview.Window | None = None
        self._pending_ops: queue.SimpleQueue[tuple[str, Any]] = queue.SimpleQueue()
        self._started = threading.Event()
        self._stopped = threading.Event()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, url_provider: Callable[[], str]) -> None:
        """Replace the URL provider before ``start()`` is called.

        Parameters
        ----------
        url_provider:
            Zero-argument callable returning the base URL
            (e.g. ``"http://127.0.0.1:8765"``).

        """
        self._url_provider = url_provider

    # ------------------------------------------------------------------
    # Thread-safe public API (callable from any thread)
    # ------------------------------------------------------------------

    def open(self, path: str = "/") -> None:
        """Show the window and navigate to *path*.

        Thread-safe.  If ``start()`` has not been called yet the request is
        queued and replayed once the window is created.

        Parameters
        ----------
        path:
            URL path relative to the base URL, e.g. ``"/dashboard"``.

        """
        self._pending_ops.put(("open", path))

    def close(self) -> None:
        """Hide the window without destroying the WebView2 process.

        This allows fast re-open.  Thread-safe.
        """
        self._pending_ops.put(("close", None))

    def stop(self) -> None:
        """Destroy the window and terminate pywebview's message loop.

        Thread-safe.  After this call ``start()`` will return.
        """
        self._pending_ops.put(("stop", None))

    # ------------------------------------------------------------------
    # Blocking main-thread entry point
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the pywebview / WebView2 main loop.

        **MUST BE CALLED FROM THE MAIN THREAD.**

        This is a blocking call.  It returns only when the window is closed
        (via ``stop()``) or the process exits.

        SPEC-10 drives this from the composition root.
        """
        log.debug("WebviewWindow.start() — entering main loop")
        # pywebview requires at least one window created BEFORE start() —
        # otherwise it raises "You must create a window first before calling
        # this function." Create a hidden bootstrap window pointing at the
        # base URL; subsequent .open(path) calls will .load_url + .show it.
        if self._window is None:
            base_url = self._url_provider()
            self._window = webview.create_window(
                self._title,
                url=base_url,
                width=1100,
                height=720,
                resizable=True,
                hidden=True,
            )
        self._started.set()
        webview.start(
            func=self._process_queue,
            args=(),
            gui="edgechromium",
            debug=False,
        )
        self._stopped.set()
        log.debug("WebviewWindow.start() — main loop exited")

    # ------------------------------------------------------------------
    # Internal — runs on main thread inside pywebview's message loop
    # ------------------------------------------------------------------

    def _process_queue(self) -> None:
        """Process pending operations for the lifetime of the process.

        Runs on a background worker thread (spawned by ``webview.start``).
        Uses a blocking ``get`` with a short timeout so ops are handled with
        low latency while idle CPU remains near zero.
        """
        log.debug("WebviewWindow worker thread up")
        while not self._stopped.is_set():
            try:
                op, arg = self._pending_ops.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if op == "open":
                    self._do_open(str(arg))
                elif op == "close":
                    self._do_close()
                elif op == "stop":
                    self._do_stop()
                    break  # stop op exits worker
                else:
                    log.warning("WebviewWindow: unknown op %r", op)
            except Exception:
                log.exception("op %r failed", op)
        log.debug("WebviewWindow worker thread exiting")

    def _do_open(self, path: str) -> None:
        """Navigate to *path*; show the (already-created) window."""
        base_url = self._url_provider()
        url = f"{base_url}{path}"
        if self._window is None:
            # start() creates the bootstrap window before webview.start;
            # if we're here, something skipped start() (e.g., a test).
            log.warning("WebviewWindow._do_open before start(); nothing to do")
            return
        self._window.load_url(url)
        try:
            self._window.show()
        except Exception:  # noqa: BLE001
            log.debug("window.show() no-op'd", exc_info=True)
        log.debug("Navigated window to %s", url)

    def _do_close(self) -> None:
        """Hide the window."""
        if self._window is not None:
            self._window.hide()
            log.debug("WebviewWindow hidden")

    def _do_stop(self) -> None:
        """Destroy all windows — pywebview will exit its message loop."""
        if self._window is not None:
            self._window.destroy()
            self._window = None
        log.debug("WebviewWindow stopped")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_url_provider() -> str:
        """Read port from SPEC-07A's ui-port file, falling back to 8765."""
        import os  # noqa: PLC0415
        import pathlib  # noqa: PLC0415

        port_file = pathlib.Path(os.environ.get("APPDATA", ""), "WorkstationAgent", "ui-port")
        try:
            port = port_file.read_text(encoding="utf-8").strip()
        except OSError:
            log.warning("ui-port file not found; defaulting to 8765")
            return "http://127.0.0.1:8765"
        else:
            return f"http://127.0.0.1:{port}"
