"""SystemTray — pystray-based Windows system-tray icon for PersonaCore-Agent.

See ``workstation_agent.ui.systray`` module docstring for the threading model.
"""

from __future__ import annotations

import logging
import os
import pathlib
from typing import TYPE_CHECKING, Any

import httpx
import pystray
from PIL import Image

if TYPE_CHECKING:
    from collections.abc import Callable

    from workstation_agent.ui.webview.window import WebviewWindow

log = logging.getLogger(__name__)

_ASSET_DIR = pathlib.Path(__file__).parent / "assets"
_SESSION_MODES = ("single_shot", "sticky", "persistent")


def _load_icon() -> Image.Image:
    icon_path = _ASSET_DIR / "icon.png"
    if icon_path.exists():
        return Image.open(icon_path).convert("RGBA")
    # Fallback: plain blue square
    return Image.new("RGBA", (32, 32), (60, 90, 200, 255))


class SystemTray:
    """Windows system-tray icon with a full right-click context menu.

    Parameters
    ----------
    webview_window:
        The shared ``WebviewWindow`` instance.  Menu callbacks will call
        ``open(path)`` on it from the pystray thread (thread-safe).
    url_provider:
        Zero-argument callable returning the FastAPI base URL,
        e.g. ``"http://127.0.0.1:8765"``.  Used for HTTP API calls.
    on_exit:
        Called when the user selects *Exit*.  Should trigger clean shutdown.
    logs_dir:
        Path to the logs directory opened by *Show logs folder*.
    pending_plugin_count:
        Zero-argument callable returning how many plugins are reload-pending
        (used to badge the *Reload plugins* menu item).

    """

    def __init__(
        self,
        *,
        webview_window: WebviewWindow | None = None,
        url_provider: Callable[[], str] | None = None,
        on_exit: Callable[[], None] | None = None,
        logs_dir: str | pathlib.Path | None = None,
        pending_plugin_count: Callable[[], int] | None = None,
    ) -> None:
        """Initialise the system tray."""
        self._webview = webview_window
        self._url_provider = url_provider or self._default_url_provider
        self._on_exit = on_exit or (lambda: None)
        self._logs_dir = pathlib.Path(logs_dir) if logs_dir else self._default_logs_dir()
        self._pending_plugin_count = pending_plugin_count or (lambda: 0)

        # Mutable state
        self._muted: bool = False
        self._session_mode: str = "single_shot"

        # pystray.Icon has no py.typed stubs; store as Any to keep pyright happy
        self._icon: Any = None

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run_detached(self) -> None:
        """Start the tray icon on its own background thread.

        Safe to call from the main thread before ``WebviewWindow.start()``.
        Returns immediately; the tray thread keeps running until ``stop()``
        or the process exits.
        """
        icon = self._build_icon()
        self._icon = icon
        icon.run_detached()
        log.debug("SystemTray started (detached thread)")

    def stop(self) -> None:
        """Stop the tray icon and release its thread."""
        if self._icon is not None:
            self._icon.stop()
            self._icon = None
            log.debug("SystemTray stopped")

    def update_plugin_badge(self) -> None:
        """Refresh the menu to reflect the current pending-plugin count."""
        if self._icon is not None:
            self._icon.menu = self._build_menu()
            self._icon.update_menu()

    # ------------------------------------------------------------------
    # Menu construction
    # ------------------------------------------------------------------

    def _build_icon(self) -> Any:  # noqa: ANN401
        """Build a pystray.Icon.  Return type is Any due to missing stubs."""
        return pystray.Icon(
            name="workstation-agent",
            icon=_load_icon(),
            title="PersonaCore Agent",
            menu=self._build_menu(),
        )

    def _build_menu(self) -> Any:  # noqa: ANN401
        """Build the pystray.Menu.  Return type is Any due to missing stubs."""
        count = self._pending_plugin_count()
        reload_label = (
            f"Reload plugins [{count} pending]" if count > 0 else "Reload plugins"
        )

        return pystray.Menu(
            # Open (default — also fires on double-click)
            pystray.MenuItem(
                "Open",
                action=self._on_open,
                default=True,
            ),
            pystray.Menu.SEPARATOR,
            # Mute agent (checkbox)
            pystray.MenuItem(
                "Mute agent",
                action=self._on_mute_toggle,
                checked=lambda _: self._muted,
            ),
            # Session mode submenu
            pystray.MenuItem(
                "Session mode >",
                pystray.Menu(
                    pystray.MenuItem(
                        "Single shot",
                        action=self._make_session_mode_action("single_shot"),
                        checked=lambda _: self._session_mode == "single_shot",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "Sticky",
                        action=self._make_session_mode_action("sticky"),
                        checked=lambda _: self._session_mode == "sticky",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "Persistent",
                        action=self._make_session_mode_action("persistent"),
                        checked=lambda _: self._session_mode == "persistent",
                        radio=True,
                    ),
                ),
            ),
            pystray.Menu.SEPARATOR,
            # Reload plugins
            pystray.MenuItem(reload_label, action=self._on_reload_plugins),
            # Check for updates
            pystray.MenuItem("Check for updates now", action=self._on_check_updates),
            pystray.Menu.SEPARATOR,
            # WebView2 pages
            pystray.MenuItem("Open config", action=self._on_open_config),
            pystray.MenuItem("Show audit log", action=self._on_show_audit_log),
            pystray.MenuItem("About", action=self._on_about),
            pystray.Menu.SEPARATOR,
            # Filesystem
            pystray.MenuItem("Show logs folder", action=self._on_show_logs_folder),
            pystray.Menu.SEPARATOR,
            # Exit
            pystray.MenuItem("Exit", action=self._on_exit_action),
        )

    # ------------------------------------------------------------------
    # Menu callbacks
    # pystray callback signature: (icon, item) — both untyped (no stubs).
    # Unused parameters are suppressed via ARG002/ARG001 noqa directives.
    # ------------------------------------------------------------------

    def _on_open(self, _icon, _item) -> None:  # noqa: ANN001
        log.debug("Tray: Open clicked")
        if self._webview is not None:
            self._webview.open("/dashboard")

    def _on_mute_toggle(self, _icon, _item) -> None:  # noqa: ANN001
        self._muted = not self._muted
        log.debug("Tray: mute toggled -> %s", self._muted)
        self._post_config({"muted": self._muted})

    def _make_session_mode_action(self, mode: str) -> Callable[..., None]:
        def _action(_icon, _item) -> None:  # noqa: ANN001
            self._session_mode = mode
            log.debug("Tray: session mode -> %s", mode)
            self._post_config({"session_mode": mode})

        return _action

    def _on_reload_plugins(self, _icon, _item) -> None:  # noqa: ANN001
        log.debug("Tray: Reload plugins clicked")
        try:
            base = self._url_provider()
            httpx.post(f"{base}/plugins/reload", timeout=5)
        except Exception:
            log.exception("Tray: reload plugins request failed")

    def _on_check_updates(self, _icon, _item) -> None:  # noqa: ANN001
        log.debug("Tray: Check for updates now clicked")
        try:
            base = self._url_provider()
            httpx.post(f"{base}/about/check-updates", timeout=10)
        except Exception:
            log.exception("Tray: check-updates request failed")

    def _on_open_config(self, _icon, _item) -> None:  # noqa: ANN001
        if self._webview is not None:
            self._webview.open("/config")

    def _on_show_audit_log(self, _icon, _item) -> None:  # noqa: ANN001
        if self._webview is not None:
            self._webview.open("/audit-log")

    def _on_about(self, _icon, _item) -> None:  # noqa: ANN001
        if self._webview is not None:
            self._webview.open("/about")

    def _on_show_logs_folder(self, _icon, _item) -> None:  # noqa: ANN001
        log.debug("Tray: Show logs folder clicked -> %s", self._logs_dir)
        try:
            os.startfile(str(self._logs_dir))  # noqa: S606
        except Exception:
            log.exception("Tray: could not open logs folder")

    def _on_exit_action(self, _icon, _item) -> None:  # noqa: ANN001
        log.debug("Tray: Exit clicked")
        self.stop()
        self._on_exit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _post_config(self, payload: dict[str, Any]) -> None:
        try:
            base = self._url_provider()
            httpx.post(f"{base}/config", json=payload, timeout=5)
        except Exception:
            log.exception("Tray: config POST failed")

    @staticmethod
    def _default_url_provider() -> str:
        port_file = pathlib.Path(
            os.environ.get("APPDATA", ""),
            "WorkstationAgent",
            "ui-port",
        )
        try:
            port = port_file.read_text(encoding="utf-8").strip()
        except OSError:
            return "http://127.0.0.1:8765"
        else:
            return f"http://127.0.0.1:{port}"

    @staticmethod
    def _default_logs_dir() -> pathlib.Path:
        appdata = os.environ.get("LOCALAPPDATA", os.environ.get("APPDATA", ""))
        return pathlib.Path(appdata) / "WorkstationAgent" / "logs"
