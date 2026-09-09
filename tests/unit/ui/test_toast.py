"""Tests for workstation_agent.ui.notifications.toast — ToastPresenter.

winrt mock strategy
--------------------
The module uses module-level ``_wun`` and ``_wxml`` references (assigned
during import).  Tests inject mocked winrt modules into ``sys.modules``
and then call ``importlib.reload(toast_mod)`` **inside** the same
``patch.dict`` context.  The reload re-evaluates the platform guard and
re-assigns ``_wun`` / ``_wxml`` from the mocked modules.  All subsequent
calls on ``ToastPresenter`` use those module-level references, so no
real winrt SDK is needed.

Calling ``show()`` inside the same ``with`` block ensures the module-level
``_wun`` / ``_wxml`` globals are still the mocks when ``_show_winrt`` runs.
"""

from __future__ import annotations

import importlib
import logging
from unittest.mock import MagicMock, patch


def _build_winrt_mocks() -> tuple[MagicMock, MagicMock, MagicMock]:
    """Return (wun_mock, wxml_mock, wfoundation_mock)."""
    wun = MagicMock(name="winrt.windows.ui.notifications")
    wxml = MagicMock(name="winrt.windows.data.xml.dom")
    wfoundation = MagicMock(name="winrt.windows.foundation")
    return wun, wxml, wfoundation


def _patch_winrt(
    wun_mock: MagicMock,
    wxml_mock: MagicMock,
    wfoundation_mock: MagicMock | None = None,
):
    # Build parent mocks with the correct child attribute set so that Python's
    # import machinery (which resolves subpackage names via parent attributes)
    # returns our exact mock objects, not auto-generated child mocks.
    #
    # ``winrt.windows.foundation`` is imported unconditionally alongside the
    # two namespaces below (see toast.py's module-level import block) because
    # ``ToastNotification.add_activated`` needs it at call time — every entry
    # here must be registered in ``sys.modules``, or Python's real import
    # machinery falls through to the *actual* installed ``winrt`` package for
    # whichever submodule is missing, which — for a plain ``MagicMock``
    # standing in as the parent package with an empty ``__path__`` — raises
    # ``ModuleNotFoundError`` and trips the module's own "winrt not
    # installed" fallback instead of exercising the mocked WinRT path.
    if wfoundation_mock is None:
        wfoundation_mock = MagicMock(name="winrt.windows.foundation")

    winrt_windows_ui = MagicMock()
    winrt_windows_ui.notifications = wun_mock

    winrt_windows_data_xml = MagicMock()
    winrt_windows_data_xml.dom = wxml_mock

    winrt_windows_data = MagicMock()
    winrt_windows_data.xml = winrt_windows_data_xml

    winrt_windows = MagicMock()
    winrt_windows.ui = winrt_windows_ui
    winrt_windows.data = winrt_windows_data
    winrt_windows.foundation = wfoundation_mock

    winrt_root = MagicMock()
    winrt_root.windows = winrt_windows

    extra_modules = {
        "winrt": winrt_root,
        "winrt.windows": winrt_windows,
        "winrt.windows.ui": winrt_windows_ui,
        "winrt.windows.ui.notifications": wun_mock,
        "winrt.windows.data": winrt_windows_data,
        "winrt.windows.data.xml": winrt_windows_data_xml,
        "winrt.windows.data.xml.dom": wxml_mock,
        "winrt.windows.foundation": wfoundation_mock,
    }
    return patch.dict("sys.modules", extra_modules)


class TestToastPresenterNoOp:
    def test_show_is_noop_without_winrt(self, caplog) -> None:
        """When winrt is unavailable, show() logs a warning and does not raise."""
        with patch.dict("sys.modules", {"winrt": None}):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            presenter = toast_mod.ToastPresenter()
            logger_name = "workstation_agent.ui.notifications.toast"
            with caplog.at_level(logging.WARNING, logger=logger_name):
                presenter.show(title="Hello", body="World")
        # No exception raised


class TestToastXML:
    def test_xml_escaping(self) -> None:
        from workstation_agent.ui.notifications.toast import ToastPresenter

        xml = ToastPresenter._build_xml(
            title="A & B",
            body='<test "quoted">',
            actions={},
        )
        assert "&amp;" in xml
        assert "&lt;" in xml
        assert "&quot;" in xml

    def test_action_xml_included(self) -> None:
        from workstation_agent.ui.notifications.toast import ToastPresenter

        xml = ToastPresenter._build_xml(
            title="T",
            body="B",
            actions={"update_now": ("Update now", lambda: None)},
        )
        assert "<actions>" in xml
        assert 'arguments="update_now"' in xml

    def test_no_actions_no_actions_element(self) -> None:
        from workstation_agent.ui.notifications.toast import ToastPresenter

        xml = ToastPresenter._build_xml(title="T", body="B", actions={})
        assert "<actions>" not in xml


class TestShowUpdateToastHelper:
    def test_show_update_toast_helper(self) -> None:
        from workstation_agent.ui.notifications.toast import show_update_toast

        mock_presenter = MagicMock()
        show_update_toast(
            mock_presenter,
            "2.0.0",
            on_update_now=lambda: None,
            on_later=lambda: None,
            on_skip=lambda: None,
        )
        mock_presenter.show.assert_called_once()
        _, kwargs = mock_presenter.show.call_args
        assert kwargs["title"] == "Update available"
        assert "2.0.0" in kwargs["body"]
        assert len(kwargs["actions"]) == 3

    def test_show_update_toast_no_callbacks(self) -> None:
        from workstation_agent.ui.notifications.toast import show_update_toast

        mock_presenter = MagicMock()
        show_update_toast(mock_presenter, "1.0.0")
        mock_presenter.show.assert_called_once()


class TestToastPresenterWinRT:
    """Exercise the WinRT code path via module reload with mocked sys.modules."""

    def test_show_calls_notifier(self) -> None:
        wun, wxml, _wfoundation = _build_winrt_mocks()

        with _patch_winrt(wun, wxml), patch("platform.system", return_value="Windows"):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            assert toast_mod._WINRT_AVAILABLE  # guard passed
            presenter = toast_mod.ToastPresenter(app_id="TestApp")
            presenter.show(title="Hi", body="There")
            # _notifier.show is called inside _show_winrt
            presenter._notifier.show.assert_called_once()

    def test_construction_uses_create_toast_notifier_with_id(self) -> None:
        """Regression test for the real winrt projection's method name.

        The Python/WinRT binding does not overload on argument count: the
        C#-side ``CreateToastNotifier()`` and ``CreateToastNotifier(string)``
        overloads become two *separate* Python methods,
        ``create_toast_notifier`` (no args) and
        ``create_toast_notifier_with_id`` (one arg). Calling the no-arg name
        with ``app_id`` raises ``TypeError: Invalid parameter count`` against
        the real binding — a mock would not have caught that, so this test
        pins the exact method name ``ToastPresenter.__init__`` must call.
        """
        wun, wxml, _wfoundation = _build_winrt_mocks()

        with _patch_winrt(wun, wxml), patch("platform.system", return_value="Windows"):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            toast_mod.ToastPresenter(app_id="TestApp")

            wun.ToastNotificationManager.create_toast_notifier_with_id.assert_called_once_with(
                "TestApp",
            )
            wun.ToastNotificationManager.create_toast_notifier.assert_not_called()

    def test_construction_failure_leaves_notifier_none(self, caplog) -> None:
        """A construction-time WinRT failure must not raise out of __init__.

        ``confirm.toast_stack_available`` fails closed on ``_notifier is
        None`` — this proves a broken notifier factory (real winrt present,
        but e.g. no shell notification host reachable) lands exactly there
        instead of taking the caller down with an unhandled exception.
        """
        wun, wxml, _wfoundation = _build_winrt_mocks()
        wun.ToastNotificationManager.create_toast_notifier_with_id.side_effect = RuntimeError(
            "Element not found.",
        )

        with (
            _patch_winrt(wun, wxml),
            patch("platform.system", return_value="Windows"),
            caplog.at_level(logging.ERROR, logger="workstation_agent.ui.notifications.toast"),
        ):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            presenter = toast_mod.ToastPresenter(app_id="TestApp")  # must not raise

        assert presenter._notifier is None

    def test_action_callback_fires(self) -> None:
        wun, wxml, _wfoundation = _build_winrt_mocks()
        callback_called: list[str] = []
        activated_handlers: list = []

        with _patch_winrt(wun, wxml), patch("platform.system", return_value="Windows"):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)

            # _show_winrt uses module-level _wun; capture the notif mock's handler
            notif_mock = wun.ToastNotification.return_value
            notif_mock.add_activated.side_effect = activated_handlers.append

            presenter = toast_mod.ToastPresenter(app_id="TestApp")
            presenter.show(
                title="Update",
                body="1.2.3 ready",
                actions={
                    "update_now": ("Update now", lambda: callback_called.append("update_now")),
                    "later": ("Later", lambda: callback_called.append("later")),
                },
            )

            assert activated_handlers, "add_activated was never called"

            fake_args = MagicMock()
            fake_args.arguments = "update_now"
            activated_handlers[0](None, fake_args)

        assert callback_called == ["update_now"]

    def test_show_handles_winrt_exception_gracefully(self) -> None:
        wun, wxml, _wfoundation = _build_winrt_mocks()

        with _patch_winrt(wun, wxml), patch("platform.system", return_value="Windows"):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            presenter = toast_mod.ToastPresenter(app_id="TestApp")
            presenter._notifier.show.side_effect = RuntimeError("winrt boom")
            presenter.show(title="Hi", body="There")  # must not raise

    def test_action_callback_with_unknown_id_is_ignored(self) -> None:
        wun, wxml, _wfoundation = _build_winrt_mocks()
        activated_handlers: list = []

        with _patch_winrt(wun, wxml), patch("platform.system", return_value="Windows"):
            import workstation_agent.ui.notifications.toast as toast_mod

            importlib.reload(toast_mod)
            notif_mock = wun.ToastNotification.return_value
            notif_mock.add_activated.side_effect = activated_handlers.append

            presenter = toast_mod.ToastPresenter(app_id="TestApp")
            presenter.show(
                title="T",
                body="B",
                actions={"update_now": ("Update now", lambda: None)},
            )

            assert activated_handlers, "add_activated was never called"

            fake_args = MagicMock()
            fake_args.arguments = "nonexistent_action"
            activated_handlers[0](None, fake_args)  # must not raise
