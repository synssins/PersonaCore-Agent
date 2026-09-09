"""ToastPresenter — Windows toast notifications with action buttons.

Uses ``winrt.windows.ui.notifications`` when available.  Falls back to a
no-op + WARNING on non-Windows or when winrt is not installed.

Example
-------
::

    presenter = ToastPresenter(app_id="PersonaCore.Agent")
    presenter.show(
        title="Update available",
        body="Version 1.2.3 is ready.",
        actions={
            "update_now": ("Update now", on_update_now),
            "later":      ("Later",      on_later),
            "skip":       ("Skip version", on_skip),
        },
    )
"""

from __future__ import annotations

import logging
import platform
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional winrt import — guarded so the module loads on non-Windows / CI
#
# _wun and _wxml are module-level references used by ToastPresenter methods.
# Tests can reload this module inside a patch.dict(sys.modules) context to
# exercise the WinRT code path without a real SDK.
# ---------------------------------------------------------------------------

_WINRT_AVAILABLE = False
_wun: Any = None
_wxml: Any = None

if platform.system() == "Windows":
    try:
        # ``winrt.windows.ui.notifications`` needs ``winrt.windows.foundation``
        # at call time (not import time) for ``ToastNotification.add_activated``,
        # whose C#-side signature takes a
        # ``Windows.Foundation.TypedEventHandler`` — every confirm-flow toast
        # wires an Allow/Deny handler via ``add_activated``, so without the
        # ``winrt-Windows.Foundation`` package that call raises
        # ``ModuleNotFoundError`` at first use even though the two imports
        # below succeed on their own.  Importing it eagerly here, alongside
        # the two namespaces ``toast.py`` uses directly, means a missing
        # install is caught once at import time (falling into the except
        # below) instead of surfacing later as an unhandled failure deep
        # inside ``_show_winrt``.
        import winrt.windows.data.xml.dom as _wxml  # type: ignore[import-untyped]
        import winrt.windows.foundation  # noqa: F401  # type: ignore[import-untyped]
        import winrt.windows.ui.notifications as _wun  # type: ignore[import-untyped]

        _WINRT_AVAILABLE = True
    except ModuleNotFoundError:
        log.warning(
            "winrt is not installed — ToastPresenter will be a no-op.  "
            "Install `winrt-runtime`, `winrt-Windows.UI.Notifications`, "
            "`winrt-Windows.Data.Xml.Dom` and `winrt-Windows.Foundation` "
            "to enable toasts.",
        )
else:
    log.warning(
        "ToastPresenter: non-Windows platform (%s) — toasts disabled.",
        platform.system(),
    )


# ---------------------------------------------------------------------------
# ToastPresenter
# ---------------------------------------------------------------------------


class ToastPresenter:
    """Show Windows toast notifications with optional action buttons.

    Parameters
    ----------
    app_id:
        Application User Model ID (AUMID) shown in Action Center.
        Use a registered AUMID for toasts to appear reliably.

    """

    def __init__(self, app_id: str = "WorkstationAgent") -> None:
        """Initialise the toast presenter."""
        self._app_id = app_id
        self._notifier: Any = None

        if _WINRT_AVAILABLE and _wun is not None:
            try:
                # The Python projection does not overload on argument count —
                # the no-arg C#-side overload becomes ``create_toast_notifier()``
                # (which raises "Element not found" for an unpackaged app with
                # no AppUserModelID of its own) and the ``string appId``
                # overload becomes the *separate* method
                # ``create_toast_notifier_with_id``.  Calling
                # ``create_toast_notifier(app_id)`` — the single-overload C#
                # spelling — raises ``TypeError: Invalid parameter count``
                # against this binding.
                self._notifier = _wun.ToastNotificationManager.create_toast_notifier_with_id(
                    app_id,
                )
            except Exception:
                # Never let a construction-time WinRT failure (e.g. no shell
                # notification host reachable in this session) propagate out
                # of __init__ and take the caller down with it — the confirm
                # path's fail-closed check (``toast_stack_available``) reads
                # ``self._notifier is None`` and denies exactly as it would
                # for "winrt not installed".
                log.exception(
                    "ToastPresenter: create_toast_notifier_with_id(%r) failed — "
                    "toasts will be a no-op for this instance.",
                    app_id,
                )
                self._notifier = None

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def show(
        self,
        *,
        title: str,
        body: str,
        actions: dict[str, tuple[str, Callable[[], None]]] | None = None,
    ) -> None:
        """Display a toast notification.

        Parameters
        ----------
        title:
            Bold heading line.
        body:
            Secondary text.
        actions:
            Mapping of ``action_id -> (button_label, callback)``.
            Supported action ids (shown as buttons): ``"update_now"``,
            ``"later"``, ``"skip_version"``.  Any id is accepted; the
            callback is invoked when the user clicks the button.

        """
        if not _WINRT_AVAILABLE or self._notifier is None:
            log.warning(
                "Toast suppressed (winrt unavailable): [%s] %s",
                title,
                body,
            )
            return

        try:
            self._show_winrt(title=title, body=body, actions=actions or {})
        except Exception:
            log.exception("ToastPresenter: failed to show toast")

    # ------------------------------------------------------------------
    # WinRT implementation — uses module-level _wun / _wxml references
    # so tests can reload the module with mocked sys.modules entries.
    # ------------------------------------------------------------------

    def _show_winrt(
        self,
        *,
        title: str,
        body: str,
        actions: dict[str, tuple[str, Callable[[], None]]],
    ) -> None:
        xml_str = self._build_xml(title=title, body=body, actions=actions)

        doc = _wxml.XmlDocument()
        doc.load_xml(xml_str)

        notif = _wun.ToastNotification(doc)

        # Wire action callbacks via the Activated event
        if actions:
            callbacks = {aid: cb for aid, (_, cb) in actions.items()}

            def _on_activated(sender: Any, args: Any) -> None:  # noqa: ANN401, ARG001
                try:
                    action_id: str = args.arguments if hasattr(args, "arguments") else ""
                    cb = callbacks.get(action_id)
                    if cb is not None:
                        cb()
                except Exception:
                    log.exception("ToastPresenter: action callback raised")

            notif.add_activated(_on_activated)

        self._notifier.show(notif)

    @staticmethod
    def _build_xml(
        *,
        title: str,
        body: str,
        actions: dict[str, tuple[str, Callable[[], None]]],
    ) -> str:
        """Build a Toast XML payload compatible with Windows 10+."""

        def _esc(s: str) -> str:
            return (
                s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;")
            )

        actions_xml = ""
        if actions:
            action_elements = "".join(
                f'<action content="{_esc(label)}" arguments="{_esc(aid)}" />'
                for aid, (label, _) in actions.items()
            )
            actions_xml = f"<actions>{action_elements}</actions>"

        return (
            "<toast>"
            "<visual>"
            "<binding template='ToastGeneric'>"
            f"<text>{_esc(title)}</text>"
            f"<text>{_esc(body)}</text>"
            "</binding>"
            "</visual>"
            f"{actions_xml}"
            "</toast>"
        )


# ---------------------------------------------------------------------------
# Convenience factory for "update available" toasts (SPEC-06 integration)
# ---------------------------------------------------------------------------


def show_update_toast(
    presenter: ToastPresenter,
    version: str,
    *,
    on_update_now: Callable[[], None] | None = None,
    on_later: Callable[[], None] | None = None,
    on_skip: Callable[[], None] | None = None,
) -> None:
    """Display a standard "update available" toast with three action buttons.

    Parameters
    ----------
    presenter:
        Shared ``ToastPresenter`` instance.
    version:
        New version string shown in the body text.
    on_update_now:
        Callback when "Update now" is clicked (omitted if ``None``).
    on_later:
        Callback when "Later" is clicked (omitted if ``None``).
    on_skip:
        Callback when "Skip version" is clicked (omitted if ``None``).

    """
    actions: dict[str, tuple[str, Callable[[], None]]] = {}
    if on_update_now is not None:
        actions["update_now"] = ("Update now", on_update_now)
    if on_later is not None:
        actions["later"] = ("Later", on_later)
    if on_skip is not None:
        actions["skip_version"] = ("Skip version", on_skip)

    presenter.show(
        title="Update available",
        body=f"Version {version} is ready to install.",
        actions=actions or None,
    )
