"""Windows toast notifications for PersonaCore-Agent.

``ToastPresenter`` uses ``winrt.windows.ui.notifications`` on Windows.

On non-Windows platforms or when the ``winrt`` package is not installed the
presenter falls back to a no-op implementation and emits a ``WARNING`` log so
that the rest of the application continues to work in CI/dev environments.

Threading model
---------------
Toast operations are fire-and-forget.  ``ToastPresenter.show()`` may be
called from any thread (it does not touch the asyncio loop or pywebview).
Action callbacks supplied by the caller are invoked on the WinRT notification
thread; callers that need asyncio must use
``asyncio.run_coroutine_threadsafe`` themselves.
"""

from workstation_agent.ui.notifications.toast import ToastPresenter

__all__ = ["ToastPresenter"]
