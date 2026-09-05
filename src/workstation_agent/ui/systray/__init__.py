"""System tray integration for PersonaCore-Agent via pystray.

Thread-safety model
-------------------
``pywebview`` owns the main thread (its ``start()`` call is a blocking
Windows message-loop pump).  ``pystray`` would also like to own the main
thread — but on Windows it supports ``Icon.run_detached()``, which spawns
the tray loop on a dedicated background thread.

Coordination::

    Main thread (reserved for pywebview)
        └─ WebviewWindow.start()  ← SPEC-10 calls this

    Systray thread  (pystray.Icon.run_detached)
        └─ SystemTray.run_detached()  ← SPEC-10 calls this *before* start()
              └─ menu callbacks → WebviewWindow.open(path)
                                  asyncio.run_coroutine_threadsafe(coro, loop)

Cross-thread safety:

* ``WebviewWindow.open/close/stop`` are queue-based and safe from any thread.
* HTTP calls to FastAPI (``/config``, ``/about/check-updates``, …) are made
  with plain ``httpx`` (synchronous) inside the pystray callback thread —
  no asyncio involvement needed for fire-and-forget requests.
* Heavy asyncio operations go through ``asyncio.run_coroutine_threadsafe``.
"""

from workstation_agent.ui.systray.tray import SystemTray

__all__ = ["SystemTray"]
