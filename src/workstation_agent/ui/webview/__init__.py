"""WebView2 window integration via pywebview.

Thread-safety model
-------------------
**pywebview requires the main thread on Windows.**

* ``WebviewWindow.start()`` is a *blocking* call that must be invoked from the
  main thread.  It calls ``webview.start(gui="edgechromium")`` which pumps the
  Windows message loop until the process exits or ``stop()`` is called.

* All other callers (asyncio tasks, pystray callbacks, background threads) must
  *not* call pywebview APIs directly.  Instead they call ``WebviewWindow.open()``
  or ``WebviewWindow.close()``, which post a request to a ``queue.SimpleQueue``.
  A timer function registered with ``webview.start(func=…)`` drains that queue
  on each tick — safe because that callback runs inside pywebview's own message
  loop (i.e. the main thread).

Cross-thread flow (asyncio → UI)::

    asyncio task
        └─ WebviewWindow.open(path)       # any thread — just enqueues
              └─ _pending_ops: SimpleQueue
                    └─ _process_queue()   # called by pywebview timer on main thread
                          └─ window.load_url(url) / window.show()

Cross-thread flow (UI → asyncio)::

    pystray callback
        └─ asyncio.run_coroutine_threadsafe(coro, loop)
"""

from workstation_agent.ui.webview.window import WebviewWindow

__all__ = ["WebviewWindow"]
