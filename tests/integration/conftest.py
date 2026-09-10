"""Fixtures shared by the integration suite.

Nothing here is autouse at directory scope on purpose. A file opts in with a
module-level ``pytest.mark.usefixtures``, so every file that depends on one of
these says so at the top of itself — see ``docs/defects-found-2026-09-08.md``
defect 6 for what a quietly-applied fixture cost last time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def sse_shutdown_latch_cleared() -> Iterator[None]:
    """Keep ``sse_starlette``'s process-global shutdown latch out of this test.

    ``sse_starlette.sse.AppStatus.should_exit`` is a class attribute shared by
    the whole process and never reset. A watcher task polls every 0.5s, finds a
    uvicorn ``Server`` by introspecting ``signal.getsignal(SIGTERM)``, and latches
    the flag True for good if that server is stopping. Afterwards every
    ``EventSourceResponse`` ends right after its headers — and the MCP SDK builds
    all three streamable-HTTP paths on one — so a later test's tool call dies with
    ``RemoteProtocolError: peer closed connection without sending complete message
    body (incomplete chunked read)``.

    Under pytest the loop is on the main thread, so uvicorn's ``capture_signals()``
    does bind SIGTERM and the watcher can find a server. Whether it gets a tick
    inside the window between ``NetworkMCPServer.stop()`` and loop teardown is a
    race decided by scheduling: an 8-core dev box usually wins it, GitHub's runner
    does not. That is the whole difference between green here and seven failures
    there, and it is why the failures move around when tests are reordered.

    The shipped Agent is not exposed to this: it runs its loop on a non-main
    thread, where ``capture_signals()`` installs nothing and the watcher's lookup
    returns ``None``.

    Clearing on the way in stops one test inheriting the latch from an earlier
    one; clearing on the way out stops these tests exporting it to the rest of
    the session, which nothing else does — ``NetworkMCPServer.start`` clears the
    latch on the way *up*, so the last endpoint a network-MCP test stops can
    still leave it set for whatever runs next. Both ends restore the library's
    own default rather than suppressing anything, so a genuine latch inside a
    single test still shows up as that test failing.

    An *intra*-test restart — ``stop()`` then ``start()`` in one test body, which
    is what ``ui/backend/routers/network_mcp_routes._apply_endpoint`` does in the
    product — is out of this fixture's reach by construction, and measurably so:
    with the watcher poll shortened to 0.01s, a stream/stop/start/stream sequence
    fails without the clear in ``NetworkMCPServer.start`` and passes with it.
    """
    from sse_starlette.sse import AppStatus

    AppStatus.should_exit = False
    try:
        yield
    finally:
        AppStatus.should_exit = False
