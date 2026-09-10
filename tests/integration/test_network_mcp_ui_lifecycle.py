"""Subtask P7 -- the Network MCP page against the *real* endpoint.

``tests/unit/ui/test_network_mcp_endpoint_ui.py`` drives the router with a
fake endpoint, which is the right way to exercise its branches but proves
nothing about the claim the page actually makes: that ticking "Enabled" and
saving puts a real TLS listener on a real socket without an Agent restart.

These tests use the real
:class:`~workstation_agent.network_mcp.server.NetworkMCPServer`, bind a real
ephemeral loopback port, and connect to it. If the router's ``await
server.start()`` ever stopped meaning what it says, nothing else in the suite
would notice.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import zipfile

import pytest

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.registration_export import MANIFEST_ARCNAME, REGISTRATION_ZIP_NAME
from workstation_agent.ui.backend.routers import network_mcp_routes

# This file drives `_apply_endpoint`, which stops one real uvicorn server and
# starts another in-process, so it is both a possible source and a possible
# victim of sse_starlette's process-global shutdown latch. Which tests that
# latch actually breaks is decided by collection order and by scheduling luck,
# so the file opts in rather than waiting to be reordered into failing. See the
# fixture's docstring in tests/integration/conftest.py.
pytestmark = pytest.mark.usefixtures("sse_shutdown_latch_cleared")


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    """Certificate, token, reveal state and exported zip all live under tmp_path."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _tls_handshakes(host: str, port: int) -> bool:
    """True if something is serving TLS at *host*:*port*.

    The certificate is self-signed and pinned by fingerprint on the core, so
    verification is switched off here for the same reason the core switches it
    off: this asks "is the endpoint up", not "is it trusted".
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as raw, ctx.wrap_socket(raw):
            return True
    except OSError:
        return False


def _form(port: int, *, enabled: bool = True, host: str = "127.0.0.1"):
    data = {"bind_host_choice": host, "bind_host_other": "", "port": str(port)}
    if enabled:
        data["enabled"] = "true"
    return data


@contextlib.contextmanager
def _live_client(tmp_path, store=None):
    """A TestClient whose event loop outlives the individual request.

    This matters, and it took a real failure to see why. ``TestClient`` spins
    up a fresh anyio portal -- a fresh event loop -- *per request* unless it is
    entered as a context manager. The endpoint the router starts is a task on
    whatever loop served the request, so a one-shot ``client.post`` starts
    uvicorn and then cancels it on the way out: the page truthfully reports
    "listening", and by the time the test connects there is nothing there.

    That is an artefact of the test client, not of the design. In the Agent the
    FastAPI backend and the endpoint are both tasks on the single loop owned by
    ``Application._loop_thread``, which lives as long as the process -- and
    that shared, long-lived loop is exactly what makes "enable it from the UI,
    no restart" possible at all. Holding one portal open for the whole test
    reproduces that arrangement, and only then do these tests mean anything.
    """
    client, ctx = make_client(
        config_store=store or FakeConfigStore(), tmp_path=tmp_path, return_ctx=True,
    )
    with client:
        try:
            yield client, ctx
        finally:
            server = ctx.network_mcp
            if server is not None and getattr(server, "running", False):
                with contextlib.suppress(Exception):
                    client.post(
                        "/network-mcp/settings",
                        data=_form(server.info().port, enabled=False),
                    )


def test_enabling_from_the_page_puts_a_real_tls_listener_on_the_port(tmp_path):
    """The whole product requirement, end to end and with no fakes in the path."""
    port = _free_port()
    store = FakeConfigStore()
    assert not _tls_handshakes("127.0.0.1", port)

    with _live_client(tmp_path, store) as (client, ctx):
        resp = client.post("/network-mcp/settings", data=_form(port))

        assert resp.status_code == 200
        assert "listening" in resp.text.lower()
        assert store.load().network_mcp.enabled is True
        assert ctx.network_mcp is not None
        assert ctx.network_mcp.running is True
        assert _tls_handshakes("127.0.0.1", port)


def test_disabling_from_the_page_really_releases_the_port(tmp_path):
    port = _free_port()
    with _live_client(tmp_path) as (client, _ctx):
        client.post("/network-mcp/settings", data=_form(port))
        assert _tls_handshakes("127.0.0.1", port)

        client.post("/network-mcp/settings", data=_form(port, enabled=False))

        assert not _tls_handshakes("127.0.0.1", port)


def test_changing_the_port_moves_the_real_listener(tmp_path):
    """A rebind must vacate the old port, not leave two listeners behind."""
    first, second = _free_port(), _free_port()
    with _live_client(tmp_path) as (client, _ctx):
        client.post("/network-mcp/settings", data=_form(first))
        assert _tls_handshakes("127.0.0.1", first)

        client.post("/network-mcp/settings", data=_form(second))

        assert _tls_handshakes("127.0.0.1", second)
        assert not _tls_handshakes("127.0.0.1", first)


def test_a_port_already_in_use_is_reported_and_nothing_is_left_half_up(tmp_path):
    """The most likely real failure, and the one a silent UI would hide."""
    with socket.socket() as squatter:
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        port = int(squatter.getsockname()[1])

        with _live_client(tmp_path) as (client, ctx):
            resp = client.post("/network-mcp/settings", data=_form(port))

            assert resp.status_code == 200
            assert "could not start" in resp.text.lower()
            assert ctx.network_mcp is not None
            assert ctx.network_mcp.running is False


def test_the_export_describes_the_endpoint_that_is_actually_listening(tmp_path):
    """Port 0 through the real server: the OS assigns, the export must follow.

    Exporting from the saved config would write ``:0`` into the manifest. The
    endpoint really is listening on an assigned port, and this asserts the
    manifest names that port -- the same port a TLS handshake just succeeded on.
    """
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(0))

        assigned = ctx.network_mcp.info().port
        assert assigned != 0
        assert _tls_handshakes("127.0.0.1", assigned)

        # Loopback and port 0 are both flagged, so this needs the explicit confirm.
        first = client.post("/network-mcp/export-registration")
        assert "loopback interface" in first.text
        assert not (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).exists()

        client.post("/network-mcp/export-registration", data={"confirm": "true"})

        zip_path = network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME
        with zipfile.ZipFile(zip_path) as zf:
            manifest = zf.read(MANIFEST_ARCNAME).decode("utf-8")
        assert f'"https://127.0.0.1:{assigned}/mcp"' in manifest


def test_the_exported_zip_downloads_intact_over_http(tmp_path):
    """The bytes the webview receives are the bytes on disk."""
    port = _free_port()
    with _live_client(tmp_path) as (client, _ctx):
        client.post("/network-mcp/settings", data=_form(port))
        client.post("/network-mcp/export-registration", data={"confirm": "true"})
        resp = client.get("/network-mcp/registration.zip")

        on_disk = (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).read_bytes()
        assert resp.content == on_disk
        assert "attachment" in resp.headers["content-disposition"]


def test_the_real_certificates_san_is_checked_against_the_real_bind_host(tmp_path):
    """``certs.local_identities`` puts loopback in the SAN, so 127.0.0.1 is covered.

    The value of asserting this against the real certificate rather than a
    fake: it is the same code path that decides whether the operator is shown
    a "regenerate the certificate" warning, and a SAN comparison that quietly
    stopped matching would make that warning permanent and train them to
    rotate a fingerprint that was fine.
    """
    port = _free_port()
    with _live_client(tmp_path) as (client, ctx):
        resp = client.post("/network-mcp/settings", data=_form(port))
        assert "127.0.0.1" in ctx.network_mcp.info().certificate_sans
        assert "does not cover" not in resp.text


# ---------------------------------------------------------------------------
# P24 -- the owner's own sequence, against real sockets
#
# What he did, in order: the box was ticked; Join refused with "the endpoint is
# not running"; he switched it off; he switched it back on and was told the
# port was in use, "which it was not before"; he changed the port and it worked
# immediately.
#
# Every assertion below is on whether the port can actually be bound, never on
# what the endpoint object reports -- the defect was an object whose state
# disagreed with reality, so asking it would prove nothing.
# ---------------------------------------------------------------------------


def _port_is_free(host: str, port: int) -> bool:
    probe = socket.socket()
    try:
        probe.bind((host, port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _on_the_agents_loop(client, fn, *args):
    """Run *fn* on the loop the endpoint is actually serving on.

    ``TestClient.portal`` is only non-None while the client is entered as a
    context manager, which ``_live_client`` guarantees and this asserts rather
    than assumes: a portal that had quietly gone away would run the coroutine
    on some other loop, where the task under test does not exist.
    """
    portal = client.portal
    assert portal is not None, "the test client is not holding a portal"
    return portal.call(fn, *args)


async def _kill_the_serve_task(server) -> None:
    """End the serve task from outside, the way an unhandled error would.

    A lifespan that fails after startup, an error escaping uvicorn, a
    cancellation: the endpoint cannot tell them apart and must not need to. All
    that matters is that the task is over and nothing is serving.
    """
    task = server._task
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    await asyncio.sleep(0)


def test_enable_disable_enable_on_one_port_succeeds(tmp_path):
    """Steps 3 to 5 with nothing else wrong: the port has to come back."""
    port = _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        assert _tls_handshakes("127.0.0.1", port)

        client.post("/network-mcp/settings", data=_form(port, enabled=False))
        assert _port_is_free("127.0.0.1", port)

        resp = client.post("/network-mcp/settings", data=_form(port))

        assert "could not start" not in resp.text.lower()
        assert ctx.network_mcp.running is True
        assert _tls_handshakes("127.0.0.1", port)


def test_a_dead_serve_task_does_not_keep_the_port(tmp_path):
    """Step 2: the box says Enabled, Join says not running, nothing is serving.

    Whatever is true of the configuration, a port this process is holding with
    nothing behind it is a lie the operator cannot see and cannot clear.
    """
    port = _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        server = ctx.network_mcp
        assert server.running is True

        _on_the_agents_loop(client, _kill_the_serve_task, server)

        assert server.running is False
        assert _port_is_free("127.0.0.1", port)


def test_the_owners_whole_sequence_on_one_port(tmp_path):
    """Enabled, serving stops underneath it, off, on again -- on the same port.

    This is the failure as it reached him, and the disable in the middle is the
    one that changes the bind set, because a ``<select multiple>`` posts in
    document order rather than the order the addresses were saved in: an
    ordinary save can therefore count as a rebind, and a rebind while the
    endpoint is not running is what published a fresh endpoint object over one
    that was still holding the socket.
    """
    port, elsewhere = _free_port(), _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        server = ctx.network_mcp
        _on_the_agents_loop(client, _kill_the_serve_task, server)
        assert server.running is False

        # Switch it off. Whatever else this does, it must not leave a socket
        # behind that no object in the process can reach any more.
        client.post("/network-mcp/settings", data=_form(elsewhere, enabled=False))
        assert _port_is_free("127.0.0.1", port)

        # Switch it back on, on the port he started with.
        resp = client.post("/network-mcp/settings", data=_form(port))

        assert "already listening on this address" not in resp.text
        assert "could not start" not in resp.text.lower()
        assert ctx.network_mcp.running is True
        assert _tls_handshakes("127.0.0.1", port)


def test_switching_off_releases_the_port_even_when_serving_already_stopped(tmp_path):
    """Step 3 on its own. "Off" means nothing is listening, unconditionally."""
    port = _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        _on_the_agents_loop(client, _kill_the_serve_task, ctx.network_mcp)

        client.post("/network-mcp/settings", data=_form(port, enabled=False))

        assert _port_is_free("127.0.0.1", port)


def test_replacing_the_live_endpoint_never_strands_its_listening_socket(tmp_path):
    """The other half of defect A, isolated from the first half.

    ``ctx.network_mcp`` is the only reference this process keeps to an
    endpoint. Overwrite it while the outgoing object still owns a bound socket
    and that socket is unreachable forever: no object holds it, nothing will
    close it, and the port stays taken for the life of the Agent by something
    that appears in no port listing the operator would think to run.

    Staged without touching the serve task, so this fails for its own reason
    rather than for the dead-task one: detaching ``_task`` leaves uvicorn
    serving and the socket bound while ``running`` reports False -- which is
    exactly the disagreement between an object and reality that the whole
    defect consists of, and exactly the report the router used to decide
    whether to bother stopping it.
    """
    port, elsewhere = _free_port(), _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        stranded = ctx.network_mcp
        assert not _port_is_free("127.0.0.1", port)

        stranded._task = None
        assert stranded.running is False

        # A disable that also changes the port: `rebind` is true, so the router
        # publishes a fresh endpoint over the one still holding the socket.
        client.post("/network-mcp/settings", data=_form(elsewhere, enabled=False))

        assert ctx.network_mcp is not stranded, "the premise -- the object was replaced"
        assert _port_is_free("127.0.0.1", port)
