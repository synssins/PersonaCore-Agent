"""Subtask P13 -- the endpoint answering on a *set* of operator-chosen addresses.

Real sockets throughout. The claim under test is not "the config holds a list"
but "every address the operator picked has a TLS listener behind the same
application on it, they start and stop together, and when one of them cannot be
had the operator is told which".

Why the certificate is generated up front in most of these: the endpoint refuses
to bind an address its certificate does not cover (see
:func:`~workstation_agent.network_mcp.listeners.open_listeners`), so a test that
wants a multi-address bind has to arrange a certificate that covers them --
which is exactly what the UI's regenerate flow arranges for the operator.
"""
# ruff: noqa: SIM105
# A socket teardown the server already tore down raises something different on
# every platform and none of them are the assertion.

from __future__ import annotations

import asyncio
import socket
import ssl

import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp import certs
from workstation_agent.network_mcp.server import NetworkMCPServer

#: Addresses this machine can actually bind, out of the ones worth trying. A
#: box without IPv6, or one where 127.0.0.2 is not routed to loopback, must skip
#: rather than fail: the property under test is about several addresses, not
#: about which several.
_CANDIDATES = ("127.0.0.1", "127.0.0.2", "::1")


def _bindable(host: str) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
    except OSError:
        return False
    return True


@pytest.fixture(scope="module")
def usable() -> tuple[str, ...]:
    hosts = tuple(h for h in _CANDIDATES if _bindable(h))
    if len(hosts) < 2:  # pragma: no cover — depends on the machine
        pytest.skip("this machine has fewer than two bindable loopback addresses")
    return hosts


def _config(hosts, port: int = 0) -> NetworkMcpConfig:
    return NetworkMcpConfig(
        enabled=True, bind_host=hosts[0], additional_bind_hosts=list(hosts[1:]), port=port,
    )


async def _speaks_https(host: str, port: int) -> bool:
    """True if the hardened MCP app is answering TLS at *host*:*port*.

    A bare handshake would only prove *something* is listening; an
    unauthenticated ``POST /mcp`` proves it is **this** application, because the
    401 comes from :class:`~workstation_agent.network_mcp.hardening.Hardening`
    and nothing else on the machine would produce it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=10,
        )
    except (OSError, ssl.SSLError, TimeoutError):
        return False
    try:
        target = f"[{host}]" if ":" in host else host
        writer.write(
            f"POST /mcp HTTP/1.1\r\nHost: {target}:{port}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n".encode(),
        )
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=10)
        return b" 401 " in status
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (OSError, ssl.SSLError, TimeoutError):
            pass


def _port_is_free(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        return False
    return True


# ---------------------------------------------------------------------------
# Several addresses bind, and every one of them answers
# ---------------------------------------------------------------------------


async def test_every_chosen_address_gets_a_listener_that_answers(tmp_path, usable):
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable), state_dir=tmp_path)

    info = await server.start()
    try:
        assert info.bind_hosts == usable
        assert len(info.urls) == len(usable)
        assert info.bind_failures == ()
        assert info.degraded is False
        for host in usable:
            assert await _speaks_https(host, info.port), host
    finally:
        await server.stop()


async def test_one_port_is_shared_even_when_the_os_picks_it(tmp_path, usable):
    """``port = 0`` must not become a different ephemeral port per address.

    One endpoint answering on three different ports is not one endpoint: the
    registration carries one port, and the operator was shown one.
    """
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable, port=0), state_dir=tmp_path)

    info = await server.start()
    try:
        assert info.port != 0
        assert {u.rsplit(":", 1)[1] for u in info.urls} == {f"{info.port}/mcp"}
    finally:
        await server.stop()


async def test_urls_carry_one_entry_per_bound_address_with_ipv6_bracketed(tmp_path, usable):
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable), state_dir=tmp_path)

    info = await server.start()
    try:
        expected = tuple(
            f"https://[{h}]:{info.port}/mcp" if ":" in h else f"https://{h}:{info.port}/mcp"
            for h in usable
        )
        assert info.urls == expected
        # The preferred URL stays singular and first, because the core reads one.
        assert info.url == expected[0]
        for host, url in zip(usable, info.urls, strict=True):
            if ":" in host:
                assert url.startswith(f"https://[{host}]:"), "an IPv6 literal must be bracketed"
    finally:
        await server.stop()


async def test_stopping_releases_every_socket_not_just_the_first(tmp_path, usable):
    """A stop that freed one of three listeners leaves the others bound with
    nothing behind them, and the next start fails on an address the operator
    can see nothing wrong with."""
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable), state_dir=tmp_path)
    info = await server.start()
    port = info.port
    for host in usable:
        assert not _port_is_free(host, port), f"{host} should be in use while running"

    await server.stop()

    assert server.running is False
    for host in usable:
        assert _port_is_free(host, port), f"{host}:{port} was not released by stop()"


async def test_a_failure_after_binding_still_releases_every_socket(tmp_path, usable, monkeypatch):
    """The window between "bound" and "uvicorn owns them".

    A certificate file that vanished, an SDK that builds an app it cannot serve
    -- anything raising in there would otherwise leave every chosen address held
    by a process that is not listening on it, and the operator's next attempt
    would fail on an address nothing appears to be using.
    """
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable, port=_free_port(usable[0])), state_dir=tmp_path)

    def _boom(_token):
        msg = "the ASGI app could not be built"
        raise RuntimeError(msg)

    monkeypatch.setattr(server, "_build_app", _boom)
    with pytest.raises(RuntimeError, match="could not be built"):
        await server.start()

    assert server.running is False
    port = server.info().port
    for host in usable:
        assert _port_is_free(host, port), f"{host}:{port} was left bound by a failed start"


def _free_port(host: str) -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


async def test_the_endpoint_starts_again_on_every_address_after_a_stop(tmp_path, usable):
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    server = NetworkMCPServer(_config(usable), state_dir=tmp_path)
    first = await server.start()
    await server.stop()

    second = await server.start()
    try:
        assert second.bind_hosts == first.bind_hosts
        for host in second.bind_hosts:
            assert await _speaks_https(host, second.port), host
    finally:
        await server.stop()


# ---------------------------------------------------------------------------
# A partial bind: told which, and never shown as healthy
# ---------------------------------------------------------------------------


async def test_a_partial_bind_names_the_address_and_does_not_look_healthy(tmp_path, usable):
    """One of three already in use. The other two must serve; the operator must
    be told which one is missing and why, and nothing must report health."""
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    blocked = usable[1]
    family = socket.AF_INET6 if ":" in blocked else socket.AF_INET
    squatter = socket.socket(family, socket.SOCK_STREAM)
    try:
        squatter.bind((blocked, 0))
        squatter.listen(1)
        port = squatter.getsockname()[1]

        server = NetworkMCPServer(_config(usable, port=port), state_dir=tmp_path)
        info = await server.start()
        try:
            failed = {f.host for f in info.bind_failures}
            assert failed == {blocked}
            assert "already listening" in info.bind_failures[0].reason
            # Serving on the rest...
            assert set(info.bind_hosts) == set(usable) - {blocked}
            for host in info.bind_hosts:
                assert await _speaks_https(host, port), host
            # ...but emphatically not healthy.
            assert info.running is True
            assert info.degraded is True
            assert blocked not in " ".join(info.urls)
        finally:
            await server.stop()
    finally:
        squatter.close()


async def test_a_partial_bind_is_reported_unhealthy_by_the_agents_own_check(tmp_path, usable):
    """``Application._start_network_mcp`` must not record ok=True for it.

    The page saying "degraded" and the Agent's health saying "ok" is the exact
    disagreement that lets a partial bind pass unnoticed.
    """
    from workstation_agent.app import Application, _Subsystems

    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    blocked = usable[1]
    family = socket.AF_INET6 if ":" in blocked else socket.AF_INET
    squatter = socket.socket(family, socket.SOCK_STREAM)
    try:
        squatter.bind((blocked, 0))
        squatter.listen(1)
        port = squatter.getsockname()[1]

        app = Application.__new__(Application)
        app._subs = _Subsystems()
        cfg = _Cfg(_config(usable, port=port))
        await app._start_network_mcp(cfg)
        try:
            health = app._subs.started["network_mcp"]
            assert health.ok is False
            assert blocked in health.detail
        finally:
            if app._subs.network_mcp is not None:
                await app._subs.network_mcp.stop()
    finally:
        squatter.close()


class _Cfg:
    def __init__(self, network_mcp) -> None:
        self.network_mcp = network_mcp


async def test_no_address_binding_at_all_is_still_a_loud_failure(tmp_path, usable):
    """The existing contract: a wholly failed bind raises rather than leaving a
    dead endpoint that reports running."""
    certs.ensure_certificate(tmp_path, bind_hosts=list(usable))
    squatters = []
    try:
        first = socket.socket(
            socket.AF_INET6 if ":" in usable[0] else socket.AF_INET, socket.SOCK_STREAM,
        )
        first.bind((usable[0], 0))
        first.listen(1)
        squatters.append(first)
        port = first.getsockname()[1]
        for host in usable[1:]:
            sock = socket.socket(
                socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM,
            )
            try:
                sock.bind((host, port))
                sock.listen(1)
                squatters.append(sock)
            except OSError:  # pragma: no cover — the port was taken on that address anyway
                sock.close()

        server = NetworkMCPServer(_config(usable, port=port), state_dir=tmp_path)
        with pytest.raises(RuntimeError, match="could not bind"):
            await server.start()
        assert server.running is False
        await server.stop()
    finally:
        for sock in squatters:
            sock.close()


# ---------------------------------------------------------------------------
# The SAN rule, enforced where it cannot be clicked past
# ---------------------------------------------------------------------------


async def test_an_address_outside_the_san_is_never_bound(tmp_path, usable):
    """The invariant that does not depend on the UI at all.

    Whatever reaches the config -- a crafted POST, a hand-edited file, a stale
    page -- the endpoint will not put a listener on an address it cannot present
    a matching certificate for.
    """
    # A certificate that covers only the first address.
    certs.ensure_certificate(tmp_path, bind_hosts=[usable[0]])
    stored = certs.ensure_certificate(tmp_path)
    outside = next(h for h in usable[1:] if h not in stored.sans)

    server = NetworkMCPServer(_config((usable[0], outside)), state_dir=tmp_path)
    info = await server.start()
    try:
        assert info.bind_hosts == (usable[0],)
        assert [f.host for f in info.bind_failures] == [outside]
        assert "certificate does not cover" in info.bind_failures[0].reason
        assert info.degraded is True
        assert not await _speaks_https(outside, info.port)
    finally:
        await server.stop()


async def test_a_name_resolving_to_a_wildcard_never_reaches_a_socket(
    tmp_path, usable, monkeypatch,
):
    """The whole endpoint, not just the helper.

    The wildcard prohibition is enforced on the configured *string* by
    ``NetworkMcpConfig`` -- but a hostname is not an address, and a name in DNS
    or in the hosts file can resolve to ``0.0.0.0``. This asserts that such a
    name reaches ``start()``, passes the schema and the SAN check, and still
    never gets a listening socket: nothing on this machine ends up answering on
    an interface the owner did not choose.
    """
    poisoned = "bridge.lan"
    certs.ensure_certificate(tmp_path, bind_hosts=[poisoned, usable[0]])
    real = socket.getaddrinfo

    def _fake(host, port, *args, **kwargs):
        if host == poisoned:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", port))]  # noqa: S104
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake)

    # The schema accepts it: it is a hostname, and hostnames are legal.
    cfg = _config((poisoned, usable[0]), port=_free_port(usable[0]))
    assert cfg.bind_hosts == (poisoned, usable[0])

    server = NetworkMCPServer(cfg, state_dir=tmp_path)
    info = await server.start()
    try:
        assert [f.host for f in info.bind_failures] == [poisoned]
        assert "every interface on this machine" in info.bind_failures[0].reason
        assert info.degraded is True
        # The chosen address still answers; one poisoned name does not take the
        # set down with it.
        assert info.bind_hosts == (usable[0],)
        assert await _speaks_https(usable[0], info.port)
    finally:
        await server.stop()


async def test_regenerating_for_the_pending_hosts_lets_them_bind(tmp_path, usable):
    """The sanctioned way through, end to end against the real certificate."""
    certs.ensure_certificate(tmp_path, bind_hosts=[usable[0]])
    server = NetworkMCPServer(_config(usable), state_dir=tmp_path)

    fresh = server.regenerate_certificate(for_hosts=usable)

    for host in usable:
        assert host in fresh.sans
    info = await server.start()
    try:
        assert info.bind_failures == ()
        assert info.bind_hosts == usable
    finally:
        await server.stop()
