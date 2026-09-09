"""Subtask P13 -- the chosen *set* of bind addresses, at the level below sockets.

The socket-level claims live in
``tests/integration/test_network_mcp_multi_bind.py``. These are the rules that
have to hold before a socket is ever opened: that a set is still not a wildcard,
that the set is de-duplicated the way addresses compare rather than the way
strings do, and that ``urls`` is built the way a URL parser reads it.
"""

from __future__ import annotations

import socket

import pytest
from pydantic import ValidationError

from workstation_agent.config.schema import AgentConfig, NetworkMcpConfig
from workstation_agent.network_mcp import certs
from workstation_agent.network_mcp.listeners import (
    BindFailure,
    _is_unspecified,
    close_listeners,
    endpoint_url,
    open_listeners,
)
from workstation_agent.network_mcp.server import NetworkMCPServer

WILDCARDS = ["0.0.0.0", "::", "[::]", "*", "", "   ", "0", "::0"]  # noqa: S104


# ---------------------------------------------------------------------------
# A set is still not a wildcard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("wildcard", WILDCARDS)
def test_a_wildcard_is_still_refused_as_the_preferred_address(wildcard):
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(bind_host=wildcard)


@pytest.mark.parametrize("wildcard", WILDCARDS)
def test_a_wildcard_is_refused_in_the_additional_set_too(wildcard):
    """Otherwise the multi-address field is the wildcard bind by another door."""
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(bind_host="192.168.1.50", additional_bind_hosts=[wildcard])


@pytest.mark.parametrize("wildcard", WILDCARDS)
def test_a_wildcard_hidden_among_valid_entries_is_refused(wildcard):
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(
            bind_host="192.168.1.50",
            additional_bind_hosts=["10.0.0.7", wildcard, "127.0.0.1"],
        )


def test_selecting_several_addresses_is_accepted_and_is_not_all_of_them():
    cfg = NetworkMcpConfig(
        bind_host="192.168.1.50", additional_bind_hosts=["10.0.0.7", "127.0.0.1"],
    )
    assert cfg.bind_hosts == ("192.168.1.50", "10.0.0.7", "127.0.0.1")


def test_the_default_is_still_one_loopback_address():
    cfg = AgentConfig().network_mcp
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.additional_bind_hosts == []
    assert cfg.bind_hosts == ("127.0.0.1",)


# ---------------------------------------------------------------------------
# The resolved set
# ---------------------------------------------------------------------------


def test_the_preferred_address_is_first_because_the_registration_names_one():
    cfg = NetworkMcpConfig(bind_host="10.0.0.7", additional_bind_hosts=["192.168.1.50"])
    assert cfg.bind_hosts[0] == "10.0.0.7"


def test_addresses_are_de_duplicated_as_addresses_not_as_strings():
    """``::1`` and ``[::1]`` are one address; two sockets would be a bind failure
    on the second and an error the operator could do nothing about."""
    cfg = NetworkMcpConfig(bind_host="::1", additional_bind_hosts=["[::1]", "0:0:0:0:0:0:0:1"])
    assert cfg.bind_hosts == ("::1",)


def test_a_name_is_de_duplicated_case_insensitively_because_dns_is():
    cfg = NetworkMcpConfig(bind_host="Workstation", additional_bind_hosts=["workstation"])
    assert cfg.bind_hosts == ("Workstation",)


def test_assigning_bind_host_directly_still_changes_the_set():
    """Pydantic allows the assignment (no ``validate_assignment``), so
    ``bind_hosts`` must be derived rather than stored, or it goes stale."""
    cfg = NetworkMcpConfig(bind_host="127.0.0.1")
    cfg.bind_host = "192.168.1.50"
    assert cfg.bind_hosts == ("192.168.1.50",)


def test_a_round_trip_through_model_dump_preserves_the_set():
    cfg = NetworkMcpConfig(bind_host="10.0.0.7", additional_bind_hosts=["192.168.1.50"])
    again = NetworkMcpConfig.model_validate(cfg.model_dump())
    assert again.bind_hosts == cfg.bind_hosts


# ---------------------------------------------------------------------------
# urls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("192.168.1.50", "https://192.168.1.50:8765/mcp"),
        ("workstation.lan", "https://workstation.lan:8765/mcp"),
        ("::1", "https://[::1]:8765/mcp"),
        ("fe80::1", "https://[fe80::1]:8765/mcp"),
        ("[fe80::1]", "https://[fe80::1]:8765/mcp"),
    ],
)
def test_an_ipv6_literal_is_bracketed_and_nothing_else_is(host, expected):
    assert endpoint_url(host, 8765) == expected


def test_info_lists_a_url_per_configured_address_before_the_endpoint_starts(tmp_path):
    """So the page can show what switching it on would produce."""
    cfg = NetworkMcpConfig(
        bind_host="192.168.1.50", additional_bind_hosts=["fe80::1"], port=8765,
    )
    info = NetworkMCPServer(cfg, state_dir=tmp_path).info()

    assert info.urls == (
        "https://192.168.1.50:8765/mcp",
        "https://[fe80::1]:8765/mcp",
    )
    assert info.url == info.urls[0]
    assert info.bind_hosts == ("192.168.1.50", "fe80::1")
    assert info.running is False
    assert info.degraded is False
    assert info.bind_failures == ()


def test_the_single_url_stays_the_preferred_one_for_the_core(tmp_path):
    """The core reads one ``url``; adding ``urls`` must not move it."""
    cfg = NetworkMcpConfig(
        bind_host="192.168.1.50", additional_bind_hosts=["10.0.0.7"], port=8765,
    )
    info = NetworkMCPServer(cfg, state_dir=tmp_path).info()
    assert info.url == "https://192.168.1.50:8765/mcp"
    assert info.bind_host == "192.168.1.50"


# ---------------------------------------------------------------------------
# open_listeners: the SAN rule and partial outcomes, without a live server
# ---------------------------------------------------------------------------


@pytest.fixture
def cert_for(tmp_path):
    """A real certificate file covering the hosts asked for.

    ``open_listeners`` takes the certificate *path* and parses the SAN itself
    rather than accepting a list, so these tests exercise the same read the
    endpoint does. There is no way to hand it a SAN that has nothing to do with
    the certificate being served, which is the point.
    """

    def _make(*hosts: str):
        certs.ensure_certificate(tmp_path, bind_hosts=list(hosts), regenerate=True)
        return tmp_path / "server.crt"

    return _make


def test_an_address_outside_the_san_is_refused_before_a_socket_is_made(cert_for):
    outcome = open_listeners(["203.0.113.9"], 0, cert_path=cert_for("127.0.0.1"))

    assert outcome.sockets == ()
    assert outcome.bound == ()
    assert [f.host for f in outcome.failures] == ["203.0.113.9"]
    assert "certificate does not cover" in outcome.failures[0].reason
    # And the message says what to do about it, including the cost.
    assert "Regenerate" in outcome.failures[0].reason
    assert "fingerprint" in outcome.failures[0].reason


def test_the_san_is_read_from_the_certificate_no_caller_can_substitute_one(cert_for):
    """The constraint the module holds, it also enforces.

    A ``sans=`` argument would be a rule this function could not keep: a caller
    that forgot it would silently disable the check, and one that passed a list
    unrelated to the certificate would disable it just as quietly. There is no
    such argument -- omitting the certificate is a ``TypeError``.
    """
    import inspect

    params = inspect.signature(open_listeners).parameters
    assert "sans" not in params
    assert params["cert_path"].default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        open_listeners(["127.0.0.1"], 0)  # type: ignore[call-arg]

    # And the entries really come from the file, with no argument changing at
    # all: the same call is refused against a certificate that omits the address
    # and accepted against one that carries it. (Loopback would prove nothing --
    # ``local_identities`` puts it in every certificate it generates.)
    outside = "198.51.100.7"
    refused = open_listeners([outside], 0, cert_path=cert_for("203.0.113.9"))
    assert [f.host for f in refused.failures] == [outside]
    assert "certificate does not cover" in refused.failures[0].reason

    allowed = open_listeners([outside], 0, cert_path=cert_for(outside))
    assert [f.host for f in allowed.failures] == [outside]
    # Now it gets as far as the socket, and fails for a different reason
    # entirely -- this machine does not have that address.
    assert "does not currently have this address" in allowed.failures[0].reason


def test_an_unreadable_certificate_is_not_degraded_into_a_guess(tmp_path):
    """Neither "covers nothing" nor "assume covered" is an answer to "may this
    address be bound", and guessing either way is the hole the check closes."""
    missing = tmp_path / "server.crt"
    with pytest.raises(FileNotFoundError):
        open_listeners(["127.0.0.1"], 0, cert_path=missing)

    missing.write_text("not a certificate", encoding="utf-8")
    with pytest.raises(ValueError, match=r"(?i)load|pem|unable"):
        open_listeners(["127.0.0.1"], 0, cert_path=missing)


def test_a_bind_failure_renders_as_the_address_and_the_reason():
    assert str(BindFailure("10.0.0.7", "busy")) == "10.0.0.7 (busy)"


def test_an_address_this_machine_does_not_have_is_named_not_swallowed(cert_for):
    outcome = open_listeners(["203.0.113.9"], 0, cert_path=cert_for("203.0.113.9"))

    assert outcome.bound == ()
    assert outcome.failures[0].host == "203.0.113.9"
    assert "does not currently have this address" in outcome.failures[0].reason


def test_a_covered_address_binds_and_reports_its_url(cert_for):
    outcome = open_listeners(["127.0.0.1"], 0, cert_path=cert_for("127.0.0.1"))
    try:
        assert len(outcome.sockets) == 1
        assert outcome.failures == ()
        assert outcome.bound[0].host == "127.0.0.1"
        assert outcome.bound[0].url == f"https://127.0.0.1:{outcome.port}/mcp"
    finally:
        for sock in outcome.sockets:
            sock.close()


def test_a_partial_outcome_carries_both_halves(cert_for):
    """What bound and what did not, in one answer -- the caller needs both to
    decide whether "running" is the whole truth."""
    outcome = open_listeners(
        ["127.0.0.1", "203.0.113.9"], 0, cert_path=cert_for("127.0.0.1"),
    )
    try:
        assert [b.host for b in outcome.bound] == ["127.0.0.1"]
        assert [f.host for f in outcome.failures] == ["203.0.113.9"]
    finally:
        for sock in outcome.sockets:
            sock.close()


# ---------------------------------------------------------------------------
# The wildcard ban survives resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    ["0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0", "::0.0.0.0", "::ffff:0.0.0.0"],  # noqa: S104
)
def test_every_written_form_of_the_unspecified_address_is_recognised(spelling):
    assert _is_unspecified(spelling) is True


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "192.168.1.50", "::1", "fe80::1", "::ffff:192.168.1.50", "workstation"],
)
def test_a_real_address_is_not_mistaken_for_the_unspecified_one(address):
    assert _is_unspecified(address) is False


@pytest.mark.parametrize("spelling", ["::ffff:0.0.0.0", "::0.0.0.0", "0:0:0:0:0:0:0:0"])
def test_a_pasted_wildcard_the_literal_list_misses_is_still_refused(spelling):
    """The schema's literal set catches what is typed; parsing catches what is
    pasted. ``::ffff:0.0.0.0`` looks like an ordinary address and is not one."""
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(bind_host=spelling)
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(bind_host="127.0.0.1", additional_bind_hosts=[spelling])


def test_a_name_that_resolves_to_a_wildcard_is_refused_at_bind_time(cert_for, monkeypatch):
    """The finding this closes: the ban was enforced on the configured string,
    and a name is not an address.

    A hostname in DNS or in the hosts file that resolves to ``0.0.0.0`` passes
    the schema and passes the SAN check, and would have been handed to
    ``bind()`` as a wildcard socket -- the endpoint listening on every interface
    the owner did not choose, which is the exact outcome the prohibition exists
    to prevent.
    """
    poisoned = "bridge.lan"
    real = socket.getaddrinfo

    def _fake(host, port, *args, **kwargs):
        if host == poisoned:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", port))]  # noqa: S104
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake)

    outcome = open_listeners(
        [poisoned, "127.0.0.1"], 0, cert_path=cert_for(poisoned, "127.0.0.1"),
    )
    try:
        assert [f.host for f in outcome.failures] == [poisoned]
        assert "every interface on this machine" in outcome.failures[0].reason
        # Reported as an ordinary per-address failure, so the other chosen
        # address still answers -- one poisoned name must not take the set down.
        assert [b.host for b in outcome.bound] == ["127.0.0.1"]
    finally:
        for sock in outcome.sockets:
            sock.close()


def test_a_name_resolving_to_the_ipv4_mapped_wildcard_is_refused_too(cert_for, monkeypatch):
    """``::ffff:0.0.0.0`` reports ``is_unspecified == False`` and binds every
    IPv4 interface anyway."""
    poisoned = "bridge6.lan"
    real = socket.getaddrinfo

    def _fake(host, port, *args, **kwargs):
        if host == poisoned:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                     ("::ffff:0.0.0.0", port, 0, 0))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _fake)

    outcome = open_listeners([poisoned], 0, cert_path=cert_for(poisoned))
    assert outcome.bound == ()
    assert "every interface on this machine" in outcome.failures[0].reason


# ---------------------------------------------------------------------------
# Nothing is left bound when something unexpected escapes the loop
# ---------------------------------------------------------------------------


def test_an_unexpected_exception_mid_loop_releases_what_was_already_bound(
    cert_for, monkeypatch,
):
    """An expected ``OSError`` per address is a ``BindFailure`` and the loop
    carries on -- that is what makes a partial bind reportable. Anything else
    escaping would leave every socket opened so far bound to a process that is
    not listening on it, and the next attempt would fail on addresses nothing
    appears to be using. ``KeyboardInterrupt`` is exactly the case, which is why
    the guard catches ``BaseException``.
    """
    from workstation_agent.network_mcp import listeners as listeners_mod

    opened: list[socket.socket] = []
    real_bind = listeners_mod._bind_one

    def _bind_then_explode(host, port):
        if opened:
            raise KeyboardInterrupt
        sock = real_bind(host, port)
        opened.append(sock)
        return sock

    monkeypatch.setattr(listeners_mod, "_bind_one", _bind_then_explode)

    cert_path = cert_for("127.0.0.1", "localhost")
    with pytest.raises(KeyboardInterrupt):
        open_listeners(["127.0.0.1", "localhost"], 0, cert_path=cert_path)

    assert opened, "the first address should have bound before the interruption"
    assert opened[0].fileno() == -1, "the already-bound socket was left open"


def test_a_socket_interrupted_before_its_port_is_read_is_still_released(
    cert_for, monkeypatch,
):
    """The window between the bind and the bookkeeping is not a place to be
    interrupted.

    The cleanup can only release sockets the loop has already recorded, so a
    ``KeyboardInterrupt`` arriving after ``bind()`` but before the socket was
    recorded used to leave it bound to a process that is not listening on it --
    and the operator's next start would fail on an address nothing appears to be
    using, which is the exact failure the cleanup exists to prevent. Asserted on
    the socket's own state rather than on whether close was called, because the
    close *was* called for the earlier addresses either way.
    """
    from workstation_agent.network_mcp import listeners as listeners_mod

    cert_path = cert_for("127.0.0.1", "localhost")
    opened: list[socket.socket] = []
    real_bind = listeners_mod._bind_one

    def _remember(host, port):
        sock = real_bind(host, port)
        opened.append(sock)
        return sock

    def _interrupt_instead_of_reporting_the_port(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(listeners_mod, "_bind_one", _remember)
    monkeypatch.setattr(socket.socket, "getsockname", _interrupt_instead_of_reporting_the_port)

    with pytest.raises(KeyboardInterrupt):
        open_listeners(["127.0.0.1", "localhost"], 0, cert_path=cert_path)

    assert opened, "the first address should have bound before the interruption"
    assert all(sock.fileno() == -1 for sock in opened), (
        "a socket that bound was left bound because it had not been recorded yet"
    )


def test_closing_finishes_the_set_even_when_one_close_is_interrupted():
    """The last-resort release path is the one that has to finish what it starts.

    An operator hitting Ctrl+C during a failing startup is exactly when this
    runs, and an interruption on one socket used to abandon every socket after
    it. The interrupt still has to arrive -- one that vanishes is worse than one
    that is late, and ``open_listeners`` re-raises straight after calling this --
    so it is held back until the last socket is closed rather than dropped.
    """

    class _InterruptsOnClose(socket.socket):
        def close(self):
            super().close()
            raise KeyboardInterrupt

    first = socket.socket()
    interrupting = _InterruptsOnClose()
    last = socket.socket()
    try:
        with pytest.raises(KeyboardInterrupt):
            close_listeners([first, interrupting, last])

        assert first.fileno() == -1
        assert last.fileno() == -1, "the sockets after the interruption were abandoned"
    finally:
        for sock in (first, last):
            socket.socket.close(sock)


def test_the_sequence_is_read_before_any_socket_is_closed():
    """Closing must not be diverted through caller code between two closes.

    ``close_listeners`` takes an ``Iterable``, so the caller decides what
    advancing it runs -- and here closing one socket shortens the very list
    being iterated. Iterating it directly then walks past the sockets that
    shifted down and leaves them open, which is the one thing this function is
    not allowed to do. Reading the sequence into a list first makes what the
    caller does to it afterwards none of the loop's business.
    """
    live: list[socket.socket] = []

    class _RemovesItselfOnClose(socket.socket):
        def close(self):
            live.remove(self)
            super().close()

    live.extend(_RemovesItselfOnClose() for _ in range(4))
    every = list(live)

    close_listeners(live)

    assert [sock.fileno() for sock in every] == [-1, -1, -1, -1], (
        "a socket was skipped because the sequence shrank while it was iterated"
    )


def test_a_lazy_sequence_that_fails_partway_still_releases_what_it_yielded():
    """A generator that raises is a failure to *produce* sockets, and it is
    answered the same way as a failure to close one: everything already obtained
    is released, and the failure is raised afterwards rather than instead."""
    yielded: list[socket.socket] = []

    def _sockets():
        for _ in range(3):
            sock = socket.socket()
            yielded.append(sock)
            yield sock
        raise KeyboardInterrupt

    try:
        with pytest.raises(KeyboardInterrupt):
            close_listeners(_sockets())

        assert len(yielded) == 3
        assert all(sock.fileno() == -1 for sock in yielded)
    finally:
        for sock in yielded:
            socket.socket.close(sock)


class _InterruptsOnClose(socket.socket):
    def close(self):
        super().close()
        raise KeyboardInterrupt


class _ExitsOnClose(socket.socket):
    def close(self):
        super().close()
        raise SystemExit(3)


def test_the_first_interruption_is_the_one_that_propagates():
    """Which one leaves is a choice, and it is the first.

    Two sockets raising means two instructions, and only one can be the
    exception that propagates. Taking the first keeps the answer independent of
    how many sockets happened to be left to close after it -- and the later ones
    are deliberately let go rather than assembled into a chain, which is a lot
    of exception-graph machinery on the path least likely to ever run.
    """
    first = _InterruptsOnClose()
    second = _ExitsOnClose()
    last = socket.socket()
    try:
        with pytest.raises(KeyboardInterrupt):
            close_listeners([first, second, last])

        assert last.fileno() == -1, "the sockets after the interruptions were abandoned"
    finally:
        socket.socket.close(last)


def test_the_failure_that_started_the_shutdown_is_still_reachable():
    """The link an incident is reconstructed from, and it costs nothing to keep.

    ``open_listeners`` calls this from inside its own ``except`` block, so an
    interruption raised from here while that block is running gets the original
    failure as its ``__context__`` -- assigned by CPython, not by us. It is the
    one piece of the exception graph worth having: "the shutdown was already
    under way because of *this*, and then it was interrupted".
    """
    interrupting = _InterruptsOnClose()
    original = RuntimeError("the failure that started the shutdown")

    def _release_because_of(exc):
        try:
            raise exc
        except RuntimeError:
            close_listeners([interrupting])

    with pytest.raises(KeyboardInterrupt) as caught:
        _release_because_of(original)

    assert caught.value.__context__ is original, "the failure that started it was lost"

