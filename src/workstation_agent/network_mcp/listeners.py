"""One listening socket per operator-chosen address.

``uvicorn`` binds *one* host per :class:`uvicorn.Server`. Binding a chosen set
of addresses therefore means one of two things, and the choice matters:

1. **Several server instances over one application.** Each has its own
   lifespan, its own graceful-shutdown clock and its own ``should_exit`` flag.
   The MCP SDK's ``StreamableHTTPSessionManager`` is started *by the lifespan*
   and is not re-entrant, so running the same ASGI app under several lifespans
   would start several session managers over one shared server object — two
   views of "live session", two idle reapers, and a shutdown that has to be
   choreographed across N servers that can each fail independently. Building
   one app per address instead would mean N session managers, N bearer-token
   gates and N enrolment windows, so a Join opened on one address would be
   invisible on the others.

2. **Create the sockets here and hand the whole list to one server.**
   ``uvicorn.Server.serve(sockets=[...])`` accepts a list, calls
   ``loop.create_server(sock=...)`` once per socket, and closes every one of
   them in ``Server.shutdown``. One application, one lifespan, one session
   manager, one enrolment window, one shutdown — and every socket released
   together, because they are released by the same call that releases the
   first.

This module is option 2. The bind is done here, before uvicorn is given
anything, which is also what makes a *partial* bind reportable: each address
fails on its own ``bind()`` call, with its own errno, and the caller gets a
list of what bound and a list of what did not. uvicorn's own bind path answers
a failure with ``sys.exit(3)``, which cannot say *which* address failed because
it only ever had one.

Three deliberate departures from what ``uvicorn.Config.bind_socket`` does:

* **No ``SO_REUSEADDR`` on Windows.** There it does not mean what it means on
  POSIX: it lets a second process bind an address:port another process is
  already listening on, silently, and the two then split incoming connections
  unpredictably. Setting it would turn "that port is already in use" — the one
  failure this module exists to report — into a bind that succeeds and an
  endpoint that answers half the time. It is set on POSIX, where it means the
  ordinary TIME_WAIT reuse.
* **``IPV6_V6ONLY``.** An IPv6 socket that also accepts IPv4 is a wildcard the
  operator did not choose. The schema refuses ``::``; this refuses the same
  thing arriving through a dual-stack socket.
* **The wildcard prohibition is enforced on the *resolved* address.** uvicorn
  binds whatever it is given. ``NetworkMcpConfig`` refuses ``0.0.0.0``, ``::``
  and ``*`` as configured *strings*, but a hostname is not an address: a name in
  DNS or in the hosts file can resolve to ``0.0.0.0``, and ``::ffff:0.0.0.0``
  never looks like a wildcard as a string at all. Checking the string alone
  would make the ban bypassable by anything that controls a name. See
  :func:`_bind_one`.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import logging
import socket
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from workstation_agent.network_mcp.certs import sans_of_file

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable, Sequence
    from pathlib import Path

log = logging.getLogger(__name__)

#: errno values worth translating into a sentence an operator can act on.
#: Windows reports WSAEADDRINUSE/WSAEADDRNOTAVAIL through these same names.
_IN_USE = {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", errno.EADDRINUSE)}
_NOT_AVAILABLE = {
    errno.EADDRNOTAVAIL,
    getattr(errno, "WSAEADDRNOTAVAIL", errno.EADDRNOTAVAIL),
}


@dataclass(frozen=True)
class BoundAddress:
    """One address the endpoint is actually answering on."""

    host: str
    """As the operator wrote it — not the resolved sockaddr.

    The registration, the certificate SAN and the Host-header allowlist all
    speak in the operator's spelling, and a hostname silently replaced by the
    address it resolved to today would quietly stop matching a SAN that carries
    the name.
    """
    port: int
    url: str
    """``https://<host>:<port>/mcp``, IPv6 bracketed."""


@dataclass(frozen=True)
class BindFailure:
    """One address the endpoint is *not* answering on, and why.

    Carried all the way to the UI. A partial bind that reported only a count
    would leave the operator to work out which of their three addresses is
    missing, which is the whole difficulty.
    """

    host: str
    reason: str

    def __str__(self) -> str:
        return f"{self.host} ({self.reason})"


@dataclass(frozen=True)
class BindOutcome:
    """What :func:`open_listeners` managed, and what it did not."""

    sockets: tuple[socket.socket, ...]
    bound: tuple[BoundAddress, ...]
    failures: tuple[BindFailure, ...]

    @property
    def port(self) -> int | None:
        """The port every bound socket shares, or ``None`` if none bound."""
        return self.bound[0].port if self.bound else None


def endpoint_url(host: str, port: int) -> str:
    """``https://<host>:<port>/mcp``, with an IPv6 literal bracketed.

    ``https://fe80::1:8765/mcp`` is not a wrong-looking URL, it is a *different*
    URL: without brackets the parser reads the port as part of the address. The
    core would fail to connect and the message would be about the host, not the
    brackets.
    """
    bare = host.strip()
    if ":" in bare and not bare.startswith("["):
        bare = f"[{bare}]"
    return f"https://{bare}:{port}/mcp"


def _reason_for(exc: OSError) -> str:
    """Turn an errno into something the operator can act on."""
    if isinstance(exc, WildcardBindError):
        return (
            f"{exc}. Binding it would expose this workstation on interfaces you have "
            "not thought about, so it is refused however it is spelled — including "
            "when a name resolves to one. Choose an address from the list"
        )
    if exc.errno in _IN_USE:
        return "another process is already listening on this address and port"
    if exc.errno in _NOT_AVAILABLE:
        return "this machine does not currently have this address"
    if isinstance(exc, socket.gaierror):
        return f"this address could not be resolved ({exc})"
    return str(exc) or type(exc).__name__


def _is_unspecified(address: object) -> bool:
    """True if *address* is "every interface", in any spelling.

    ``ipaddress`` is the authority rather than a list of strings, because the
    strings are unbounded: ``0.0.0.0``, ``::``, ``0:0:0:0:0:0:0:0``,
    ``::0.0.0.0``, ``::ffff:0.0.0.0`` and a scoped ``::%0`` are all the same
    socket and only two of them look like a wildcard to a human. The
    IPv4-mapped arm is the one that matters: ``::ffff:0.0.0.0`` has
    ``is_unspecified == False`` because it is not ``::``, yet binding it hands
    out every IPv4 interface on the machine.
    """
    if not isinstance(address, str):
        return False
    bare = address.strip().strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return False
    if ip.is_unspecified:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_unspecified)


def _resolve(host: str, port: int) -> tuple[int, tuple[object, ...]]:
    """Resolve *host* to ``(family, sockaddr)`` for a passive (listening) socket.

    ``getaddrinfo`` rather than a bare ``bind((host, port))`` so a link-local
    IPv6 address carries its scope id, and so a name that has both an A and an
    AAAA record resolves predictably instead of by whichever the resolver
    happened to order first. IPv4 is preferred for a *name* — that is what the
    single-address path did before this, and changing which family a hostname
    binds would be an invisible behaviour change — while an address written as
    an IPv6 literal binds IPv6.
    """
    cleaned = host.strip().strip("[]")
    infos = socket.getaddrinfo(
        cleaned, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE,
    )
    if not infos:  # pragma: no cover — getaddrinfo raises rather than returning []
        msg = f"no address information for {host!r}"
        raise OSError(msg)
    preferred = (
        (socket.AF_INET6, socket.AF_INET)
        if ":" in cleaned
        else (socket.AF_INET, socket.AF_INET6)
    )
    for family in preferred:
        for info in infos:
            if info[0] == family:
                return info[0], info[4]
    return infos[0][0], infos[0][4]


class WildcardBindError(OSError):
    """Raised when a name resolved to "every interface".

    An :class:`OSError` subclass so it travels the same path as a failed
    ``bind()`` and is reported as an ordinary per-address failure, rather than
    aborting the whole set: one poisoned name must not stop the operator's other
    two addresses from answering.
    """


def _bind_one(host: str, port: int) -> socket.socket:
    """Bind one listening socket for *host*:*port*. Raises :class:`OSError`.

    The wildcard prohibition is enforced **here**, on the resolved ``sockaddr``,
    and not only on the configured string. ``NetworkMcpConfig`` refuses
    ``0.0.0.0``, ``::`` and ``*`` as *values*, which stops the operator typing
    one — but a hostname is not an address, and nothing stops a name in DNS or
    in ``%SystemRoot%\\System32\\drivers\\etc\\hosts`` resolving to ``0.0.0.0``.
    A check on the string alone therefore means the ban is bypassable by
    anything that controls a name: the endpoint would end up listening on every
    interface the owner did not choose, which is the precise outcome the
    prohibition exists to prevent. Resolution happens once, immediately before
    ``bind()``, and the resolved address is what is judged.
    """
    family, sockaddr = _resolve(host, port)
    if sockaddr and _is_unspecified(sockaddr[0]):
        msg = (
            f"{host!r} resolves to {sockaddr[0]}, which is every interface on this "
            f"machine and not an interface you chose"
        )
        raise WildcardBindError(msg)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if family == socket.AF_INET6:
            # Not fatal if the platform refuses it; the address is still a
            # single chosen one, this only stops it also answering on IPv4.
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if sys.platform != "win32":  # pragma: no cover — Windows-only target
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(sockaddr)
    except BaseException:
        sock.close()
        raise
    return sock


def open_listeners(
    hosts: Sequence[str],
    port: int,
    *,
    cert_path: Path,
) -> BindOutcome:
    """Open one listening socket per entry of *hosts*, in order.

    Args:
        hosts: The operator's chosen addresses, preferred first. Already
            wildcard-checked as *strings* and de-duplicated by
            ``NetworkMcpConfig``; checked again as *resolved addresses* here,
            because a name is not an address (see :func:`_bind_one`).
        port: The port every address binds. ``0`` asks the OS to pick — see
            below.
        cert_path: The endpoint's certificate file — the same one handed to
            ``uvicorn`` as ``ssl_certfile``. Its SAN entries are parsed **here**,
            from that file, and **an address the SAN does not cover is not bound
            at all**; it comes back as a :class:`BindFailure` naming it. Binding
            it would produce the exact failure this endpoint's design cannot
            tolerate: the core's pin succeeds while any hostname-verifying
            client is rejected, with nothing on either side saying why.

            Taking the path rather than a list of SAN strings is deliberate and
            was a review finding. A ``sans: Sequence[str] = ()`` parameter is a
            constraint this module *holds* but cannot *enforce* — a future
            caller that forgot the argument would silently disable the check
            rather than fail, and any caller could hand over a list that has
            nothing to do with the certificate being served. Reading the file
            means the addresses are judged against the certificate that will
            actually be presented on the wire, at the moment of binding, and no
            caller can weaken that by supplying something else.

    Returns:
        A :class:`BindOutcome`. ``sockets`` may be empty — the caller decides
        whether "nothing bound" is fatal — and ``failures`` may be non-empty
        alongside a non-empty ``sockets``, which is a *partial* bind and must
        never be reported as simply healthy.

    Raises:
        OSError, ValueError: if *cert_path* cannot be read or parsed. Not
            degraded into "covers nothing" or "assume covered": neither is an
            answer to "may this address be bound", and guessing either way is
            the hole the check exists to close. No socket is open when this
            happens — the certificate is read before the first bind.

    ``port = 0`` and several addresses: the OS would otherwise pick a
    *different* ephemeral port per socket, and one endpoint answering on three
    different ports is not one endpoint. The first socket to bind fixes the
    port and the rest are bound to it explicitly, so ``info().urls`` can carry
    one port for the whole set.
    """
    from workstation_agent.registration_export import san_covers  # noqa: PLC0415

    # The file read here and the one uvicorn does later as ``ssl_certfile`` are
    # two separate reads of the same path, so a certificate replaced in between
    # would mean the addresses were judged against one file and another was
    # served. That is accepted, not overlooked: uvicorn's parameter is a path,
    # not bytes, so there is no way to hand it the exact file we inspected, and
    # re-reading or hashing before the bind would only narrow a window that our
    # own startup already bounds rather than close it.
    sans = sans_of_file(cert_path)

    sockets: list[socket.socket] = []
    bound: list[BoundAddress] = []
    failures: list[BindFailure] = []
    wanted_port = port

    # An expected `OSError` per address is a `BindFailure` and the loop carries
    # on -- that is what makes a partial bind reportable. Anything *else*
    # escaping mid-loop (a `KeyboardInterrupt` between two binds, `san_covers`
    # meeting a shape it did not expect) would otherwise leave every socket
    # opened so far bound to a process that is not listening on it, and the
    # operator's next attempt would fail on addresses nothing appears to be
    # using. `BaseException`, because `KeyboardInterrupt` is exactly the case.
    try:
        for host in hosts:
            if not san_covers(host, sans):
                listed = ", ".join(str(s) for s in sans) or "empty"
                failures.append(BindFailure(
                    host,
                    "the endpoint's certificate does not cover this address (its SAN is "
                    f"{listed}), so a client that verifies hostnames would reject it. "
                    "Regenerate the certificate to cover it -- that changes the pinned "
                    "fingerprint, so the registration must be re-exported afterwards",
                ))
                continue
            try:
                sock = _bind_one(host, wanted_port)
            except OSError as exc:
                failures.append(BindFailure(host, _reason_for(exc)))
                continue
            # Tracked in the same breath as it is bound. The cleanup below can
            # only release what is in `sockets`, so every statement between the
            # bind and the append is a window in which an asynchronous
            # exception -- `KeyboardInterrupt`, realistically -- leaves a bound
            # socket owned by a process that is not listening on it, and the
            # operator's next start fails on an address nothing appears to be
            # using. That is the failure this wrapper exists to prevent, so the
            # window is closed rather than made small.
            sockets.append(sock)
            try:
                actual = int(sock.getsockname()[1])
            except (OSError, IndexError, TypeError):  # pragma: no cover — defensive
                # Untracked before it is closed, so a socket that never yielded
                # a port is not counted among the ones that bound. The port is
                # deliberately *not* propagated from here: a socket whose port
                # could not be read must not fix the port every later address
                # inherits.
                sockets.remove(sock)
                sock.close()
                failures.append(BindFailure(host, "the bound socket reported no port"))
                continue
            if wanted_port == 0:
                wanted_port = actual
            bound.append(BoundAddress(host=host, port=actual, url=endpoint_url(host, actual)))
    except BaseException:
        close_listeners(sockets)
        raise

    return BindOutcome(tuple(sockets), tuple(bound), tuple(failures))


def close_listeners(sockets: Iterable[socket.socket]) -> None:
    """Close every socket, tolerating ones already closed.

    ``socket.close()`` is idempotent, so this is safe to call after uvicorn's
    own shutdown has already closed them — which is exactly why it is called
    there: "stopping released every socket" must not depend on uvicorn having
    reached its shutdown path.

    It also promises to finish. This is the last-resort release path, and an
    operator pressing Ctrl+C during a failing startup is precisely when it runs;
    a ``KeyboardInterrupt`` landing on the third of five closes would otherwise
    abandon the last two at the moment they most need releasing. So every socket
    is closed whatever happens to the ones before it, and the first interruption
    caught is re-raised once the loop is done. Delayed, never swallowed: an
    interrupt that disappears is worse than a late one, and
    :func:`open_listeners` re-raises immediately after calling this.

    The parameter is an ``Iterable``, so the sequence is **read into a list
    first** and every close is done from that list. Advancing a lazy caller's
    iterator inside the closing loop would put caller code — a generator body,
    or a list something else is mutating as it shrinks — between two closes, in
    the one function that must not be diverted between two closes. Reading it
    first also means a failure to *produce* the sockets is answered the same way
    as a failure to close one: recorded, and raised only after everything that
    was obtained has been released.

    Only the first interruption is kept, and the ones behind it are let go.
    Recording the rest would mean hand-building an exception graph on the path
    least likely to ever run and the most expensive to be subtly wrong in, to
    salvage the second and third press of Ctrl+C. The link that actually matters
    is not hand-built at all: re-raising from inside :func:`open_listeners`' own
    ``except`` block leaves CPython to set ``__context__`` to the failure that
    started the shutdown, which is the one an incident is reconstructed from.
    """
    interrupted: BaseException | None = None

    closing: list[socket.socket] = []
    try:
        for sock in sockets:
            # A comprehension would be tidier and would also throw away every
            # socket already obtained if the iterator raises on the next one.
            closing.append(sock)  # noqa: PERF402
    except BaseException as exc:  # noqa: BLE001 — re-raised once everything is closed
        interrupted = exc

    for sock in closing:
        try:
            with contextlib.suppress(OSError):
                sock.close()
        except BaseException as exc:  # noqa: BLE001 — re-raised once everything is closed
            if interrupted is None:
                interrupted = exc

    if interrupted is not None:
        raise interrupted
