"""The streamable-HTTP MCP endpoint PersonaCore connects to (contract §1-§3).

``https://<operator-chosen-interface>:<port>/mcp``. Self-signed, pinned
certificate; 32-byte bearer token; a static families-only tool allowlist; every
call routed through :meth:`MCPHost.invoke`, which is the gate.

The endpoint binds a **set** of operator-chosen interfaces — a machine that
bridges two networks has to answer on both — with one of them designated the
preferred address, because the registration carries one ``url`` and the core
reads one ``url``. :attr:`NetworkEndpointInfo.urls` carries the whole list. See
:mod:`~workstation_agent.network_mcp.listeners` for how several addresses are
served by one application, and ``DECISION.md`` §4 for why that way.

**Self-contained by design.** This module performs no application wiring: it does
not touch ``app.py``, does not create an ``MCPHost``, and does not read the config
store. It takes a config object and a host, and exposes :meth:`NetworkMCPServer.start`
and :meth:`NetworkMCPServer.stop`. Subtask B1 owns ``app.py`` this phase and B5 does
the wiring; see this package's ``DECISION.md`` and the B4 summary for the single
hook B5 needs.

What is *not* here, on purpose
------------------------------
* The §5.2 result envelope and §5.6 special-token stripping are **B2's**. This
  module bridges to them: if a tool result already carries an ``ok`` key it is
  passed through untouched, so B2's work lands without a change here.
* ``export-registration`` is **B5's**. It generates the manifest from
  :func:`~workstation_agent.network_mcp.tools.served_tool_names`, the same list
  this server serves from, which is what makes the two provably equal.
* The UI surface showing the token and fingerprint is **B5's**.
  :meth:`NetworkMCPServer.info` returns everything that surface needs.
"""
# ruff: noqa: PLC0415, ANN401
# PLC0415: mcp/uvicorn imports are deferred so importing this module (for the tool
#   table, the cert helpers or the config schema) does not pull in a web server.
# ANN401: MCPHost, the uvicorn server and the SDK's ASGI app are structurally
#   typed here on purpose — this module must not import them at module scope.

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from workstation_agent.network_mcp.certs import CertificateInfo, ensure_certificate
from workstation_agent.network_mcp.credentials import (
    DEFAULT_STATE_DIR,
    ensure_token,
    store_token,
)
from workstation_agent.network_mcp.enrolment import (
    DEFAULT_JOIN_TTL,
    ENDPOINT_NOT_RUNNING,
    EnrolmentError,
    EnrolmentReceiver,
    JoinStatus,
)
from workstation_agent.network_mcp.hardening import (
    MAX_HEADER_BYTES,
    Hardening,
)
from workstation_agent.network_mcp.listeners import (
    BindFailure,
    BindOutcome,
    BoundAddress,
    close_listeners,
    endpoint_url,
    open_listeners,
)
from workstation_agent.network_mcp.tools import (
    SERVED_TOOLS,
    SERVED_TOOLS_BY_NAME,
    validate_tool_names,
)

if TYPE_CHECKING:  # pragma: no cover
    import datetime as dt
    import socket
    from collections.abc import Sequence
    from pathlib import Path

    from workstation_agent.config.schema import NetworkMcpConfig

log = logging.getLogger(__name__)

#: §5.3: text results are capped by the Agent at 60,000 characters.
RESULT_CHAR_CAP: Final = 60_000

#: How long :meth:`NetworkMCPServer.start` waits for uvicorn to bind.
_BIND_TIMEOUT: Final = 10.0

_SERVER_NAME: Final = "workstation"


@dataclass(frozen=True)
class NetworkEndpointInfo:
    """Everything the operator, the UI and the registration generator need.

    This is what subtask B5's "show the token and fingerprint once, with copy
    buttons" surface renders, and what its ``export-registration`` writes into
    ``workstation/manifest.toml``.
    """

    url: str
    """``https://<host>:<port>/mcp`` — the registration's ``url`` field.

    The **preferred** URL, kept singular and first for compatibility: the core
    reads one ``url`` today, and everything downstream of this — the manifest,
    the export pre-flight, the page's copy button — still means "the one to
    connect to". It is always an element of :attr:`urls`, and while the endpoint
    is running it always names an address that actually bound, even when that is
    not the operator's first choice because their first choice failed.
    """
    bind_host: str
    """The preferred address, matching :attr:`url`."""
    port: int
    fingerprint: str
    """``sha256:<64 hex>`` — the registration's ``tls_fingerprint`` field."""
    token: str
    """The bearer token. Pasted into the core's secret store as ``workstation_token``."""
    certificate_sans: tuple[str, ...]
    certificate_expires: dt.datetime
    tool_names: tuple[str, ...]
    """The served set. B5 asserts the exported set equals this."""
    running: bool
    urls: tuple[str, ...] = ()
    """One full ``https://host:port/mcp`` per address, IPv6 bracketed.

    While running this is the addresses that actually **bound**; while stopped
    it is the addresses that *would* be bound, so the page can show the operator
    what they are choosing before they switch it on. ``urls[0]`` is
    :attr:`url`.

    This is what the enrolment payload will carry once that contract is frozen.
    Building the outbound call is not this subtask's; answering the question is.
    """
    bind_hosts: tuple[str, ...] = ()
    """The addresses behind :attr:`urls`, same order. ``bind_hosts[0]`` is
    :attr:`bind_host`."""
    bind_failures: tuple[BindFailure, ...] = ()
    """Chosen addresses that are **not** answering, each with its reason.

    Non-empty alongside :attr:`running` is a partial bind. See :attr:`degraded`.
    """
    degraded: bool = False
    """Serving, but not on every address the operator chose.

    Separate from :attr:`running` because both facts are true at once and
    collapsing them loses the one that matters: an operator who chose three
    addresses and got two must not be shown a green light. Every consumer that
    renders a status reads this, and the Agent's own health check reports the
    endpoint unhealthy while it is set.
    """


class NetworkMCPServer:
    """The LAN-facing MCP endpoint.

    Args:
        config: The endpoint's settings. Every entry of ``bind_hosts`` is
            validated by the schema to be a named interface, never a wildcard.
        mcp_host: The :class:`~workstation_agent.mcp_host.host.MCPHost` every call
            is routed through. Passing ``None`` serves ``tools/list`` and answers
            every ``tools/call`` with the §5.2 ``error`` envelope, which is what
            the endpoint should do before the host has started.
        state_dir: Where the certificate, key and token live. Defaults to
            ``%APPDATA%\\WorkstationAgent\\network-mcp``.

    Raises:
        RuntimeError: from :meth:`start` if the endpoint is already running.
    """

    def __init__(
        self,
        config: NetworkMcpConfig,
        *,
        mcp_host: Any | None = None,
        state_dir: Path | None = None,
    ) -> None:
        self._config = config
        self._mcp_host = mcp_host
        self._state_dir = state_dir
        self._token: str | None = None
        self._cert: CertificateInfo | None = None
        self._uvicorn: Any = None
        self._task: asyncio.Task[None] | None = None
        self._port: int = config.port
        self._hardening: Hardening | None = None
        #: The sockets this endpoint opened, handed to uvicorn as a set. Held so
        #: :meth:`stop` can close them itself rather than trusting uvicorn to
        #: have reached its own shutdown path.
        self._sockets: tuple[socket.socket, ...] = ()
        self._bound: tuple[BoundAddress, ...] = ()
        self._bind_failures: tuple[BindFailure, ...] = ()
        #: The enrolment window and the receiver for the token PersonaCore
        #: pushes into it. Built here rather than in :meth:`_build_app` so a Join
        #: is not silently dropped by a stop/start, and held only in memory so
        #: it *is* dropped by a restart — see ``enrolment.py``.
        self._enrolment = EnrolmentReceiver(apply_token=self._accept_pushed_token)

    # -- lifecycle -------------------------------------------------------

    async def start(self) -> NetworkEndpointInfo:
        """Generate/load credentials, bind every chosen address over TLS, serve.

        Every address in ``config.bind_hosts`` gets its own listening socket,
        opened here (see :mod:`~workstation_agent.network_mcp.listeners` for why
        here and not by uvicorn), and the whole set is handed to **one**
        ``uvicorn.Server`` over **one** ASGI app: one lifespan, one MCP session
        manager, one bearer gate, one enrolment window, and — because
        ``Server.shutdown`` closes the sockets it was given — one release.

        Returns:
            The bound endpoint's :class:`NetworkEndpointInfo`. A *partial* bind
            returns normally with :attr:`~NetworkEndpointInfo.degraded` set and
            :attr:`~NetworkEndpointInfo.bind_failures` naming what did not bind;
            it does not raise, because refusing to serve on the two addresses
            that worked would be a worse answer to "one of your three is busy"
            than serving and saying so.

        Raises:
            RuntimeError: if the endpoint is already running, if the served-tool
                table violates contract §2, or if **no** chosen address could be
                bound — the message names every address and its reason.
        """
        if self._task is not None and not self._task.done():
            msg = "network MCP endpoint is already running"
            raise RuntimeError(msg)

        # Checked at startup, not only in tests. A name the core's manifest
        # loader rejects is a *terminal load failure* on its side (contract §2),
        # reported there rather than here; refusing to serve is the cheaper and
        # far more legible failure.
        problems = validate_tool_names()
        if problems:
            msg = "the served-tool table violates contract §2: " + "; ".join(problems)
            raise RuntimeError(msg)

        # Before anything is generated, bound or bound-to: a version mismatch
        # must be a named dependency error here, not a TypeError out of the SDK
        # once the endpoint is half-built.
        _require_mcp_api()

        import uvicorn

        self._token = ensure_token(self._state_dir)
        cert, outcome = self._open_listeners()

        # From here to `create_task` the sockets are bound and nothing owns them
        # yet. Anything that raises in between -- a certificate file that
        # disappeared between `ensure_certificate` and `uvicorn.Config`, an SDK
        # that builds an app it cannot serve -- would otherwise leave every
        # chosen address held by a process that is not listening on it, and the
        # operator's next attempt would fail on an address nothing appears to be
        # using.
        try:
            app = self._build_app(self._token)
            config = self._uvicorn_config(uvicorn, app, outcome.bound[0], cert)
            server = uvicorn.Server(config)
            self._uvicorn = server
            self._task = asyncio.create_task(
                _guarded_serve(server, list(outcome.sockets)), name="network-mcp-serve",
            )
        except BaseException:
            self._release_sockets()
            self._bound = ()
            self._uvicorn = None
            raise

        loop = asyncio.get_running_loop()
        deadline = loop.time() + _BIND_TIMEOUT
        while loop.time() < deadline:
            if self._task.done():
                # serve() failed (a bad certificate, a lifespan refusal, ...).
                # The sockets are ours: uvicorn only closes them from its own
                # shutdown path, which a failure before `started` never reaches.
                self._release_sockets()
                self._bound = ()
                self._task.result()
                msg = "network MCP endpoint exited during startup"
                raise RuntimeError(msg)
            if getattr(server, "started", False) and server.servers:
                break
            await asyncio.sleep(0.02)
        else:  # pragma: no cover — only on a wedged bind
            await self.stop()
            msg = f"network MCP endpoint did not bind within {_BIND_TIMEOUT}s"
            raise RuntimeError(msg)

        # Registered only once the bind has succeeded, and dropped in stop().
        # ``join.join_core`` opens an enrolment window on whatever is registered
        # here, and a window is only meaningful on an endpoint that can actually
        # receive the core's push — so what is registered is an endpoint that is
        # *serving*, never merely one that was constructed.
        from workstation_agent.network_mcp.join import register_endpoint

        register_endpoint(self)

        info = self.info()
        log.info(
            "network MCP endpoint listening on %s (fingerprint %s, %d tools)",
            ", ".join(info.urls) or info.url, info.fingerprint, len(info.tool_names),
        )
        return info

    def _open_listeners(self) -> tuple[CertificateInfo, BindOutcome]:
        """Bind one socket per chosen address. Raises if none of them bind.

        Done before the app is built and before uvicorn exists, because that is
        the only place the answer to "which address?" is available: each one
        fails on its own ``bind()`` with its own errno. uvicorn's own bind path
        answers with ``sys.exit(3)`` and cannot name an address — it only ever
        had one.
        """
        hosts = self._config.bind_hosts
        cert = self._cert = ensure_certificate(self._state_dir, bind_hosts=hosts)

        outcome = open_listeners(hosts, self._config.port, cert_path=cert.cert_path)
        self._bind_failures = outcome.failures
        if not outcome.bound:
            detail = "; ".join(str(f) for f in outcome.failures) or "no address was chosen"
            msg = f"the network MCP endpoint could not bind any chosen address: {detail}"
            raise RuntimeError(msg)
        if outcome.failures:
            log.warning(
                "network MCP endpoint bound %d of %d chosen addresses; not answering on: %s",
                len(outcome.bound), len(hosts),
                "; ".join(str(f) for f in outcome.failures),
            )

        self._sockets = outcome.sockets
        self._bound = outcome.bound
        self._port = outcome.bound[0].port
        return cert, outcome

    def _uvicorn_config(
        self, uvicorn: Any, app: Any, preferred: BoundAddress, cert: CertificateInfo,
    ) -> Any:
        """The one ``uvicorn.Config`` every listening socket is served under."""
        return uvicorn.Config(
            app,
            # Only reached by uvicorn's own start-up log line, which it skips
            # entirely when it is handed sockets. The addresses that matter are
            # the ones already bound above.
            host=preferred.host,
            port=preferred.port,
            # TLS is structural: there is no code path in this module that
            # serves plain HTTP, and no setting that turns it off.
            ssl_certfile=str(cert.cert_path),
            ssl_keyfile=str(cert.key_path),
            ssl_version=ssl.PROTOCOL_TLS_SERVER,
            log_level="warning",
            lifespan="on",  # the SDK's session manager runs in the app's lifespan
            # Pin the HTTP parser so the header bound below is the one we set,
            # not whichever implementation happened to be installed.
            http="h11",
            h11_max_incomplete_event_size=MAX_HEADER_BYTES,
            limit_concurrency=self._config.max_connections,
            timeout_keep_alive=int(self._config.keep_alive_seconds),
            # Bounded, or a peer holding a keep-alive connection (which the core
            # always does) makes shutdown wait forever and the lifespan task gets
            # cancelled out from under the SDK's session manager.
            timeout_graceful_shutdown=self._config.graceful_shutdown_seconds,
            server_header=False,  # do not advertise the stack to the LAN
            date_header=True,
        )

    async def stop(self) -> None:
        """Stop serving. Safe to call when not running, and safe to call twice.

        Every socket opened by :meth:`start` is closed, whether or not uvicorn
        got as far as its own shutdown: a stop that released two of three
        listeners would leave the third bound with nothing behind it, and the
        next start would then fail on an address the operator can see nothing
        wrong with.
        """
        # First, before anything can await: an endpoint that is on its way down
        # must not be handed a Join. Passing ``self`` means a stop() racing a
        # start() cannot unregister the endpoint that has just replaced it.
        from workstation_agent.network_mcp.join import unregister_endpoint

        unregister_endpoint(self)

        server, task = self._uvicorn, self._task
        self._uvicorn = self._task = None
        if server is not None:
            server.should_exit = True
        if task is not None and not task.done():
            with contextlib.suppress(asyncio.TimeoutError, asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
            if not task.done():  # pragma: no cover — uvicorn normally exits
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._release_sockets()
        self._bound = ()
        log.info("network MCP endpoint stopped")

    def _release_sockets(self) -> None:
        """Close every listening socket this endpoint opened. Idempotent."""
        sockets, self._sockets = self._sockets, ()
        close_listeners(sockets)

    @property
    def running(self) -> bool:
        """True while the endpoint is bound and serving."""
        return self._task is not None and not self._task.done()

    @property
    def state_dir(self) -> Path:
        """Where the certificate, the key, the token and the enrolled-core rows live.

        Exposed because ``join.py`` writes its listing beside them and must not
        guess: a listing read from one directory and a token rotated in another
        is a removal with no effect and no symptom. Resolved rather than
        returning the constructor's ``None``, so every caller sees the directory
        actually in use.
        """
        return self._state_dir if self._state_dir is not None else DEFAULT_STATE_DIR

    # -- operator surface (B5 renders this) -------------------------------

    def info(self) -> NetworkEndpointInfo:
        """Return the endpoint's identity, credentials and served set.

        Works before :meth:`start`, generating the certificate and token if they
        do not exist yet, so the UI can show the operator what to paste into
        PersonaCore without the endpoint being up.

        ``urls`` carries one entry per address. While the endpoint is running
        those are the addresses that **bound**, so a URL in this list is a URL
        something is answering on; while it is stopped they are the addresses
        configured, so the page can show what switching it on would produce.
        ``url`` is ``urls[0]`` — the preferred address — kept singular for the
        core, which reads one ``url``.
        """
        if self._token is None:
            self._token = ensure_token(self._state_dir)
        if self._cert is None:
            self._cert = ensure_certificate(
                self._state_dir, bind_hosts=self._config.bind_hosts,
            )

        running = self.running
        if running and self._bound:
            hosts = tuple(b.host for b in self._bound)
            urls = tuple(b.url for b in self._bound)
            port = self._bound[0].port
        else:
            hosts = self._config.bind_hosts or (self._config.bind_host,)
            port = self._port
            urls = tuple(endpoint_url(h, port) for h in hosts)

        return NetworkEndpointInfo(
            url=urls[0],
            bind_host=hosts[0],
            port=port,
            fingerprint=self._cert.fingerprint,
            token=self._token,
            certificate_sans=self._cert.sans,
            certificate_expires=self._cert.not_valid_after,
            tool_names=tuple(t.name for t in SERVED_TOOLS),
            running=running,
            urls=urls,
            bind_hosts=hosts,
            bind_failures=self._bind_failures if running else (),
            degraded=bool(running and self._bind_failures),
        )

    def rotate_token(self) -> str:
        """Generate a fresh bearer token. Takes effect on the next :meth:`start`.

        Invalidates the value the operator pasted into PersonaCore's secret
        store, so this is an explicit operator action, never automatic.
        """
        self._token = ensure_token(self._state_dir, rotate=True)
        return self._token

    def revoke_token(self) -> str:
        """Rotate the bearer token and put the new one in force **immediately**.

        The difference from :meth:`rotate_token` is the whole reason this exists.
        That one is the operator's "give me a fresh value to paste into
        PersonaCore": it changes what the *next* start will demand, deliberately,
        so the endpoint keeps working while they go and update the secret store.
        This one is removal — ``join.remove_enrolled_core`` — where the point is
        that the core being removed stops being able to call, and a rotation that
        waits for a restart does not do that.

        Same order as :meth:`_accept_pushed_token`: the file first, then the
        in-memory value, then the live gate. A failure to write leaves the
        previous token in force everywhere rather than in force on disk and
        revoked in memory, which is the state a restart would silently undo.

        Returns:
            The new token. **Not logged**, here or anywhere.
        """
        token = ensure_token(self._state_dir, rotate=True)
        self._token = token
        if self._hardening is not None:
            self._hardening.set_token(token)
        log.warning(
            "network MCP bearer token revoked and replaced; any core still holding the "
            "previous token now gets 401 and must enrol again",
        )
        return token

    def regenerate_certificate(
        self, *, for_hosts: Sequence[str] | None = None,
    ) -> CertificateInfo:
        """Generate a fresh certificate. Takes effect on the next :meth:`start`.

        **Changes the fingerprint**, so the registration must be regenerated and
        reinstalled on PersonaCore's Plugins page or the core's pin will fail.

        Args:
            for_hosts: The addresses the new certificate must cover. Defaults to
                the addresses currently configured. The UI passes the operator's
                *pending* selection instead, because that is the whole point of
                the offer: regenerating for the addresses already saved would
                produce a certificate that still does not cover the address they
                are trying to add, and the second attempt would fail exactly as
                the first did.
        """
        hosts = tuple(for_hosts) if for_hosts else self._config.bind_hosts
        self._cert = ensure_certificate(
            self._state_dir, bind_hosts=hosts, regenerate=True,
        )
        return self._cert

    # -- enrolment (contract amendment: the core pushes us a token) --------

    def begin_join(
        self, code: str, *, ttl_seconds: float = DEFAULT_JOIN_TTL,
    ) -> JoinStatus:
        """Open the enrolment window PersonaCore will push a token into.

        The owner reads a pairing code off the core's console, types it here and
        presses Join; the core then pushes the token it minted to
        ``POST /enrol/token`` on *this* endpoint, over HTTPS, pinned to the
        fingerprint the Agent supplied. See ``enrolment.py`` for the handshake.

        **The reachability checks are the point of doing this here** rather than
        in the UI. A window opened around an endpoint that is stopped, or bound
        to loopback, is a window nothing can reach: the owner would type the
        code, watch a countdown, and be told nothing until it expired. Saying so
        now is the difference between a five-second correction and a five-minute
        mystery.

        Args:
            code: The pairing code the core is showing.
            ttl_seconds: How long the window stays open.

        Returns:
            The pending window's :class:`~...enrolment.JoinStatus`. It carries no
            code.

        Raises:
            EnrolmentError: if the endpoint cannot receive a push, or the code is
                not one that can secure a window. The message is written to be
                shown to the owner verbatim.
        """
        if not self.running:
            raise EnrolmentError(ENDPOINT_NOT_RUNNING)

        from workstation_agent.registration_export import is_loopback_host

        # Every address, not just the preferred one: a machine bound to
        # loopback *and* a LAN address is perfectly reachable, and refusing the
        # Join because the first entry happens to be 127.0.0.1 would be a
        # refusal the owner cannot act on.
        hosts = tuple(b.host for b in self._bound) or self._config.bind_hosts
        if all(is_loopback_host(h) for h in hosts):
            listed = ", ".join(hosts)
            msg = (
                f"The endpoint is bound to {listed}, which is this machine only. "
                f"PersonaCore runs elsewhere and cannot reach it to push the token. "
                f"Bind a LAN address first, then join."
            )
            raise EnrolmentError(msg)

        return self._enrolment.open_join(code, ttl_seconds=ttl_seconds)

    def cancel_join(self) -> None:
        """Close any pending enrolment window. Safe when there is none."""
        self._enrolment.cancel_join()

    def join_status(self) -> JoinStatus | None:
        """The pending enrolment window, or ``None``. Never carries the code."""
        return self._enrolment.status()

    def join_completed(self, join_id: int) -> bool:
        """True if the enrolment window *join_id* was closed by an accepted push.

        ``join.join_core`` asks this when its outbound POST fails without an
        answer: the core pushes before it replies, so a token that arrived here
        settles a question the network left open. See
        :meth:`~...enrolment.EnrolmentReceiver.completed` for why it is asked by
        window id rather than by "is a window open".
        """
        return self._enrolment.completed(join_id)

    def _accept_pushed_token(self, token: str) -> bool:
        """Install a token PersonaCore pushed. Returns True once it is in force.

        Persist first, then swap. The order is load-bearing in both directions:

        * If the write fails, nothing has changed — the previous token still
          works, the Join stays open, and the core is refused rather than told a
          success it would immediately persist against.
        * If the write succeeds, a restart reads the same value back
          (:func:`ensure_token` reads this file), so the core's stored token and
          ours cannot disagree across a reboot.

        The token itself is never logged, and never reaches the audit database:
        no path from here writes an audit row, which is deliberate. That
        database truncates ``args_json`` to 200 characters, and truncation is
        not redaction — a 64-character token would survive it whole.
        """
        try:
            store_token(token, self._state_dir)
        except (OSError, ValueError):
            # No exc_info: a traceback from the write path can carry the path but
            # a ValueError's message here would be about the value.
            log.error(  # noqa: TRY400 — see above; a traceback is the leak risk
                "network MCP enrolment: the pushed token could not be stored, "
                "so the push was refused. Check that the endpoint's state "
                "directory is writable.",
            )
            return False

        self._token = token
        if self._hardening is not None:
            self._hardening.set_token(token)
        log.info(
            "network MCP enrolment: a token issued by PersonaCore is now the "
            "bearer this endpoint requires",
        )
        return True

    # -- the ASGI app ----------------------------------------------------

    def _build_app(self, token: str) -> Any:
        """Build the hardened ASGI app: our middleware wrapping the SDK's."""
        from mcp import types
        from mcp.server.lowlevel import Server
        from mcp.server.transport_security import TransportSecuritySettings

        async def _on_list_tools(
            _ctx: Any, _params: Any,
        ) -> types.ListToolsResult:
            # Built through model_validate rather than the constructor: the
            # SDK models carry snake_case field names with camelCase wire
            # aliases, and which of the two the generated __init__ accepts
            # differs from what a type checker sees. Validating a plain dict
            # of wire names is unambiguous to both.
            return types.ListToolsResult.model_validate({
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        # A fresh mutable copy: the served table's own schema is
                        # a frozen mapping the SDK could neither validate nor
                        # serialise, and handing out the real one would let a
                        # consumer edit what every future client is told.
                        "inputSchema": tool.json_schema(),
                    }
                    for tool in SERVED_TOOLS
                ],
            })

        async def _on_call_tool(
            _ctx: Any, params: types.CallToolRequestParams,
        ) -> types.CallToolResult:
            envelope = await self._invoke(params.name, dict(params.arguments or {}))
            text = json.dumps(envelope, ensure_ascii=False, default=str)
            return types.CallToolResult.model_validate({
                "content": [{"type": "text", "text": self._scrub(text)}],
                # §5.2: a denied or unconfirmed call is a normal result carrying
                # ok:false, not an MCP-level error. The core fences the text
                # either way; isError would make the persona report a fault
                # instead of saying plainly that nobody confirmed it.
                "isError": False,
            })

        server: Any = Server(
            _SERVER_NAME,
            version=_agent_version(),
            instructions=(
                "Acts on the owner's workstation and the devices plugged into it."
            ),
            on_list_tools=_on_list_tools,
            on_call_tool=_on_call_tool,
        )

        host = self._config.bind_host  # the preferred one; the SDK takes a scalar
        # Only keyword arguments that exist in *every* version this project
        # declares. `max_sessions` and `session_idle_timeout` are 2.2 additions to
        # this signature and passing either raises TypeError on 2.1.1 — the
        # version the core runs. See DECISION.md §3; `_require_mcp_api` above has
        # already checked each of these by name.
        sdk_app = server.streamable_http_app(
            streamable_http_path="/mcp",
            # Stateful: the Mcp-Session-Id the SDK issues is the transport-level
            # session identifier B2 plumbs into the permissions evaluator so B3's
            # "remember for this session" is implementable. See DECISION.md §1.4.
            stateless_http=False,
            json_response=False,
            max_request_body_size=self._config.max_request_bytes,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=self._allowed_hosts(),
                allowed_origins=[],
            ),
            host=host,
        )

        # Idle session reaping. `session_idle_timeout` is a documented
        # constructor parameter of StreamableHTTPSessionManager in both 2.1.1 and
        # 2.2, stored on a public attribute of the same name and read live when
        # each session is created — but 2.1.1's `streamable_http_app` does not
        # forward it. Setting the attribute is how you reach it on 2.1.1 without
        # reimplementing the app factory's routing and lifespan wiring.
        #
        # Without this the SDK drops a session only on an explicit DELETE, so a
        # peer that reconnects without tearing down leaks a transport each time.
        # With it, the SDK's own session map and `Hardening`'s agree on when a
        # session is gone, which is what lets the cap below be a real bound
        # rather than a slow route to an outage.
        server.session_manager.session_idle_timeout = self._config.session_idle_seconds

        self._hardening = Hardening(
            sdk_app,
            token=token,
            path="/mcp",
            max_body_bytes=self._config.max_request_bytes,
            max_json_depth=self._config.max_json_depth,
            max_concurrent=self._config.max_connections,
            body_read_timeout=self._config.body_read_timeout_seconds,
            # The session cap the SDK's 2.2-only `max_sessions` used to provide,
            # enforced in the layer we own and on the same idle timeout the SDK
            # reaps with, so the two views of "live session" cannot disagree.
            max_sessions=self._config.max_sessions,
            session_idle_timeout=self._config.session_idle_seconds,
            # The one route ahead of the bearer gate. Always mounted, never
            # "enabled": whether it answers depends solely on whether a Join is
            # pending, and with none it refuses exactly as an unknown path does.
            # Mounting it conditionally would make its presence observable.
            enrolment=self._enrolment,
        )
        return self._hardening

    def _allowed_hosts(self) -> list[str]:
        """Host-header allowlist for the SDK's DNS-rebinding protection.

        The core connects by whatever ``url`` the registration carries, which is
        one of the bind addresses or a name that resolves to one, so the
        certificate's SAN entries are exactly the right allowlist — they are the
        names this endpoint claims to be. Every chosen address is added too:
        with a set of addresses, a Host header naming any of them is legitimate,
        and the SAN already covers all of them because
        :func:`~...listeners.open_listeners` refuses to bind one it does not.
        """
        names: list[str] = list(self._config.bind_hosts)
        names.extend(b.host for b in self._bound)
        if self._cert is not None:
            names.extend(self._cert.sans)
        allowed: list[str] = []
        for name in dict.fromkeys(names):
            bracketed = f"[{name}]" if ":" in name else name
            allowed.append(f"{bracketed}:*")
            allowed.append(bracketed)
        return allowed

    # -- invocation ------------------------------------------------------

    async def _invoke(  # noqa: PLR0911 — one return per §5.2 result code
        self, name: str, args: dict[str, Any],
    ) -> dict[str, Any]:
        """Route one tool call through the gate and return a §5.2 envelope.

        Never raises and never leaks: no stack trace, no traceback object, and
        the bearer token is scrubbed from the rendered text by
        :meth:`_scrub` before it leaves.
        """
        tool = SERVED_TOOLS_BY_NAME.get(name)
        if tool is None:
            # Not reachable through a well-behaved client, since tools/list only
            # advertises the table — but an authenticated peer can send anything.
            return _fail("not_found", f"This workstation does not serve a tool called {name!r}.")

        if self._mcp_host is None:
            return _fail("error", "The Agent's plugin host is not running.")

        try:
            result = await self._mcp_host.invoke(tool.internal_name, args)
        except PermissionError as exc:
            # MCPHost.invoke raises PermissionError for both a policy denial and
            # a confirmation the operator did not give. §5.2 distinguishes them,
            # and only the confirm path mentions confirmation.
            text = str(exc)
            if "confirm" in text.lower():
                return _fail(
                    "unconfirmed",
                    "A prompt was shown on the workstation and nobody confirmed it in time.",
                )
            return _fail("denied", f"The Agent's permissions refuse {name}.")
        except KeyError:
            # No running plugin owns the tool: the family has not been built or
            # loaded yet. Advertised in tools/list because the registration and
            # the served set must agree (contract §2).
            return _fail(
                "error",
                f"The {tool.family!r} capability family is not loaded on this workstation.",
            )
        except TimeoutError:
            return _fail("timeout", f"{name} ran out of its own time budget.")
        except Exception as exc:  # nothing may escape onto the LAN
            log.exception("network MCP tool %s failed", name)
            return _fail("error", f"{type(exc).__name__}: {exc}"[:500])

        return _envelope_from_result(result)

    def _scrub(self, text: str) -> str:
        """Remove the bearer token from outgoing text (§5.2: never the token)."""
        if self._token and self._token in text:
            log.error("network MCP result contained the bearer token; redacted")
            return text.replace(self._token, "[redacted]")
        return text


#: Keyword arguments this module passes to ``Server.streamable_http_app``. Every
#: one must exist in every ``mcp`` version ``pyproject.toml`` allows.
_REQUIRED_APP_KWARGS: Final = (
    "streamable_http_path",
    "stateless_http",
    "json_response",
    "max_request_body_size",
    "transport_security",
    "host",
)

#: Keyword arguments this module passes to ``Server(...)``.
_REQUIRED_SERVER_KWARGS: Final = ("version", "instructions", "on_list_tools", "on_call_tool")


def _require_mcp_api() -> None:
    """Fail loudly, at startup, if the installed ``mcp`` lacks an API we use.

    The alternative is a ``TypeError`` out of ``streamable_http_app`` on the
    operator's machine at first bind, which is the worst possible place to
    discover a version mismatch: the Agent is already running, the UI has
    already shown a URL, and the message names a keyword argument rather than a
    dependency.

    This is not hypothetical. The first cut of this module passed
    ``max_sessions=`` and ``session_idle_timeout=``, which exist on 2.2's
    signature and not on 2.1.1's — the version the core runs (contract §12) —
    under a ``>=2.1`` floor that a fresh resolve satisfied with 2.2.0. The
    declared dependency did not describe the code, and nothing said so until the
    server tried to start.

    Checked by introspection rather than by version string, because the version
    is a proxy for the thing that actually matters.
    """
    import inspect
    from importlib.metadata import PackageNotFoundError, version

    from mcp.server.lowlevel import Server

    try:
        installed = version("mcp")
    except PackageNotFoundError:  # pragma: no cover — mcp is a hard dependency
        installed = "unknown"

    missing: list[str] = []
    server_params = inspect.signature(Server.__init__).parameters
    missing.extend(
        f"Server(...) does not accept {name!r}"
        for name in _REQUIRED_SERVER_KWARGS
        if name not in server_params
    )
    app_params = inspect.signature(Server.streamable_http_app).parameters
    missing.extend(
        f"Server.streamable_http_app() does not accept {name!r}"
        for name in _REQUIRED_APP_KWARGS
        if name not in app_params
    )
    if not hasattr(Server, "session_manager"):
        missing.append("Server has no 'session_manager' property")
    else:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

        manager_params = inspect.signature(StreamableHTTPSessionManager.__init__).parameters
        if "session_idle_timeout" not in manager_params:
            missing.append(
                "StreamableHTTPSessionManager does not accept 'session_idle_timeout'",
            )

    if missing:
        msg = (
            f"the installed 'mcp' package ({installed}) is missing APIs the network "
            f"MCP endpoint depends on: " + "; ".join(missing) + ". "
            "pyproject.toml declares 'mcp>=2.1.1,<2.2'; reinstall with "
            ".venv\\Scripts\\python.exe -m pip install -e .[dev]"
        )
        raise RuntimeError(msg)


async def _guarded_serve(server: Any, sockets: list[socket.socket]) -> None:
    """Run ``uvicorn.Server.serve()`` without letting it kill the event loop.

    uvicorn answers a failed start — an unreadable key file, a lifespan that
    refuses — with ``sys.exit(3)`` (``uvicorn/server.py``). ``SystemExit`` is a
    ``BaseException``, and asyncio deliberately re-raises those straight out of
    ``Task.__step`` into the running loop rather than storing them on the task.
    In a standalone ``uvicorn`` process that is exactly right; inside the Agent,
    where this endpoint is one subsystem among many, it would tear down the whole
    application loop. Translating it here keeps a startup failure a reportable
    error on :meth:`NetworkMCPServer.start`.

    *sockets* are already bound (see
    :func:`~workstation_agent.network_mcp.listeners.open_listeners`), so the
    address-in-use case never reaches uvicorn at all; it was reported per
    address before this task was created. Handing the list here is what makes
    uvicorn serve all of them from one server and close all of them from one
    shutdown.
    """
    try:
        await server.serve(sockets=sockets)
    except SystemExit as exc:
        msg = (
            "the network MCP endpoint could not bind "
            f"(uvicorn exited with status {exc.code})"
        )
        raise RuntimeError(msg) from exc


def _fail(code: str, reason: str) -> dict[str, Any]:
    """A §5.2 failure envelope."""
    return {"ok": False, "code": code, "reason": reason}


_TRAILER = "\n[... {} more characters; use jobs_output to page ...]"


def _cap(text: str) -> str:
    """Apply §5.3's 60,000-character cap with its documented trailer.

    Applied at the transport because "never put more than the cap onto the LAN"
    is a property of this endpoint, not of any one family.

    The trailer's own length is reserved out of the cap so the whole returned
    string — trailer included — stays within :data:`RESULT_CHAR_CAP`. That is
    what §5.3 says ("text results are capped by the Agent at 60,000
    characters"), and it also makes the function **idempotent**: capping an
    already-capped string returns it unchanged, so B2 capping earlier in the
    chain cannot cause a second truncation that eats real content and reports a
    wrong remaining count. The reservation uses ``len(text)`` for the digit
    width, which is an upper bound on the number actually printed, so the
    reserved room is never too small.
    """
    if len(text) <= RESULT_CHAR_CAP:
        return text
    keep = max(RESULT_CHAR_CAP - len(_TRAILER.format(len(text))), 0)
    return text[:keep] + _TRAILER.format(len(text) - keep)


def _envelope_from_result(result: Any) -> dict[str, Any]:
    """Adapt a :class:`MCPHost` result into a §5.2 envelope.

    Two shapes are handled deliberately:

    * **B2's shape (forward-compatible).** Once subtask B2 lands, a tool result's
      text is already the §5.2 envelope. If the text parses as a JSON object with
      an ``ok`` key, it is returned untouched — B2's work needs no change here.
    * **Today's shape.** ``MCPHost.invoke`` returns ``ToolResultImpl`` carrying
      raw MCP content blocks. They are joined and wrapped so the endpoint is
      contract-shaped before B2 exists.
    """
    is_error = bool(getattr(result, "is_error", False))
    blocks = getattr(result, "content", None) or []
    parts: list[str] = []
    for block in blocks:
        if isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            else:
                parts.append(json.dumps(block, ensure_ascii=False, default=str))
        else:  # pragma: no cover — plugins return dict blocks today
            parts.append(str(block))
    text = _cap("\n".join(parts))

    if text:
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError):
            parsed = None
        if isinstance(parsed, dict) and "ok" in parsed:
            return parsed

    if is_error:
        return _fail("error", text or "The tool reported a failure with no message.")
    return {"ok": True, "text": text}


def _agent_version() -> str:
    """The Agent's version, reported to the core in ``serverInfo``."""
    try:
        from importlib.metadata import version

        return version("workstation-agent")
    except Exception:  # noqa: BLE001 — a frozen build may have no metadata
        return "0.0.0"
