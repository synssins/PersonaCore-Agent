"""The streamable-HTTP MCP endpoint PersonaCore connects to (contract §1-§3).

``https://<operator-chosen-interface>:<port>/mcp``. Self-signed, pinned
certificate; 32-byte bearer token; a static families-only tool allowlist; every
call routed through :meth:`MCPHost.invoke`, which is the gate.

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
from workstation_agent.network_mcp.credentials import ensure_token
from workstation_agent.network_mcp.hardening import (
    MAX_HEADER_BYTES,
    Hardening,
)
from workstation_agent.network_mcp.tools import (
    SERVED_TOOLS,
    SERVED_TOOLS_BY_NAME,
    validate_tool_names,
)

if TYPE_CHECKING:  # pragma: no cover
    import datetime as dt
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
    """``https://<host>:<port>/mcp`` — the registration's ``url`` field."""
    bind_host: str
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


class NetworkMCPServer:
    """The LAN-facing MCP endpoint.

    Args:
        config: The endpoint's settings. ``bind_host`` is validated by the schema
            to be a named interface, never a wildcard.
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

    # -- lifecycle -------------------------------------------------------

    async def start(self) -> NetworkEndpointInfo:
        """Generate/load credentials, bind the interface over TLS, and serve.

        Returns:
            The bound endpoint's :class:`NetworkEndpointInfo`.

        Raises:
            RuntimeError: if the endpoint is already running, if the served-tool
                table violates contract §2, or if uvicorn cannot bind.
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
        self._cert = ensure_certificate(self._state_dir, bind_host=self._config.bind_host)

        app = self._build_app(self._token)

        config = uvicorn.Config(
            app,
            host=self._config.bind_host,
            port=self._config.port,
            # TLS is structural: there is no code path in this module that
            # serves plain HTTP, and no setting that turns it off.
            ssl_certfile=str(self._cert.cert_path),
            ssl_keyfile=str(self._cert.key_path),
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
        server = uvicorn.Server(config)
        self._uvicorn = server
        self._task = asyncio.create_task(_guarded_serve(server), name="network-mcp-serve")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + _BIND_TIMEOUT
        while loop.time() < deadline:
            if self._task.done():
                # serve() failed (port in use, bad certificate, ...). Surface it.
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

        self._port = _assigned_port(server, self._config.port)
        info = self.info()
        log.info(
            "network MCP endpoint listening on %s (fingerprint %s, %d tools)",
            info.url, info.fingerprint, len(info.tool_names),
        )
        return info

    async def stop(self) -> None:
        """Stop serving. Safe to call when not running, and safe to call twice."""
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
        log.info("network MCP endpoint stopped")

    @property
    def running(self) -> bool:
        """True while the endpoint is bound and serving."""
        return self._task is not None and not self._task.done()

    # -- operator surface (B5 renders this) -------------------------------

    def info(self) -> NetworkEndpointInfo:
        """Return the endpoint's identity, credentials and served set.

        Works before :meth:`start`, generating the certificate and token if they
        do not exist yet, so the UI can show the operator what to paste into
        PersonaCore without the endpoint being up.
        """
        if self._token is None:
            self._token = ensure_token(self._state_dir)
        if self._cert is None:
            self._cert = ensure_certificate(self._state_dir, bind_host=self._config.bind_host)
        host = self._config.bind_host
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        return NetworkEndpointInfo(
            url=f"https://{host}:{self._port}/mcp",
            bind_host=self._config.bind_host,
            port=self._port,
            fingerprint=self._cert.fingerprint,
            token=self._token,
            certificate_sans=self._cert.sans,
            certificate_expires=self._cert.not_valid_after,
            tool_names=tuple(t.name for t in SERVED_TOOLS),
            running=self.running,
        )

    def rotate_token(self) -> str:
        """Generate a fresh bearer token. Takes effect on the next :meth:`start`.

        Invalidates the value the operator pasted into PersonaCore's secret
        store, so this is an explicit operator action, never automatic.
        """
        self._token = ensure_token(self._state_dir, rotate=True)
        return self._token

    def regenerate_certificate(self) -> CertificateInfo:
        """Generate a fresh certificate. Takes effect on the next :meth:`start`.

        **Changes the fingerprint**, so the registration must be regenerated and
        reinstalled on PersonaCore's Plugins page or the core's pin will fail.
        """
        self._cert = ensure_certificate(
            self._state_dir, bind_host=self._config.bind_host, regenerate=True,
        )
        return self._cert

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

        host = self._config.bind_host
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
        )
        return self._hardening

    def _allowed_hosts(self) -> list[str]:
        """Host-header allowlist for the SDK's DNS-rebinding protection.

        The core connects by whatever ``url`` the registration carries, which is
        the bind address or a name that resolves to it, so the certificate's SAN
        entries are exactly the right allowlist — they are the names this
        endpoint claims to be.
        """
        names: list[str] = [self._config.bind_host]
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


async def _guarded_serve(server: Any) -> None:
    """Run ``uvicorn.Server.serve()`` without letting it kill the event loop.

    uvicorn answers a failed bind — a port already in use, an unreadable key
    file — with ``sys.exit(3)`` (``uvicorn/server.py:183``). ``SystemExit`` is a
    ``BaseException``, and asyncio deliberately re-raises those straight out of
    ``Task.__step`` into the running loop rather than storing them on the task.
    In a standalone ``uvicorn`` process that is exactly right; inside the Agent,
    where this endpoint is one subsystem among many, it would tear down the whole
    application loop because a port was busy. Translating it here keeps a bind
    failure a reportable error on :meth:`NetworkMCPServer.start`.
    """
    try:
        await server.serve()
    except SystemExit as exc:
        msg = (
            "the network MCP endpoint could not bind "
            f"(uvicorn exited with status {exc.code}); the port may already be in use"
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


def _assigned_port(server: Any, requested: int) -> int:
    """Read the port uvicorn actually bound (``port=0`` means the OS picks)."""
    for sock in getattr(server, "servers", []) or []:
        for raw in getattr(sock, "sockets", []) or []:
            with contextlib.suppress(OSError, IndexError, TypeError):
                return int(raw.getsockname()[1])
    return requested


def _agent_version() -> str:
    """The Agent's version, reported to the core in ``serverInfo``."""
    try:
        from importlib.metadata import version

        return version("workstation-agent")
    except Exception:  # noqa: BLE001 — a frozen build may have no metadata
        return "0.0.0"
