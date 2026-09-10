"""End-to-end: a real TLS socket, a real MCP client, real hostile packets.

The unit tests drive the ASGI layer directly. This file drives the actual
listening socket, because the properties that matter here are only true of the
whole stack: that the endpoint really is HTTPS, that the certificate the core
would pin is the one presented, that the ``mcp`` client the core uses can
complete a handshake and call a tool, and that the hostile-input matrix survives
a trip through uvicorn's parser rather than only through a synthetic scope.
"""
# ruff: noqa: ANN401, ARG001, S110, SIM105, SIM117
# Tearing down a socket the server has already closed on raises a different
# error on every platform and none of them matter; the assertions that follow
# are the test. tmp_path is a fixture the `endpoint` fixture needs even where
# the test body does not name it.

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
from typing import Any

import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp.server import NetworkMCPServer
from workstation_agent.network_mcp.tools import served_tool_names

# This file stands up a real uvicorn server on pytest's main-thread loop and
# stops it again, so it is both a possible source and a possible victim of
# sse_starlette's process-global shutdown latch. Which tests that latch actually
# breaks is decided by collection order and by scheduling luck, so the file opts
# in rather than waiting to be reordered into failing. See the fixture's
# docstring in tests/integration/conftest.py.
pytestmark = pytest.mark.usefixtures("sse_shutdown_latch_cleared")

# The mcp SDK builds its streamable-HTTP client on httpx2 and takes an
# httpx2.AsyncClient; fall back to httpx where an older resolution pins that
# instead. Typed as Any because which one is present is a runtime fact.
httpx: Any
try:
    import httpx2 as httpx  # type: ignore[no-redef]
except ImportError:  # pragma: no cover
    import httpx  # type: ignore[no-redef]


class Result:
    def __init__(self, text: str, *, is_error: bool = False) -> None:
        self.content = [{"type": "text", "text": text}]
        self.is_error = is_error


class Host:
    """Stands in for MCPHost. Records what the gate was asked to run."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def invoke(self, tool_id: str, args: dict) -> Result:
        self.calls.append((tool_id, args))
        if tool_id == "files.write":
            msg = f"tool {tool_id!r} rejected by user confirmation"
            raise PermissionError(msg)
        return Result(json.dumps({"ok": True, "tool": tool_id, "args": args}))


@pytest.fixture
async def endpoint(tmp_path):
    host = Host()
    config = NetworkMcpConfig(enabled=True, bind_host="127.0.0.1", port=0)
    server = NetworkMCPServer(config, mcp_host=host, state_dir=tmp_path)
    info = await server.start()
    try:
        yield server, info, host
    finally:
        await server.stop()


async def _raw_tls(port: int):
    """Open a raw TLS connection, bypassing every HTTP client."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return await asyncio.open_connection("127.0.0.1", port, ssl=ctx)


async def _close(reader, writer) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2)
    except (OSError, ssl.SSLError, TimeoutError):
        pass
    reader.feed_eof()


def _text_of(result: Any) -> str:
    """The text of a CallToolResult's first content block."""
    return str(result.content[0].text)


def _tls_context(state_dir) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=str(state_dir / "server.crt"))
    # The core pins the fingerprint instead of the trust store (contract §3), so
    # hostname matching is not what proves identity here.
    ctx.check_hostname = False
    return ctx


# ---------------------------------------------------------------------------
# The transport itself
# ---------------------------------------------------------------------------


async def test_the_endpoint_is_https_and_refuses_plain_http(endpoint):
    _server, info, _host = endpoint
    assert info.url.startswith("https://")
    async with httpx.AsyncClient(verify=False) as client:  # noqa: S501
        with pytest.raises(Exception):  # noqa: B017, PT011 — any transport failure will do
            await client.get(info.url.replace("https://", "http://"), timeout=5)


async def test_the_presented_certificate_matches_the_advertised_fingerprint(endpoint):
    """Contract §3: the core pins this exact value and verifies nothing else."""
    _server, info, _host = endpoint
    reader, writer = await _raw_tls(info.port)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        await _close(reader, writer)
    assert info.fingerprint == "sha256:" + hashlib.sha256(der).hexdigest()


async def test_tls_is_at_least_1_2(endpoint):
    _server, info, _host = endpoint
    reader, writer = await _raw_tls(info.port)
    try:
        version = writer.get_extra_info("ssl_object").version()
    finally:
        await _close(reader, writer)
    assert version in {"TLSv1.2", "TLSv1.3"}


async def test_the_fingerprint_survives_a_restart(endpoint, tmp_path):
    """Contract §11 item 8: starting the Agent brings the endpoint back."""
    server, info, _host = endpoint
    await server.stop()
    again = await server.start()
    assert again.fingerprint == info.fingerprint
    assert again.token == info.token

    reader, writer = await _raw_tls(again.port)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        await _close(reader, writer)
    assert again.fingerprint == "sha256:" + hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------------------
# The MCP conversation the core actually has
# ---------------------------------------------------------------------------


async def test_the_real_mcp_client_can_handshake_list_and_call(endpoint, tmp_path):
    """The single most important test here: the core's own client interoperates."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    _server, info, host = endpoint
    async with httpx.AsyncClient(
        verify=_tls_context(tmp_path),
        headers={"Authorization": f"Bearer {info.token}"},
    ) as client, streamable_http_client(info.url, http_client=client) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()

            listed = await session.list_tools()
            assert [t.name for t in listed.tools] == list(served_tool_names())
            assert all(t.description for t in listed.tools)

            ok = await session.call_tool("shell_run", {"command": "dir"})
            assert ok.is_error is False
            assert json.loads(_text_of(ok)) == {
                "ok": True, "tool": "shell.run", "args": {"command": "dir"},
            }

            # §5.2: an unconfirmed call is a normal result, not an MCP error.
            unconfirmed = await session.call_tool(
                "files_write", {"path": "x", "content": "y"},
            )
            assert unconfirmed.is_error is False
            assert json.loads(_text_of(unconfirmed)) == {
                "ok": False,
                "code": "unconfirmed",
                "reason": (
                    "A prompt was shown on the workstation and nobody confirmed it in time."
                ),
            }

    assert [c[0] for c in host.calls] == ["shell.run", "files.write"]


async def test_the_served_set_is_exactly_the_list_b5_exports_from(endpoint, tmp_path):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    _server, info, _host = endpoint
    async with httpx.AsyncClient(
        verify=_tls_context(tmp_path),
        headers={"Authorization": f"Bearer {info.token}"},
    ) as client, streamable_http_client(info.url, http_client=client) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            listed = await session.list_tools()
    assert {t.name for t in listed.tools} == set(served_tool_names())
    assert not any(t.name.startswith(("agent", "screen", "clipboard")) for t in listed.tools)


# ---------------------------------------------------------------------------
# Authentication over the real socket
# ---------------------------------------------------------------------------

RPC = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


async def _post(info, tmp_path, *, headers: dict[str, str], content: Any = None, **kw):
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        return await client.post(
            info.url,
            headers={**MCP_HEADERS, **headers},
            content=content if content is not None else json.dumps(RPC).encode(),
            timeout=10,
            **kw,
        )


@pytest.mark.parametrize(
    "auth",
    [
        pytest.param(None, id="no-header"),
        pytest.param("", id="empty"),
        pytest.param("Bearer", id="scheme-only"),
        pytest.param("Bearer wrong", id="wrong-token"),
        pytest.param("Bearer " + "0" * 64, id="right-length-wrong-value"),
        pytest.param("Basic Zm9vOmJhcg==", id="wrong-scheme"),
    ],
)
async def test_bad_tokens_get_401_with_no_body_over_the_wire(endpoint, tmp_path, auth):
    _server, info, host = endpoint
    headers = {} if auth is None else {"Authorization": auth}
    response = await _post(info, tmp_path, headers=headers)
    assert response.status_code == 401
    assert response.content == b"", "contract §3: no body detail"
    assert info.token not in response.text
    assert host.calls == []


async def test_a_non_ascii_authorization_header_is_401_not_a_crash(endpoint, tmp_path):
    """B0 crash class 1, over the real wire this time."""
    _server, info, _host = endpoint
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        request = client.build_request(
            "POST", info.url, headers=MCP_HEADERS, content=json.dumps(RPC).encode(),
        )
        request.headers["authorization"] = "Bearer éèê"
        response = await client.send(request)
    assert response.status_code == 401
    # The listener is unharmed: a good request still works afterwards.
    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200


@pytest.mark.parametrize("path", ["/", "/mcp/", "/admin", "/.env", "/mcp/x"])
async def test_other_paths_are_404_even_with_a_good_token(endpoint, tmp_path, path):
    _server, info, _host = endpoint
    base = info.url.removesuffix("/mcp")
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        response = await client.get(
            base + path,
            headers={"Authorization": f"Bearer {info.token}"},
            timeout=10,
        )
    assert response.status_code == 404


@pytest.mark.parametrize("path", ["/mcp", "/", "/admin", "/.env", "/mcp/x"])
@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "OPTIONS"])
async def test_an_anonymous_peer_gets_the_same_answer_everywhere(
    endpoint, tmp_path, path, method,
):
    """Nothing about this surface is discoverable without the token.

    Every path and every method must be indistinguishable to an unauthenticated
    peer, or the 404/405/401 split becomes a map of the endpoint.
    """
    _server, info, host = endpoint
    base = info.url.removesuffix("/mcp")
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        response = await client.request(method, base + path, timeout=10)
    assert response.status_code == 401
    assert response.content == b""
    assert "allow" not in {k.lower() for k in response.headers}
    assert host.calls == []


# ---------------------------------------------------------------------------
# Hostile bodies over the real wire
# ---------------------------------------------------------------------------

HOSTILE = [
    pytest.param(b"", id="empty-body"),
    pytest.param(b"   ", id="whitespace-body"),
    pytest.param(b"\xff\xfe\xfd\xfc", id="invalid-utf8"),
    pytest.param('{"a":"caf\udcff"}'.encode("utf-8", "surrogateescape"), id="surrogate-bytes"),
    pytest.param(b'{"a":"\\ud800"}', id="lone-high-surrogate-escape"),
    pytest.param(b'{"a":"\\udfff"}', id="lone-low-surrogate-escape"),
    pytest.param(b"[" * 50_000 + b"]" * 50_000, id="deeply-nested"),
    pytest.param(b'{"a" 1}', id="no-separator"),
    pytest.param(b"garbage", id="not-json"),
    pytest.param(b'"a string"', id="not-a-message"),
    pytest.param(b"7", id="bare-number"),
]


@pytest.mark.parametrize("payload", HOSTILE)
async def test_hostile_bodies_are_rejected_and_the_server_survives(
    endpoint, tmp_path, payload,
):
    _server, info, host = endpoint
    auth = {"Authorization": f"Bearer {info.token}"}
    response = await _post(info, tmp_path, headers=auth, content=payload)
    assert response.status_code == 400
    assert host.calls == []
    # The listener, the session manager and every other connection survive.
    ok = await _post(info, tmp_path, headers=auth)
    assert ok.status_code == 200


async def test_an_oversized_content_length_is_413_before_any_body_is_sent(
    endpoint, tmp_path,
):
    """The bound is enforced on the header: the client never sends the body.

    Written against a raw TLS socket rather than an HTTP client because that is
    the only way to observe the ordering that matters — headers out, response
    back, body never sent. A client would still be streaming two megabytes when
    the server answered and closed on it, and would surface a connection reset
    instead of the 413 the server actually produced.
    """
    _server, info, host = endpoint
    reader, writer = await _raw_tls(info.port)
    try:
        writer.write(
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Accept: application/json, text/event-stream\r\n"
            b"Authorization: Bearer " + info.token.encode() + b"\r\n"
            b"Content-Length: 2097152\r\n\r\n",
        )
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=10)
    finally:
        await _close(reader, writer)
    assert b"413" in status, status
    assert host.calls == []

    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200


async def test_an_oversized_streamed_body_is_refused_and_the_server_survives(
    endpoint, tmp_path,
):
    """The drain aborts mid-stream rather than buffering to reply politely.

    Either observable answer is correct: a 413 if the server wins the race, or a
    transport error if the client is still uploading when the server closes on
    it. What must hold is that the gate never ran and the endpoint is healthy
    afterwards.
    """
    _server, info, host = endpoint
    auth = {"Authorization": f"Bearer {info.token}"}
    huge = b'{"a":"' + b"x" * (2 * 1024 * 1024) + b'"}'
    try:
        response = await _post(info, tmp_path, headers=auth, content=huge)
    except Exception:  # noqa: BLE001 — a reset mid-upload is a valid outcome
        pass
    else:
        assert response.status_code == 413
    assert host.calls == []

    ok = await _post(info, tmp_path, headers=auth)
    assert ok.status_code == 200


async def test_an_unauthenticated_oversized_body_is_401_not_413(endpoint, tmp_path):
    """The pre-auth bound is zero bytes: identity is decided before size."""
    _server, info, _host = endpoint
    reader, writer = await _raw_tls(info.port)
    try:
        writer.write(
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2097152\r\n\r\n",
        )
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=10)
    finally:
        await _close(reader, writer)
    assert b"401" in status, status
    assert b"413" not in status


async def test_an_oversized_header_block_is_refused_and_the_server_survives(
    endpoint, tmp_path,
):
    """The only memory an unauthenticated peer can make us hold is bounded.

    ``MAX_HEADER_BYTES`` is handed to uvicorn as ``h11_max_incomplete_event_size``
    with ``http="h11"`` pinned, so the number enforcing this is ours rather than
    whichever parser happened to be installed. Sent unauthenticated on purpose:
    this bound is the *pre-authentication* one.
    """
    from workstation_agent.network_mcp.hardening import MAX_HEADER_BYTES

    _server, info, host = endpoint
    reader, writer = await _raw_tls(info.port)
    try:
        writer.write(
            b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"X-Filler: " + b"A" * (MAX_HEADER_BYTES * 2) + b"\r\n\r\n",
        )
        try:
            await writer.drain()
            status = await asyncio.wait_for(reader.readline(), timeout=10)
        except (OSError, ssl.SSLError, TimeoutError):
            status = b""
    finally:
        await _close(reader, writer)
    # Either a 4xx from h11 or a closed connection; never an accepted request.
    assert b" 200 " not in status
    assert host.calls == []

    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200


async def test_a_slow_loris_connection_does_not_wedge_the_server(endpoint, tmp_path):
    """A peer that opens a socket and says almost nothing must not block anyone."""
    _server, info, _host = endpoint
    reader, writer = await _raw_tls(info.port)
    writer.write(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 500\r\n")
    await writer.drain()
    try:
        ok = await _post(
            info, tmp_path, headers={"Authorization": f"Bearer {info.token}"},
        )
        assert ok.status_code == 200
    finally:
        await _close(reader, writer)


async def test_a_raw_garbage_connection_does_not_wedge_the_server(endpoint, tmp_path):
    """Not even HTTP: bytes that are not a request line at all."""
    _server, info, _host = endpoint
    reader, writer = await _raw_tls(info.port)
    writer.write(b"\x00\xff" * 5000 + b"\r\n\r\n")
    try:
        await writer.drain()
    except (OSError, ssl.SSLError):
        pass
    await _close(reader, writer)

    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200


async def test_a_plain_tcp_connection_with_no_tls_does_not_wedge_the_server(
    endpoint, tmp_path,
):
    _server, info, _host = endpoint
    plain = socket.create_connection(("127.0.0.1", info.port), timeout=5)
    try:
        plain.sendall(b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n")
    except OSError:
        pass
    finally:
        plain.close()
    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200


async def test_many_hostile_requests_in_a_row_leave_the_endpoint_healthy(
    endpoint, tmp_path,
):
    """Volume, not just variety: the cap must release every slot it takes."""
    server, info, _host = endpoint
    for _ in range(30):
        await _post(info, tmp_path, headers={}, content=b"garbage")
    ok = await _post(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert ok.status_code == 200
    assert server._hardening is not None
    assert server._hardening.rejections >= 30
    # Every slot the cap took must come back. The final request's SSE response
    # unwinds a moment after the client has finished reading it.
    for _ in range(100):
        if server._hardening.in_flight == 0:
            break
        await asyncio.sleep(0.02)
    assert server._hardening.in_flight == 0
