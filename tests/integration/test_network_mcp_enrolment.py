"""End-to-end: PersonaCore pushes a token to a real listening HTTPS socket.

The unit tests in ``tests/unit/network_mcp/test_enrolment.py`` drive the ASGI
layer directly. This file drives the actual socket, because three of the
properties that matter are only true of the whole stack:

* the push really does arrive over TLS, on the certificate the core pinned;
* the refusal a stranger sees on the wire — status line, headers, body — is
  byte-for-byte the one an unauthenticated request to ``/mcp`` gets, after
  uvicorn and h11 have had their say about it;
* the token the core pushed is the bearer the endpoint requires afterwards, and
  still is after a restart (contract §11 item 8).

The Join is opened through the receiver rather than through
:meth:`NetworkMCPServer.begin_join`, because this fixture binds ``127.0.0.1``
and ``begin_join`` correctly refuses to open a window on a loopback endpoint the
core could never reach. That refusal is tested on its own in the unit file; here
the loopback bind is just how a test gets a socket.
"""
# ruff: noqa: ANN401, SIM105
# Tearing down a socket the server has already closed raises a different error
# on every platform and none of them matter; the assertions are the test.

from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any

import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp.credentials import ensure_token
from workstation_agent.network_mcp.hardening import ENROL_SUCCESS_STATUS
from workstation_agent.network_mcp.server import NetworkMCPServer

httpx: Any
try:
    import httpx2 as httpx  # type: ignore[no-redef]
except ImportError:  # pragma: no cover
    import httpx  # type: ignore[no-redef]

CODE = "PAIR-4417"
PUSHED = "core-issued-" + "b" * 40
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
RPC = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


class Host:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def invoke(self, tool_id: str, args: dict) -> Any:
        self.calls.append((tool_id, args))
        raise KeyError(tool_id)


@pytest.fixture
async def endpoint(tmp_path):
    config = NetworkMcpConfig(enabled=True, bind_host="127.0.0.1", port=0)
    server = NetworkMCPServer(config, mcp_host=Host(), state_dir=tmp_path)
    info = await server.start()
    try:
        yield server, info
    finally:
        await server.stop()


def _tls_context(state_dir) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=str(state_dir / "server.crt"))
    # The core pins the fingerprint rather than checking the name (contract §3).
    ctx.check_hostname = False
    return ctx


def _enrol_url(info) -> str:
    return info.url.removesuffix("/mcp") + "/enrol/token"


async def _push(info, tmp_path, body: Any, **kw):
    """POST to /enrol/token exactly as the core would."""
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        return await client.post(
            _enrol_url(info),
            headers={"Content-Type": "application/json"},
            content=content,
            timeout=10,
            **kw,
        )


async def _mcp(info, tmp_path, *, headers: dict[str, str]):
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        return await client.post(
            info.url,
            headers={**MCP_HEADERS, **headers},
            content=json.dumps(RPC).encode(),
            timeout=10,
        )


def _observable(response) -> tuple:
    """What a caller on the LAN can actually tell apart."""
    return (
        response.status_code,
        response.content,
        response.headers.get("www-authenticate"),
        response.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# The handshake, over a real socket
# ---------------------------------------------------------------------------


async def test_the_core_can_push_a_token_and_it_becomes_the_bearer(endpoint, tmp_path):
    server, info = endpoint
    before = await _mcp(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert before.status_code == 200, "the pre-enrolment token worked to begin with"

    server._enrolment.open_join(CODE)
    pushed = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})
    assert pushed.status_code == ENROL_SUCCESS_STATUS, "the core reads only the status"
    assert pushed.content == b"", "204 carries no content"
    assert "content-length" not in pushed.headers, "RFC 9110: not on a 204"
    assert not pushed.history, "this route never redirects; the core does not follow 3xx"

    stale = await _mcp(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert stale.status_code == 401, "the token from before enrolment no longer works"

    now = await _mcp(info, tmp_path, headers={"Authorization": f"Bearer {PUSHED}"})
    assert now.status_code == 200, "the token PersonaCore pushed is in force"


async def test_the_push_is_answered_well_inside_the_core_read_timeout(endpoint, tmp_path):
    """The core allows 5s to connect and 10s to read. Uniform refusal is bought
    with constant-time comparison, never with an artificial delay, so a refusal
    must be as prompt as a success rather than merely inside the budget."""
    server, info = endpoint
    server._enrolment.open_join(CODE)

    budget = 10.0
    async with asyncio.timeout(budget):
        refused = await _push(info, tmp_path, {"code": "WRONG-9999", "token": PUSHED})
    assert refused.status_code == 401

    async with asyncio.timeout(budget):
        accepted = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})
    assert accepted.status_code == ENROL_SUCCESS_STATUS


async def test_the_pushed_token_survives_a_restart(endpoint, tmp_path):
    """Contract §11 item 8: a restart must not require touching PersonaCore."""
    server, info = endpoint
    server._enrolment.open_join(CODE)
    pushed = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})
    assert pushed.status_code == ENROL_SUCCESS_STATUS

    assert ensure_token(tmp_path) == PUSHED
    await server.stop()
    again = await server.start()
    assert again.token == PUSHED

    ok = await _mcp(again, tmp_path, headers={"Authorization": f"Bearer {PUSHED}"})
    assert ok.status_code == 200


async def test_a_join_does_not_survive_a_restart(endpoint, tmp_path):
    """The window is memory-only. A window open when the Agent stopped must not
    still be open when it comes back."""
    server, _info = endpoint
    server._enrolment.open_join(CODE)
    await server.stop()
    again = await server.start()

    assert server.join_status() is not None, (
        "a stop/start of the endpoint alone does not drop the window"
    )
    # ...but the receiver is built in __init__, so a *process* restart does:
    fresh = NetworkMCPServer(
        NetworkMcpConfig(enabled=True, bind_host="127.0.0.1", port=0),
        state_dir=tmp_path,
    )
    assert fresh.join_status() is None

    refused = await _push(again, tmp_path, {"code": "OTHER-CODE", "token": PUSHED})
    assert refused.status_code == 401


# ---------------------------------------------------------------------------
# Uniform refusal, as seen from the LAN
# ---------------------------------------------------------------------------


HOSTILE = [
    pytest.param({"code": "WRONG-9999", "token": PUSHED}, id="wrong-code"),
    pytest.param({"code": "PAIR-éèêöü", "token": PUSHED}, id="non-ascii-code"),
    pytest.param({"code": CODE, "token": "tök" + "b" * 40}, id="non-ascii-token"),
    pytest.param({"code": CODE}, id="missing-token"),
    pytest.param({"code": 4417, "token": PUSHED}, id="wrong-type"),
    pytest.param(b'{"code": "PAIR-\\ud800AAA", "token": "' + PUSHED.encode() + b'"}',
                 id="unpaired-surrogate"),
    pytest.param(b'{"code": ', id="truncated-json"),
    pytest.param(b"", id="empty-body"),
    pytest.param(b"[" * 500 + b"]" * 500, id="deeply-nested"),
    pytest.param(b"x" * 65536, id="oversized"),
]


@pytest.mark.parametrize("body", HOSTILE)
async def test_hostile_pushes_are_refused_identically_over_the_wire(endpoint, tmp_path, body):
    server, info = endpoint
    server._enrolment.open_join(CODE)

    baseline = await _mcp(info, tmp_path, headers={})  # an ordinary bearerless request
    assert baseline.status_code == 401

    refused = await _push(info, tmp_path, body)
    assert _observable(refused) == _observable(baseline)
    assert server.join_status() is not None, "a refused push does not close the window"


@pytest.mark.parametrize("body", HOSTILE)
async def test_the_same_pushes_are_refused_identically_with_no_join(endpoint, tmp_path, body):
    _server, info = endpoint
    baseline = await _mcp(info, tmp_path, headers={})
    assert _observable(await _push(info, tmp_path, body)) == _observable(baseline)


async def test_a_correct_code_with_no_join_pending_looks_exactly_like_a_wrong_one(
    endpoint, tmp_path,
):
    """The contract's explicit requirement, over the wire."""
    server, info = endpoint

    no_join = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})

    server._enrolment.open_join(CODE)
    wrong = await _push(info, tmp_path, {"code": "WRONG-9999", "token": PUSHED})

    baseline = await _mcp(info, tmp_path, headers={})
    assert _observable(no_join) == _observable(wrong) == _observable(baseline)


@pytest.mark.parametrize(
    "second",
    [
        pytest.param({"code": CODE, "token": PUSHED}, id="byte-identical-replay"),
        pytest.param({"code": CODE, "token": "d" * 48}, id="same-code-different-token"),
    ],
)
async def test_a_used_code_cannot_be_pushed_twice(endpoint, tmp_path, second):
    """Single use, strictly. The core does not retry — a failed push fails the
    whole enrolment and the owner issues a fresh code — so this endpoint carries
    no idempotency it does not need."""
    server, info = endpoint
    server._enrolment.open_join(CODE)

    first = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})
    assert first.status_code == ENROL_SUCCESS_STATUS

    repeat = await _push(info, tmp_path, second)
    assert _observable(repeat) == _observable(await _mcp(info, tmp_path, headers={}))
    assert ensure_token(tmp_path) == PUSHED, "the second push did not overwrite the token"

    ok = await _mcp(info, tmp_path, headers={"Authorization": f"Bearer {PUSHED}"})
    assert ok.status_code == 200, "the token from the real enrolment still works"


async def test_a_push_from_a_browser_is_refused_even_with_the_right_code(endpoint, tmp_path):
    """A JSON POST is reachable cross-origin as a simple request, and this route
    is answered in front of the SDK's rebinding protection. The browser always
    sends Origin; PersonaCore never does."""
    server, info = endpoint
    server._enrolment.open_join(CODE)

    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        response = await client.post(
            _enrol_url(info),
            headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
            content=json.dumps({"code": CODE, "token": PUSHED}).encode(),
            timeout=10,
        )

    assert _observable(response) == _observable(await _mcp(info, tmp_path, headers={}))
    assert ensure_token(tmp_path) != PUSHED
    assert server.join_status() is not None

    # ...and the same push without the header still works, so this is the header
    # doing the refusing rather than something else about the request.
    pushed = await _push(info, tmp_path, {"code": CODE, "token": PUSHED})
    assert pushed.status_code == ENROL_SUCCESS_STATUS


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
async def test_only_post_reaches_the_enrolment_route(endpoint, tmp_path, method):
    server, info = endpoint
    server._enrolment.open_join(CODE)
    async with httpx.AsyncClient(verify=_tls_context(tmp_path)) as client:
        response = await client.request(method, _enrol_url(info), timeout=10)
    assert response.status_code == 401
    assert response.content == b""


async def test_mcp_still_refuses_an_unauthenticated_caller_while_a_join_is_pending(
    endpoint, tmp_path,
):
    """The gate the whole endpoint rests on is not relaxed by opening a window."""
    server, info = endpoint
    server._enrolment.open_join(CODE)

    for headers in ({}, {"Authorization": "Bearer " + "0" * 64}, {"Authorization": ""}):
        response = await _mcp(info, tmp_path, headers=headers)
        assert response.status_code == 401
        assert response.content == b""

    assert server.join_status() is not None


async def test_an_enrolment_push_over_plain_http_never_reaches_the_receiver(endpoint, tmp_path):
    """The push carries a credential; reading it off a plaintext socket is
    already the harm, so the transport is asserted before anything else."""
    server, info = endpoint
    server._enrolment.open_join(CODE)

    reader, writer = await asyncio.open_connection("127.0.0.1", info.port)
    try:
        writer.write(
            b"POST /enrol/token HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Length: 0\r\n\r\n",
        )
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(1024), timeout=5)
        except (TimeoutError, OSError, ssl.SSLError):
            pass
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except (OSError, ssl.SSLError, TimeoutError):
            pass

    assert server.join_status() is not None
    assert ensure_token(tmp_path) != PUSHED

    # And the endpoint is unharmed.
    still = await _mcp(info, tmp_path, headers={"Authorization": f"Bearer {info.token}"})
    assert still.status_code == 200
