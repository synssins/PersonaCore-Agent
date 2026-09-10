"""End-to-end: the Join goes out, the core's push comes back on a real socket.

``tests/unit/network_mcp/test_join.py`` drives ``join.py`` against fakes. This
file drives it against a **running endpoint**, because the three things that
make the outbound leg correct are properties of the whole stack and of the
*order* two calls happen in:

* **The window really is open while the request is in flight.** The fake core
  here does what the real one does — it pushes the minted token to the Agent's
  own ``POST /enrol/token``, over TLS, *before* answering the Join. If the window
  were opened after the POST returned, that push would get a ``401`` and this
  file would fail rather than a comment claiming otherwise.
* **A failed Join leaves nothing open.** Asserted by pushing at the real socket
  afterwards with the right code and getting the same refusal a stranger gets.
* **Revocation is immediate.** ``remove_enrolled_core`` rotates the bearer, and
  the running listener has to stop accepting the old one *now* — not at the next
  restart, which is when :meth:`NetworkMCPServer.rotate_token` takes effect.

Two accommodations, both because this fixture binds loopback so a test can have
a socket at all: ``begin_join`` correctly refuses to open a window on a
loopback-bound endpoint (the core could never reach it), and the core refuses a
loopback ``url``. Neither refusal is what this file is about — both are covered
where they live — so the first is monkeypatched out and the second never runs,
since the core here is a fake.
"""
# ruff: noqa: ANN401, ARG002
# The MCPHost stand-in implements a signature it does not use; that signature is
# the shape being imitated.

from __future__ import annotations

import json
import ssl
from typing import Any

import httpx
import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp import join
from workstation_agent.network_mcp.credentials import ensure_token
from workstation_agent.network_mcp.hardening import ENROL_SUCCESS_STATUS
from workstation_agent.network_mcp.server import NetworkMCPServer

# Every test here stands up a real uvicorn server on pytest's main-thread loop
# and stops it again, which makes each one both a possible source and a possible
# victim of sse_starlette's process-global shutdown latch. Three of the failures
# that opted this file in were exactly that. See the fixture's docstring in
# tests/integration/conftest.py.
pytestmark = pytest.mark.usefixtures("sse_shutdown_latch_cleared")

CODE = "PAIR-4417"
MINTED = "core-issued-" + "c" * 40
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
RPC = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
UNAUTHORISED = 401
NO_ANSWER = "the core never answered"


class Host:
    async def invoke(self, tool_id: str, args: dict) -> Any:
        raise KeyError(tool_id)


@pytest.fixture
async def endpoint(tmp_path, monkeypatch):
    # See the module docstring: loopback is how a test gets a socket, and the
    # refusal it would otherwise trigger is tested where it belongs.
    monkeypatch.setattr(
        "workstation_agent.registration_export.is_loopback_host", lambda _host: False,
    )
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
    ctx.check_hostname = False  # the core pins the fingerprint, not the name
    return ctx


async def _push(info, state_dir, body: dict) -> httpx.Response:
    """POST to ``/enrol/token`` exactly as the core does."""
    async with httpx.AsyncClient(verify=_tls_context(state_dir)) as client:
        return await client.post(
            info.url.removesuffix("/mcp") + "/enrol/token",
            headers={"Content-Type": "application/json"},
            content=json.dumps(body).encode(),
            timeout=10,
        )


async def _mcp(info, state_dir, token: str) -> httpx.Response:
    async with httpx.AsyncClient(verify=_tls_context(state_dir)) as client:
        return await client.post(
            info.url,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
            content=json.dumps(RPC).encode(),
            timeout=10,
        )


def fake_core(info, state_dir, *, pushes: bool = True, answer: httpx.Response | None = None):
    """A core that pushes the token before it answers, as the real one does."""
    seen: dict[str, Any] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        body = json.loads(request.content)
        if pushes:
            pushed = await _push(info, state_dir, {"code": body["code"], "token": MINTED})
            seen["push_status"] = pushed.status_code
        if answer is not None:
            return answer
        return httpx.Response(
            201,
            json={
                "plugin": "workstation-front-desk",
                "display_name": "FRONT-DESK",
                "state": "ok",
                "message": "FRONT-DESK joined as workstation-front-desk and is switched on.",
            },
        )

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)

    return factory, seen


async def test_the_push_lands_while_the_join_is_still_in_flight(endpoint, tmp_path):
    """The whole reason the window is opened before the POST, proved on a socket."""
    server, info = endpoint
    factory, seen = fake_core(info, tmp_path)

    result = await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        display_name="FRONT-DESK", endpoint=server, client_factory=factory,
    )

    assert seen["push_status"] == ENROL_SUCCESS_STATUS
    assert result.plugin == "workstation-front-desk"
    # The pushed token is now the bearer this endpoint requires.
    assert (await _mcp(info, tmp_path, MINTED)).status_code != UNAUTHORISED
    assert ensure_token(tmp_path) == MINTED


async def test_the_join_sends_this_endpoint_s_real_fingerprint(endpoint, tmp_path):
    server, info = endpoint
    factory, seen = fake_core(info, tmp_path)

    await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=server, client_factory=factory,
    )

    body = json.loads(seen["request"].content)
    assert body["tls_fingerprint"] == info.fingerprint
    assert body["url"] == f"https://192.168.1.50:{info.port}/mcp"
    # One certificate covers the whole bound set (its SAN does), so the pin on
    # the singular field and the pin on the entry are the same real value --
    # this endpoint's, read off a certificate that exists on disk rather than
    # off a fake.
    assert body["urls"] == [
        {"url": body["url"], "tls_fingerprint": info.fingerprint},
    ]


async def test_a_ranking_reaches_the_wire_in_the_owners_order(endpoint, tmp_path):
    """Against a running endpoint and a real certificate, not a stand-in.

    The order asserted is neither alphabetical nor the endpoint's own, so any
    layer that sorts shows up here as a different list rather than as a list
    that happens to still be right.
    """
    server, info = endpoint
    factory, seen = fake_core(info, tmp_path)

    await join.join_and_report(
        "192.168.1.150:8053",
        CODE,
        ["fd00::5", "desk.lan", "192.168.1.50"],
        endpoint=server,
        client_factory=factory,
    )

    body = json.loads(seen["request"].content)
    assert [entry["url"] for entry in body["urls"]] == [
        f"https://[fd00::5]:{info.port}/mcp",
        f"https://desk.lan:{info.port}/mcp",
        f"https://192.168.1.50:{info.port}/mcp",
    ]
    assert body["url"] == body["urls"][0]["url"]
    assert all(entry["tls_fingerprint"] == info.fingerprint for entry in body["urls"])


async def test_a_refused_join_leaves_no_window_open_on_the_socket(endpoint, tmp_path):
    """The hazard in one test: a stranger with the code must find nothing."""
    server, info = endpoint
    before = ensure_token(tmp_path)
    factory, _ = fake_core(
        info, tmp_path, pushes=False,
        answer=httpx.Response(403, json={"detail": {"error": "That pairing code is not valid."}}),
    )

    with pytest.raises(join.CoreRefusedError, match="not valid"):
        await join.join_and_report(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=server, client_factory=factory,
        )

    late = await _push(info, tmp_path, {"code": CODE, "token": "late-" + "d" * 40})
    assert late.status_code == UNAUTHORISED
    assert ensure_token(tmp_path) == before


async def test_the_serving_endpoint_is_the_one_a_bare_join_uses(endpoint):
    """Registered by start(), so ``join_core`` needs no fourth argument."""
    server, _info = endpoint
    assert join._resolve_endpoint(None) is server

    await server.stop()
    with pytest.raises(join.EnrolmentError, match="not running"):
        await join.join_core("192.168.1.150:8053", CODE, "192.168.1.50")


async def test_removal_stops_the_removed_core_calling_immediately(endpoint, tmp_path):
    """Not at the next restart — ``rotate_token`` is the one that waits."""
    server, info = endpoint
    factory, _ = fake_core(info, tmp_path)

    await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=server, client_factory=factory,
    )
    assert (await _mcp(info, tmp_path, MINTED)).status_code != UNAUTHORISED

    join.remove_enrolled_core("front-desk", state_dir=tmp_path)

    assert join.list_enrolled_cores(state_dir=tmp_path) == ()
    assert (await _mcp(info, tmp_path, MINTED)).status_code == UNAUTHORISED
    assert (await _mcp(info, tmp_path, ensure_token(tmp_path))).status_code != UNAUTHORISED


async def test_a_lost_answer_after_a_real_push_is_reported_as_success(endpoint, tmp_path):
    """The finding this file exists to pin, end to end on a real socket.

    The fake core does what a slow real one does: it pushes the minted token to
    the Agent's own HTTPS ``/enrol/token`` -- which succeeds -- and then the
    connection dies before it can answer. The network cannot say whether the
    enrolment happened. This process can: the token is on disk and is the bearer
    the endpoint now requires. Reporting a failure here would send the owner to
    burn a fresh pairing code on an enrolment that already worked.
    """
    server, info = endpoint

    async def handler(request: httpx.Request) -> httpx.Response:
        pushed = await _push(info, tmp_path, {"code": CODE, "token": MINTED})
        assert pushed.status_code == ENROL_SUCCESS_STATUS
        raise httpx.ReadTimeout(NO_ANSWER, request=request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)

    result = await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        display_name="FRONT-DESK", endpoint=server, client_factory=factory,
    )

    # Reported as an enrolment, and reported as unconfirmed -- the core got as
    # far as pushing, and what it did after that nobody here heard.
    assert result.confirmed is False
    assert result.plugin == ""
    assert ensure_token(tmp_path) == MINTED
    assert (await _mcp(info, tmp_path, MINTED)).status_code != UNAUTHORISED

    rows = join.list_enrolled_cores(state_dir=tmp_path)
    assert [(r.display_name, r.confirmed) for r in rows] == [("FRONT-DESK", False)]


async def test_a_lost_answer_with_no_push_is_reported_as_a_failure(endpoint, tmp_path):
    """The recovery reads a token that actually arrived, never a hopeful guess."""
    server, info = endpoint
    before = ensure_token(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(NO_ANSWER, request=request)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)

    with pytest.raises(join.CoreUnreachableError):
        await join.join_and_report(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=server, client_factory=factory,
        )

    assert ensure_token(tmp_path) == before
    assert join.list_enrolled_cores(state_dir=tmp_path) == ()
    # And the window it opened is shut: a stranger holding the code finds nothing.
    late = await _push(info, tmp_path, {"code": CODE, "token": "late-" + "e" * 40})
    assert late.status_code == UNAUTHORISED


async def test_a_second_join_cannot_close_the_first_one_s_window(endpoint, tmp_path):
    """The race, on a real socket: the loser must not shut the winner's door.

    Without the single-flight guard the second ``begin_join`` replaces the first
    window and the second Join's failure cancels it -- so the push below, which
    is the *first* Join's and is correct, would arrive at a closed window and be
    refused.
    """
    server, info = endpoint
    refused: list[BaseException] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        # A second Join, raced in while the first is still in flight.
        try:
            await join.join_and_report(
                "192.168.1.150:8053", "SECOND-CODE", "192.168.1.50", endpoint=server,
            )
        except BaseException as exc:  # noqa: BLE001 -- recorded, then asserted on
            refused.append(exc)
        pushed = await _push(info, tmp_path, {"code": CODE, "token": MINTED})
        assert pushed.status_code == ENROL_SUCCESS_STATUS
        return httpx.Response(201, json={
            "plugin": "workstation-front-desk", "display_name": "FRONT-DESK",
            "state": "ok", "message": "joined",
        })

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)

    result = await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=server, client_factory=factory,
    )

    assert result.confirmed is True
    assert len(refused) == 1
    assert "already in progress" in str(refused[0])
    assert ensure_token(tmp_path) == MINTED
