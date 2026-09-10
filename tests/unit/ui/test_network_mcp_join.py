"""The owner's side of enrolment: address, listen address, pairing code, Join.

``POST /network-mcp/join`` is the whole of what the owner does to enrol this
workstation with a PersonaCore, so this file pins the properties that make it
safe to press and legible when it refuses:

* **The code never leaks.** It is not echoed back into the page on any outcome,
  it is not in the pending-Join state the page renders, and it is not logged.
  The core's address is not a secret and *is* echoed back — retyping it after a
  refusal is a cost with nothing bought — but it is kept out of the log too.
* **The route calls ``join_core`` and never ``begin_join``.** ``join_core``
  opens the enrolment window inside the ``try``/``finally`` that closes it
  again; a window opened out in the route would be opened outside the block
  that closes it, leaving an unauthenticated route standing open. Pinned
  directly, because it is the one mistake this endpoint cannot afford.
* **The owner is told plainly when a Join cannot work.** A refusal — from the
  core, from the receiver, or from the "one Join at a time" rule — is rendered
  in the words of whoever wrote it. An endpoint with no address PersonaCore
  could reach shows the reason and the way to fix it, never an empty dropdown.
* **Removal says what it costs before it costs it.** This endpoint holds one
  bearer token, so removing any enrolled core locks out every enrolled core.
  The page says so beside the button and again in the browser's confirmation.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import pathlib
import re

import httpx
import pytest

from tests.unit.ui.conftest import make_client
from workstation_agent.network_mcp import join as join_module
from workstation_agent.network_mcp.credentials import ensure_token
from workstation_agent.network_mcp.enrolment import EnrolmentError, JoinStatus
from workstation_agent.network_mcp.join import CoreRefusedError
from workstation_agent.network_mcp.listeners import endpoint_url

CODE = "PAIR-4417"
CORE = "192.168.1.150:8053"
LAN = "192.168.1.50"


class _Info:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


class FakeEndpoint:
    """Stands in for NetworkMCPServer's Join surface.

    ``state_dir`` is part of it: ``join.list_enrolled_cores`` and
    ``join.remove_enrolled_core`` are directory-scoped, and a fake without one
    would send both at the real ``%APPDATA%`` of whoever ran the suite.
    """

    def __init__(
        self,
        state_dir=None,
        *,
        error: str | None = None,
        join: JoinStatus | None = None,
        bind_hosts: tuple[str, ...] = (LAN,),
    ) -> None:
        self._state_dir = state_dir
        self.error = error
        self.join = join
        self.bind_hosts = bind_hosts
        self.codes: list[str] = []
        self.cancels = 0
        self.revoked = 0
        self.join_seq = 0

    @property
    def state_dir(self):
        return self._state_dir

    def info(self):
        return _Info(
            # ``endpoint_url``, not an f-string of our own: the real endpoint
            # brackets an IPv6 literal, and a fake that does not would show the
            # picker a label the product never produces.
            url=endpoint_url(self.bind_hosts[0], 8765),
            urls=tuple(endpoint_url(h, 8765) for h in self.bind_hosts),
            bind_host=self.bind_hosts[0],
            bind_hosts=self.bind_hosts,
            port=8765,
            fingerprint="sha256:" + "ab" * 32,
            token="t" * 64,
            certificate_sans=self.bind_hosts,
            certificate_expires=dt.datetime.now(dt.UTC) + dt.timedelta(days=3650),
            tool_names=("workstation_status",),
            running=True,
        )

    def begin_join(self, code, *, ttl_seconds=300.0):
        self.codes.append(code)
        if self.error is not None:
            raise EnrolmentError(self.error)
        self.join_seq += 1
        self.join = JoinStatus(
            expires_in=ttl_seconds, opened_at=dt.datetime.now(dt.UTC), attempts=0,
        )
        return _Info(join_id=self.join_seq)

    def cancel_join(self):
        self.cancels += 1
        self.join = None

    def join_status(self):
        return self.join

    def join_completed(self, _join_id):
        return False

    def revoke_token(self):
        self.revoked += 1
        return "a-fresh-token"


ACCEPTED = {
    "plugin": "workstation-front-desk",
    "display_name": "FRONT-DESK",
    "state": "ok",
    "message": "FRONT-DESK joined as workstation-front-desk and is switched on.",
}


def core_answers(monkeypatch, handler):
    """Point ``join``'s default client at *handler* instead of the network.

    ``_post_join`` resolves ``_client`` off the module at call time, so this
    substitutes the transport and leaves every other decision the real
    ``join_core`` makes — the window, the ``finally``, the body, the scrub —
    exactly where it is. Nothing here reaches a socket.
    """

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        )

    monkeypatch.setattr(join_module, "_client", factory)


def accepting(sink=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if sink is not None:
            sink.append(json.loads(request.content))
        return httpx.Response(200, json=ACCEPTED)

    return handler


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))


@pytest.fixture(autouse=True)
def _no_stale_join_flag():
    """``_join_in_flight`` is process-global; a test that sets it must not leak."""
    join_module._join_in_flight = False
    yield
    join_module._join_in_flight = False


# ---------------------------------------------------------------------------
# The Join itself
# ---------------------------------------------------------------------------


def test_joining_sends_the_code_to_the_core_and_reports_what_it_said(
    tmp_path, monkeypatch,
):
    sink: list[dict] = []
    core_answers(monkeypatch, accepting(sink))
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert sink, "the Join reached the core"
    assert sink[0]["code"] == CODE
    # The listen address the owner picked is what the core is told to dial.
    assert sink[0]["url"] == f"https://{LAN}:8765/mcp"
    assert "joined as workstation-front-desk" in response.text


def test_the_route_opens_no_window_of_its_own(tmp_path, monkeypatch):
    """``join_core`` opens exactly one, inside the ``finally`` that closes it.

    A second ``begin_join`` out in the route would be an unauthenticated
    enrolment route left standing open when the outbound leg fails, because the
    open would sit outside the block that closes it.
    """
    core_answers(monkeypatch, accepting())
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert endpoint.codes == [CODE], "exactly one window, opened by join_core"


def test_the_enrolled_row_appears_after_a_successful_join(tmp_path, monkeypatch):
    core_answers(monkeypatch, accepting())
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )
    text = client.get("/network-mcp").text

    assert "FRONT-DESK" in text
    assert CORE in text


# ---------------------------------------------------------------------------
# The pairing code
# ---------------------------------------------------------------------------


def test_the_pairing_code_is_never_echoed_back_into_the_page(tmp_path, monkeypatch):
    """A code re-rendered into the form is a code in a screenshot."""
    core_answers(monkeypatch, accepting())
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    posted = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )
    assert CODE not in posted.text
    assert CODE not in client.get("/network-mcp").text


def test_the_pairing_code_is_not_echoed_back_when_the_join_is_refused(tmp_path):
    """The failure path is the tempting place to helpfully preserve the field."""
    endpoint = FakeEndpoint(
        tmp_path, error="The endpoint is not running, so PersonaCore has nowhere.",
    )
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert CODE not in response.text
    assert "not running" in response.text


def test_the_pairing_code_is_not_echoed_back_when_the_core_refuses(
    tmp_path, monkeypatch,
):
    core_answers(
        monkeypatch,
        lambda _r: httpx.Response(400, json={"detail": "That pairing code has expired."}),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert CODE not in response.text
    assert "expired" in response.text


def test_the_pairing_code_is_never_logged_on_success(tmp_path, monkeypatch, caplog):
    core_answers(monkeypatch, accepting())
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    with caplog.at_level(logging.DEBUG):
        client.post(
            "/network-mcp/join",
            data={"code": CODE, "core_address": CORE, "listen_address": LAN},
        )

    assert "joined a PersonaCore" in caplog.text, (
        "this assertion is what makes the next ones mean something: if nothing "
        "were captured, 'the code is absent' would be vacuously true"
    )
    assert CODE not in caplog.text
    assert all(CODE not in str(r.args) for r in caplog.records)


def test_neither_the_code_nor_the_core_address_is_logged_on_a_failure(
    tmp_path, monkeypatch, caplog,
):
    """The code is absolute; the address is a habit worth keeping.

    The address check is scoped to this project's own loggers on purpose.
    ``httpx`` logs every request line it sends, including the URL, at ``INFO``
    from ``httpx._client`` — that is its behaviour and not something this router
    can or should reach into. What is being pinned is that *nothing we write*
    puts the address in a log line, which is the part we control. The pairing
    code is held to the stricter rule and checked against every record from
    every library, because it is a live secret and there is no logger anywhere
    it would be acceptable in.
    """
    core_answers(
        monkeypatch,
        lambda _r: httpx.Response(409, json={"detail": "A workstation already holds it."}),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/network-mcp/join",
            data={"code": CODE, "core_address": CORE, "listen_address": LAN},
        )

    assert "already holds it" in response.text
    assert CODE not in caplog.text
    assert all(CODE not in str(r.args) for r in caplog.records)

    ours = [r for r in caplog.records if r.name.startswith("workstation_agent")]
    assert ours, "if nothing of ours were captured the next assertion is vacuous"
    assert all(CORE not in r.getMessage() for r in ours)


def test_the_core_address_is_kept_so_a_refusal_costs_one_correction(tmp_path):
    endpoint = FakeEndpoint(tmp_path, error="That pairing code is too short to be safe")
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert CORE in response.text
    assert CODE not in response.text


# ---------------------------------------------------------------------------
# Refusals, rendered in the words of whoever wrote them
# ---------------------------------------------------------------------------


def test_a_refusal_message_from_the_endpoint_is_shown_verbatim(tmp_path):
    message = "The endpoint is bound to 127.0.0.1, which is this machine only."
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path, error=message))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert "this machine only" in response.text


def test_a_core_refusal_is_shown_verbatim(tmp_path, monkeypatch):
    refusal = "A workstation called front-desk is already enrolled on this core."
    core_answers(monkeypatch, lambda _r: httpx.Response(409, json={"detail": refusal}))
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert refusal in response.text


def test_a_second_join_is_refused_not_queued(tmp_path):
    """``join_core`` enforces this; the route renders it and builds no second guard.

    The flag is set the way a Join in flight sets it, and the real ``join_core``
    runs — it refuses before anything is sent, so no transport is involved.
    """
    join_module._join_in_flight = True
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert "already in progress" in response.text
    assert endpoint.codes == [], "a refused Join opens no window"
    assert CODE not in response.text


def test_a_missing_address_says_what_to_type(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join", data={"code": CODE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert "Type the address PersonaCore is reachable at" in response.text


def test_an_unexpected_failure_names_the_type_and_not_the_exception(
    tmp_path, monkeypatch,
):
    """``str(exc)`` on an httpx error can quote the request, and the request
    carries the body the pairing code was in."""

    async def explode(*_args, **_kwargs):
        leaky = f"failed while sending code={CODE}"
        raise httpx.ConnectError(leaky)

    monkeypatch.setattr(
        "workstation_agent.ui.backend.routers.network_mcp_routes.join_and_report",
        explode,
    )
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert "ConnectError" in response.text
    assert CODE not in response.text


def test_joining_with_no_endpoint_at_all_says_to_switch_it_on(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=None)
    response = client.post("/network-mcp/join", data={"code": CODE})
    assert response.status_code == 200
    assert "Switch it on" in response.text


def test_joining_with_an_endpoint_that_cannot_join_does_not_500(tmp_path):
    """A stub or an older endpoint object degrades to a message, not a crash."""

    class Bare:
        def info(self):
            msg = "no info here"
            raise RuntimeError(msg)

    client = make_client(tmp_path=tmp_path, network_mcp=Bare())
    response = client.post("/network-mcp/join", data={"code": CODE})
    assert response.status_code == 200
    assert "no endpoint to enrol" in response.text


def test_a_missing_code_field_reaches_the_call_as_empty_not_a_422(tmp_path):
    """A 422 JSON body is a dead end in a webview with no way back to the form."""
    endpoint = FakeEndpoint(tmp_path, error="That pairing code is too short to be safe")
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join", data={"core_address": CORE, "listen_address": LAN},
    )

    assert response.status_code == 200
    assert "too short" in response.text


# ---------------------------------------------------------------------------
# The listen-address picker
# ---------------------------------------------------------------------------


def test_the_picker_offers_the_addresses_the_endpoint_is_answering_on(tmp_path):
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    picker = listen_picker(client.get("/network-mcp").text)

    assert f'value="{LAN}"' in picker
    assert 'value="10.0.0.7"' in picker
    assert f"https://{LAN}:8765/mcp" in picker, "the owner is picking a connection string"


def listen_picker(text: str) -> str:
    """Just the listen-address control.

    Scoped, because the bind-address multi-select at the top of the same page
    legitimately offers loopback — binding it is fine, *advertising* it to
    another machine is not — and an unscoped search would find that one.
    """
    _, _, after = text.partition('id="nm-listen-address"')
    picker, _, _ = after.partition("</select>")
    return picker


def test_the_picker_never_offers_loopback(tmp_path):
    """Telling the core to connect to 127.0.0.1 tells it to connect to itself."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "127.0.0.1"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    picker = listen_picker(client.get("/network-mcp").text)

    assert f'value="{LAN}"' in picker
    assert "127.0.0.1" not in picker


def test_a_loopback_only_endpoint_gets_a_reason_and_a_way_out_not_an_empty_list(
    tmp_path,
):
    """An empty dropdown is where the product stops working with no explanation."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=("127.0.0.1", "::1"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    text = client.get("/network-mcp").text

    assert "which is this machine only" in text
    assert "cannot reach it to push the token" in text
    assert 'href="#nm-endpoint"' in text
    assert 'name="code"' not in text, "no form to fill in that could not work"


def test_the_empty_state_uses_begin_joins_own_words(tmp_path):
    """Two voices for one condition reads as two different problems.

    The endpoint refuses a loopback-only Join with these sentences; the page
    pre-empts it with the same ones.
    """
    endpoint = FakeEndpoint(tmp_path, bind_hosts=("127.0.0.1",))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    text = client.get("/network-mcp").text

    assert (
        "The endpoint is bound to 127.0.0.1, which is this machine only. "
        "PersonaCore runs elsewhere and cannot reach it to push the token. "
        "Bind a LAN address first, then join."
    ) in text


def test_a_listen_address_the_endpoint_is_not_serving_is_refused(tmp_path):
    """The dropdown constrains a browser and constrains nothing else."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN,))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": "203.0.113.9"},
    )

    assert response.status_code == 200
    assert "not answering on the address that was submitted" in response.text
    assert LAN in response.text, "the refusal names what it IS answering on"
    assert endpoint.codes == [], "refused before the window opens"


def test_a_hand_made_post_cannot_advertise_loopback(tmp_path):
    """The loopback-only state the template handles so carefully is enforced
    nowhere if a direct POST can walk past it.

    ``begin_join`` does not catch this: what it asks is whether the endpoint is
    loopback-*bound*, which on a LAN-bound endpoint is false, and is a different
    question from what address the core is being told to dial.
    """
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN,))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert "not an address another machine can be reached at" in response.text
    assert endpoint.codes == [], "refused before the window opens"


def test_an_address_the_picker_did_offer_is_not_refused(tmp_path, monkeypatch):
    """The other half of the gate: it must refuse only what it should."""
    core_answers(monkeypatch, accepting())
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": "10.0.0.7"},
    )

    assert "joined as workstation-front-desk" in response.text


# ---------------------------------------------------------------------------
# The ranking: a set of addresses, in the order the owner put them
# ---------------------------------------------------------------------------


def join_form(text: str) -> str:
    """Just the Join form, so the bind-address controls above cannot match."""
    _, _, after = text.partition('action="/network-mcp/join"')
    form, _, _ = after.partition("</form>")
    return form


def test_the_picker_ranks_rather_than_multi_selecting(tmp_path):
    """A ``<select multiple>`` submits in document order, never click order, so
    it cannot express a preference at all. One control per rank can, and the
    rank is the label rather than help text."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7", "fd00::5"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    form = join_form(client.get("/network-mcp").text)

    assert "multiple" not in form, "a multi-select would lose the order in the browser"
    assert form.count('name="listen_address"') == 3, "one rank slot per address"
    assert "1st — tried first" in form
    assert "2nd" in form
    assert "3rd" in form


def test_the_first_rank_cannot_be_left_unused(tmp_path):
    """A ranking with nothing in first place is not a ranking."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    form = join_form(client.get("/network-mcp").text)
    first, _, rest = form.partition('id="nm-listen-address-1"')

    assert "— not used —" not in first
    assert "— not used —" in rest


def test_the_default_ranking_is_the_one_preferred_address(tmp_path):
    """What this page has always done, unchanged: the endpoint's own preferred
    address, and nothing else unless the owner adds it."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    form = join_form(client.get("/network-mcp").text)
    first, _, rest = form.partition('id="nm-listen-address-1"')

    assert re.search(rf'value="{re.escape(LAN)}"\s+selected', first)
    assert not re.search(r'value="10\.0\.0\.7"\s+selected', first)
    assert re.search(r'value=""\s+selected', rest), "later ranks default to not used"


def test_a_ranking_reaches_the_core_in_the_owners_order(tmp_path, monkeypatch):
    """The property this feature turns on, from the form to the wire.

    The order posted is not the endpoint's own order and not alphabetical, so a
    sort or a silent re-ordering anywhere between here and ``httpx`` shows up
    as a different list rather than as a list that happens to still be right.
    """
    sink: list[dict] = []
    core_answers(monkeypatch, accepting(sink))
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7", "fd00::5"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={
            "code": CODE,
            "core_address": CORE,
            "listen_address": ["fd00::5", LAN, "10.0.0.7"],
        },
    )

    assert response.status_code == 200
    assert [entry["url"] for entry in sink[0]["urls"]] == [
        "https://[fd00::5]:8765/mcp",
        f"https://{LAN}:8765/mcp",
        "https://10.0.0.7:8765/mcp",
    ]
    assert sink[0]["url"] == "https://[fd00::5]:8765/mcp", "the preferred one, still singular"


def test_an_unused_rank_slot_drops_out_without_reordering_the_rest(tmp_path, monkeypatch):
    sink: list[dict] = []
    core_answers(monkeypatch, accepting(sink))
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7", "fd00::5"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post(
        "/network-mcp/join",
        data={
            "code": CODE,
            "core_address": CORE,
            "listen_address": ["10.0.0.7", "", "fd00::5"],
        },
    )

    assert [entry["url"] for entry in sink[0]["urls"]] == [
        "https://10.0.0.7:8765/mcp",
        "https://[fd00::5]:8765/mcp",
    ]


def test_every_submitted_address_is_checked_and_not_only_the_preferred_one(tmp_path):
    """The gate is per entry. A good first address and a loopback third would
    otherwise put "dial yourself" into ``urls`` as a fallback the owner never
    sees, because the preferred address connects."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN,))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": [LAN, "127.0.0.1"]},
    )

    assert response.status_code == 200
    assert "not an address another machine can be reached at" in response.text
    assert endpoint.codes == [], "refused before the window opens"


def test_an_address_the_endpoint_does_not_serve_is_refused_wherever_it_is_ranked(
    tmp_path,
):
    """The picker constrains a browser and constrains nothing else."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={
            "code": CODE,
            "core_address": CORE,
            "listen_address": [LAN, "10.0.0.7", "203.0.113.9"],
        },
    )

    assert "not answering on the address that was submitted (203.0.113.9)" in response.text
    assert endpoint.codes == [], "refused before the window opens"


def test_a_refusal_hands_the_ranking_back_rather_than_the_default(tmp_path):
    """A correction must cost one edit, not a re-ranking."""
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7", "fd00::5"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={
            "code": CODE,
            "core_address": CORE,
            "listen_address": ["fd00::5", "10.0.0.7", "203.0.113.9"],
        },
    )

    form = join_form(response.text)
    first, _, rest = form.partition('id="nm-listen-address-1"')
    second, _, _third = rest.partition('id="nm-listen-address-2"')
    assert re.search(r'value="fd00::5"\s+selected', first)
    assert re.search(r'value="10\.0\.0\.7"\s+selected', second)
    assert 'name="code"' in form, "and the form is still there to correct"
    assert CODE not in response.text, "but never the code"


def test_the_ranking_that_comes_back_after_a_refusal_still_carries_no_code(tmp_path):
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN,))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": [LAN, "203.0.113.9"]},
    )

    assert CODE not in response.text
    assert 'value=""' in join_form(response.text), "the code field is rendered empty"


def test_a_ranking_that_repeats_an_address_keeps_the_higher_rank(tmp_path, monkeypatch):
    """An obvious intent, so it is honoured rather than refused: first wins,
    because first is the higher preference."""
    sink: list[dict] = []
    core_answers(monkeypatch, accepting(sink))
    endpoint = FakeEndpoint(tmp_path, bind_hosts=(LAN, "10.0.0.7"))
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": [LAN, "10.0.0.7", LAN]},
    )

    assert [entry["url"] for entry in sink[0]["urls"]] == [
        f"https://{LAN}:8765/mcp",
        "https://10.0.0.7:8765/mcp",
    ]


def test_one_address_posted_the_old_way_is_unchanged(tmp_path, monkeypatch):
    """A single ``listen_address`` -- a script, a bookmark, a one-address
    machine -- still sends ``url`` and a ``urls`` of exactly that one."""
    sink: list[dict] = []
    core_answers(monkeypatch, accepting(sink))
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert sink[0]["url"] == f"https://{LAN}:8765/mcp"
    assert sink[0]["urls"] == [
        {"url": f"https://{LAN}:8765/mcp", "tls_fingerprint": "sha256:" + "ab" * 32},
    ]


def test_an_empty_listen_address_is_left_to_join_pys_own_sentence(tmp_path):
    """Answering the same condition twice is two wordings of one problem."""
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": ""},
    )

    assert "Choose the address PersonaCore should reach this workstation at" in response.text


def test_the_core_address_is_left_to_join_pys_validation(tmp_path):
    """``core_enrol_url`` runs ahead of the window and already refuses an empty
    address, an unparseable authority, a scheme that is not http(s), an address
    naming no host, and one carrying userinfo. A second set of rules out in the
    route could only agree with those or contradict them."""
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    refused = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": "ftp://box", "listen_address": LAN},
    )
    assert "reached over http, not ftp" in refused.text

    sneaky = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": "http://u:p@box", "listen_address": LAN},
    )
    assert "carries a username or a password" in sneaky.text
    assert endpoint.codes == [], "both refused before the window opens"


def test_an_enormous_refusal_from_the_core_cannot_stretch_the_page(
    tmp_path, monkeypatch,
):
    """The verbatim pass-through is right and stays; the length is not the
    core's to choose. ``_refusal_of`` reads a detail out of a 64 KiB body and
    does not bound the sentence."""
    flood = "A" * 20000
    core_answers(monkeypatch, lambda _r: httpx.Response(400, json={"detail": flood}))
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/join",
        data={"code": CODE, "core_address": CORE, "listen_address": LAN},
    )

    assert flood not in response.text
    assert "message truncated" in response.text, "a cut message must admit it"
    assert "A" * 100 in response.text, "and the readable part still gets through"


def test_a_bounded_message_still_wraps_rather_than_stretching():
    """The other half of the defence: 400 characters with nowhere to break is
    still one unbroken run, so the class it lands in has to wrap it."""
    css = (
        pathlib.Path("src/workstation_agent/ui/backend/static/skeleton.css")
        .read_text(encoding="utf-8")
    )
    assert ".error, .success, .info { overflow-wrap: anywhere; }" in css
    assert "td { overflow-wrap: anywhere; }" in css


def test_the_page_offers_the_join_form_when_no_window_is_open(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))
    text = client.get("/network-mcp").text
    assert 'name="code"' in text
    assert 'name="core_address"' in text
    assert 'name="listen_address"' in text
    assert "/network-mcp/join" in text


# ---------------------------------------------------------------------------
# The pending window and cancelling it
# ---------------------------------------------------------------------------


def test_a_pending_join_is_shown_without_its_code(tmp_path):
    endpoint = FakeEndpoint(
        tmp_path,
        join=JoinStatus(expires_in=241.0, opened_at=dt.datetime.now(dt.UTC), attempts=0),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    text = client.get("/network-mcp").text

    assert "A join is open" in text
    assert "241" in text
    assert CODE not in text


def test_attempts_against_a_pending_join_are_surfaced_to_the_owner(tmp_path):
    """A count climbing without a success is the owner's only signal that
    something on the LAN is guessing."""
    endpoint = FakeEndpoint(
        tmp_path,
        join=JoinStatus(expires_in=100.0, opened_at=dt.datetime.now(dt.UTC), attempts=7),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    text = client.get("/network-mcp").text

    assert "7" in text
    assert "trying codes" in text


def test_cancelling_closes_the_window(tmp_path):
    endpoint = FakeEndpoint(
        tmp_path,
        join=JoinStatus(expires_in=100.0, opened_at=dt.datetime.now(dt.UTC), attempts=0),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/join/cancel", follow_redirects=False)

    assert response.status_code == 303
    assert endpoint.cancels == 1
    assert endpoint.join is None


def test_cancelling_with_no_endpoint_is_harmless(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=None)
    assert client.post("/network-mcp/join/cancel", follow_redirects=False).status_code == 303


def test_an_endpoint_whose_join_status_raises_still_renders_the_page(tmp_path):
    class Broken(FakeEndpoint):
        def join_status(self):
            msg = "boom"
            raise RuntimeError(msg)

    client = make_client(tmp_path=tmp_path, network_mcp=Broken(tmp_path))
    response = client.get("/network-mcp")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# The enrolled listing
# ---------------------------------------------------------------------------


def enrol(tmp_path, **overrides):
    """Write one enrolled row the way a completed Join writes it."""
    row = {
        "slug": "front-desk",
        "plugin": "workstation-front-desk",
        "display_name": "FRONT-DESK",
        "core_address": CORE,
        "joined_at": dt.datetime.now(dt.UTC).isoformat(),
        "confirmed": True,
    }
    row.update(overrides)
    existing = []
    path = tmp_path / "enrolled.json"
    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))["cores"]
    path.write_text(
        json.dumps({"version": 1, "cores": [*existing, row]}), encoding="utf-8",
    )
    return row


def test_an_empty_listing_says_so_rather_than_showing_an_empty_table(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))
    assert "not enrolled with any PersonaCore yet" in client.get("/network-mcp").text


def test_an_enrolled_row_shows_the_core_and_the_name(tmp_path):
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert CORE in text
    assert "FRONT-DESK" in text


def test_the_enrolled_table_has_no_plugin_column(tmp_path):
    """PersonaCore now installs one plugin, named ``workstation``, for every
    enrolled machine -- so a "Plugin on the core" column would read the same
    on every confirmed row and distinguish nothing. It was removed rather
    than kept as dead space in the table the owner uses to pick a core to
    remove.
    """
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "Plugin on the core" not in text
    assert "workstation-front-desk" not in text


def test_an_unconfirmed_row_says_what_is_and_is_not_known(tmp_path):
    """Neither a healthy row nor a failed one: the token landed, the core went quiet."""
    enrol(tmp_path, plugin="", confirmed=False, slug="front-desk")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "PersonaCore never confirmed this one" in text
    assert "is in force" in text
    assert "Plugins screen" in text


def test_an_unconfirmed_row_is_still_visibly_distinct_without_a_plugin_cell(tmp_path):
    """The plugin column is gone, so the unconfirmed marker has to live
    elsewhere -- and it does, on the Name cell and the full-width notice
    below the row. Nothing here should invent a plugin name the core never
    gave."""
    enrol(tmp_path, plugin="", confirmed=False, display_name="FRONT-DESK")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "workstation-front-desk" not in text
    assert "the name this Agent sent" in text


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


def test_an_enormous_display_name_cannot_make_the_table_useless(tmp_path):
    """The cells are remote text too. ``overflow-wrap`` stops the page
    stretching sideways; nothing stopped it stretching down."""
    flood = "N" * 64000
    enrol(tmp_path, display_name=flood)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert flood not in text
    assert "(truncated)" in text, "a cut name must never look whole"
    assert "N" * 40 in text, "and the readable part still gets through"


def test_a_name_the_core_could_really_send_is_never_cut(tmp_path):
    """64 is the core's own ceiling on a machine's display name, so nothing a
    working core produces reaches the cap."""
    longest = "a" * 64
    enrol(tmp_path, display_name=longest)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert longest in text
    assert "(truncated)" not in text


def test_truncation_does_not_merge_two_different_names_into_one(tmp_path):
    """The removal decision is made off these cells, so a collision created by
    the *display* would be the display picking the wrong core."""
    shared = "S" * 64000
    enrol(tmp_path, slug="one", display_name=shared + "-study", plugin="workstation-one")
    enrol(tmp_path, slug="two", display_name=shared + "-workshop", plugin="workstation-two")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    # The tail is kept precisely so this common case needs no digest at all.
    assert "-study" in text
    assert "-workshop" in text


def test_names_differing_only_in_the_elided_middle_are_still_told_apart(tmp_path):
    """Head and tail identical, difference in the part that is cut away."""
    head, tail = "H" * 100, "T" * 100
    enrol(tmp_path, slug="one", display_name=head + "AAA" + tail, plugin="workstation-one")
    enrol(tmp_path, slug="two", display_name=head + "BBB" + tail, plugin="workstation-two")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    rows = client.get("/network-mcp").text
    _, _, table = rows.partition('<section id="nm-enrolled">')
    cells = re.findall(r"\[([0-9a-f]{6})\]", table)

    assert len(cells) == 2, "both colliding cells are marked"
    assert cells[0] != cells[1], "and the marks distinguish them"


def test_two_rows_genuinely_sharing_a_name_are_not_given_a_false_distinction(
    tmp_path,
):
    """Only truncation-created collisions get a mark. Inventing a distinction
    between two rows that really do carry the same name would be a lie."""
    enrol(tmp_path, slug="one", display_name="FRONT-DESK", plugin="workstation-one")
    enrol(tmp_path, slug="two", display_name="FRONT-DESK", plugin="workstation-two")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert not re.search(r"\[[0-9a-f]{6}\]", text)


def test_the_slug_the_remove_button_posts_is_never_truncated(tmp_path):
    """It is not rendered as text -- it is the value the row is matched on.
    Cutting it would post something naming no row, and the guard would refuse
    a removal the owner correctly asked for."""
    enrol(tmp_path, display_name="N" * 64000)
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    assert 'value="front-desk"' in client.get("/network-mcp").text

    response = client.post("/network-mcp/enrolled/remove", data={"slug": "front-desk"})
    assert join_module.list_enrolled_cores(state_dir=tmp_path) == ()
    assert "(truncated)" in response.text, "the name is capped in the message too"


def test_the_page_warns_that_removal_locks_out_everything_before_it_happens(tmp_path):
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "Removing any core here locks out every core here" in text
    assert "has to join again" in text


def test_the_remove_button_asks_before_it_does_it(tmp_path):
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "return confirm(" in text
    assert "EVERY core enrolled here is locked out, not just this one" in text


def test_removing_drops_the_row_and_rotates_the_token(tmp_path):
    """Rotation is what makes removal mean something: the owner asked that a
    removed core actually stop being able to connect."""
    enrol(tmp_path)
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/enrolled/remove", data={"slug": "front-desk"})

    assert response.status_code == 200
    # Autoescaped, so the apostrophe in "workstation's" is &#39; in the source.
    assert "bearer token so it cannot reconnect" in response.text
    assert "not enrolled with any PersonaCore yet" in response.text


def test_removing_one_of_several_names_what_else_it_just_locked_out(tmp_path):
    """'Every enrolled core' is an abstraction until it is a list of names."""
    enrol(tmp_path, slug="front-desk", display_name="FRONT-DESK")
    enrol(tmp_path, slug="study", display_name="STUDY", plugin="workstation-study")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post("/network-mcp/enrolled/remove", data={"slug": "front-desk"})

    assert "locked out everything else that was enrolled here: STUDY" in response.text
    assert "has to join again" in response.text


def test_removing_nothing_says_so_rather_than_rotating(tmp_path):
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/enrolled/remove", data={})

    assert response.status_code == 200
    assert "No core was named to remove" in response.text
    assert endpoint.revoked == 0


def test_an_unknown_slug_removes_nothing_and_rotates_nothing(tmp_path):
    """The worst thing this product can do, done for a typo, with nothing to show.

    ``remove_enrolled_core`` rotates the token for a slug it cannot find, on
    purpose — it is written for a caller that has already decided a core must
    lose access, and a missing row is not evidence that it has. From a *form*
    that rule is the wrong one: a mistyped or crafted slug would lock out every
    enrolled core and delete nothing, leaving the owner no removed row to
    connect the effect back to. So the route refuses first.

    Asserted on the token, not on the response: the response says something
    reasonable either way, and only the token says whether the destructive half
    actually ran.
    """
    enrol(tmp_path)
    before = ensure_token(tmp_path)
    endpoint = FakeEndpoint(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post(
        "/network-mcp/enrolled/remove", data={"slug": "front-desx"},
    )

    assert response.status_code == 200
    assert ensure_token(tmp_path) == before, "an unknown slug must not rotate"
    assert endpoint.revoked == 0
    assert [c.slug for c in join_module.list_enrolled_cores(state_dir=tmp_path)] == [
        "front-desk",
    ]
    assert "was NOT rotated" in response.text


def test_a_real_slug_still_rotates_so_the_guard_did_not_break_removal(tmp_path):
    """The other half of the guard: it must refuse only what it should.

    With nothing registered as the live endpoint, ``join._revoke_token`` rotates
    the token *file*, which it documents as the whole of what "in force" can
    mean when nothing is serving. The next test covers the other branch.
    """
    enrol(tmp_path)
    before = ensure_token(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    client.post("/network-mcp/enrolled/remove", data={"slug": "front-desk"})

    assert ensure_token(tmp_path) != before, "a real slug must rotate"
    assert join_module.list_enrolled_cores(state_dir=tmp_path) == ()


def test_a_running_endpoint_is_revoked_through_itself_not_through_the_file(
    tmp_path, monkeypatch,
):
    """Rotating the file alone leaves the running listener accepting the old
    value until the next restart, which is the window a removal exists to close."""
    enrol(tmp_path)
    endpoint = FakeEndpoint(tmp_path)
    monkeypatch.setattr(join_module, "_endpoint", endpoint)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post("/network-mcp/enrolled/remove", data={"slug": "front-desk"})

    assert endpoint.revoked == 1
    assert join_module.list_enrolled_cores(state_dir=tmp_path) == ()


def test_an_unknown_slug_does_not_revoke_a_running_endpoint_either(
    tmp_path, monkeypatch,
):
    """Finding 1 on the branch that actually locks a live core out."""
    enrol(tmp_path)
    endpoint = FakeEndpoint(tmp_path)
    monkeypatch.setattr(join_module, "_endpoint", endpoint)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    client.post("/network-mcp/enrolled/remove", data={"slug": "front-desx"})

    assert endpoint.revoked == 0
    assert [c.slug for c in join_module.list_enrolled_cores(state_dir=tmp_path)] == [
        "front-desk",
    ]


def test_an_unexpected_removal_failure_names_the_type_and_not_the_exception(
    tmp_path, monkeypatch,
):
    """Consistent with join_post, deliberately: str(exc) on an httpx error can
    quote the request, and the request carries the body the code was in."""
    enrol(tmp_path)

    def explode(*_args, **_kwargs):
        leaky = f"revocation blew up while holding code={CODE}"
        raise RuntimeError(leaky)

    monkeypatch.setattr(
        "workstation_agent.ui.backend.routers.network_mcp_routes.remove_enrolled_core",
        explode,
    )
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    response = client.post(
        "/network-mcp/enrolled/remove", data={"slug": "front-desk"},
    )

    assert response.status_code == 200
    assert "RuntimeError" in response.text
    assert CODE not in response.text
    assert "blew up" not in response.text


def test_the_remove_button_says_what_it_does(tmp_path):
    """Someone who reads only the button, never the paragraph or the dialog,
    must not be surprised. A bare "Remove" in a row reads as row-scoped."""
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "Remove — locks out every enrolled core</button>" in text
    # The other two warnings stay; the label is an addition, not a replacement.
    assert "Removing any core here locks out every core here" in text
    assert "return confirm(" in text


def test_no_bearer_token_is_offered_anywhere_in_the_enrolment_surface(tmp_path):
    """Join exists so nobody ever handles the token. Nothing on the whole
    page may hand one back out -- the Bearer token panel that used to sit
    above Join is gone, so there is no longer a part of the page this needs
    to carve out and ignore."""
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "t" * 64 not in text
    assert 'name="token"' not in text


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


def test_the_export_flow_is_kept_and_marked_recovery(tmp_path):
    """The owner asked for it to stay, and to stop competing with Join."""
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "Recovery" in text
    assert "/network-mcp/export-registration" in text
    assert text.index('<section id="nm-join">') < text.index('<section id="nm-recovery">')


def test_a_core_refusal_type_is_the_one_the_route_renders_unwrapped():
    """``JoinError`` subclasses ``EnrolmentError``, which is why the route needs
    no second ``except`` for it. Pinned so a future split of the hierarchy shows
    up here rather than as an unhandled 500 in front of the owner."""
    assert issubclass(CoreRefusedError, EnrolmentError)
