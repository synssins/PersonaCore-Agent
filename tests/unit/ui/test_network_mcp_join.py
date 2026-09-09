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

import httpx
import pytest

from tests.unit.ui.conftest import make_client
from workstation_agent.network_mcp import join as join_module
from workstation_agent.network_mcp.enrolment import EnrolmentError, JoinStatus
from workstation_agent.network_mcp.join import CoreRefusedError

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
            url=f"https://{self.bind_hosts[0]}:8765/mcp",
            urls=tuple(f"https://{h}:8765/mcp" for h in self.bind_hosts),
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

    assert "workstation-front-desk" in text
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


def test_an_enrolled_row_shows_the_core_the_name_and_the_plugin(tmp_path):
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert CORE in text
    assert "FRONT-DESK" in text
    assert "workstation-front-desk" in text


def test_an_unconfirmed_row_says_what_is_and_is_not_known(tmp_path):
    """Neither a healthy row nor a failed one: the token landed, the core went quiet."""
    enrol(tmp_path, plugin="", confirmed=False, slug="front-desk")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "PersonaCore never confirmed this one" in text
    assert "is in force" in text
    assert "Plugins screen" in text


def test_an_unconfirmed_rows_plugin_name_is_not_invented(tmp_path):
    """``workstation-<slug>`` is the core's rule. Applying it here would be this
    Agent asserting a name no core ever gave it."""
    enrol(tmp_path, plugin="", confirmed=False, display_name="FRONT-DESK")
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text

    assert "workstation-front-desk" not in text
    assert "Not known" in text
    assert "the name this Agent sent" in text


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


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


def test_no_bearer_token_is_offered_anywhere_in_the_enrolment_surface(tmp_path):
    """Join exists so nobody ever handles the token. Nothing added here may
    hand one back out."""
    enrol(tmp_path)
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint(tmp_path))

    text = client.get("/network-mcp").text
    _, _, after_join = text.partition('<section id="nm-join">')

    assert "t" * 64 not in after_join
    assert 'name="token"' not in after_join


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
