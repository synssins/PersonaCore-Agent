"""The owner's side of enrolment: typing a pairing code and pressing Join.

``POST /network-mcp/join`` is the only thing that can open the window
``POST /enrol/token`` answers in, so this file pins two classes of property:

* **The code never leaks.** It is not echoed back into the page on any outcome,
  it is not in the pending-Join state the page renders, and it is not logged.
* **The owner is told plainly when a Join cannot work.** A window opened on a
  stopped endpoint, or one bound to loopback, is a window PersonaCore cannot
  reach; the page says so instead of starting a countdown to nothing.
"""

from __future__ import annotations

import datetime as dt
import logging

import pytest

from tests.unit.ui.conftest import make_client
from workstation_agent.network_mcp.enrolment import EnrolmentError, JoinStatus

CODE = "PAIR-4417"


class _Info:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


class FakeEndpoint:
    """Stands in for NetworkMCPServer's Join surface."""

    def __init__(self, *, error: str | None = None, join: JoinStatus | None = None) -> None:
        self.error = error
        self.join = join
        self.codes: list[str] = []
        self.cancels = 0

    def info(self):
        return _Info(
            url="https://192.168.1.50:8765/mcp",
            bind_host="192.168.1.50",
            port=8765,
            fingerprint="sha256:" + "ab" * 32,
            token="t" * 64,
            certificate_sans=("192.168.1.50",),
            certificate_expires=dt.datetime.now(dt.UTC) + dt.timedelta(days=3650),
            tool_names=("workstation_status",),
            running=True,
        )

    def begin_join(self, code, *, ttl_seconds=300.0):
        self.codes.append(code)
        if self.error is not None:
            raise EnrolmentError(self.error)
        self.join = JoinStatus(
            expires_in=ttl_seconds, opened_at=dt.datetime.now(dt.UTC), attempts=0,
        )
        return self.join

    def cancel_join(self):
        self.cancels += 1
        self.join = None

    def join_status(self):
        return self.join


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))


def test_joining_opens_the_window_and_says_what_happens_next(tmp_path):
    endpoint = FakeEndpoint()
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/join", data={"code": CODE})

    assert response.status_code == 200
    assert endpoint.codes == [CODE]
    assert "Waiting for PersonaCore" in response.text
    assert endpoint.join is not None


def test_the_pairing_code_is_never_echoed_back_into_the_page(tmp_path):
    """A code re-rendered into the form is a code in a screenshot."""
    endpoint = FakeEndpoint()
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    assert CODE not in client.post("/network-mcp/join", data={"code": CODE}).text
    assert CODE not in client.get("/network-mcp").text


def test_the_pairing_code_is_not_echoed_back_when_the_join_is_refused(tmp_path):
    """The failure path is the tempting place to helpfully preserve the field."""
    endpoint = FakeEndpoint(error="The endpoint is not running, so PersonaCore has nowhere.")
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/join", data={"code": CODE})

    assert response.status_code == 200
    assert CODE not in response.text
    assert "not running" in response.text


def test_the_pairing_code_is_never_logged(tmp_path, caplog):
    endpoint = FakeEndpoint()
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    with caplog.at_level(logging.DEBUG):
        client.post("/network-mcp/join", data={"code": CODE})

    assert "enrolment window opened" in caplog.text, (
        "this assertion is what makes the next one mean something: if nothing "
        "were captured, 'the code is absent' would be vacuously true"
    )
    assert CODE not in caplog.text
    assert all(CODE not in str(r.args) for r in caplog.records)


def test_a_refusal_message_from_the_endpoint_is_shown_verbatim(tmp_path):
    message = "The endpoint is bound to 127.0.0.1, which is this machine only."
    endpoint = FakeEndpoint(error=message)
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/join", data={"code": CODE})

    assert "this machine only" in response.text


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


def test_a_missing_code_field_reaches_the_endpoint_as_empty_not_a_422(tmp_path):
    """A 422 JSON body is a dead end in a webview with no way back to the form."""
    endpoint = FakeEndpoint(error="That pairing code is too short to be safe")
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    response = client.post("/network-mcp/join", data={})

    assert response.status_code == 200
    assert "too short" in response.text


def test_a_pending_join_is_shown_without_its_code(tmp_path):
    endpoint = FakeEndpoint(
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
        join=JoinStatus(expires_in=100.0, opened_at=dt.datetime.now(dt.UTC), attempts=7),
    )
    client = make_client(tmp_path=tmp_path, network_mcp=endpoint)

    text = client.get("/network-mcp").text

    assert "7" in text
    assert "trying codes" in text


def test_cancelling_closes_the_window(tmp_path):
    endpoint = FakeEndpoint(
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


def test_the_page_offers_the_join_form_when_no_window_is_open(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=FakeEndpoint())
    text = client.get("/network-mcp").text
    assert 'name="code"' in text
    assert "/network-mcp/join" in text


def test_an_endpoint_whose_join_status_raises_still_renders_the_page(tmp_path):
    class Broken(FakeEndpoint):
        def join_status(self):
            msg = "boom"
            raise RuntimeError(msg)

    client = make_client(tmp_path=tmp_path, network_mcp=Broken())
    response = client.get("/network-mcp")
    assert response.status_code == 200
