"""The outbound half of enrolment — ``network_mcp/join.py``.

Organised around the four properties the Join has to hold rather than around
the happy path, because three of them are only observable on a failure:

* **A failed Join closes the window it opened.** Every way the outbound call can
  end badly — refused connection, timeout, non-2xx, an answer we cannot read, an
  exception of our own, the task being cancelled — is enumerated here, and each
  asserts the window is shut afterwards. A window left open is an
  unauthenticated route standing open against a short pairing code.
* **The tool list cannot drift from the registration export.** Asserted in both
  directions against the one source both read, because a mismatch between what
  we enrol with and what we serve is a terminal load failure on the core.
* **``risk`` is ``"safe"`` on every serialised tool**, injected here rather than
  read off the served table.
* **The core's refusals arrive verbatim.** Its error strings name the actual
  problem; a reworded one loses the diagnosis. When the answer is not a shape a
  refusal can be read out of, the message says so instead of inventing one.

And one that is observable nowhere except by looking: **the pairing code is
never logged and never put in an exception.**
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from types import SimpleNamespace

import httpx
import pytest

from workstation_agent.network_mcp import join
from workstation_agent.network_mcp.credentials import ensure_token
from workstation_agent.network_mcp.enrolment import EnrolmentError
from workstation_agent.network_mcp.tools import served_tool_names
from workstation_agent.registration_export import CONTRACT_VERSION, agent_version

CODE = "PAIR-7X4Q2"
REFUSED = "connection refused"
SLOW = "read timed out"
FINGERPRINT = "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeEndpoint:
    """The five members of ``JoinEndpoint``, and a record of what was called.

    ``window_open`` is the thing most of this file asserts on: it is set by
    ``begin_join`` and cleared by ``cancel_join``, so a test can ask the one
    question that matters after a failure.
    """

    def __init__(self, state_dir, *, port: int = 8443) -> None:
        self._state_dir = state_dir
        self.port = port
        self.fingerprint = FINGERPRINT
        self.window_open = False
        self.opened: list[str] = []
        self.cancelled = 0
        self.revoked = 0
        self.begin_error: BaseException | None = None
        self.cancel_error: BaseException | None = None
        # Window identity, as the real receiver keeps it: numbered from 1, and
        # the id of the one an accepted push completed kept after it closes.
        self.join_seq = 0
        self.completed_id: int | None = None

    @property
    def state_dir(self):
        return self._state_dir

    def info(self):
        return SimpleNamespace(port=self.port, fingerprint=self.fingerprint)

    def begin_join(self, code):
        if self.begin_error is not None:
            raise self.begin_error
        self.opened.append(code)
        self.window_open = True
        self.join_seq += 1
        return SimpleNamespace(join_id=self.join_seq)

    def cancel_join(self):
        if self.cancel_error is not None:
            raise self.cancel_error
        self.cancelled += 1
        self.window_open = False

    def join_completed(self, join_id):
        return self.completed_id is not None and self.completed_id == join_id

    def push_landed(self):
        """What the receiver does when a push is accepted: consume, remember."""
        self.completed_id = self.join_seq
        self.window_open = False

    def revoke_token(self):
        self.revoked += 1
        return "a-fresh-token"


def accepted(plugin="workstation-front-desk", display_name="FRONT-DESK", state="ok"):
    return {
        "plugin": plugin,
        "display_name": display_name,
        "state": state,
        "message": f"{display_name} joined as {plugin} and is switched on.",
    }


def client_factory(handler):
    """A client factory over ``httpx.MockTransport``, matching ``join._client``.

    The flags matter to what is being tested — ``follow_redirects=False`` in
    particular, since one test asserts a 302 is a refusal and not a hop.
    """

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        )

    return factory


def recording_handler(sink, response):
    """Handler that records the request it saw and answers *response*."""

    def handler(request):
        sink.append(request)
        return response

    return handler


@pytest.fixture(autouse=True)
def _no_registered_endpoint():
    """No test may inherit a registered endpoint from another."""
    join.unregister_endpoint()
    yield
    join.unregister_endpoint()


@pytest.fixture
def endpoint(tmp_path):
    return FakeEndpoint(tmp_path)


# ---------------------------------------------------------------------------
# The request that goes on the wire
# ---------------------------------------------------------------------------


async def test_request_carries_exactly_the_core_s_seven_fields(endpoint):
    """``REQUEST_FIELDS`` is a frozenset core-side: an eighth key is a 400."""
    seen: list[httpx.Request] = []
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        display_name="FRONT-DESK",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    body = json.loads(seen[0].content)
    assert set(body) == {
        "code",
        "display_name",
        "url",
        "tls_fingerprint",
        "agent_version",
        "contract_version",
        "tools",
    }


async def test_request_carries_no_token_field(endpoint):
    """The core mints the token; a request carrying one gets a named refusal."""
    seen: list[httpx.Request] = []
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    body = json.loads(seen[0].content)
    assert not [key for key in body if "token" in key or "secret" in key]


async def test_request_values_are_the_ones_the_core_validates(endpoint):
    seen: list[httpx.Request] = []
    await join.join_core(
        "http://192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        display_name="FRONT-DESK",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    request = seen[0]
    assert str(request.url) == "http://192.168.1.150:8053/enrol/workstation"
    body = json.loads(request.content)
    assert body["code"] == CODE
    assert body["display_name"] == "FRONT-DESK"
    assert body["url"] == "https://192.168.1.50:8443/mcp"
    assert body["tls_fingerprint"] == FINGERPRINT
    assert body["agent_version"] == agent_version()
    assert body["contract_version"] == CONTRACT_VERSION


async def test_the_outbound_leg_is_plaintext_and_unauthenticated(endpoint):
    """No Authorization header, and http unless https was typed explicitly."""
    seen: list[httpx.Request] = []
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    assert seen[0].url.scheme == "http"
    assert "authorization" not in {k.lower() for k in seen[0].headers}


# ---------------------------------------------------------------------------
# Property 2: the tool list cannot drift from the registration export
# ---------------------------------------------------------------------------


def test_tool_names_equal_the_served_set_in_both_directions():
    """Set equality both ways: neither list may gain a tool the other lacks."""
    sent = [entry["name"] for entry in join.tool_entries()]
    served = list(served_tool_names())

    assert not set(sent) - set(served)
    assert not set(served) - set(sent)
    # Ordering and multiplicity too: two lists with the same duplicate compare
    # equal as sets, which is the reason registration_export checks separately.
    assert sent == served


async def test_the_payload_s_tool_names_equal_the_export_s(endpoint):
    """The list on the wire, not merely the list the helper builds."""
    seen: list[httpx.Request] = []
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    body = json.loads(seen[0].content)
    assert [entry["name"] for entry in body["tools"]] == list(served_tool_names())


def test_the_tool_list_is_a_list_of_objects_within_the_core_s_bounds():
    entries = join.tool_entries()
    assert isinstance(entries, list)
    assert all(isinstance(entry, dict) for entry in entries)
    assert 1 <= len(entries) <= 200


# ---------------------------------------------------------------------------
# Property 3: risk is injected at serialisation
# ---------------------------------------------------------------------------


def test_every_serialised_tool_carries_risk_safe():
    """``ACCEPTED_RISK`` core-side is ``{"safe"}`` and nothing else."""
    assert join.TOOL_RISK == "safe"
    assert all(entry["risk"] == "safe" for entry in join.tool_entries())
    assert all(set(entry) == {"name", "risk"} for entry in join.tool_entries())


async def test_risk_is_safe_on_the_wire_too(endpoint):
    seen: list[httpx.Request] = []
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(
            recording_handler(seen, httpx.Response(201, json=accepted())),
        ),
    )

    body = json.loads(seen[0].content)
    assert body["tools"]
    assert all(entry["risk"] == "safe" for entry in body["tools"])


def test_risk_is_not_read_off_the_served_table(monkeypatch):
    """A served table that grew a different risk must not change the wire.

    The field says what the *core* accepts, not what the Agent thinks of the
    tool; the two coincide today and the injection is what keeps a change to one
    from silently becoming a change to the other.
    """
    from workstation_agent.network_mcp import tools as tools_module

    changed = tuple(
        SimpleNamespace(name=tool.name, risk="confirm") for tool in tools_module.SERVED_TOOLS
    )
    monkeypatch.setattr(tools_module, "SERVED_TOOLS", changed)
    assert all(entry["risk"] == "safe" for entry in join.tool_entries())


# ---------------------------------------------------------------------------
# Property 1: a failed Join closes the window it opened
# ---------------------------------------------------------------------------


async def test_the_window_is_open_while_the_request_is_in_flight(endpoint):
    """The core pushes before our POST returns, so it must already be open."""
    observed: list[bool] = []

    def handler(_request):
        observed.append(endpoint.window_open)
        return httpx.Response(201, json=accepted())

    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(handler),
    )

    assert observed == [True]


async def test_a_successful_join_does_not_cancel_the_window(endpoint):
    """The push already consumed it; cancelling would be noise, not safety."""
    await join.join_core(
        "192.168.1.150:8053",
        CODE,
        "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(
            lambda _r: httpx.Response(201, json=accepted()),
        ),
    )
    assert endpoint.cancelled == 0


async def test_a_connection_failure_closes_the_window(endpoint):
    def handler(request):
        raise httpx.ConnectError(REFUSED, request=request)

    with pytest.raises(join.CoreUnreachableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint, client_factory=client_factory(handler),
        )

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


async def test_a_timeout_closes_the_window(endpoint):
    def handler(request):
        raise httpx.ReadTimeout(SLOW, request=request)

    with pytest.raises(join.CoreUnreachableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint, client_factory=client_factory(handler),
        )

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


@pytest.mark.parametrize("status", [400, 403, 409, 413, 429, 500, 502])
async def test_a_non_2xx_closes_the_window(endpoint, status):
    with pytest.raises(join.CoreRefusedError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(status, json={"detail": {"error": "no"}}),
            ),
        )

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


async def test_a_redirect_is_a_refusal_and_closes_the_window(endpoint):
    """3xx is not 2xx and is not followed: the body carries a live code."""
    with pytest.raises(join.CoreRefusedError) as caught:
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(302, headers={"location": "http://elsewhere/x"}),
            ),
        )

    assert caught.value.status_code == 302
    assert endpoint.window_open is False


@pytest.mark.parametrize(
    "body",
    [
        b"not json at all",
        b"[]",
        b'{"plugin": 7}',
        b'{"display_name": "FRONT-DESK"}',
        b'{"plugin": "", "display_name": "x"}',
    ],
)
async def test_an_unreadable_success_closes_the_window(endpoint, body):
    with pytest.raises(join.CoreAnswerUnreadableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(lambda _r: httpx.Response(201, content=body)),
        )

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


async def test_an_exception_of_our_own_closes_the_window(endpoint):
    """Not only the failures we enumerated — anything at all past the open."""

    def factory():
        msg = "the client could not be built"
        raise RuntimeError(msg)

    with pytest.raises(RuntimeError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint, client_factory=factory,
        )

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


async def test_cancelling_the_join_closes_the_window(endpoint):
    """A UI that abandons the Join must not leave the route standing open."""
    started = asyncio.Event()

    def factory():
        class Blocking(httpx.AsyncClient):
            async def __aenter__(self) -> httpx.AsyncClient:
                started.set()
                await asyncio.sleep(30)
                return self  # pragma: no cover — the test cancels first

        return Blocking()

    task = asyncio.create_task(
        join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint, client_factory=factory,
        ),
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert endpoint.window_open is False
    assert endpoint.cancelled == 1


async def test_a_cancel_that_itself_fails_does_not_replace_the_reason(endpoint, caplog):
    """Cleanup must not swallow, or become, the failure being reported."""

    def exploding_cancel():
        msg = "the window could not be closed"
        raise RuntimeError(msg)

    endpoint.cancel_join = exploding_cancel

    with caplog.at_level(logging.ERROR), pytest.raises(join.CoreRefusedError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(400, json={"detail": {"error": "no"}}),
            ),
        )


async def test_nothing_that_fails_before_the_window_opens_leaves_one(endpoint):
    """Every address check happens above the open, so there is nothing to close."""
    for bad in ("", "   ", "ftp://core", "http://user:pw@core"):
        with pytest.raises(EnrolmentError):
            await join.join_core(bad, CODE, "192.168.1.50", endpoint=endpoint)
    assert endpoint.opened == []
    assert endpoint.cancelled == 0


async def test_a_receiver_that_refuses_the_code_opens_nothing(endpoint):
    """``begin_join`` validates the code and the endpoint's reachability."""
    endpoint.begin_error = EnrolmentError("That pairing code is too short to be safe")

    with pytest.raises(EnrolmentError, match="too short"):
        await join.join_core("192.168.1.150:8053", "x", "192.168.1.50", endpoint=endpoint)

    assert endpoint.cancelled == 0


# ---------------------------------------------------------------------------
# Property 4: the core's refusals arrive verbatim
# ---------------------------------------------------------------------------

COLLISION = (
    "A workstation is already enrolled as 'workstation-front-desk', so FRONT-DESK "
    "cannot join under that name. Remove the old one from the Plugins screen "
    "first, or rename this machine and try again."
)
NO_LETTERS = (
    "'---' has no letters or digits in it, so there is no name to give this "
    "workstation. Rename the machine and try again."
)
TOO_LONG = "That address is too long to be a workstation address."


@pytest.mark.parametrize("sentence", [COLLISION, NO_LETTERS, TOO_LONG])
async def test_the_core_s_sentence_is_what_the_operator_sees(endpoint, sentence):
    """Not paraphrased, not wrapped, not prefixed. The diagnosis is the wording."""
    with pytest.raises(join.CoreRefusedError) as caught:
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(
                    409, json={"detail": {"error": sentence, "problems": []}},
                ),
            ),
        )

    assert str(caught.value) == sentence
    assert caught.value.reason == sentence
    assert caught.value.status_code == 409


async def test_a_bare_detail_string_is_read_too(endpoint):
    """FastAPI's own errors — a 404 from a core too old to have the route."""
    with pytest.raises(join.CoreRefusedError) as caught:
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(404, json={"detail": "Not Found"}),
            ),
        )

    assert str(caught.value) == "Not Found"


@pytest.mark.parametrize(
    "body",
    [b"<html>502 Bad Gateway</html>", b"{}", b'{"detail": {}}', b'{"detail": []}', b""],
)
async def test_an_unreadable_refusal_says_so_rather_than_inventing_one(endpoint, body):
    with pytest.raises(join.CoreRefusedError) as caught:
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(lambda _r: httpx.Response(502, content=body)),
        )

    assert caught.value.reason is None
    assert caught.value.status_code == 502
    assert "not in the shape this Agent understands" in str(caught.value)


def test_every_join_failure_is_catchable_as_one_error():
    """``JoinError`` subclasses ``EnrolmentError`` so the UI has one clause."""
    assert issubclass(join.JoinError, EnrolmentError)
    for cls in (join.CoreUnreachableError, join.CoreRefusedError, join.CoreAnswerUnreadableError):
        assert issubclass(cls, join.JoinError)


# ---------------------------------------------------------------------------
# The pairing code is a short-lived secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(201, json=accepted()),
        httpx.Response(403, json={"detail": {"error": "That pairing code is not valid."}}),
        httpx.Response(500, content=b"boom"),
    ],
)
async def test_the_pairing_code_never_reaches_a_log_line(endpoint, caplog, response):
    with caplog.at_level(logging.DEBUG), contextlib.suppress(EnrolmentError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(lambda _r: response),
        )

    assert CODE not in caplog.text


async def test_the_pairing_code_never_reaches_an_exception(endpoint):
    """Including through ``__cause__``: an httpx request holds the body."""

    def handler(request):
        raise httpx.ConnectError(REFUSED, request=request)

    with pytest.raises(join.CoreUnreachableError) as caught:
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint, client_factory=client_factory(handler),
        )

    assert CODE not in str(caught.value)
    # Neither link of the chain. ``from None`` alone would leave __context__
    # holding the httpx error, and that error holds the request, and the
    # request holds the body the code was sent in.
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


async def test_the_core_s_answer_is_bounded_before_it_is_parsed(endpoint):
    """The reply comes from an address an unauthenticated stranger may answer on."""
    flood = b"a" * (join.MAX_RESPONSE_BYTES * 3)

    with pytest.raises(join.CoreAnswerUnreadableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(lambda _r: httpx.Response(201, content=flood)),
        )

    assert endpoint.window_open is False


# ---------------------------------------------------------------------------
# Address handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("192.168.1.150", "http://192.168.1.150/enrol/workstation"),
        ("192.168.1.150:8053", "http://192.168.1.150:8053/enrol/workstation"),
        ("  core.local:8053  ", "http://core.local:8053/enrol/workstation"),
        ("http://core.local:8053/", "http://core.local:8053/enrol/workstation"),
        ("http://core.local:8053/admin", "http://core.local:8053/enrol/workstation"),
        ("https://core.example:443", "https://core.example:443/enrol/workstation"),
        ("[fd00::1]:8053", "http://[fd00::1]:8053/enrol/workstation"),
    ],
)
def test_core_addresses_the_operator_might_type(typed, expected):
    assert join.core_enrol_url(typed) == expected


@pytest.mark.parametrize("typed", ["", "  ", "ftp://core", "http://user:pw@core", "http://"])
def test_core_addresses_that_are_not_addresses(typed):
    with pytest.raises(EnrolmentError):
        join.core_enrol_url(typed)


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("192.168.1.50", "https://192.168.1.50:8443/mcp"),
        ("192.168.1.50:9999", "https://192.168.1.50:9999/mcp"),
        ("desk.lan", "https://desk.lan:8443/mcp"),
        ("fd00::5", "https://[fd00::5]:8443/mcp"),
        ("[fd00::5]:9999", "https://[fd00::5]:9999/mcp"),
        ("https://desk.lan:9999/mcp", "https://desk.lan:9999/mcp"),
    ],
)
def test_listen_addresses_the_operator_might_pick(typed, expected):
    assert join.listen_url(typed, default_port=8443) == expected


def test_loopback_is_left_for_the_core_and_the_receiver_to_refuse():
    """Not refused here: two other places already say it in better words."""
    assert join.listen_url("127.0.0.1", default_port=8443) == "https://127.0.0.1:8443/mcp"


def test_a_listen_address_that_is_not_one():
    with pytest.raises(EnrolmentError):
        join.listen_url("   ", default_port=8443)


def test_the_display_name_defaults_to_the_machine_and_keeps_its_case(monkeypatch):
    monkeypatch.setattr(join.socket, "gethostname", lambda: "  FRONT   DESK  ")
    assert join.default_display_name() == "FRONT DESK"


# ---------------------------------------------------------------------------
# The registered endpoint
# ---------------------------------------------------------------------------


async def test_with_no_endpoint_running_the_join_says_so():
    with pytest.raises(EnrolmentError, match="not running"):
        await join.join_core("192.168.1.150:8053", CODE, "192.168.1.50")


async def test_the_registered_endpoint_is_used_when_none_is_passed(endpoint):
    join.register_endpoint(endpoint)
    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )
    assert endpoint.opened == [CODE]


def test_unregistering_a_stale_endpoint_leaves_the_current_one(tmp_path):
    """A stop() racing a start() must not unregister its replacement."""
    old, new = FakeEndpoint(tmp_path), FakeEndpoint(tmp_path)
    join.register_endpoint(old)
    join.register_endpoint(new)
    join.unregister_endpoint(old)
    assert join._resolve_endpoint(None) is new


# ---------------------------------------------------------------------------
# The listing, and what removal has to mean
# ---------------------------------------------------------------------------


async def test_a_completed_join_is_recorded(endpoint, tmp_path):
    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )

    rows = join.list_enrolled_cores(state_dir=tmp_path)
    assert len(rows) == 1
    assert rows[0].slug == "front-desk"
    assert rows[0].plugin == "workstation-front-desk"
    assert rows[0].display_name == "FRONT-DESK"
    assert rows[0].core_address == "192.168.1.150:8053"
    assert rows[0].joined_at.tzinfo is not None


async def test_re_joining_replaces_the_row_rather_than_adding_one(endpoint, tmp_path):
    for _ in range(3):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
        )

    assert len(join.list_enrolled_cores(state_dir=tmp_path)) == 1


async def test_a_failed_join_records_nothing(endpoint, tmp_path):
    with pytest.raises(join.CoreRefusedError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(403, json={"detail": {"error": "nope"}}),
            ),
        )

    assert join.list_enrolled_cores(state_dir=tmp_path) == ()


def test_an_absent_or_broken_listing_reads_as_empty(tmp_path):
    assert join.list_enrolled_cores(state_dir=tmp_path) == ()
    (tmp_path / "enrolled.json").write_bytes(b"{ not json")
    assert join.list_enrolled_cores(state_dir=tmp_path) == ()
    (tmp_path / "enrolled.json").write_text('{"version": 1, "cores": "nope"}')
    assert join.list_enrolled_cores(state_dir=tmp_path) == ()


def test_half_a_row_is_not_a_row(tmp_path):
    (tmp_path / "enrolled.json").write_text(
        json.dumps({
            "version": 1,
            "cores": [
                {"plugin": "workstation-a", "display_name": "A", "core_address": "x",
                 "joined_at": "2026-09-09T00:00:00+00:00"},
                {"display_name": "B"},
                "not a row",
                {"plugin": "workstation-c", "display_name": "C", "core_address": "y",
                 "joined_at": "nonsense"},
            ],
        }),
    )
    rows = join.list_enrolled_cores(state_dir=tmp_path)
    assert [row.plugin for row in rows] == ["workstation-a", "workstation-c"]
    assert all(row.joined_at.tzinfo is not None for row in rows)


async def test_removal_drops_the_row_and_revokes_the_token(endpoint, tmp_path):
    """Hiding a row would leave a core holding a working credential."""
    join.register_endpoint(endpoint)
    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )

    join.remove_enrolled_core("front-desk", state_dir=tmp_path)

    assert join.list_enrolled_cores(state_dir=tmp_path) == ()
    assert endpoint.revoked == 1


def test_removal_with_no_endpoint_running_still_rotates_the_token(tmp_path):
    """Nothing is serving, so the file is the whole of what 'in force' means."""
    before = ensure_token(tmp_path)
    join.remove_enrolled_core("front-desk", state_dir=tmp_path)
    assert ensure_token(tmp_path) != before


def test_removing_a_slug_that_is_not_listed_still_revokes(tmp_path):
    """Remove was pressed because a core must lose access; a missing row is not
    evidence that it has."""
    before = ensure_token(tmp_path)
    join.remove_enrolled_core("never-enrolled", state_dir=tmp_path)
    assert ensure_token(tmp_path) != before


def test_removal_keeps_the_other_rows_listed(tmp_path):
    (tmp_path / "enrolled.json").write_text(
        json.dumps({
            "version": 1,
            "cores": [
                {"slug": "a", "plugin": "workstation-a", "display_name": "A",
                 "core_address": "x", "joined_at": "2026-09-09T00:00:00+00:00"},
                {"slug": "b", "plugin": "workstation-b", "display_name": "B",
                 "core_address": "y", "joined_at": "2026-09-09T00:00:00+00:00"},
            ],
        }),
    )
    join.remove_enrolled_core("a", state_dir=tmp_path)
    assert [row.slug for row in join.list_enrolled_cores(state_dir=tmp_path)] == ["b"]


@pytest.mark.parametrize(
    ("plugin", "slug"),
    [
        ("workstation-front-desk", "front-desk"),
        ("WORKSTATION-FRONT-DESK", "front-desk"),
        ("something-else", "something-else"),
    ],
)
def test_the_slug_is_recovered_from_the_plugin_name(plugin, slug):
    assert join.slug_of(plugin) == slug


def test_a_listing_that_cannot_be_saved_still_locks_the_core_out(tmp_path, monkeypatch, endpoint):
    """Order is the safety property: revoke first, bookkeeping second.

    The other way round, a failed write would abort before the revocation and
    leave a core that is gone from the page still holding a working credential.
    """
    join.register_endpoint(endpoint)

    def refuse(_directory, _cores):
        msg = "The list of enrolled cores could not be saved"
        raise EnrolmentError(msg)

    monkeypatch.setattr(join, "_write_enrolled", refuse)

    with pytest.raises(EnrolmentError, match="could not be saved"):
        join.remove_enrolled_core("front-desk", state_dir=tmp_path)

    assert endpoint.revoked == 1


# ---------------------------------------------------------------------------
# The window open is inside the guarded region
# ---------------------------------------------------------------------------


async def test_a_begin_join_that_fails_cancels_nothing(endpoint):
    """It opened no window, and the one it must not close may be someone else's.

    ``POST /network-mcp/join`` can open a window without going through here. A
    blanket cancel on our own failure would shut theirs.
    """
    endpoint.begin_error = EnrolmentError("That pairing code is too short to be safe")

    with pytest.raises(EnrolmentError, match="too short"):
        await join.join_core("192.168.1.150:8053", "x", "192.168.1.50", endpoint=endpoint)

    assert endpoint.cancelled == 0


async def test_the_window_open_is_inside_the_guarded_region(endpoint):
    """Anything raised at or after the open must still reach the ``finally``."""
    endpoint.begin_error = RuntimeError("the receiver exploded")

    with pytest.raises(RuntimeError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50", endpoint=endpoint,
        )

    assert endpoint.window_open is False
    # Nothing opened, so nothing to close -- and cancelling anyway would be
    # reaching for a window this call does not own.
    assert endpoint.cancelled == 0


# ---------------------------------------------------------------------------
# Cleanup survives the interruptions that are not Exceptions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("interruption", [asyncio.CancelledError(), KeyboardInterrupt()])
async def test_an_interrupted_cleanup_does_not_escape_or_mask(endpoint, caplog, interruption):
    """``CancelledError`` and ``KeyboardInterrupt`` are not ``Exception``.

    An ``except Exception`` in the cleanup would let either through, replacing
    the reason the Join failed with the reason the cleanup did -- and leaving
    the window open, which is both of the things the cleanup exists to prevent.
    """
    endpoint.cancel_error = interruption

    with caplog.at_level(logging.ERROR), pytest.raises(join.CoreRefusedError, match="no"):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(400, json={"detail": {"error": "no"}}),
            ),
        )


# ---------------------------------------------------------------------------
# One Join at a time
# ---------------------------------------------------------------------------


async def test_a_second_concurrent_join_is_refused_not_queued(endpoint):
    """The race that closes the winner's window, refused at the door.

    Without this, the second ``begin_join`` replaces the first window and the
    first failure to finish cancels it for both -- so the core's push lands on
    a shut door and the Join that was working fails inexplicably.
    """
    release = asyncio.Event()
    second: list[BaseException] = []

    async def handler(_request):
        # The first Join is now in flight and holding the guard.
        try:
            await join.join_core(
                "192.168.1.150:8053", "OTHER-CODE", "192.168.1.50", endpoint=endpoint,
            )
        except BaseException as exc:  # noqa: BLE001 — recorded, then asserted on
            second.append(exc)
        release.set()
        return httpx.Response(201, json=accepted())

    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint, client_factory=client_factory(handler),
    )

    assert release.is_set()
    assert len(second) == 1
    assert "already in progress" in str(second[0])
    # The refused one opened nothing and closed nothing: the first Join's
    # window is untouched, which is the entire point.
    assert endpoint.opened == [CODE]
    assert endpoint.cancelled == 0


async def test_the_guard_is_released_after_a_failed_join(endpoint):
    """A guard that leaked would lock the owner out for the process's life."""
    with pytest.raises(join.CoreUnreachableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda r: (_ for _ in ()).throw(httpx.ConnectError(REFUSED, request=r)),
            ),
        )

    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )
    assert endpoint.opened == [CODE, CODE]


async def test_the_guard_is_released_after_a_refusal_before_the_window(endpoint):
    with pytest.raises(EnrolmentError):
        await join.join_core("", CODE, "192.168.1.50", endpoint=endpoint)

    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )
    assert endpoint.opened == [CODE]


# ---------------------------------------------------------------------------
# A Join whose answer never arrives, but whose token did
# ---------------------------------------------------------------------------


def _lost_answer(endpoint, error):
    """A core that pushes (so our receiver completes) and then never answers."""

    def handler(request):
        endpoint.push_landed()
        raise error(SLOW, request=request)

    return client_factory(handler)


async def test_a_timeout_after_the_push_landed_is_a_success(endpoint, tmp_path):
    """The network cannot say what happened; this process can.

    The push arrives at our own receiver, so a token held for *this* window is
    proof the core minted and handed one over. Reporting a failure for that
    would send the owner to burn a fresh code on an enrolment that worked.
    """
    result = await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        display_name="FRONT-DESK",
        endpoint=endpoint,
        client_factory=_lost_answer(endpoint, httpx.ReadTimeout),
    )

    assert result.confirmed is False
    assert result.display_name == "FRONT-DESK"
    # Never guessed: workstation-<slug> is the core's to derive.
    assert result.plugin == ""
    assert result.state == "unknown"

    rows = join.list_enrolled_cores(state_dir=tmp_path)
    assert [(r.slug, r.confirmed, r.plugin) for r in rows] == [("front-desk", False, "")]


async def test_a_dropped_connection_after_the_push_landed_is_a_success(endpoint):
    """Not only timeouts: any answerless failure asks the same question."""
    result = await join.join_and_report(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=_lost_answer(endpoint, httpx.RemoteProtocolError),
    )
    assert result.confirmed is False


async def test_a_timeout_with_no_push_is_still_a_failure(endpoint, tmp_path):
    with pytest.raises(join.CoreUnreachableError):
        await join.join_and_report(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda r: (_ for _ in ()).throw(httpx.ReadTimeout(SLOW, request=r)),
            ),
        )

    assert endpoint.window_open is False
    assert join.list_enrolled_cores(state_dir=tmp_path) == ()


async def test_an_earlier_join_s_token_is_not_read_as_this_one_s(endpoint):
    """Asked by window id precisely so this cannot happen.

    A previous Join completed and its id is still recorded. This Join opens a
    *new* window and times out with nothing pushed into it; a receiver that
    answered "did anything ever complete?" would call that a success.
    """
    endpoint.join_seq = 4
    endpoint.completed_id = 4  # an earlier, genuinely completed Join

    with pytest.raises(join.CoreUnreachableError):
        await join.join_and_report(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda r: (_ for _ in ()).throw(httpx.ReadTimeout(SLOW, request=r)),
            ),
        )


async def test_a_refusal_is_never_recovered_from(endpoint):
    """The core answered. Its sentence is authoritative and is what is shown."""
    endpoint.push_landed()

    with pytest.raises(join.CoreRefusedError) as caught:
        await join.join_and_report(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(500, json={"detail": {"error": TOO_LONG}}),
            ),
        )

    assert str(caught.value) == TOO_LONG


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("FRONT-DESK", "front-desk"),
        ("Front Desk 2", "front-desk-2"),
        ("  a..b  ", "a-b"),
        ("---", "unconfirmed"),
        ("", "unconfirmed"),
    ],
)
def test_a_row_handle_is_built_locally_when_the_core_never_named_one(name, slug):
    assert join._local_slug(name) == slug


def test_an_unconfirmed_row_survives_a_round_trip(tmp_path):
    (tmp_path / "enrolled.json").write_text(
        json.dumps({
            "version": 1,
            "cores": [{
                "slug": "front-desk", "plugin": "", "display_name": "FRONT-DESK",
                "core_address": "192.168.1.150:8053",
                "joined_at": "2026-09-09T00:00:00+00:00", "confirmed": False,
            }],
        }),
    )
    rows = join.list_enrolled_cores(state_dir=tmp_path)
    assert [(r.slug, r.plugin, r.confirmed) for r in rows] == [("front-desk", "", False)]


def test_a_row_written_before_there_was_a_confirmed_column_reads_as_confirmed(tmp_path):
    (tmp_path / "enrolled.json").write_text(
        json.dumps({
            "version": 1,
            "cores": [{
                "plugin": "workstation-front-desk", "display_name": "FRONT-DESK",
                "core_address": "x", "joined_at": "2026-09-09T00:00:00+00:00",
            }],
        }),
    )
    assert join.list_enrolled_cores(state_dir=tmp_path)[0].confirmed is True


async def test_the_guard_is_released_when_the_window_never_opened(endpoint):
    """A guard set and then leaked is the least recoverable state in the module.

    It is set one line above the ``try``, so anything raised between the two
    would keep it set for the life of the process and refuse every later Join
    with "a Join is already in progress" -- with nothing the owner can do about
    it short of restarting the Agent. This drives that region through the
    reachable failure in it: ``begin_join`` itself raising.
    """
    endpoint.begin_error = RuntimeError("the receiver exploded")

    with pytest.raises(RuntimeError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50", endpoint=endpoint,
        )

    # The guard is clear, so the next Join runs rather than being refused.
    endpoint.begin_error = None
    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )
    assert endpoint.opened == [CODE]


def _spy_on_the_request_body(monkeypatch):
    """Capture the dict ``_post_join`` is handed -- the object, not a copy.

    Asserting on ``join_and_report``'s own local would pass against a scrub that
    only rebinds a name, which is exactly the bug this guards: ``_post_join``
    holds the *same* dict, and rebinding in the caller leaves the code sitting
    in the object that frame still references.
    """
    seen: list[dict] = []
    real = join._post_join

    async def spy(enrol_url, body, *, client_factory):
        seen.append(body)
        return await real(enrol_url, body, client_factory=client_factory)

    monkeypatch.setattr(join, "_post_join", spy)
    return seen


async def test_the_code_is_gone_from_the_dict_the_callee_holds_after_a_failure(
    endpoint, monkeypatch,
):
    seen = _spy_on_the_request_body(monkeypatch)

    with pytest.raises(join.CoreRefusedError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda _r: httpx.Response(403, json={"detail": {"error": "nope"}}),
            ),
        )

    assert len(seen) == 1
    assert seen[0] == {}


async def test_the_code_is_gone_from_the_dict_the_callee_holds_after_a_success(
    endpoint, monkeypatch,
):
    seen = _spy_on_the_request_body(monkeypatch)

    await join.join_core(
        "192.168.1.150:8053", CODE, "192.168.1.50",
        endpoint=endpoint,
        client_factory=client_factory(lambda _r: httpx.Response(201, json=accepted())),
    )

    assert seen[0] == {}


async def test_the_code_is_gone_after_a_transport_failure(endpoint, monkeypatch):
    """The path where the callee's frame is most likely to be in a traceback."""
    seen = _spy_on_the_request_body(monkeypatch)

    with pytest.raises(join.CoreUnreachableError):
        await join.join_core(
            "192.168.1.150:8053", CODE, "192.168.1.50",
            endpoint=endpoint,
            client_factory=client_factory(
                lambda r: (_ for _ in ()).throw(httpx.ConnectError(REFUSED, request=r)),
            ),
        )

    assert seen[0] == {}
