"""Subtask P13 -- choosing a *set* of addresses from the page, and the SAN gate.

Two things are pinned here, and only one of them is about the HTML.

The first is that the interface control is a multi-select and that what it posts
becomes the endpoint's address set, preferred address first.

The second is the one the owner asked to be *proved*: an address the
certificate does not cover must not be reachable by clicking. The greyed-out
option is the convenience half; a ``disabled`` attribute stops a mouse and
nothing else. So the tests below bypass the page entirely -- posting the field
directly, exactly as a crafted request or a stale form would -- and assert the
router refuses anyway. The third layer, the endpoint's own refusal to bind an
uncovered address, is proved against real sockets in
``tests/integration/test_network_mcp_multi_bind.py``.
"""

from __future__ import annotations

import pytest

from tests.unit.ui.conftest import FakeConfigStore, make_client
from tests.unit.ui.test_network_mcp_endpoint_ui import Factory
from workstation_agent.ui.backend.routers import network_mcp_routes


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))


def _client(tmp_path, store=None, **factory_kwargs):
    store = store or FakeConfigStore()
    factory = Factory(**factory_kwargs)
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )
    return client, store, factory


# ---------------------------------------------------------------------------
# The multi-select really produces a set
# ---------------------------------------------------------------------------


def test_selecting_several_addresses_saves_all_of_them_preferred_first(tmp_path):
    client, store, factory = _client(
        tmp_path, sans=("192.168.1.50", "10.0.0.7", "127.0.0.1"),
    )

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765",
              "bind_hosts": ["192.168.1.50", "10.0.0.7", "127.0.0.1"]},
    )

    assert resp.status_code == 200
    saved = store.load().network_mcp
    assert saved.bind_host == "192.168.1.50"
    assert saved.additional_bind_hosts == ["10.0.0.7", "127.0.0.1"]
    assert saved.bind_hosts == ("192.168.1.50", "10.0.0.7", "127.0.0.1")
    assert factory.last.config.bind_hosts == saved.bind_hosts
    assert factory.last.start_calls == 1


def test_the_page_renders_a_multi_select_with_the_saved_set_marked(tmp_path):
    client, _store, _factory = _client(
        tmp_path, sans=("192.168.1.50", "10.0.0.7", "127.0.0.1"),
    )
    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    page = client.get("/network-mcp").text

    assert 'name="bind_hosts" multiple' in page
    for host in ("192.168.1.50", "10.0.0.7"):
        assert host in page
    assert "https://192.168.1.50:8765/mcp" in page
    assert "https://10.0.0.7:8765/mcp" in page


def test_the_old_single_select_field_is_still_honoured(tmp_path):
    """The export flow and anything bookmarked still post ``bind_host_choice``;
    silently ignoring it would look like a save that did nothing."""
    client, store, _factory = _client(tmp_path)

    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_host_choice": "192.168.1.50"},
    )

    assert store.load().network_mcp.bind_hosts == ("192.168.1.50",)


def test_a_typed_other_address_joins_the_selected_set(tmp_path):
    client, store, _factory = _client(
        tmp_path, sans=("192.168.1.50", "10.9.9.9"),
    )

    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765",
              "bind_hosts": ["192.168.1.50", network_mcp_routes._OTHER],
              "bind_host_other": "10.9.9.9"},
    )

    assert store.load().network_mcp.bind_hosts == ("192.168.1.50", "10.9.9.9")


def test_selecting_nothing_is_a_message_next_to_the_field_not_a_422(tmp_path):
    client, store, factory = _client(tmp_path)

    resp = client.post("/network-mcp/settings", data={"enabled": "true", "port": "8765"})

    assert resp.status_code == 200
    assert "Choose the interface to bind" in resp.text
    assert store.load().network_mcp.enabled is False
    assert factory.built == []


def test_a_set_that_includes_a_lan_address_is_not_called_loopback_only(tmp_path):
    client, _store, _factory = _client(
        tmp_path, sans=("192.168.1.50", "127.0.0.1"),
    )

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "127.0.0.1"]},
    )

    assert "Every address selected is a loopback address" not in resp.text


# ---------------------------------------------------------------------------
# The bad state is unreachable: an address outside the SAN
# ---------------------------------------------------------------------------


def test_an_uncovered_address_is_rendered_unselectable(tmp_path, monkeypatch):
    """The convenience half of the rule: it cannot be clicked."""
    monkeypatch.setattr(
        "workstation_agent.network_mcp.certs.local_identities",
        lambda: (["workstation"], ["192.168.1.50", "10.0.0.7", "127.0.0.1"]),
    )
    client, _store, _factory = _client(tmp_path, sans=("192.168.1.50", "127.0.0.1"))
    # Give the page an endpoint to read a certificate from.
    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50"]},
    )

    page = client.get("/network-mcp").text

    assert '<option value="10.0.0.7"' in page
    uncovered_option = page.split('<option value="10.0.0.7"', 1)[1].split(">", 1)[0]
    assert "disabled" in uncovered_option
    covered_option = page.split('<option value="192.168.1.50"', 1)[1].split(">", 1)[0]
    assert "disabled" not in covered_option


def test_posting_an_uncovered_address_directly_is_refused(tmp_path):
    """The half that actually holds. No page, no disabled attribute -- just the
    field, posted, exactly as a crafted request or a stale form would."""
    client, store, factory = _client(tmp_path, sans=("192.168.1.50", "127.0.0.1"))

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["10.0.0.7"]},
    )

    assert resp.status_code == 200
    assert "does not cover 10.0.0.7" in resp.text
    # Nothing saved...
    assert store.load().network_mcp.bind_hosts == ("127.0.0.1",)
    assert store.load().network_mcp.enabled is False
    # ...and nothing started.
    assert all(e.start_calls == 0 for e in factory.built)


def test_one_uncovered_address_refuses_the_whole_selection(tmp_path):
    """Saving the two that are covered and dropping the third silently would be
    a save that did something other than what was asked."""
    client, store, _factory = _client(tmp_path, sans=("192.168.1.50", "127.0.0.1"))

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765",
              "bind_hosts": ["192.168.1.50", "10.0.0.7", "127.0.0.1"]},
    )

    assert "does not cover 10.0.0.7" in resp.text
    assert store.load().network_mcp.bind_hosts == ("127.0.0.1",)


def test_the_refusal_offers_the_regenerate_flow_with_its_cost_stated(tmp_path):
    client, _store, _factory = _client(tmp_path, sans=("192.168.1.50",))

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["10.0.0.7"]},
    )

    assert "Regenerate Certificate for this address" in resp.text
    assert "changes the fingerprint" in resp.text
    assert "re-exported" in resp.text
    # The offer re-posts the selection that was refused, not the stored one.
    assert 'name="regenerate" value="true"' in resp.text
    assert 'name="bind_hosts" value="10.0.0.7"' in resp.text


def test_regenerating_covers_the_pending_selection_and_then_saves(tmp_path):
    client, store, factory = _client(tmp_path, sans=("192.168.1.50",))

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "regenerate": "true",
              "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    assert "does not cover" not in resp.text
    assert store.load().network_mcp.bind_hosts == ("192.168.1.50", "10.0.0.7")
    assert set(factory.cert["sans"]) == {"192.168.1.50", "10.0.0.7"}


def test_an_address_no_certificate_can_cover_is_refused_even_after_regenerating(tmp_path):
    """A machine cannot certify an address it does not have. Rotating the
    fingerprint and binding anyway would be the worst of both."""

    store = FakeConfigStore()
    # ``regenerate_sans`` fixed: whatever is asked for, the machine can only
    # certify what it has, exactly as ``local_identities`` can only report
    # addresses that exist.
    factory = Factory(sans=("192.168.1.50",), regenerate_sans=("192.168.1.50",))
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "regenerate": "true",
              "bind_hosts": ["203.0.113.9"]},
    )

    assert "still does not cover" in resp.text
    assert store.load().network_mcp.bind_hosts == ("127.0.0.1",)
    assert all(e.start_calls == 0 for e in factory.built)


def test_a_selection_saved_with_the_endpoint_off_is_not_gated(tmp_path):
    """Switching it off binds nothing, so there is nothing to refuse -- and the
    endpoint's own refusal still stands whenever it is switched back on."""
    client, store, _factory = _client(tmp_path, sans=("192.168.1.50",))

    client.post("/network-mcp/settings", data={"port": "8765", "bind_hosts": ["10.0.0.7"]})

    assert store.load().network_mcp.bind_hosts == ("10.0.0.7",)
    assert store.load().network_mcp.enabled is False


# ---------------------------------------------------------------------------
# A partial bind is never a green light
# ---------------------------------------------------------------------------


class _Failure:
    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason


def test_a_partial_bind_names_the_address_and_is_reported_as_an_error(tmp_path):
    client, _store, factory = _client(
        tmp_path,
        sans=("192.168.1.50", "10.0.0.7"),
        bind_failures=(_Failure("10.0.0.7", "another process is already listening"),),
    )

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    assert factory.last.running is True
    # Told which address, and why.
    assert "10.0.0.7" in resp.text
    assert "already listening" in resp.text
    # Told what it *is* answering on, so they know whether the core can reach it.
    assert "https://192.168.1.50:8765/mcp" in resp.text
    # And never as a plain success.
    assert "NOT" in resp.text
    assert 'class="error"' in resp.text


def test_a_partial_bind_shows_a_degraded_status_not_running(tmp_path):
    client, _store, _factory = _client(
        tmp_path,
        sans=("192.168.1.50", "10.0.0.7"),
        bind_failures=(_Failure("10.0.0.7", "another process is already listening"),),
    )
    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    page = client.get("/network-mcp").text

    assert "not on every address you chose" in page
    assert "Not answering on every address you chose" in page


def test_saving_an_unchanged_degraded_endpoint_still_does_not_look_healthy(tmp_path):
    """"Already running with these settings" would be true and would hide it."""
    client, _store, _factory = _client(
        tmp_path,
        sans=("192.168.1.50", "10.0.0.7"),
        bind_failures=(_Failure("10.0.0.7", "another process is already listening"),),
    )
    form = {"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]}
    client.post("/network-mcp/settings", data=form)

    resp = client.post("/network-mcp/settings", data=form)

    assert "already running with these settings" not in resp.text.lower()
    assert "10.0.0.7" in resp.text


def test_the_export_preflight_reports_a_partial_bind_and_the_extra_addresses(tmp_path):
    client, _store, _factory = _client(
        tmp_path,
        sans=("192.168.1.50", "10.0.0.7"),
        bind_failures=(_Failure("10.0.0.7", "another process is already listening"),),
    )
    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    resp = client.post("/network-mcp/export-registration")

    assert "not answering on every address" in resp.text.lower()
    assert "10.0.0.7" in resp.text


def test_the_export_preflight_says_a_registration_carries_one_url(tmp_path):
    """The manifest has one ``url`` and one ``[permissions] network`` entry, so a
    registration exported from a multi-address endpoint describes the preferred
    address and nothing else. The operator reads that before installing it."""
    client, _store, _factory = _client(tmp_path, sans=("192.168.1.50", "10.0.0.7"))
    client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "port": "8765", "bind_hosts": ["192.168.1.50", "10.0.0.7"]},
    )

    resp = client.post("/network-mcp/export-registration")

    assert "bound to 2 addresses" in resp.text
    assert "https://192.168.1.50:8765/mcp" in resp.text
