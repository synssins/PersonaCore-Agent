"""Subtask P23 -- a tray click must never rewrite the owner's configuration.

The shipped bug (alpha.12, alpha.13): ``POST /config`` reads its fields as
``Form(...)`` parameters and *every one of them has a default*. The tray posted
a **JSON** body to it. A JSON body parses as an empty form, so every field fell
back to its hardcoded default and the handler saved that -- HTTP 200, no error,
and the operator's LLM base URL, model, Wyoming host, wake settings and update
channel were gone. Confirmed empirically: ``llm.model`` went from the chosen
value to ``gpt-4o``.

These tests are written against the *bug*, not against the fix. Every one of
them fails on b90e210. They assert on the persisted config -- "does the value
the owner set survive this request" -- because that is the damage, and a test
that only checked the status code would have passed all along.

The class of bug, not the instance: a handler that cannot tell "this field was
not sent" from "this field was sent as its default", on a route whose job is to
save the whole object. So there are tests here for a partial *form* body too,
and for the tray having a route that says what it actually means.
"""

# ruff: noqa: ANN401 -- the httpx.post stand-in below forwards **kwargs verbatim

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from tests.unit.ui.conftest import (
    FakeConfigStore,
    FakeMCPHost,
    FakePluginInfo,
    make_client,
)
from workstation_agent.config.schema import AgentConfig
from workstation_agent.ui.systray.tray import SystemTray

if TYPE_CHECKING:
    from pathlib import Path

    from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# A configuration that looks nothing like the route's defaults
# ---------------------------------------------------------------------------


def _owner_config() -> AgentConfig:
    """Every field the POST /config form owns, set away from its default.

    Chosen so that "the default was written" and "the value survived" cannot be
    confused for one another on any single field.
    """
    cfg = AgentConfig()
    cfg.llm.base_url = "http://192.168.1.150:9099/v1"  # type: ignore[assignment]
    cfg.llm.model = "personacore-qwen3-32b"
    cfg.llm.timeout_seconds = 180
    cfg.llm.streaming = False
    cfg.wyoming.host = "192.168.1.151"
    cfg.wyoming.port = 10500
    cfg.wake.enabled = True
    cfg.wake.threshold = 0.72
    cfg.session.mode = "single_shot"
    cfg.session.sticky_seconds = 90
    cfg.update.enabled = True
    cfg.update.channel = "alpha"
    cfg.adb.binary_path = r"C:\tools\platform-tools\adb.exe"
    return cfg


def _assert_untouched(store: FakeConfigStore, *, expect_mode: str = "single_shot") -> None:
    """Nothing the owner set has moved.

    *expect_mode* is the one field a legitimate single-setting call is allowed
    to change, so the same assertion serves both "nothing happened" and "only
    the one thing happened".
    """
    cfg = store.load()
    assert str(cfg.llm.base_url).rstrip("/") == "http://192.168.1.150:9099/v1"
    assert cfg.llm.model == "personacore-qwen3-32b"
    assert cfg.llm.timeout_seconds == 180
    assert cfg.llm.streaming is False
    assert cfg.wyoming.host == "192.168.1.151"
    assert cfg.wyoming.port == 10500
    assert cfg.wake.enabled is True
    assert cfg.wake.threshold == pytest.approx(0.72)
    assert cfg.session.sticky_seconds == 90
    assert cfg.update.enabled is True
    assert cfg.update.channel == "alpha"
    assert cfg.adb.binary_path == r"C:\tools\platform-tools\adb.exe"
    assert cfg.session.mode == expect_mode


@pytest.fixture
def owner_store() -> FakeConfigStore:
    return FakeConfigStore(_owner_config())


@pytest.fixture
def owner_client(owner_store: FakeConfigStore, tmp_path: Path) -> TestClient:
    return make_client(config_store=owner_store, tmp_path=tmp_path)


def _tray_wired_to(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> SystemTray:
    """A real ``SystemTray`` whose HTTP calls land on *client*'s app.

    The point of driving the tray itself rather than hand-rolling its request:
    the request shape under test is whatever the tray actually sends today, so
    the test cannot drift away from the caller it is about.
    """

    def _post(url: str, **kwargs: Any) -> Any:
        kwargs.pop("timeout", None)
        return client.post(url, follow_redirects=False, **kwargs)

    monkeypatch.setattr("workstation_agent.ui.systray.tray.httpx.post", _post)
    return SystemTray(
        webview_window=MagicMock(),
        url_provider=lambda: "http://testserver",
        pending_plugin_count=lambda: 0,
    )


# ---------------------------------------------------------------------------
# The shipped bug: a tray click resets everything
# ---------------------------------------------------------------------------


def test_a_json_body_at_the_settings_route_saves_nothing(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """The bug in one line.

    ``POST /config`` with a JSON body used to answer 200 and write a config
    made entirely of ``Form(...)`` defaults over the top of the operator's.
    """
    resp = owner_client.post("/config", json={"session_mode": "persistent"})

    assert resp.status_code != 200, (
        "a JSON body at a form route is a caller error and must say so, "
        "not be treated as an empty form"
    )
    _assert_untouched(owner_store)


def test_a_json_body_that_names_no_known_field_saves_nothing(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """``{"muted": true}`` -- the tray's mute toggle. ``muted`` is not even a
    config field, so this request asked for nothing at all and still wiped the
    file."""
    owner_client.post("/config", json={"muted": True})

    _assert_untouched(owner_store)


def test_an_empty_form_saves_nothing(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """The same hole reached through a correctly-encoded but empty body.

    A truncated retry, or a caller that built its form and sent none of it.
    "Save the whole configuration" and "I sent you no fields" cannot both be
    honoured; the request must lose, not the config.
    """
    resp = owner_client.post(
        "/config", content=b"", headers={"content-type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code != 200
    _assert_untouched(owner_store)


def test_a_partial_form_leaves_the_fields_it_did_not_mention_alone(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """The general form of the bug, with the encoding correct.

    A caller that sends *some* fields must not have every other field replaced
    by a hardcoded constant. Absent has to mean "leave it alone", because a
    handler that cannot tell absent from default will erase whatever the next
    caller forgets to mention.
    """
    resp = owner_client.post("/config", data={"llm_model": "personacore-qwen3-14b"})

    assert resp.status_code == 200
    cfg = owner_store.load()
    assert cfg.llm.model == "personacore-qwen3-14b"  # what was asked for
    assert str(cfg.llm.base_url).rstrip("/") == "http://192.168.1.150:9099/v1"
    assert cfg.llm.timeout_seconds == 180
    assert cfg.wyoming.host == "192.168.1.151"
    assert cfg.wyoming.port == 10500
    assert cfg.wake.threshold == pytest.approx(0.72)
    assert cfg.session.sticky_seconds == 90
    assert cfg.update.channel == "alpha"
    assert cfg.adb.binary_path == r"C:\tools\platform-tools\adb.exe"
    # The checkboxes too. HTML omits an unticked box, so a caller that never
    # mentioned one must not be read as having unticked it -- that is what the
    # hidden `checkbox_fields` marker is for, and this body has no marker.
    assert cfg.wake.enabled is True
    assert cfg.update.enabled is True


# ---------------------------------------------------------------------------
# The tray itself, driven through its own callbacks
# ---------------------------------------------------------------------------


def test_the_tray_session_mode_item_changes_only_the_session_mode(
    owner_client: TestClient,
    owner_store: FakeConfigStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One click on "Persistent" in the tray menu.

    It must change the session mode and nothing else. On b90e210 it changed
    the session mode and *everything* else.
    """
    tray = _tray_wired_to(owner_client, monkeypatch)

    tray._make_session_mode_action("persistent")(MagicMock(), MagicMock())

    _assert_untouched(owner_store, expect_mode="persistent")


def test_the_tray_mute_item_does_not_touch_the_configuration(
    owner_client: TestClient,
    owner_store: FakeConfigStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``muted`` is speaker state (``audio.sink.SpeakerSink``), not a setting.

    There is no ``muted`` key in ``AgentConfig`` and no backend route that owns
    one, so the only thing this click could ever do to the config file was
    destroy it.
    """
    tray = _tray_wired_to(owner_client, monkeypatch)

    tray._on_mute_toggle(MagicMock(), MagicMock())

    assert tray._muted is True
    _assert_untouched(owner_store)


def test_the_tray_session_mode_route_rejects_a_mode_it_does_not_know(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """A single-setting route still validates its single setting."""
    resp = owner_client.post("/config/session-mode", json={"mode": "turbo"})

    assert resp.status_code == 422
    _assert_untouched(owner_store)


# ---------------------------------------------------------------------------
# The settings page -- the caller that matters -- is untouched
# ---------------------------------------------------------------------------


def test_a_genuine_full_form_post_still_saves_every_field(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """The real settings form is a genuine form POST and must keep working."""
    resp = owner_client.post(
        "/config",
        data={
            "llm_base_url": "http://10.0.0.5:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "45",
            "llm_streaming": "true",
            "wyoming_host": "10.0.0.5",
            "wyoming_port": "10301",
            "wake_threshold": "0.31",
            "session_mode": "persistent",
            "session_sticky_seconds": "12",
            "update_channel": "beta",
            "adb_binary_path": "",
        },
    )

    assert resp.status_code == 200
    cfg = owner_store.load()
    assert str(cfg.llm.base_url).rstrip("/") == "http://10.0.0.5:8053/v1"
    assert cfg.llm.model == "gpt-4o"
    assert cfg.llm.timeout_seconds == 45
    assert cfg.llm.streaming is True
    assert cfg.wyoming.host == "10.0.0.5"
    assert cfg.wyoming.port == 10301
    assert cfg.wake.threshold == pytest.approx(0.31)
    assert cfg.session.mode == "persistent"
    assert cfg.session.sticky_seconds == 12
    assert cfg.update.channel == "beta"
    assert cfg.adb.binary_path == ""


def test_an_unchecked_checkbox_still_means_false_on_a_real_form_post(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """The one place where "absent" legitimately means "off".

    HTML omits an unchecked box entirely. That is only readable as "off"
    because the route has already established the body *is* a settings-form
    submission -- which is exactly what the gate above buys.
    """
    owner_client.post(
        "/config",
        data={
            # The hidden marker config.html submits, naming the boxes this
            # form speaks for. Without it, absence would mean "no opinion".
            "checkbox_fields": "llm_streaming wake_enabled update_enabled",
            "llm_base_url": "http://10.0.0.5:8053/v1",
            "llm_model": "gpt-4o",
            "llm_timeout_seconds": "45",
            "wyoming_host": "10.0.0.5",
            "wyoming_port": "10301",
            "wake_threshold": "0.31",
            "session_mode": "persistent",
            "session_sticky_seconds": "12",
            "update_channel": "beta",
            "adb_binary_path": "",
        },
    )

    cfg = owner_store.load()
    assert cfg.llm.streaming is False
    assert cfg.wake.enabled is False
    assert cfg.update.enabled is False


# ---------------------------------------------------------------------------
# The second bug: "Reload plugins" has never done anything
# ---------------------------------------------------------------------------


def test_the_tray_reload_plugins_item_reaches_a_real_route(tmp_path: Path) -> None:
    """``POST /plugins/reload`` answered 404. The menu item was decorative."""
    host = FakeMCPHost([FakePluginInfo(id="adb"), FakePluginInfo(id="files")])
    client = make_client(mcp_host=host, tmp_path=tmp_path)

    resp = client.post("/plugins/reload", follow_redirects=False)

    assert resp.status_code != 404
    assert sorted(host.reloaded) == ["adb", "files"]


def test_the_tray_reload_click_reloads_every_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Driven through the tray callback, so the URL under test is the tray's."""
    host = FakeMCPHost([FakePluginInfo(id="adb"), FakePluginInfo(id="files")])
    client = make_client(mcp_host=host, tmp_path=tmp_path)
    tray = _tray_wired_to(client, monkeypatch)

    tray._on_reload_plugins(MagicMock(), MagicMock())

    assert sorted(host.reloaded) == ["adb", "files"]


def test_reload_all_with_no_host_is_not_an_error(tmp_path: Path) -> None:
    """No MCP host wired (a backend running standalone) is not a 500."""
    from starlette.testclient import TestClient

    from tests.unit.ui.conftest import _LoopbackASGI
    from workstation_agent.ui.backend.app import BackendContext, create_app

    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    client = TestClient(_LoopbackASGI(create_app(ctx)))

    resp = client.post("/plugins/reload", follow_redirects=False)

    assert resp.status_code < 500


# ---------------------------------------------------------------------------
# The sweep: the same shape on other routes that save a whole object
#
# Same hole, different handler. None of these is reachable from the tray, but
# each writes the operator's real settings from a body Starlette will happily
# parse as empty, and each is closed by the same guard.
# ---------------------------------------------------------------------------


def test_the_confirmation_policy_route_refuses_a_non_form_body(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """``POST /config/confirmation`` rebuilds the whole §7 policy from the raw
    form. An empty parse reads as "nothing is never-prompt, nothing is
    always-prompt, nothing is remembered" -- which quietly drops a tool the
    operator pinned to always-prompt down to ask. A weaker policy than they
    chose, arrived at by accident."""
    cfg = owner_store.load()
    cfg.confirmation.always_prompt = ["shell_run"]
    cfg.confirmation.never_prompt = ["files_read"]
    cfg.confirmation.remember_for_session = ["files_read"]
    owner_store.save(cfg)

    resp = owner_client.post("/config/confirmation", json={"policy_shell_run": "never"})

    assert resp.status_code == 415
    after = owner_store.load()
    assert after.confirmation.always_prompt == ["shell_run"]
    assert after.confirmation.never_prompt == ["files_read"]
    assert after.confirmation.remember_for_session == ["files_read"]


def test_the_confirmation_policy_route_still_takes_a_real_form(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    """An empty *form* stays legitimate -- there is no "ask" radio, so "ask for
    everything" really does submit no policy fields."""
    resp = owner_client.post(
        "/config/confirmation",
        data={"policy_shell_run": "always", "remember_shell_run": "true"},
    )

    assert resp.status_code == 200
    after = owner_store.load()
    assert after.confirmation.always_prompt == ["shell_run"]
    assert after.confirmation.remember_for_session == ["shell_run"]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/first-run/llm", {"llm_host": "192.168.1.150", "model": "gpt-4o"}),
        ("/first-run/wyoming", {"wyoming_host": "192.168.1.150"}),
        ("/first-run/audio", {"input_device": ""}),
    ],
)
def test_a_first_run_step_refuses_a_non_form_body(
    owner_client: TestClient,
    owner_store: FakeConfigStore,
    path: str,
    body: dict[str, str],
) -> None:
    """Every wizard step has the tray bug's shape: defaulted ``Form(...)``
    parameters written straight into the saved config. A JSON body would
    replace the operator's LLM base URL with ``192.168.1.150:8053``, their
    model with ``gpt-4o``, or clear their audio device selection."""
    before = owner_store.load().model_dump()

    resp = owner_client.post(path, json=body)

    assert resp.status_code == 415
    assert owner_store.load().model_dump() == before


def test_the_first_run_llm_step_still_saves_a_real_form(
    owner_client: TestClient, owner_store: FakeConfigStore,
) -> None:
    resp = owner_client.post(
        "/first-run/llm",
        data={"llm_host": "10.0.0.9", "llm_port": "8053", "model": "personacore-mini"},
    )

    assert resp.status_code == 200
    cfg = owner_store.load()
    assert "10.0.0.9" in str(cfg.llm.base_url)
    assert cfg.llm.model == "personacore-mini"
