"""About page: choosing the update channel, and reading the last check (P28).

The updater asked GitHub for ``/releases/latest`` -- an endpoint that excludes
prereleases -- while every release of this project is a prerelease, so the check
404'd every time and the page showed the owner nothing at all. The client half
of that is covered in ``tests/unit/updater_client/test_channels_and_outcomes.py``.

These are the half he can see: he picks his channel by clicking, never by
editing a file; the change takes effect without a restart, and says so honestly
when it cannot; and a failed check never reads as "you are up to date".
"""

# ruff: noqa: ANN401

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.config.schema import AgentConfig
from workstation_agent.updater_client.manifest import UpdateManifest
from workstation_agent.updater_client.poller import UpdateCheckOutcome, UpdateCheckResult
from workstation_agent.updater_client.source_pin import DEFAULT_REPO

if TYPE_CHECKING:
    from pathlib import Path

    from starlette.testclient import TestClient


def _result(outcome: UpdateCheckOutcome, message: str, **kw: Any) -> UpdateCheckResult:
    """An ``UpdateCheckResult`` as a running poller would have recorded one."""
    return UpdateCheckResult(
        outcome=outcome,
        checked_at=datetime(2026, 9, 10, 14, 3, 0, tzinfo=UTC),
        channel=kw.pop("channel", "dev"),
        current_version=kw.pop("current_version", "0.1.0-alpha.14"),
        message=message,
        **kw,
    )


def _manifest(version: str = "0.1.0-alpha.17") -> UpdateManifest:
    base = f"https://github.com/{DEFAULT_REPO}/releases/download/v{version}"
    return UpdateManifest.model_validate({
        "version": version,
        "channel": "dev",
        "released_at": "2026-09-05T00:00:00Z",
        "mandatory": False,
        "notes_url": f"https://github.com/{DEFAULT_REPO}/releases/tag/v{version}",
        "min_updater_version": "0.1.0",
        "artifacts": {
            "agent": {"url": f"{base}/agent.zip", "sha256": "a" * 64, "size": 10},
            "updater": {"url": f"{base}/Updater.exe", "sha256": "b" * 64, "size": 20},
        },
    })


class _FakePoller:
    """Stands in for a real poller running on the Agent's own event loop."""

    def __init__(
        self,
        *,
        last_check: UpdateCheckResult | None = None,
        channel: str = "dev",
        pending: tuple[Any, bytes, bytes] | None = None,
    ) -> None:
        self.last_check = last_check
        self.channel = channel
        self.pending = pending
        self.channels_set: list[str] = []
        self.polls = 0
        self.nudges = 0

    def set_channel(self, channel: str) -> None:
        self.channels_set.append(channel)
        self.channel = channel

    async def poll_once(self) -> None:
        self.polls += 1

    def check_now(self) -> None:
        # Recorded, not raised: the assertion that matters is that the route
        # awaited poll_once instead, and a test can check both counters.
        self.nudges += 1


def _client(
    tmp_path: Path,
    poller: Any = None,
    store: FakeConfigStore | None = None,
) -> TestClient:
    return make_client(
        config_store=store or FakeConfigStore(),
        tmp_path=tmp_path,
        update_poller=poller,
    )


# ---------------------------------------------------------------------------
# What the last check found -- and what it did not find
# ---------------------------------------------------------------------------


def test_a_failed_check_reads_nothing_like_being_up_to_date(tmp_path: Path) -> None:
    """The defect in one assertion.

    "GitHub answered 404" and "there is nothing newer" used to be the same
    blank page. They must now be plainly different, and the failure must never
    carry the sentence the owner would read as reassurance.
    """
    refused = _client(tmp_path, _FakePoller(last_check=_result(
        UpdateCheckOutcome.REFUSED_BY_GITHUB,
        "GitHub was reached and refused the request with HTTP 404. Nothing was "
        "compared against the version you are running, so this is not the same "
        "as being up to date.",
    ))).get("/about")
    current = _client(tmp_path, _FakePoller(last_check=_result(
        UpdateCheckOutcome.UP_TO_DATE,
        "GitHub answered. The newest build on the dev channel is 0.1.0-alpha.14, "
        "which is not newer than the 0.1.0-alpha.14 you are running. You are up "
        "to date.",
        available_version="0.1.0-alpha.14",
    ))).get("/about")

    assert refused.status_code == 200
    assert current.status_code == 200
    assert "GitHub refused the request" in refused.text
    assert "HTTP 404" in refused.text
    assert "You are up to date" not in refused.text
    assert "Up to date" in current.text
    # When it ran, and against what.
    assert "2026-09-10 14:03:00 UTC" in refused.text
    assert "0.1.0-alpha.14" in refused.text


def test_no_check_yet_is_reported_as_no_check_yet(tmp_path: Path) -> None:
    """Absence of a result is absence, not success."""
    page = _client(tmp_path, _FakePoller()).get("/about").text
    assert "No update check has run yet" in page
    assert "up to date" not in page.lower()


def test_nothing_checking_at_all_is_said_out_loud(tmp_path: Path) -> None:
    """With no poller the page must imply nothing whatever about GitHub."""
    page = _client(tmp_path, None).get("/about").text
    assert "No update checker is running" in page
    assert "will not take effect until the Agent restarts" in page


def test_check_updates_runs_the_check_the_click_asked_for(tmp_path: Path) -> None:
    """It used to nudge a loop and redirect, so the page showed the *previous*
    check's nothing. The click now awaits its own check."""
    poller = _FakePoller()
    resp = _client(tmp_path, poller).post("/about/check-updates", follow_redirects=False)
    assert resp.status_code == 303
    assert poller.polls == 1
    assert poller.nudges == 0


def test_check_updates_still_works_with_no_poller(tmp_path: Path) -> None:
    resp = _client(tmp_path, None).post("/about/check-updates", follow_redirects=False)
    assert resp.status_code == 303


# ---------------------------------------------------------------------------
# Choosing the channel, by clicking
# ---------------------------------------------------------------------------


def test_the_channel_control_offers_exactly_the_three_valid_channels(
    tmp_path: Path,
) -> None:
    page = _client(tmp_path, _FakePoller(channel="beta")).get("/about").text
    for name in ("stable", "beta", "dev"):
        assert f'value="{name}"' in page
    assert '<option value="beta" selected>' in page


def test_saving_a_channel_takes_effect_without_a_restart(tmp_path: Path) -> None:
    poller = _FakePoller(channel="stable")
    store = FakeConfigStore()

    resp = _client(tmp_path, poller, store).post(
        "/about/channel",
        data={"speaks_for": "update_prefs", "update_channel": "dev"},
    )

    assert resp.status_code == 200
    assert store.load().update.channel == "dev"
    assert poller.channels_set == ["dev"]
    assert "In force now" in resp.text


def test_saving_a_channel_admits_when_it_cannot_take_effect_yet(tmp_path: Path) -> None:
    """No poller to push into, so the page says the change is not live yet
    rather than letting him think it is."""
    store = FakeConfigStore()

    resp = _client(tmp_path, None, store).post(
        "/about/channel",
        data={"speaks_for": "update_prefs", "update_channel": "beta"},
    )

    assert resp.status_code == 200
    assert store.load().update.channel == "beta"
    assert "takes effect the next time the Agent starts" in resp.text
    assert "In force now" not in resp.text


def test_a_channel_that_is_not_a_channel_is_refused(tmp_path: Path) -> None:
    store = FakeConfigStore()

    resp = _client(tmp_path, _FakePoller(), store).post(
        "/about/channel",
        data={"speaks_for": "update_prefs", "update_channel": "alpha"},
    )

    assert resp.status_code == 400
    assert store.load().update.channel == "stable"
    assert "is not an update channel" in resp.text


def test_a_body_that_did_not_come_from_this_form_saves_nothing(tmp_path: Path) -> None:
    """The tray-shaped hole, closed here too: encoding first, declaration second.

    An unticked checkbox is submitted as no field at all, so without the
    declaration an empty body would read as "switch auto-install off"."""
    store = FakeConfigStore()
    client = _client(tmp_path, _FakePoller(), store)

    assert client.post("/about/channel", json={"update_channel": "dev"}).status_code == 415
    assert client.post("/about/channel", data={"update_channel": "dev"}).status_code == 400

    assert store.load().update.channel == "stable"
    assert store.load().update.auto_install is False


def test_auto_install_is_off_by_default_and_moves_only_when_asked(
    tmp_path: Path,
) -> None:
    """Notify, do not install. The other behaviour exists, opt-in, and reverses."""
    store = FakeConfigStore()
    client = _client(tmp_path, _FakePoller(), store)
    assert store.load().update.auto_install is False

    client.post("/about/channel", data={
        "speaks_for": "update_prefs", "update_channel": "dev", "auto_install": "true",
    })
    assert store.load().update.auto_install is True

    client.post("/about/channel", data={
        "speaks_for": "update_prefs", "update_channel": "dev",
    })
    assert store.load().update.auto_install is False


def test_a_channel_the_config_holds_that_is_not_one_is_named_on_the_page(
    tmp_path: Path,
) -> None:
    """A hand-edited channel is reported, not silently treated as stable."""
    cfg = AgentConfig()
    cfg.update.channel = "alpha"
    page = _client(tmp_path, None, FakeConfigStore(cfg)).get("/about").text
    assert "is not one this Agent knows" in page


def test_the_page_shows_the_channel_actually_in_force(tmp_path: Path) -> None:
    """If the running poller and the stored config ever disagree, the page shows
    the one doing the checking."""
    cfg = AgentConfig()
    cfg.update.channel = "stable"
    page = _client(tmp_path, _FakePoller(channel="dev"), FakeConfigStore(cfg)).get(
        "/about",
    ).text
    assert '<option value="dev" selected>' in page


# ---------------------------------------------------------------------------
# Taking the update -- by clicking, never on its own
# ---------------------------------------------------------------------------


def test_install_is_offered_only_once_something_has_been_verified(
    tmp_path: Path,
) -> None:
    without = _client(tmp_path, _FakePoller()).get("/about").text
    assert "/about/install" not in without

    with_pending = _client(
        tmp_path, _FakePoller(pending=(_manifest(), b"raw", b"sig")),
    ).get("/about").text
    assert "/about/install" in with_pending
    assert "Install 0.1.0-alpha.17" in with_pending
    assert "Nothing has been installed" in with_pending


def test_install_stages_the_bytes_that_verified_and_hands_off(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """What is installed is what passed the signature check, not a second fetch."""
    from workstation_agent.updater_client import handoff

    staged: list[tuple[str, bytes, bytes]] = []
    monkeypatch.setattr(
        handoff,
        "stage_pending",
        lambda m, *, manifest_bytes, signature_bytes: staged.append(
            (m.version, manifest_bytes, signature_bytes),
        ),
    )
    monkeypatch.setattr(handoff, "spawn_updater", lambda: 4321)

    resp = _client(
        tmp_path, _FakePoller(pending=(_manifest(), b"raw-manifest", b"sig-bytes")),
    ).post("/about/install")

    assert resp.status_code == 200
    assert staged == [("0.1.0-alpha.17", b"raw-manifest", b"sig-bytes")]
    assert "Installing 0.1.0-alpha.17" in resp.text


def test_install_with_nothing_staged_changes_nothing(tmp_path: Path) -> None:
    resp = _client(tmp_path, _FakePoller()).post("/about/install")
    assert resp.status_code == 200
    assert "no verified update staged" in resp.text


# ---------------------------------------------------------------------------
# The Config page's copy of the field
# ---------------------------------------------------------------------------


def test_config_channel_is_a_choice_not_a_free_text_box(tmp_path: Path) -> None:
    """A typo used to save happily and then match no release, ever."""
    store = FakeConfigStore()
    client = _client(tmp_path, None, store)

    page = client.get("/config").text
    assert '<select name="update_channel">' in page

    resp = client.post("/config", data={"update_channel": "stabel"})
    assert resp.status_code == 200
    assert "Channel must be one of" in resp.text
    assert store.load().update.channel == "stable"
