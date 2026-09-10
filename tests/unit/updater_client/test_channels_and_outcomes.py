"""The update check: which release a channel means, and what a failure says.

Two defects are pinned down here.

**The updater could never find a release.** It asked GitHub for
``/repos/<repo>/releases/latest``, an endpoint that excludes prereleases by
definition, while every release this project has published is a prerelease. The
live endpoint answered ``404`` and the poller logged one line. The test that
matters is :func:`test_a_prerelease_only_repo_yields_an_update_on_dev` and its
stable-channel twin: a release list containing nothing but prereleases must
produce an available update on a prerelease channel, and must produce a *named
failure* -- not "up to date" -- on stable.

**Every failure looked like silence.** ``poll_once`` returned ``None`` for "you
are current", for "GitHub is unreachable", and for "GitHub said 404". Those are
three different situations with three different next actions, so they are
asserted here as three different outcomes carrying three different messages,
and none of the failures is allowed to contain the phrase the owner would read
as reassurance.

The HTTP double routes by exact URL, so these tests also prove *which* endpoint
the client reaches for -- and every request still goes through the real source
pin, which is not relaxed anywhere in this module.
"""

# ruff: noqa: ANN401

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from nacl.signing import SigningKey

from workstation_agent.updater_client.channels import (
    accepts,
    channel_of_release,
    channel_of_tag,
    is_newer,
    normalise_channel,
    version_key,
)
from workstation_agent.updater_client.manifest import (
    NoMatchingReleaseError,
    UpdateFeedError,
    select_release,
)
from workstation_agent.updater_client.poller import UpdateCheckOutcome, UpdatePoller
from workstation_agent.updater_client.source_pin import DEFAULT_REPO

pytestmark = pytest.mark.asyncio

REPO = DEFAULT_REPO
API_LIST = f"https://api.github.com/repos/{REPO}/releases?per_page=100"


def _download(tag: str, name: str) -> str:
    return f"https://github.com/{REPO}/releases/download/{tag}/{name}"


# ---------------------------------------------------------------------------
# The mapping, and why each half of it is the way it is
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("v0.1.0", "stable"),
        ("v1.2.3", "stable"),
        ("v0.1.0-alpha.17", "dev"),
        ("v0.1.0-dev.1", "dev"),
        ("v0.1.0-beta.2", "beta"),
        ("v0.1.0-rc1", "beta"),
        ("V0.1.0-ALPHA.3", "dev"),
    ],
)
async def test_the_tag_suffix_decides_the_channel(tag: str, expected: str) -> None:
    """The workflow picks the prerelease flag off the tag; so does the client."""
    assert channel_of_tag(tag) == expected


async def test_the_prerelease_flag_only_vetoes_stable() -> None:
    """It can take a release out of stable; it cannot promote one into it."""
    # Flagged prerelease with an unsuffixed tag: not stable, and we have no
    # evidence it is beta-quality, so it goes to the channel that asked for
    # everything rather than to one that did not.
    assert channel_of_release("v0.1.0", prerelease=True) == "dev"
    # The tag wins in the other direction: an alpha is an alpha even if nobody
    # ticked the box, because the alternative is shipping it to stable.
    assert channel_of_release("v0.1.0-alpha.17", prerelease=False) == "dev"
    assert channel_of_release("v0.1.0", prerelease=False) == "stable"


async def test_a_channel_is_a_floor_not_an_equality_test() -> None:
    """dev takes everything, beta takes betas and releases, stable only releases."""
    assert [accepts("dev", c) for c in ("stable", "beta", "dev")] == [True, True, True]
    assert [accepts("beta", c) for c in ("stable", "beta", "dev")] == [True, True, False]
    assert [accepts("stable", c) for c in ("stable", "beta", "dev")] == [True, False, False]
    # A channel this build does not know matches nothing rather than everything.
    assert accepts("alpha", "dev") is False
    assert normalise_channel("alpha") is None
    assert normalise_channel(" DEV ") == "dev"


# ---------------------------------------------------------------------------
# Version precedence
# ---------------------------------------------------------------------------


async def test_prereleases_of_the_same_version_are_ordered() -> None:
    """The old comparison threw the suffix away, so these two were *equal*.

    That alone would have stopped an update being offered even once the right
    release was in hand: alpha.17 was not "newer" than alpha.9.
    """
    assert is_newer("0.1.0-alpha.17", "0.1.0-alpha.9") is True
    assert is_newer("0.1.0-alpha.9", "0.1.0-alpha.17") is False
    assert is_newer("0.1.0-alpha.17", "0.1.0-alpha.17") is False


async def test_a_prerelease_is_older_than_its_own_release() -> None:
    assert is_newer("0.1.0-alpha.17", "0.1.0") is False
    assert is_newer("0.1.0", "0.1.0-alpha.17") is True
    assert is_newer("0.1.0-beta.1", "0.1.0-alpha.17") is True


async def test_pep440_spellings_compare_with_tag_spellings() -> None:
    """The running agent's version comes from packaging; the release's from a tag."""
    # The same build, spelled both ways, must not look like an update.
    assert is_newer("0.1.0-alpha.18", "0.1.0a18") is False
    assert is_newer("0.1.0a18", "0.1.0-alpha.18") is False
    # A checkout's placeholder is below every published alpha, as PEP 440 says.
    assert is_newer("0.1.0-alpha.1", "0.1.0.dev0") is True
    assert is_newer("0.1.0.dev0", "0.1.0-alpha.1") is False
    assert version_key("0.1.0.dev0") < version_key("0.1.0a1") < version_key("0.1.0rc1")


async def test_an_unparseable_version_raises_rather_than_comparing_false() -> None:
    """"I cannot tell" must not be delivered as "there is nothing newer"."""
    with pytest.raises(ValueError, match="invalid version"):
        is_newer("not-a-version", "0.1.0")


# ---------------------------------------------------------------------------
# Picking a release out of the list
# ---------------------------------------------------------------------------


def _release(tag: str, *, prerelease: bool = True, draft: bool = False) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "assets": [
            {"name": "manifest.json", "browser_download_url": _download(tag, "manifest.json")},
            {
                "name": "manifest.json.sig",
                "browser_download_url": _download(tag, "manifest.json.sig"),
            },
        ],
    }


#: This project's actual publishing history: alphas, and nothing else.
PRERELEASES_ONLY = [
    _release("v0.1.0-alpha.9"),
    _release("v0.1.0-alpha.17"),
    _release("v0.1.0-alpha.14"),
]


async def test_select_release_takes_the_newest_by_version_not_by_list_order() -> None:
    """GitHub's ordering is not authority; a back-dated re-tag must not win."""
    chosen = select_release(PRERELEASES_ONLY, "dev")
    assert chosen["tag_name"] == "v0.1.0-alpha.17"


async def test_select_release_refuses_a_payload_that_is_not_a_list() -> None:
    with pytest.raises(UpdateFeedError, match="not a list"):
        select_release({"message": "Not Found"}, "dev")


async def test_select_release_skips_drafts() -> None:
    only_draft = [_release("v0.9.0-alpha.1", draft=True)]
    with pytest.raises(NoMatchingReleaseError):
        select_release(only_draft, "dev")


async def test_select_release_on_stable_reports_what_the_repo_does_publish() -> None:
    with pytest.raises(NoMatchingReleaseError) as excinfo:
        select_release(PRERELEASES_ONLY, "stable")
    assert excinfo.value.channel == "stable"
    assert excinfo.value.seen == {"dev": 3}


# ---------------------------------------------------------------------------
# The whole check, through the real source pin
# ---------------------------------------------------------------------------


class _Resp:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code: int, *, content: bytes = b"", payload: Any = None) -> None:
        self.status_code = status_code
        self.content = content
        self.headers: dict[str, str] = {}
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _Client:
    """Routes by exact URL, so a test also proves which endpoint was reached."""

    def __init__(self, routes: dict[str, _Resp], *, raises: Exception | None = None) -> None:
        self.routes = routes
        self.seen: list[str] = []
        self._raises = raises

    async def get(self, url: str, **kwargs: Any) -> _Resp:
        assert kwargs.get("follow_redirects") is False
        self.seen.append(url)
        if self._raises is not None:
            raise self._raises
        if url not in self.routes:
            msg = f"unexpected request to {url}"
            raise AssertionError(msg)
        return self.routes[url]


def _manifest_dict(version: str) -> dict[str, Any]:
    tag = f"v{version}"
    return {
        "version": version,
        "channel": "dev",
        "released_at": "2026-09-05T00:00:00Z",
        "mandatory": False,
        "notes_url": f"https://github.com/{REPO}/releases/tag/{tag}",
        "min_updater_version": "0.1.0",
        "artifacts": {
            "agent": {
                "url": _download(tag, f"agent-{version}-win-x64.zip"),
                "sha256": "a" * 64,
                "size": 10,
            },
            "updater": {
                "url": _download(tag, f"updater-{version}-win-x64.exe"),
                "sha256": "b" * 64,
                "size": 20,
            },
        },
    }


@pytest.fixture
def keypair() -> tuple[SigningKey, bytes]:
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key)


def _routes(keypair: tuple[SigningKey, bytes], version: str = "0.1.0-alpha.17") -> dict[str, _Resp]:
    sk, _ = keypair
    tag = f"v{version}"
    raw = json.dumps(_manifest_dict(version)).encode()
    sig = sk.sign(raw).signature
    return {
        API_LIST: _Resp(200, payload=PRERELEASES_ONLY),
        _download(tag, "manifest.json"): _Resp(200, content=raw),
        _download(tag, "manifest.json.sig"): _Resp(200, content=sig),
    }


async def _poller(
    keypair: tuple[SigningKey, bytes],
    client: Any,
    *,
    channel: str,
    current_version: str = "0.1.0-alpha.9",
) -> UpdatePoller:
    _, pub = keypair
    fired: list[str] = []

    async def _on_update(manifest: Any, _raw: bytes, _sig: bytes) -> None:
        fired.append(manifest.version)

    poller = UpdatePoller(
        github_repo=REPO,
        current_version=current_version,
        pubkey=pub,
        http=client,
        on_update_available=_on_update,
        channel=channel,
    )
    poller.fired = fired  # type: ignore[attr-defined]
    return poller


async def test_a_prerelease_only_repo_yields_an_update_on_dev(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """The exact situation that has been silently broken since alpha.9.

    Every published release is a prerelease. On a prerelease channel that must
    produce an available update -- and it must be the *newest* alpha, verified,
    with the callback fired.
    """
    client = _Client(_routes(keypair))
    poller = await _poller(keypair, client, channel="dev")

    result = await poller.poll_once()

    assert result is not None
    assert result.version == "0.1.0-alpha.17"
    assert poller.fired == ["0.1.0-alpha.17"]  # type: ignore[attr-defined]
    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.UPDATE_AVAILABLE
    assert last.available_version == "0.1.0-alpha.17"
    assert last.succeeded
    # It really did read the release list, not /releases/latest.
    assert API_LIST in client.seen
    assert not any(url.endswith("/releases/latest") for url in client.seen)
    # Notify, do not install: the manifest is held for the owner's click.
    assert poller.pending is not None
    assert "Nothing has been installed" in last.message


async def test_the_same_repo_yields_no_update_and_a_named_failure_on_stable(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """Same payload, stable channel: no update, and it is not "up to date"."""
    client = _Client(_routes(keypair))
    poller = await _poller(keypair, client, channel="stable")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.NO_RELEASE_ON_CHANNEL
    assert last.failed
    assert "not the same as being up to date" in last.message
    # And it says where the builds actually are, so the owner can act.
    assert "3 on dev" in last.message
    assert poller.pending is None
    assert poller.fired == []  # type: ignore[attr-defined]


async def test_the_newest_alpha_is_not_offered_to_someone_already_on_it(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """Up to date is a *conclusion*, and it names both versions."""
    client = _Client(_routes(keypair))
    poller = await _poller(
        keypair, client, channel="dev", current_version="0.1.0-alpha.17",
    )

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.UP_TO_DATE
    assert last.succeeded
    assert "You are up to date." in last.message
    assert "0.1.0-alpha.17" in last.message
    assert poller.pending is None


async def test_a_404_is_reported_as_a_refusal_and_never_as_up_to_date(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """What the live endpoint answered for the whole life of the project."""
    client = _Client({API_LIST: _Resp(404, payload={"message": "Not Found"})})
    poller = await _poller(keypair, client, channel="dev")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.REFUSED_BY_GITHUB
    assert last.failed
    assert "HTTP 404" in last.message
    assert "not the same as being up to date" in last.message
    assert "up to date." not in last.message.lower().replace(
        "not the same as being up to date.", "",
    )
    # Actionable: it names what a 404 here means and what to look at.
    assert REPO in last.message
    assert "repository" in last.message


async def test_an_unreachable_host_is_a_different_message_from_a_404(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """"GitHub said no" and "GitHub never answered" need different fixes."""
    client = _Client({}, raises=httpx.ConnectError("[Errno 11001] getaddrinfo failed"))
    poller = await _poller(keypair, client, channel="dev")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.UNREACHABLE
    assert last.failed
    assert "could not be reached at all" in last.message
    assert "getaddrinfo failed" in last.message
    assert "not the same as being up to date" in last.message
    # Actionable, and about the network rather than about the repository.
    assert "firewall" in last.message
    assert "HTTP" not in last.message


async def test_the_three_outcomes_are_distinguishable_from_each_other(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """The property the owner asked for, stated directly."""
    up_to_date = await _poller(
        keypair, _Client(_routes(keypair)), channel="dev",
        current_version="0.1.0-alpha.17",
    )
    refused = await _poller(keypair, _Client({API_LIST: _Resp(404)}), channel="dev")
    unreachable = await _poller(
        keypair, _Client({}, raises=httpx.ConnectTimeout("timed out")), channel="dev",
    )
    for poller in (up_to_date, refused, unreachable):
        await poller.poll_once()

    results = [p.last_check for p in (up_to_date, refused, unreachable)]
    assert all(r is not None for r in results)
    outcomes = [r.outcome for r in results if r is not None]
    messages = [r.message for r in results if r is not None]
    assert len(set(outcomes)) == 3
    assert len(set(messages)) == 3
    # Exactly one of the three means "you are current".
    assert [r.succeeded for r in results if r is not None] == [True, False, False]


async def test_a_release_whose_manifest_is_signed_by_another_key_is_rejected(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """Signature verification is untouched, and its failure is now visible."""
    other = SigningKey.generate()
    client = _Client(_routes((other, bytes(other.verify_key))))
    poller = await _poller(keypair, client, channel="dev")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.UNTRUSTED
    assert last.failed
    assert "not signed by the key this build trusts" in last.message
    assert poller.pending is None
    assert poller.fired == []  # type: ignore[attr-defined]


async def test_an_off_origin_asset_url_is_refused_and_said_so(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """The source pin still governs, and a refusal is reported, not swallowed."""
    hostile = [
        {
            "tag_name": "v0.1.0-alpha.18",
            "prerelease": True,
            "draft": False,
            "assets": [
                {"name": "manifest.json",
                 "browser_download_url": "https://evil.example/manifest.json"},
                {"name": "manifest.json.sig",
                 "browser_download_url": "https://evil.example/manifest.json.sig"},
            ],
        },
    ]
    client = _Client({API_LIST: _Resp(200, payload=hostile)})
    poller = await _poller(keypair, client, channel="dev")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.UNTRUSTED
    assert "https://evil.example/manifest.json" not in client.seen
    assert "not the same as being up to date" in last.message


async def test_an_unrecognised_configured_channel_is_reported_not_guessed(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """A hand-edited channel must not silently become "stable"."""
    client = _Client(_routes(keypair))
    poller = await _poller(keypair, client, channel="alpha")

    assert await poller.poll_once() is None

    last = poller.last_check
    assert last is not None
    assert last.outcome is UpdateCheckOutcome.MISCONFIGURED
    assert last.failed
    assert "'alpha'" in last.message
    # Nothing was even asked of GitHub.
    assert client.seen == []


async def test_changing_the_channel_applies_to_the_next_check_without_a_restart(
    keypair: tuple[SigningKey, bytes],
) -> None:
    """The property the About page promises when a poller is running."""
    client = _Client(_routes(keypair))
    poller = await _poller(keypair, client, channel="stable")

    assert await poller.poll_once() is None
    first = poller.last_check
    assert first is not None
    assert first.outcome is UpdateCheckOutcome.NO_RELEASE_ON_CHANNEL

    poller.set_channel("dev")
    assert poller.channel == "dev"
    result = await poller.poll_once()

    assert result is not None
    assert result.version == "0.1.0-alpha.17"
    second = poller.last_check
    assert second is not None
    assert second.outcome is UpdateCheckOutcome.UPDATE_AVAILABLE
    assert second.channel == "dev"
