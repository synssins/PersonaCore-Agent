"""Update manifest schema and fetch helpers.

Matches design §4.7. Canonical JSON serialisation must byte-match the Go
updater's implementation so a single Ed25519 signature verifies on both sides.

:func:`fetch` reads the repository's release **list** and picks the newest
release the owner's channel accepts. It used to read ``/releases/latest``,
which excludes prereleases and so answered ``404`` for every release this
project has ever published; see
:mod:`workstation_agent.updater_client.channels` for the mapping that replaced
it. Nothing about the source pin changed: the feed URL, every asset URL the
API hands back, and every redirect hop are checked exactly as before.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from workstation_agent.updater_client.channels import (
    accepts,
    channel_of_release,
    is_newer,
    version_key,
)
from workstation_agent.updater_client.source_pin import (
    MAX_REDIRECTS,
    REDIRECT_STATUS,
    SourcePin,
    SourcePinError,
    check_artifact_origin,
    resolve_redirect,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    import httpx

__all__ = [
    "ArtifactRef",
    "ArtifactSet",
    "NoMatchingReleaseError",
    "UpdateFeedError",
    "UpdateManifest",
    "fetch",
    "is_newer",
    "select_release",
]

_HTTP_ERROR_STATUS = 400


class UpdateFeedError(RuntimeError):
    """GitHub was reached but would not serve the update feed.

    Distinct from a transport failure on purpose: "GitHub said no" and "GitHub
    never answered" are different problems with different fixes, and the whole
    reason this class exists is so the poller can say which one happened
    instead of logging both as ``fetch failed``.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class NoMatchingReleaseError(LookupError):
    """The release list was read fine and held nothing on the owner's channel.

    Also not "you are up to date": nothing was compared against the running
    version, because there was no candidate to compare. :attr:`seen` carries
    what the repository *does* publish, so the message can say which channel
    would have found something.
    """

    def __init__(
        self,
        channel: str,
        *,
        seen: Mapping[str, int],
        unusable_tags: Iterable[str] = (),
    ) -> None:
        self.channel = channel
        self.seen = dict(seen)
        self.unusable_tags = list(unusable_tags)
        total = sum(self.seen.values())
        elsewhere = ", ".join(
            f"{count} on {name}" for name, count in sorted(self.seen.items())
        )
        detail = f" ({elsewhere})" if elsewhere else ""
        super().__init__(
            f"none of the {total} published release(s) is on the {channel!r} "
            f"channel{detail}",
        )


_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArtifactRef(BaseModel):
    """A single downloadable artifact (agent zip or updater exe)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    sha256: str
    size: int = Field(gt=0)

    @field_validator("sha256")
    @classmethod
    def _sha_lower_hex(cls, v: str) -> str:
        v_low = v.lower()
        if not _SHA256_RE.match(v_low):
            msg = "sha256 must be 64 lowercase hex characters"
            raise ValueError(msg)
        return v_low

    @field_validator("url")
    @classmethod
    def _url_shape(cls, v: str) -> str:
        """Reject anything that is not a GitHub release download.

        This is the shape gate — https, ``github.com``, a
        ``…/releases/download/<tag>/<asset>`` path — and it runs wherever a
        manifest is parsed. Which *repository* the download must belong to is
        checked in :func:`fetch`, where the locally-configured pin is known.
        """
        return check_artifact_origin(v)


class ArtifactSet(BaseModel):
    """The pair of artifacts referenced by a manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent: ArtifactRef
    updater: ArtifactRef


class UpdateManifest(BaseModel):
    """Signed release manifest (see design §4.7)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    channel: str
    released_at: str
    mandatory: bool = False
    notes_url: str
    artifacts: ArtifactSet
    min_updater_version: str

    @field_validator("version", "min_updater_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _VERSION_RE.match(v):
            msg = f"version {v!r} not semver-like (X.Y.Z)"
            raise ValueError(msg)
        return v

    @field_validator("channel")
    @classmethod
    def _channel(cls, v: str) -> str:
        if v not in {"stable", "beta", "dev"}:
            msg = "channel must be one of stable|beta|dev"
            raise ValueError(msg)
        return v

    @field_validator("notes_url")
    @classmethod
    def _notes_url(cls, v: str) -> str:
        # Not origin-pinned (release notes may legitimately live elsewhere),
        # but it may end up in front of a user, so no cleartext and no
        # javascript:/file: smuggling.
        if not v.startswith("https://"):
            msg = "notes_url must be https://"
            raise ValueError(msg)
        return v


def select_release(releases: object, channel: str) -> dict[str, Any]:
    """The newest published release *channel* accepts, from a GitHub list payload.

    Drafts are skipped (they have no downloadable assets). Each remaining
    release's own channel comes from :func:`~channels.channel_of_release`, and
    the newest of the acceptable ones is chosen by SemVer precedence over the
    tag rather than by the order GitHub happened to return — a re-tagged or
    back-dated release must not be able to present itself as the newest one.

    Args:
        releases: the decoded ``GET /repos/<repo>/releases`` body.
        channel: the owner's configured channel.

    Returns:
        The chosen release object.

    Raises:
        UpdateFeedError: if the payload is not a list of releases at all.
        NoMatchingReleaseError: if nothing in it is on *channel*.
    """
    if not isinstance(releases, list):
        msg = (
            "GitHub's release list was not a list "
            f"(got {type(releases).__name__}); the update feed cannot be read"
        )
        raise UpdateFeedError(msg)

    seen: Counter[str] = Counter()
    unusable: list[str] = []
    best: dict[str, Any] | None = None
    best_key = None

    for entry in releases:
        if not isinstance(entry, dict) or entry.get("draft"):
            continue
        tag = str(entry.get("tag_name") or "")
        entry_channel = channel_of_release(tag, prerelease=bool(entry.get("prerelease")))
        seen[entry_channel] += 1
        if not accepts(channel, entry_channel):
            continue
        try:
            key = version_key(tag.lstrip("vV"))
        except ValueError:
            # On the right channel but the tag is not a version we can order.
            # Skipped rather than guessed at, and reported if nothing else fits.
            unusable.append(tag)
            continue
        if best_key is None or key > best_key:
            best, best_key = entry, key

    if best is None:
        raise NoMatchingReleaseError(channel, seen=seen, unusable_tags=unusable)
    return best


async def _get_pinned(
    http: httpx.AsyncClient,
    url: str,
    *,
    check_initial: Callable[[str], str],
    headers: Mapping[str, str] | None = None,
) -> httpx.Response:
    """GET *url* with the update-source pin enforced at every stage.

    The initial URL goes through *check_initial*; redirects are followed by
    hand — with ``follow_redirects=False`` on each request, so the caller's
    client settings cannot quietly hand control of the chain to the server —
    and each hop is checked against the redirect allowlist.

    Raises:
        SourcePinError: the initial URL or some hop is off the pinned source,
            or the chain is longer than :data:`MAX_REDIRECTS`.
    """
    check_initial(url)
    current = url
    for _ in range(MAX_REDIRECTS):
        resp = await http.get(current, headers=dict(headers or {}), follow_redirects=False)
        if resp.status_code not in REDIRECT_STATUS:
            if resp.status_code >= _HTTP_ERROR_STATUS:
                # Raised as our own type, carrying the status, so the poller can
                # tell the owner *what GitHub said* rather than "fetch failed".
                msg = f"GitHub answered HTTP {resp.status_code} for {current}"
                raise UpdateFeedError(msg, status_code=resp.status_code)
            return resp
        current = resolve_redirect(current, resp.headers.get("location", ""))
    msg = f"update fetch exceeded {MAX_REDIRECTS} redirects starting at {url}"
    raise SourcePinError(msg)


async def fetch(
    github_repo: str,
    http: httpx.AsyncClient,
    *,
    channel: str = "stable",
) -> tuple[UpdateManifest, bytes, bytes]:
    """Fetch and parse the newest release manifest on *channel*.

    Reads the repository's release **list** and selects from it (see
    :func:`select_release`). The previous implementation asked for
    ``/releases/latest``, which GitHub defines as the newest *non*-prerelease;
    since every release of this project is a prerelease, that endpoint has
    always answered ``404`` and the updater has never seen a release.

    Every request is pinned to *github_repo*'s GitHub release hosting exactly
    as before: the feed must be that repo's ``api.github.com`` endpoint, the
    two asset URLs the API hands back must be that repo's release downloads,
    and redirects may only land on GitHub-operated hosts. See
    :mod:`workstation_agent.updater_client.source_pin`.

    Returns a tuple of ``(manifest, raw_manifest_bytes, signature_bytes)``.
    The raw bytes are exactly what the server sent — they are the input to
    the Ed25519 verifier and must NOT be re-serialised before verification.

    Args:
        github_repo: e.g. ``"synssins/PersonaCore-Agent"``. A local setting;
            never taken from the payload being validated.
        http: an ``httpx.AsyncClient`` (or drop-in test double).
        channel: the owner's configured channel; also a local setting.

    Raises:
        SourcePinError: if the feed, an asset URL, or a redirect leaves the
            pinned repository's GitHub release hosting.
        UpdateFeedError: if GitHub answered with an error status, or with
            something that is not a release list.
        NoMatchingReleaseError: if nothing published is on *channel*.
        ValueError: if the chosen release is missing the manifest or its
            signature.
    """
    pin = SourcePin(github_repo)
    resp = await _get_pinned(
        http,
        pin.api_releases_url,
        check_initial=pin.check_api_url,
        headers={"Accept": "application/vnd.github+json"},
    )
    release = select_release(resp.json(), channel)

    manifest_url: str | None = None
    sig_url: str | None = None
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name == "manifest.json":
            manifest_url = asset.get("browser_download_url")
        elif name == "manifest.json.sig":
            sig_url = asset.get("browser_download_url")

    if not manifest_url or not sig_url:
        tag = release.get("tag_name") or "(untagged)"
        msg = (
            f"the newest {channel} release ({tag}) has no manifest.json and/or "
            "manifest.json.sig asset, so there is nothing signed to install"
        )
        raise ValueError(msg)

    # The API response is payload, not authority: its download URLs get the
    # same stage-1 gate as anything the manifest itself names.
    manifest_bytes = (
        await _get_pinned(http, manifest_url, check_initial=pin.check_artifact_url)
    ).content
    sig_bytes = (await _get_pinned(http, sig_url, check_initial=pin.check_artifact_url)).content

    manifest = UpdateManifest.model_validate_json(manifest_bytes)
    # The model gate proved the artifacts are GitHub release downloads; this
    # proves they are *this* repository's.
    pin.check_artifact_url(manifest.artifacts.agent.url)
    pin.check_artifact_url(manifest.artifacts.updater.url)
    return manifest, manifest_bytes, sig_bytes
