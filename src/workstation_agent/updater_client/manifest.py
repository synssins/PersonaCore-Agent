"""Update manifest schema and fetch helpers.

Matches design §4.7. Canonical JSON serialisation must byte-match the Go
updater's implementation so a single Ed25519 signature verifies on both sides.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

from workstation_agent.updater_client.source_pin import (
    MAX_REDIRECTS,
    REDIRECT_STATUS,
    SourcePin,
    SourcePinError,
    check_artifact_origin,
    resolve_redirect,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    import httpx


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


_SEMVER_PARTS = 3


def _parse_version(v: str) -> tuple[int, int, int]:
    """Parse an X.Y.Z version, ignoring any pre-release/build suffix."""
    core = re.split(r"[-+]", v, maxsplit=1)[0]
    parts = core.split(".")
    if len(parts) != _SEMVER_PARTS:
        msg = f"invalid version: {v!r}"
        raise ValueError(msg)
    return int(parts[0]), int(parts[1]), int(parts[2])


def is_newer(candidate: str, current: str) -> bool:
    """True if *candidate* > *current*, using numeric semver comparison."""
    return _parse_version(candidate) > _parse_version(current)


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
            resp.raise_for_status()
            return resp
        current = resolve_redirect(current, resp.headers.get("location", ""))
    msg = f"update fetch exceeded {MAX_REDIRECTS} redirects starting at {url}"
    raise SourcePinError(msg)


async def fetch(
    github_repo: str,
    http: httpx.AsyncClient,
) -> tuple[UpdateManifest, bytes, bytes]:
    """Fetch and parse the latest release manifest.

    Every request is pinned to *github_repo*'s GitHub release hosting: the
    manifest feed must be that repo's ``api.github.com`` endpoint, the two
    asset URLs the API hands back must be that repo's release downloads, and
    redirects may only land on GitHub-operated hosts. See
    :mod:`workstation_agent.updater_client.source_pin`.

    Returns a tuple of ``(manifest, raw_manifest_bytes, signature_bytes)``.
    The raw bytes are exactly what the server sent — they are the input to
    the Ed25519 verifier and must NOT be re-serialised before verification.

    Args:
        github_repo: e.g. ``"synssins/PersonaCore-Agent"``. A local setting;
            never taken from the payload being validated.
        http: an ``httpx.AsyncClient`` (or drop-in test double).

    Raises:
        SourcePinError: if the feed, an asset URL, or a redirect leaves the
            pinned repository's GitHub release hosting.
        ValueError: if the release is missing the manifest or its signature.
    """
    pin = SourcePin(github_repo)
    resp = await _get_pinned(
        http,
        pin.api_latest_release_url,
        check_initial=pin.check_api_url,
        headers={"Accept": "application/vnd.github+json"},
    )
    payload = resp.json()

    manifest_url: str | None = None
    sig_url: str | None = None
    for asset in payload.get("assets", []):
        name = asset.get("name", "")
        if name == "manifest.json":
            manifest_url = asset.get("browser_download_url")
        elif name == "manifest.json.sig":
            sig_url = asset.get("browser_download_url")

    if not manifest_url or not sig_url:
        msg = "release missing manifest.json and/or manifest.json.sig assets"
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
