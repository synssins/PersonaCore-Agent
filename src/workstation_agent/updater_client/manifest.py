"""Update manifest schema and fetch helpers.

Matches design §4.7. Canonical JSON serialisation must byte-match the Go
updater's implementation so a single Ed25519 signature verifies on both sides.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
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
        if not v.startswith(("http://", "https://")):
            msg = "url must be http:// or https://"
            raise ValueError(msg)
        return v


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


async def fetch(
    github_repo: str,
    http: httpx.AsyncClient,
) -> tuple[UpdateManifest, bytes, bytes]:
    """Fetch and parse the latest release manifest.

    Returns a tuple of ``(manifest, raw_manifest_bytes, signature_bytes)``.
    The raw bytes are exactly what the server sent — they are the input to
    the Ed25519 verifier and must NOT be re-serialised before verification.

    Args:
        github_repo: e.g. ``"synssins/PersonaCore-Agent"``.
        http: an ``httpx.AsyncClient`` (or drop-in test double).
    """
    api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
    resp = await http.get(api_url, headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
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

    manifest_bytes = (await http.get(manifest_url)).content
    sig_bytes = (await http.get(sig_url)).content

    manifest = UpdateManifest.model_validate_json(manifest_bytes)
    return manifest, manifest_bytes, sig_bytes
