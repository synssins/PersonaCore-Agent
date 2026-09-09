"""Update-source pinning: downloads may only come from the project's repo.

These tests deliberately live outside ``tests/integration/updater/``, whose
conftest opens a loopback escape for its fixture server. Here the pin is at
full strength, which is the configuration a shipped agent runs in.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from workstation_agent.updater_client.manifest import (
    ArtifactRef,
    UpdateManifest,
    fetch,
)
from workstation_agent.updater_client.source_pin import (
    DEFAULT_REPO,
    MAX_REDIRECTS,
    SourcePin,
    SourcePinError,
    allow_extra_origins,
    check_artifact_origin,
    check_redirect_url,
    resolve_redirect,
)

REPO = DEFAULT_REPO
RELEASE = f"https://github.com/{REPO}/releases/download/v0.2.0"
GOOD_URL = f"{RELEASE}/agent.zip"
CDN_URL = "https://objects.githubusercontent.com/blob/agent.zip"


# ---------------------------------------------------------------------------
# Stage 1: the URL we are handed
# ---------------------------------------------------------------------------


def test_default_pin_is_this_project() -> None:
    assert DEFAULT_REPO == "synssins/PersonaCore-Agent"
    assert SourcePin(DEFAULT_REPO).repo == DEFAULT_REPO


@pytest.mark.parametrize(
    "url",
    [
        GOOD_URL,
        f"https://github.com:443/{REPO}/releases/download/v0.2.0/agent.zip",
        f"https://GITHUB.com/{REPO.upper()}/releases/download/v0.2.0/agent.zip",
        f"https://github.com./{REPO}/releases/download/v0.2.0/agent.zip",
        f"{RELEASE}/Updater.exe?token=abc",
    ],
)
def test_legitimate_release_urls_accepted(url: str) -> None:
    assert SourcePin(REPO).check_artifact_url(url) == url


@pytest.mark.parametrize(
    ("label", "url"),
    [
        ("non-github host", "https://cdn.evil.example/agent.zip"),
        ("non-github host, github-ish path", f"https://evil.example/{REPO}/releases/download/v1/a.zip"),
        ("suffix lookalike", f"https://github.com.evil.example/{REPO}/releases/download/v1/a.zip"),
        ("prefix lookalike", f"https://notgithub.com/{REPO}/releases/download/v1/a.zip"),
        ("plain http", f"http://github.com/{REPO}/releases/download/v1/agent.zip"),
        ("ftp", f"ftp://github.com/{REPO}/releases/download/v1/agent.zip"),
        ("file", "file:///C:/Windows/Temp/agent.zip"),
        ("javascript", "javascript:alert(1)"),
        ("relative", f"/{REPO}/releases/download/v1/agent.zip"),
        ("empty", ""),
        ("credentials", "https://github.com@evil.example/agent.zip"),
        ("odd port", f"https://github.com:8443/{REPO}/releases/download/v1/agent.zip"),
        ("not a release path", f"https://github.com/{REPO}/raw/main/agent.zip"),
        ("truncated release path", f"https://github.com/{REPO}/releases/download/v1"),
        ("traversal", f"https://github.com/{REPO}/releases/download/../../../agent.zip"),
        ("encoded traversal", f"https://github.com/{REPO}/releases/download/%2e%2e/a.zip"),
        ("cdn as a starting point", CDN_URL),
    ],
)
def test_off_origin_artifact_urls_refused(label: str, url: str) -> None:
    with pytest.raises(SourcePinError):
        SourcePin(REPO).check_artifact_url(url)
    assert label  # the id is the documentation


def test_other_repo_refused_even_on_github() -> None:
    pin = SourcePin(REPO)
    # Shape is fine; identity is not. A "curated repo" pin has to check both.
    url = "https://github.com/attacker/lookalike/releases/download/v1/agent.zip"
    assert check_artifact_origin(url) == url
    with pytest.raises(SourcePinError, match="release download of"):
        pin.check_artifact_url(url)


def test_error_does_not_echo_credentials() -> None:
    with pytest.raises(SourcePinError) as exc:
        SourcePin(REPO).check_artifact_url("https://user:hunter2@evil.example/agent.zip")
    assert "hunter2" not in str(exc.value)


@pytest.mark.parametrize(
    "repo",
    ["", "noslash", "/name", "owner/", "owner/name/extra", "owner/../evil",
     "own er/name", "owner/na%2Fme", "https://evil.example/owner/name", "a" * 101 + "/n"],
)
def test_malformed_repo_pin_rejected(repo: str) -> None:
    with pytest.raises(SourcePinError):
        SourcePin(repo)


def test_fork_can_retarget_the_pin() -> None:
    pin = SourcePin("someone-else/PersonaCore-Agent.fork")
    ok = "https://github.com/someone-else/PersonaCore-Agent.fork/releases/download/v1/a.zip"
    assert pin.check_artifact_url(ok) == ok
    with pytest.raises(SourcePinError):
        pin.check_artifact_url(GOOD_URL)


def test_api_url_is_pinned() -> None:
    pin = SourcePin(REPO)
    assert pin.api_latest_release_url == (
        f"https://api.github.com/repos/{REPO}/releases/latest"
    )
    assert pin.check_api_url(pin.api_latest_release_url)
    for bad in [
        f"http://api.github.com/repos/{REPO}/releases/latest",
        f"https://api.evil.example/repos/{REPO}/releases/latest",
        f"https://github.com/repos/{REPO}/releases/latest",
        "https://api.github.com/repos/attacker/evil/releases/latest",
        "https://api.github.com/",
    ]:
        with pytest.raises(SourcePinError):
            pin.check_api_url(bad)


# ---------------------------------------------------------------------------
# Stage 2: the redirect chain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        CDN_URL,
        "https://github-releases.githubusercontent.com/blob/agent.zip",
        "https://release-assets.githubusercontent.com/blob/agent.zip",
        f"https://github.com/{REPO}/releases/download/v1/agent.zip",
        f"https://api.github.com/repos/{REPO}/releases/latest",
    ],
)
def test_github_cdn_redirects_allowed(url: str) -> None:
    assert check_redirect_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/payload",
        "http://objects.githubusercontent.com/blob/agent.zip",
        "https://objects.githubusercontent.com.evil.example/x",
        "https://githubusercontent.com/x",
        "https://objects.githubusercontent.com:8443/x",
        "https://a:b@objects.githubusercontent.com/x",
    ],
)
def test_hostile_redirects_refused(url: str) -> None:
    with pytest.raises(SourcePinError):
        check_redirect_url(url)


def test_relative_redirect_resolves_against_current_url() -> None:
    assert resolve_redirect(GOOD_URL, "/other/asset.zip") == (
        "https://github.com/other/asset.zip"
    )
    with pytest.raises(SourcePinError, match="no Location"):
        resolve_redirect(GOOD_URL, "")
    # A scheme-relative Location must not become a way off the allowlist.
    with pytest.raises(SourcePinError):
        resolve_redirect(GOOD_URL, "//evil.example/payload")


# ---------------------------------------------------------------------------
# The manifest model
# ---------------------------------------------------------------------------


def _manifest_dict(agent_url: str = GOOD_URL) -> dict[str, Any]:
    return {
        "version": "0.2.0",
        "channel": "stable",
        "released_at": "2026-09-15T04:00:00Z",
        "mandatory": False,
        "notes_url": "https://example.invalid/notes",
        "artifacts": {
            "agent": {"url": agent_url, "sha256": "a" * 64, "size": 10},
            "updater": {"url": f"{RELEASE}/Updater.exe", "sha256": "b" * 64, "size": 5},
        },
        "min_updater_version": "0.1.0",
    }


def test_manifest_model_accepts_release_urls() -> None:
    m = UpdateManifest.model_validate(_manifest_dict())
    assert m.artifacts.agent.url == GOOD_URL


@pytest.mark.parametrize(
    "url",
    [
        "https://cdn.evil.example/agent.zip",
        f"http://github.com/{REPO}/releases/download/v1/agent.zip",
        CDN_URL,
        "https://a",
    ],
)
def test_manifest_model_refuses_off_origin_artifacts(url: str) -> None:
    with pytest.raises(ValueError, match="update artifact"):
        UpdateManifest.model_validate(_manifest_dict(url))


def test_manifest_model_refuses_cleartext_notes_url() -> None:
    d = _manifest_dict()
    d["notes_url"] = "http://example.invalid/notes"
    with pytest.raises(ValueError, match="notes_url"):
        UpdateManifest.model_validate(d)


def test_artifact_ref_rejects_http_directly() -> None:
    with pytest.raises(ValueError, match="https"):
        ArtifactRef(url=f"http://github.com/{REPO}/releases/download/v1/a.zip",
                    sha256="a" * 64, size=1)


# ---------------------------------------------------------------------------
# fetch(): the whole chain, with the real hostnames
# ---------------------------------------------------------------------------


class _Resp:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code: int, *, content: bytes = b"", location: str | None = None,
                 payload: Any = None) -> None:  # noqa: ANN401
        self.status_code = status_code
        self.content = content
        self.headers: dict[str, str] = {}
        if location is not None:
            self.headers["location"] = location
        self._payload = payload

    def json(self) -> Any:  # noqa: ANN401
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            msg = f"HTTP {self.status_code}"
            raise RuntimeError(msg)


class _Client:
    """Routing test double that records the exact URLs fetch() reached for."""

    def __init__(self, routes: dict[str, _Resp]) -> None:
        self.routes = routes
        self.seen: list[str] = []

    async def get(self, url: str, **kwargs: Any) -> _Resp:  # noqa: ANN401
        # fetch() must never delegate redirect-following to the client.
        assert kwargs.get("follow_redirects") is False
        self.seen.append(url)
        if url not in self.routes:
            msg = f"unexpected request to {url}"
            raise AssertionError(msg)
        return self.routes[url]


def _release_payload(manifest_url: str, sig_url: str) -> dict[str, Any]:
    return {
        "assets": [
            {"name": "manifest.json", "browser_download_url": manifest_url},
            {"name": "manifest.json.sig", "browser_download_url": sig_url},
        ],
    }


def _fetch_routes(*, manifest_bytes: bytes, sig_redirect_to: str) -> dict[str, _Resp]:
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    m_url = f"{RELEASE}/manifest.json"
    s_url = f"{RELEASE}/manifest.json.sig"
    return {
        api: _Resp(200, payload=_release_payload(m_url, s_url)),
        # GitHub never serves the bytes from github.com — it 302s to the CDN.
        m_url: _Resp(302, location=CDN_URL),
        CDN_URL: _Resp(200, content=manifest_bytes),
        s_url: _Resp(302, location=sig_redirect_to),
        sig_redirect_to: _Resp(200, content=b"signature-bytes"),
    }


async def test_fetch_follows_the_real_github_redirect() -> None:
    manifest_bytes = json.dumps(_manifest_dict()).encode()
    sig_cdn = "https://release-assets.githubusercontent.com/blob/manifest.json.sig"
    client = _Client(_fetch_routes(manifest_bytes=manifest_bytes, sig_redirect_to=sig_cdn))

    manifest, raw, sig = await fetch(REPO, client)  # type: ignore[arg-type]

    assert manifest.version == "0.2.0"
    assert raw == manifest_bytes
    assert sig == b"signature-bytes"
    # The chain really did leave github.com for the CDN.
    assert CDN_URL in client.seen
    assert sig_cdn in client.seen


async def test_fetch_refuses_redirect_to_hostile_host() -> None:
    manifest_bytes = json.dumps(_manifest_dict()).encode()
    client = _Client(
        _fetch_routes(manifest_bytes=manifest_bytes,
                      sig_redirect_to="https://evil.example/payload"),
    )
    with pytest.raises(SourcePinError, match="left the pinned update source"):
        await fetch(REPO, client)  # type: ignore[arg-type]
    assert "https://evil.example/payload" not in client.seen


async def test_fetch_refuses_off_origin_asset_url_from_the_api() -> None:
    """The API response is payload too — its download URLs get gated."""
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    hostile = "https://evil.example/manifest.json"
    client = _Client({
        api: _Resp(200, payload=_release_payload(hostile, f"{RELEASE}/manifest.json.sig")),
        hostile: _Resp(200, content=b"{}"),
    })
    with pytest.raises(SourcePinError):
        await fetch(REPO, client)  # type: ignore[arg-type]
    assert hostile not in client.seen


async def test_fetch_refuses_a_manifest_naming_another_repo() -> None:
    """Shape-valid, signature-irrelevant: it is simply not our repo."""
    other = _manifest_dict("https://github.com/attacker/evil/releases/download/v1/agent.zip")
    manifest_bytes = json.dumps(other).encode()
    client = _Client(
        _fetch_routes(manifest_bytes=manifest_bytes,
                      sig_redirect_to="https://objects.githubusercontent.com/sig"),
    )
    with pytest.raises((SourcePinError, ValueError)):
        await fetch(REPO, client)  # type: ignore[arg-type]


async def test_fetch_caps_the_redirect_chain() -> None:
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    loop = "https://objects.githubusercontent.com/loop"
    client = _Client({api: _Resp(302, location=loop), loop: _Resp(302, location=loop)})
    with pytest.raises(SourcePinError, match="redirects"):
        await fetch(REPO, client)  # type: ignore[arg-type]
    assert len(client.seen) <= MAX_REDIRECTS


# ---------------------------------------------------------------------------
# The test escape is process-local and narrow
# ---------------------------------------------------------------------------


def test_extra_origins_are_scoped_and_reverted() -> None:
    local = "http://127.0.0.1:5051/agent.zip"
    with pytest.raises(SourcePinError):
        check_artifact_origin(local)
    with allow_extra_origins("http://127.0.0.1"):
        assert check_artifact_origin(local) == local
        assert check_redirect_url("http://127.0.0.1:9/x")
        # Still narrow: a different host is not covered.
        with pytest.raises(SourcePinError):
            check_artifact_origin("http://127.0.0.2:5051/agent.zip")
        with pytest.raises(SourcePinError):
            check_artifact_origin("https://evil.example/agent.zip")
    # And it is gone again afterwards.
    with pytest.raises(SourcePinError):
        check_artifact_origin(local)


@pytest.mark.parametrize("origin", ["justahost", "http://[::1", "://x"])
def test_extra_origin_must_be_scheme_and_host(origin: str) -> None:
    with pytest.raises(SourcePinError), allow_extra_origins(origin):
        pass  # pragma: no cover - the context manager raises on entry


@pytest.mark.parametrize(
    "url",
    ["https://github.com:notaport/a.zip", "https://[::1/a.zip", "http://"],
)
def test_malformed_urls_are_refused_not_crashed(url: str) -> None:
    """A garbage URL must produce a stated refusal, not an unhandled error."""
    with pytest.raises(SourcePinError):
        SourcePin(REPO).check_artifact_url(url)
    with pytest.raises(SourcePinError):
        check_redirect_url(url)
