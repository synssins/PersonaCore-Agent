"""Pin update traffic to the project's own GitHub repository.

The agent downloads code that it then executes, so *where* an update may come
from is part of the trust boundary — not something the manifest gets to
choose. Signing makes a forged manifest hard; pinning the source makes a
manifest that somehow got through unable to point the download anywhere but
GitHub's release hosting for one specific repository.

Two stages, deliberately different, and mirrored by ``updater/internal/origin``
on the Go side:

Stage 1 — the URL we are handed
    Whatever the manifest (or the GitHub API payload, which is just as
    untrusted) names must be an ``https://github.com/<owner>/<repo>/releases/
    download/<tag>/<asset>`` URL on the default port; the manifest *feed*
    itself must be ``https://api.github.com/repos/<owner>/<repo>/…``. Nothing
    else ever starts a request. ``http://`` is refused outright.

Stage 2 — every hop of the redirect chain
    GitHub does not serve release bytes from ``github.com``: an asset request
    302s to GitHub's user-content CDN, and that hostname has changed over the
    years (``objects.``, ``github-releases.``, ``release-assets.``
    ``githubusercontent.com``). So a redirect may land on ``github.com``,
    ``api.github.com``, or any host under ``githubusercontent.com`` — a
    namespace GitHub allocates, not one users can claim — over https on the
    default port, and nowhere else. Anything else raises; there is no silent
    fallback.

Configurability
    The repo is a *local* setting (``update.github_repo`` in config.toml), so
    a fork is not permanently broken. It can never be sourced from the payload
    being validated. :func:`allow_extra_origins` is a test-only escape used by
    this repository's own suite to point the client at a fixture server; it is
    process-local and nothing outside this process can set it.
"""

from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote, urljoin, urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterator

DEFAULT_REPO: Final = "synssins/PersonaCore-Agent"

GITHUB_HOST: Final = "github.com"
GITHUB_API_HOST: Final = "api.github.com"
#: GitHub allocates every label under this domain, so the set stays
#: GitHub-operated even as the release-asset hostname churns.
USER_CONTENT_SUFFIX: Final = ".githubusercontent.com"

MAX_REDIRECTS: Final = 5
REDIRECT_STATUS: Final = frozenset({301, 302, 303, 307, 308})

_REPO_SEGMENT_RE: Final = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_RELEASE_PATH_SEGMENTS: Final = 6
_API_PATH_SEGMENTS: Final = 3

# Test-only, process-local widening of the allowlist. Empty in every real run.
_extra_origins: tuple[tuple[str, str], ...] = ()


class SourcePinError(ValueError):
    """An update URL was not on the pinned update source."""


@contextlib.contextmanager
def allow_extra_origins(*origins: str) -> Iterator[None]:
    """Temporarily permit extra ``scheme://host`` origins (test-only).

    Ports are ignored, so ``"http://127.0.0.1"`` covers a fixture server on
    any port. This exists so the test-suite can exercise the real code paths
    against a local server; production code must never call it.
    """
    global _extra_origins  # noqa: PLW0603 - deliberate process-local test escape
    previous = _extra_origins
    parsed: list[tuple[str, str]] = []
    for raw in origins:
        try:
            parts = urlsplit(raw.strip())
            host = _normalise_host(parts.hostname)
        except ValueError as exc:
            msg = f"extra origin {raw!r} is unparseable: {exc}"
            raise SourcePinError(msg) from exc
        if not parts.scheme or not host:
            msg = f"extra origin {raw!r} must be scheme://host"
            raise SourcePinError(msg)
        parsed.append((parts.scheme.lower(), host))
    _extra_origins = tuple(parsed)
    try:
        yield
    finally:
        _extra_origins = previous


def _normalise_host(host: str | None) -> str:
    return (host or "").strip().lower().rstrip(".")


def _redact(raw: str) -> str:
    """Render a URL for an error message without leaking any userinfo.

    Never raises: it is only ever called while building an error, and a
    malformed URL must not turn a clean refusal into a crash.
    """
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if not parts.scheme or not host:
            return raw[:200]
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "<malformed URL>"
    return f"{parts.scheme}://{host}{port}{parts.path}"


def _split(raw: str) -> tuple[str, str, int | None, str]:
    """Return ``(scheme, host, port, path)``, rejecting shapes we never want.

    Raises:
        SourcePinError: unparseable, relative, or carrying embedded
            credentials (a classic way to make a hostile URL *look* like it
            points at github.com).
    """
    if not isinstance(raw, str) or not raw.strip():
        msg = "update URL is empty"
        raise SourcePinError(msg)
    try:
        parts = urlsplit(raw.strip())
        port = parts.port
    except ValueError as exc:  # malformed netloc / non-numeric port
        msg = f"unparseable update URL: {exc}"
        raise SourcePinError(msg) from exc
    host = _normalise_host(parts.hostname)
    if not parts.scheme or not host:
        msg = f"update URL {_redact(raw)!r} is not an absolute URL"
        raise SourcePinError(msg)
    if parts.username or parts.password:
        msg = f"refusing update URL with embedded credentials: {_redact(raw)}"
        raise SourcePinError(msg)
    return parts.scheme.lower(), host, port, parts.path


def _matches_extra(scheme: str, host: str) -> bool:
    return (scheme, host) in _extra_origins


def _require_https(scheme: str, port: int | None, raw: str, what: str) -> None:
    if scheme != "https":
        msg = f"{what} must use https, got {scheme!r} in {_redact(raw)}"
        raise SourcePinError(msg)
    if port is not None and port != 443:  # noqa: PLR2004 - the https port
        msg = f"{what} must use the default https port, got :{port}"
        raise SourcePinError(msg)


def _segments(path: str, raw: str) -> list[str]:
    out: list[str] = []
    for seg in path.strip("/").split("/"):
        if not seg:
            continue
        decoded = unquote(seg)
        if decoded in {".", ".."} or "/" in decoded or "\\" in decoded:
            msg = f"refusing path traversal in {_redact(raw)}"
            raise SourcePinError(msg)
        out.append(decoded)
    return out


def _is_redirect_host(host: str) -> bool:
    if host in {GITHUB_HOST, GITHUB_API_HOST}:
        return True
    # Sub-domains only; the bare apex is not a release host.
    return host.endswith(USER_CONTENT_SUFFIX) and len(host) > len(USER_CONTENT_SUFFIX)


def check_artifact_origin(url: str) -> str:
    """Stage-1 shape check for a download URL, independent of which repo.

    Enforces https on ``github.com`` and a ``…/releases/download/<tag>/<asset>``
    path. Used by the manifest model, which is parsed before anyone knows which
    repository the caller pinned; :meth:`SourcePin.check_artifact_url` adds the
    repository identity on top.

    Returns:
        The URL unchanged, so it can be used as a pydantic validator.

    Raises:
        SourcePinError: if the URL is not a GitHub release download.
    """
    scheme, host, port, path = _split(url)
    if _matches_extra(scheme, host):
        return url
    _require_https(scheme, port, url, "update artifact URL")
    if host != GITHUB_HOST:
        msg = f"update artifact host {host!r} is not the pinned update source ({GITHUB_HOST})"
        raise SourcePinError(msg)
    segs = _segments(path, url)
    if len(segs) < _RELEASE_PATH_SEGMENTS or segs[2:4] != ["releases", "download"]:
        msg = f"update artifact URL {_redact(url)} is not a GitHub release download"
        raise SourcePinError(msg)
    return url


def check_redirect_url(url: str) -> str:
    """Stage-2 check: a redirect hop must stay on GitHub-operated hosts.

    Raises:
        SourcePinError: if the hop leaves the allowlist or downgrades to http.
    """
    scheme, host, port, _path = _split(url)
    if _matches_extra(scheme, host):
        return url
    _require_https(scheme, port, url, "update redirect")
    if not _is_redirect_host(host):
        msg = (
            f"update redirect to {host!r} left the pinned update source "
            f"(github.com or *{USER_CONTENT_SUFFIX})"
        )
        raise SourcePinError(msg)
    return url


class SourcePin:
    """An immutable pin to one ``owner/name`` GitHub repository."""

    __slots__ = ("_name", "_owner")

    def __init__(self, repo: str) -> None:
        """Build a pin for ``repo``.

        Args:
            repo: ``"owner/name"``. Comes from local configuration or the
                built-in default — never from a fetched payload.

        Raises:
            SourcePinError: if *repo* is not a plain ``owner/name`` pair. The
                strictness matters: the value is interpolated into a URL path,
                so anything exotic here could move the request off GitHub.
        """
        owner, _, name = (repo or "").strip().partition("/")
        if not _REPO_SEGMENT_RE.match(owner) or not _REPO_SEGMENT_RE.match(name):
            msg = f"update repo pin {repo!r} must be 'owner/name' using [A-Za-z0-9._-]"
            raise SourcePinError(msg)
        self._owner = owner
        self._name = name

    @property
    def repo(self) -> str:
        """The pinned ``owner/name``."""
        return f"{self._owner}/{self._name}"

    @property
    def api_latest_release_url(self) -> str:
        """This repo's ``/releases/latest`` endpoint.

        **Not what the poller reads**, and it never should have been.
        ``/releases/latest`` excludes prereleases by definition, and every
        release this project has published is one, so the endpoint answers
        ``404`` — see :attr:`api_releases_url`. Kept because it is a correct
        URL for the pin to *describe* (and the Go side mirrors it), so that a
        caller who genuinely wants the newest non-prerelease still gets a
        pinned URL rather than building one by hand.
        """
        return f"https://{GITHUB_API_HOST}/repos/{self.repo}/releases/latest"

    @property
    def api_releases_url(self) -> str:
        """The manifest feed the poller reads: this repo's release *list*.

        Listing is what lets the channel mean anything — the client picks the
        newest release matching the owner's channel (see
        :mod:`workstation_agent.updater_client.channels`) instead of asking
        GitHub for the one release type this project does not publish.

        ``per_page`` bounds the response; the pin is unaffected by it, since
        :meth:`check_api_url` reads the path and ignores the query.
        """
        return f"https://{GITHUB_API_HOST}/repos/{self.repo}/releases?per_page=100"

    def _repo_matches(self, owner: str, name: str) -> bool:
        # GitHub treats owner/repo case-insensitively; do not fail an update
        # over capitalisation.
        return owner.lower() == self._owner.lower() and name.lower() == self._name.lower()

    def check_artifact_url(self, url: str) -> str:
        """Stage-1 check for a download URL, including repository identity.

        Raises:
            SourcePinError: if the URL is not a release download of this repo.
        """
        check_artifact_origin(url)
        scheme, host, _port, path = _split(url)
        if _matches_extra(scheme, host):
            return url
        segs = _segments(path, url)
        if not self._repo_matches(segs[0], segs[1]):
            msg = f"update artifact URL {_redact(url)} is not a release download of {self.repo}"
            raise SourcePinError(msg)
        return url

    def check_api_url(self, url: str) -> str:
        """Stage-1 check for a GitHub REST URL scoped to this repository.

        Raises:
            SourcePinError: if the URL is not this repo's API endpoint.
        """
        scheme, host, port, path = _split(url)
        if _matches_extra(scheme, host):
            return url
        _require_https(scheme, port, url, "update manifest API URL")
        if host != GITHUB_API_HOST:
            msg = f"manifest API host {host!r} is not {GITHUB_API_HOST}"
            raise SourcePinError(msg)
        segs = _segments(path, url)
        if (
            len(segs) < _API_PATH_SEGMENTS
            or segs[0] != "repos"
            or not self._repo_matches(segs[1], segs[2])
        ):
            msg = f"manifest API URL {_redact(url)} is not scoped to {self.repo}"
            raise SourcePinError(msg)
        return url


def resolve_redirect(current_url: str, location: str) -> str:
    """Resolve a ``Location`` header against *current_url* and pin-check it.

    Raises:
        SourcePinError: if the header is missing/empty or the resolved hop is
            not on the allowlist.
    """
    if not location or not location.strip():
        msg = f"update redirect from {_redact(current_url)} had no Location header"
        raise SourcePinError(msg)
    return check_redirect_url(urljoin(current_url, location.strip()))
