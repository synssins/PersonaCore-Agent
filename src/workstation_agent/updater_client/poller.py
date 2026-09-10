"""Async update poller, and the record of what the last check actually found.

Runs fetch -> verify -> compare version -> notify callback on a
configurable schedule. Can also be nudged to poll immediately via
:meth:`UpdatePoller.check_now`, or run synchronously via
:meth:`UpdatePoller.poll_once` when a caller wants the answer now.

No I/O beyond the injected ``httpx.AsyncClient`` — this module owns no
state that persists across the process; callers are responsible for
scheduling and for filesystem writes (see :mod:`handoff`).

Why every check now leaves a record
-----------------------------------

The poller used to answer every question with ``None`` and a log line. From
outside there was no way to tell apart:

* "I asked GitHub and there is nothing newer than what you are running" —
  the only one of these that means you are up to date;
* "I could not reach GitHub at all";
* "GitHub answered, and the answer was 404" — which is what it answered for
  the whole life of this project, because the client asked ``/releases/latest``
  and every release here is a prerelease;
* "GitHub answered with a release, but its manifest is not signed by the key
  this build trusts" — which is an attack or a broken release, not silence;
* "your configured channel is not one I recognise, so I did not ask anything".

Those are five different situations with five different next actions, and the
owner was shown the same nothing for all of them. :class:`UpdateCheckResult`
is the fix: every check ends by recording what happened, in a sentence a person
can act on, and :attr:`UpdatePoller.last_check` is what the About page renders.
The rule is the same one the endpoint block follows — report what is true, not
what was configured.

**Notify, do not install.** A successful check that finds a build records it
and fires ``on_update_available``; it does not install anything. The owner
takes the update by clicking for it (``POST /about/install``), or by opting in
to ``update.auto_install``, which is off by default.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

import httpx

from workstation_agent.updater_client.channels import normalise_channel
from workstation_agent.updater_client.manifest import (
    NoMatchingReleaseError,
    UpdateFeedError,
    UpdateManifest,
    fetch,
    is_newer,
)
from workstation_agent.updater_client.source_pin import SourcePinError
from workstation_agent.updater_client.verifier import verify as _verify

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

OnUpdateCallback = Callable[[UpdateManifest, bytes, bytes], Awaitable[None]]
"""Callback fired when a verified newer manifest is discovered.

Receives ``(manifest, raw_manifest_bytes, signature_bytes)`` so the
handler can persist the verified pair to ``pending_update.json``.
"""

_RATE_LIMIT_STATUS = frozenset({403, 429})
_NOT_FOUND_STATUS = 404


class UpdateCheckOutcome(StrEnum):
    """What a single update check concluded.

    Exactly two of these mean the check worked: :attr:`UPDATE_AVAILABLE` and
    :attr:`UP_TO_DATE`. Everything else is a failure that must not be
    presented as "you are up to date".
    """

    UPDATE_AVAILABLE = "update_available"
    UP_TO_DATE = "up_to_date"
    NO_RELEASE_ON_CHANNEL = "no_release_on_channel"
    REFUSED_BY_GITHUB = "refused_by_github"
    UNREACHABLE = "unreachable"
    UNTRUSTED = "untrusted"
    UNREADABLE = "unreadable"
    MISCONFIGURED = "misconfigured"


#: Short label per outcome, for the heading above the sentence.
_HEADLINES: Mapping[UpdateCheckOutcome, str] = {
    UpdateCheckOutcome.UPDATE_AVAILABLE: "Update available",
    UpdateCheckOutcome.UP_TO_DATE: "Up to date",
    UpdateCheckOutcome.NO_RELEASE_ON_CHANNEL: "Check failed — nothing on this channel",
    UpdateCheckOutcome.REFUSED_BY_GITHUB: "Check failed — GitHub refused the request",
    UpdateCheckOutcome.UNREACHABLE: "Check failed — GitHub could not be reached",
    UpdateCheckOutcome.UNTRUSTED: "Check failed — the release could not be trusted",
    UpdateCheckOutcome.UNREADABLE: "Check failed — the release could not be read",
    UpdateCheckOutcome.MISCONFIGURED: "Check not attempted — update settings",
}

_SUCCEEDED = frozenset({
    UpdateCheckOutcome.UPDATE_AVAILABLE,
    UpdateCheckOutcome.UP_TO_DATE,
})


@dataclass(frozen=True, slots=True)
class UpdateCheckResult:
    """The outcome of one update check, in terms a person can act on.

    Rendered by ``GET /about``. ``message`` is a complete sentence or three,
    written for the owner rather than for a log grep — every failure says what
    failed, and says in as many words that it is *not* the same as being up to
    date, because that conflation is the defect this type exists to end.
    """

    outcome: UpdateCheckOutcome
    checked_at: datetime
    channel: str
    current_version: str
    message: str
    available_version: str | None = None
    notes_url: str | None = None

    @property
    def succeeded(self) -> bool:
        """True only when the check reached a real answer about the version."""
        return self.outcome in _SUCCEEDED

    @property
    def failed(self) -> bool:
        """True when nothing was compared against the running version."""
        return not self.succeeded

    @property
    def headline(self) -> str:
        """Short label for the outcome."""
        return _HEADLINES[self.outcome]

    @property
    def checked_at_text(self) -> str:
        """``checked_at`` as a plain UTC timestamp for the page."""
        return self.checked_at.strftime("%Y-%m-%d %H:%M:%S UTC")


#: Appended to every failure. The owner's question is always "does this mean
#: I'm current?", and for all of these the answer is "no, and nothing was
#: compared", so the answer is written down rather than implied.
_NOT_UP_TO_DATE = (
    "Nothing was compared against the version you are running, so this is not "
    "the same as being up to date."
)


class UpdatePoller:
    """Poll a GitHub Releases feed on a fixed schedule."""

    def __init__(  # noqa: PLR0913 - config-style constructor
        self,
        *,
        github_repo: str,
        current_version: str,
        pubkey: bytes,
        http: httpx.AsyncClient,
        on_update_available: OnUpdateCallback,
        poll_interval_seconds: float = 6 * 3600.0,
        channel: str = "stable",
    ) -> None:
        self._repo = github_repo
        self._current_version = current_version
        self._pubkey = pubkey
        self._http = http
        self._on_update = on_update_available
        self._interval = poll_interval_seconds
        self._channel = channel
        self._nudge = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._last_check: UpdateCheckResult | None = None
        self._pending: tuple[UpdateManifest, bytes, bytes] | None = None

    # ------------------------------------------------------------------
    # State the UI reads
    # ------------------------------------------------------------------

    @property
    def channel(self) -> str:
        """The channel the next check will use."""
        return self._channel

    @property
    def current_version(self) -> str:
        """The version this poller compares releases against."""
        return self._current_version

    @property
    def repo(self) -> str:
        """The pinned ``owner/name`` this poller reads releases from."""
        return self._repo

    @property
    def last_check(self) -> UpdateCheckResult | None:
        """The most recent :class:`UpdateCheckResult`, or ``None`` before any."""
        return self._last_check

    @property
    def pending(self) -> tuple[UpdateManifest, bytes, bytes] | None:
        """The verified ``(manifest, raw, signature)`` last found, if any.

        Held so the owner's "Install" click has something to stage without
        re-fetching — and so that what gets installed is the exact bytes that
        verified, not a second download that might not be the same.
        """
        return self._pending

    def set_channel(self, channel: str) -> None:
        """Change the channel used from the *next* check onwards.

        Takes effect without a restart: the channel is read at the top of
        every :meth:`poll_once`, so a change made in the UI applies to the
        check the same click triggers.
        """
        self._channel = channel

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background polling task."""
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="update-poller")

    async def stop(self) -> None:
        """Signal shutdown and await the polling task."""
        self._stop.set()
        self._nudge.set()
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def check_now(self) -> None:
        """Nudge the background loop to run a check immediately.

        Fire-and-forget. A caller that wants the *answer* should await
        :meth:`poll_once` instead — the About page does, so the owner sees the
        outcome of the check his click caused rather than of the one before it.
        """
        self._nudge.set()

    # ------------------------------------------------------------------
    # A single check
    # ------------------------------------------------------------------

    def _record(
        self,
        outcome: UpdateCheckOutcome,
        message: str,
        *,
        available_version: str | None = None,
        notes_url: str | None = None,
    ) -> None:
        self._last_check = UpdateCheckResult(
            outcome=outcome,
            checked_at=datetime.now(UTC),
            channel=self._channel,
            current_version=self._current_version,
            message=message,
            available_version=available_version,
            notes_url=notes_url,
        )

    def _refusal_message(self, exc: UpdateFeedError) -> str:
        """Plain English for a status GitHub answered the feed request with."""
        status = exc.status_code
        if status == _NOT_FOUND_STATUS:
            hint = (
                f"A 404 means GitHub has no releases endpoint for {self._repo} — "
                "the repository has been renamed, deleted, or made private to "
                "this machine. Check the update repository setting."
            )
        elif status in _RATE_LIMIT_STATUS:
            hint = (
                "GitHub rate-limits unauthenticated callers by IP address. "
                "This usually clears within the hour; press Check for updates "
                "now again later."
            )
        elif status is None:
            hint = "GitHub's answer could not be used."
        else:
            hint = "That is GitHub refusing the request, not an empty result."
        shown = f"HTTP {status}" if status is not None else "an unusable answer"
        return (
            f"GitHub was reached and refused the request with {shown}. "
            f"{_NOT_UP_TO_DATE} {hint}"
        )

    def _unreachable_message(self, exc: httpx.RequestError) -> str:
        """Plain English for a request that never got an answer at all."""
        detail = str(exc).strip() or exc.__class__.__name__
        return (
            f"GitHub could not be reached at all ({exc.__class__.__name__}: "
            f"{detail}). The request never got an answer from a server. "
            f"{_NOT_UP_TO_DATE} Check this machine's network connection and "
            "anything filtering it — a proxy, a VPN, a firewall — then press "
            "Check for updates now again."
        )

    def _no_release_message(self, exc: NoMatchingReleaseError) -> str:
        elsewhere = ", ".join(
            f"{count} on {name}" for name, count in sorted(exc.seen.items())
        )
        if elsewhere:
            where = (
                f"The repository does publish releases ({elsewhere}), so "
                f"switching channels below would find one."
            )
        else:
            where = f"{self._repo} has published no releases at all."
        unusable = ""
        if exc.unusable_tags:
            tags = ", ".join(exc.unusable_tags[:5])
            unusable = (
                f" {len(exc.unusable_tags)} release(s) on this channel were "
                f"skipped because their tags are not version numbers ({tags})."
            )
        return (
            f"GitHub answered, and nothing it has published is on the "
            f"{self._channel} channel. {_NOT_UP_TO_DATE} {where}{unusable}"
        )

    async def _fetch_or_record(self) -> tuple[UpdateManifest, bytes, bytes] | None:
        """Fetch the newest manifest on this channel, recording any failure."""
        try:
            return await fetch(self._repo, self._http, channel=self._channel)
        except httpx.RequestError as exc:
            logger.warning("update-poll: GitHub unreachable: %r", exc)
            self._record(UpdateCheckOutcome.UNREACHABLE, self._unreachable_message(exc))
        except UpdateFeedError as exc:
            logger.warning("update-poll: GitHub refused the feed: %s", exc)
            self._record(UpdateCheckOutcome.REFUSED_BY_GITHUB, self._refusal_message(exc))
        except NoMatchingReleaseError as exc:
            logger.info("update-poll: %s", exc)
            self._record(
                UpdateCheckOutcome.NO_RELEASE_ON_CHANNEL, self._no_release_message(exc),
            )
        except SourcePinError as exc:
            # The feed, an asset URL or a redirect tried to leave the pinned
            # repository. Never silent: this is the one failure that might not
            # be an accident.
            logger.exception("update-poll: refused off-origin update source")
            self._record(
                UpdateCheckOutcome.UNTRUSTED,
                "The update was refused because it tried to come from somewhere "
                f"other than this project's own GitHub repository ({self._repo}): "
                f"{exc}. Nothing was downloaded and nothing was installed. "
                f"{_NOT_UP_TO_DATE}",
            )
        except Exception as exc:  # any other payload problem
            logger.exception("update-poll: release could not be read")
            self._record(
                UpdateCheckOutcome.UNREADABLE,
                f"GitHub answered, but the release could not be read: {exc}. "
                f"{_NOT_UP_TO_DATE}",
            )
        return None

    async def poll_once(self) -> UpdateManifest | None:
        """Perform a single poll cycle. Returns the manifest if it fired.

        Always leaves :attr:`last_check` set to what happened. Serialised by an
        internal lock so a "Check now" click and the background loop cannot run
        two checks over each other.
        """
        async with self._lock:
            return await self._poll_once_locked()

    async def _poll_once_locked(self) -> UpdateManifest | None:
        channel = normalise_channel(self._channel)
        if channel is None:
            self._record(
                UpdateCheckOutcome.MISCONFIGURED,
                f"No check was made: your update channel reads "
                f"{self._channel!r}, which is not one of stable, beta or dev. "
                "Choose a channel below and the next check will use it.",
            )
            return None
        self._channel = channel

        fetched = await self._fetch_or_record()
        if fetched is None:
            return None
        manifest, raw, sig = fetched

        if not _verify(raw, sig, self._pubkey):
            logger.warning("update-poll: signature invalid, ignoring")
            self._record(
                UpdateCheckOutcome.UNTRUSTED,
                f"GitHub offered {manifest.version} on the {channel} channel, but "
                "its manifest is not signed by the key this build trusts, so it "
                "was rejected and nothing was downloaded. A release that fails "
                "this check is either corrupt or not from this project. "
                f"{_NOT_UP_TO_DATE}",
            )
            return None

        try:
            newer = is_newer(manifest.version, self._current_version)
        except ValueError as exc:
            logger.exception("update-poll: version parse failed")
            self._record(
                UpdateCheckOutcome.UNREADABLE,
                f"GitHub offered {manifest.version!r} on the {channel} channel, "
                f"but it could not be compared with the {self._current_version!r} "
                f"this agent reports for itself ({exc}). {_NOT_UP_TO_DATE}",
            )
            return None

        if not newer:
            self._record(
                UpdateCheckOutcome.UP_TO_DATE,
                f"GitHub answered. The newest build on the {channel} channel is "
                f"{manifest.version}, which is not newer than the "
                f"{self._current_version} you are running. You are up to date.",
                available_version=manifest.version,
            )
            return None

        self._pending = (manifest, raw, sig)
        self._record(
            UpdateCheckOutcome.UPDATE_AVAILABLE,
            f"GitHub answered. {manifest.version} is available on the {channel} "
            f"channel; you are running {self._current_version}. Its signature "
            "has been verified. Nothing has been installed — use Install below "
            "when you want it.",
            available_version=manifest.version,
            notes_url=manifest.notes_url,
        )

        try:
            await self._on_update(manifest, raw, sig)
        except Exception:
            logger.exception("update-poll: on_update_available handler raised")
        return manifest

    async def _run(self) -> None:
        while not self._stop.is_set():
            await self.poll_once()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._nudge.wait(), timeout=self._interval)
            self._nudge.clear()
