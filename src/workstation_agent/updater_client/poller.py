"""Async update poller.

Runs fetch -> verify -> compare version -> notify callback on a
configurable schedule. Can also be nudged to poll immediately via
:meth:`UpdatePoller.check_now`.

No I/O beyond the injected ``httpx.AsyncClient`` — this module owns no
state that persists across the process; callers are responsible for
scheduling and for filesystem writes (see :mod:`handoff`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from workstation_agent.updater_client.manifest import UpdateManifest, fetch, is_newer
from workstation_agent.updater_client.verifier import verify as _verify

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)

OnUpdateCallback = Callable[[UpdateManifest, bytes, bytes], Awaitable[None]]
"""Callback fired when a verified newer manifest is discovered.

Receives ``(manifest, raw_manifest_bytes, signature_bytes)`` so the
handler can persist the verified pair to ``pending_update.json``.
"""


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
    ) -> None:
        self._repo = github_repo
        self._current_version = current_version
        self._pubkey = pubkey
        self._http = http
        self._on_update = on_update_available
        self._interval = poll_interval_seconds
        self._nudge = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

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
        """Nudge the poller to run a check immediately."""
        self._nudge.set()

    async def poll_once(self) -> UpdateManifest | None:
        """Perform a single poll cycle. Returns the manifest if it fired."""
        try:
            manifest, raw, sig = await fetch(self._repo, self._http)
        except Exception:
            logger.exception("update-poll: fetch failed")
            return None

        if not _verify(raw, sig, self._pubkey):
            logger.warning("update-poll: signature invalid, ignoring")
            return None

        try:
            newer = is_newer(manifest.version, self._current_version)
        except ValueError:
            logger.exception("update-poll: version parse failed")
            return None

        if not newer:
            return None

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
