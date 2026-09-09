"""Updater client: GitHub releases polling, signature verification, hand-off."""

from workstation_agent.updater_client.handoff import spawn_updater, stage_pending
from workstation_agent.updater_client.manifest import (
    ArtifactRef,
    ArtifactSet,
    UpdateManifest,
    fetch,
)
from workstation_agent.updater_client.poller import UpdatePoller
from workstation_agent.updater_client.source_pin import (
    DEFAULT_REPO,
    SourcePin,
    SourcePinError,
)
from workstation_agent.updater_client.verifier import verify

__all__ = [
    "DEFAULT_REPO",
    "ArtifactRef",
    "ArtifactSet",
    "SourcePin",
    "SourcePinError",
    "UpdateManifest",
    "UpdatePoller",
    "fetch",
    "spawn_updater",
    "stage_pending",
    "verify",
]
