"""Updater client: GitHub releases polling, signature verification, hand-off."""

from workstation_agent.updater_client.channels import (
    CHANNEL_DESCRIPTIONS,
    CHANNELS,
    channel_of_release,
    channel_of_tag,
    is_newer,
    normalise_channel,
)
from workstation_agent.updater_client.handoff import spawn_updater, stage_pending
from workstation_agent.updater_client.manifest import (
    ArtifactRef,
    ArtifactSet,
    NoMatchingReleaseError,
    UpdateFeedError,
    UpdateManifest,
    fetch,
    select_release,
)
from workstation_agent.updater_client.poller import (
    UpdateCheckOutcome,
    UpdateCheckResult,
    UpdatePoller,
)
from workstation_agent.updater_client.source_pin import (
    DEFAULT_REPO,
    SourcePin,
    SourcePinError,
)
from workstation_agent.updater_client.verifier import verify

__all__ = [
    "CHANNELS",
    "CHANNEL_DESCRIPTIONS",
    "DEFAULT_REPO",
    "ArtifactRef",
    "ArtifactSet",
    "NoMatchingReleaseError",
    "SourcePin",
    "SourcePinError",
    "UpdateCheckOutcome",
    "UpdateCheckResult",
    "UpdateFeedError",
    "UpdateManifest",
    "UpdatePoller",
    "channel_of_release",
    "channel_of_tag",
    "fetch",
    "is_newer",
    "normalise_channel",
    "select_release",
    "spawn_updater",
    "stage_pending",
    "verify",
]
