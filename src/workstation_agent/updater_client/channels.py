"""What an update channel means, and which of two versions is actually newer.

Pure functions, no I/O. :mod:`workstation_agent.updater_client.manifest` uses
them to pick a release out of GitHub's list; the poller uses them to decide
whether the release it picked is worth telling the owner about.

Why this module exists
----------------------

The updater used to ask GitHub for ``/repos/<repo>/releases/latest``. That
endpoint **excludes prereleases by definition**, and every release this project
has published (``v0.1.0-alpha.9`` through ``-alpha.17``) is a prerelease, so the
endpoint answered ``404 Not Found`` every time. The updater has therefore never
seen a release, and could not have, whatever the owner's channel was set to.

Replacing "latest" with the full release list only moves the question: out of
everything the repository has published, which builds does *this* owner want?
That is what a channel is for, and answering it needs two things neither
GitHub's API nor the old code had.

The channel of a build
----------------------

GitHub tells us two things about a release: its ``tag_name`` and a boolean
``prerelease`` flag. The flag is one bit, and this project has three channels,
so the tag is the richer signal — and the release workflow already agrees,
deciding the prerelease flag itself with ``$tag -match "-(alpha|beta|rc|dev)"``.
:data:`_TAG_SUFFIX_RE` is that same expression, deliberately, so the two cannot
drift apart.

The mapping from suffix to channel:

``-alpha``, ``-dev`` → ``dev``
    Both mean "whatever built today". ``dev`` is the channel for people who
    want that.
``-beta``, ``-rc`` → ``beta``
    Both mean "we think this works; prove us wrong". There is no ``rc``
    channel and ``beta`` is much the closer of the two that exist — an rc is a
    beta with a shorter list of known problems, not a stable release.
no suffix → ``stable``
    Nothing claims to be stable except a release that was tagged without a
    prerelease suffix.

The ``prerelease`` flag then acts as a **veto on stable, and only that**. A
release GitHub marks prerelease is not stable whatever its tag says, so an
unsuffixed tag with the flag set is treated as ``dev``: we know it is not
stable and we have no evidence it is beta-quality, and guessing the *less*
stable of the remaining two is the guess that cannot hand an unsuspecting
``stable`` or ``beta`` subscriber something rougher than they asked for. In the
other direction the tag wins outright: ``-alpha`` is ``dev`` even if somebody
forgot to tick the box, because the alternative is shipping an alpha to the
stable channel on the strength of a checkbox.

A channel is a floor, not an equality test
------------------------------------------

Subscribing to ``dev`` and then being denied the stable release that supersedes
your alpha would be absurd, so :func:`accepts` treats the channels as nested
by risk — ``stable`` ⊂ ``beta`` ⊂ ``dev``. Choosing ``dev`` means "send me
everything"; ``beta`` means "betas and releases"; ``stable`` means "releases
only". Newness is then decided separately, by :func:`is_newer`.

Version ordering
----------------

The old comparison threw away the prerelease suffix before comparing
(``re.split(r"[-+]", v)[0]``), which made ``0.1.0-alpha.17`` and
``0.1.0-alpha.9`` *equal*: even with the right release in hand the poller would
have concluded there was nothing newer. So ordering here is SemVer 2.0.0 §11 in
full — a prerelease sorts below its own release, and prerelease identifiers are
compared field by field with numeric ones sorting below alphanumeric ones.

:func:`version_key` also accepts the PEP 440 spellings Python packaging
produces (``0.1.0.dev0``, ``0.1.0a18``, ``0.1.0rc1``, ``0.1.0.post1``), because
the running agent's version comes from Python packaging while the manifest's
comes from a git tag, and the two have to be comparable. ``.devN`` maps to the
prerelease identifiers ``0.dev.N`` rather than ``dev.N`` on purpose: SemVer
sorts a numeric identifier below any alphanumeric one, so the leading ``0``
puts a dev build below ``alpha``, which is where PEP 440 puts it.
"""

from __future__ import annotations

import re
from typing import Final

#: The channels ``manifest.UpdateManifest`` will accept, least to most risk.
CHANNELS: Final[tuple[str, str, str]] = ("stable", "beta", "dev")

#: One line per channel, for the owner-facing control on the About page.
CHANNEL_DESCRIPTIONS: Final[dict[str, str]] = {
    "stable": "Only releases tagged without a prerelease suffix. "
              "This project has not published one yet.",
    "beta": "Betas and release candidates, plus anything stable.",
    "dev": "Every build, including the alphas. This is what the project "
           "currently publishes.",
}

#: The release workflow's own test for "is this a prerelease", character for
#: character (``.github/workflows/release.yml``: ``$tag -match
#: "-(alpha|beta|rc|dev)"``). Keeping it identical is the point: the workflow
#: decides what to publish a build as, and this decides who is offered it.
_TAG_SUFFIX_RE: Final = re.compile(r"-(alpha|beta|rc|dev)", re.IGNORECASE)

_SUFFIX_CHANNEL: Final[dict[str, str]] = {
    "alpha": "dev",
    "dev": "dev",
    "beta": "beta",
    "rc": "beta",
}

#: Which build channels a subscriber to each channel will take. See the
#: module docstring: a channel is a floor, not an equality test.
_ACCEPTS: Final[dict[str, frozenset[str]]] = {
    "stable": frozenset({"stable"}),
    "beta": frozenset({"stable", "beta"}),
    "dev": frozenset({"stable", "beta", "dev"}),
}

_SEMVER_RE: Final = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?"
    r"(?:\+[0-9A-Za-z.\-]+)?$",
)

#: The PEP 440 tails Python packaging emits for a 0.1.0-series build. Longest
#: spelling first in each pair so ``alpha`` is not matched as ``a`` + ``lpha``.
_PEP440_RE: Final = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"\.?(?P<kind>alpha|beta|post|dev|rc|a|b|c)(?P<n>\d*)$",
    re.IGNORECASE,
)

#: PEP 440 tail -> the SemVer prerelease identifiers it corresponds to, with
#: ``{n}`` filled in from the trailing number. ``post`` is absent because a
#: post-release is *after* its release, not before it; it is handled separately.
_PEP440_PRE: Final[dict[str, tuple[str, ...]]] = {
    "dev": ("0", "dev", "{n}"),
    "a": ("alpha", "{n}"),
    "alpha": ("alpha", "{n}"),
    "b": ("beta", "{n}"),
    "beta": ("beta", "{n}"),
    "c": ("rc", "{n}"),
    "rc": ("rc", "{n}"),
}

#: One identifier's sort key. SemVer §11: a numeric identifier always sorts
#: below an alphanumeric one, numeric ones compare numerically, alphanumeric
#: ones compare in ASCII order. The uniform 3-tuple keeps the two comparable.
_IdentKey = tuple[int, int, str]

#: What :func:`version_key` returns. Spelled out because the ordering is the
#: whole contract: core version first, then "is this a release" (1) or "is this
#: a prerelease of it" (0), then the prerelease identifiers, then any PEP 440
#: post-release number.
VersionKey = tuple[tuple[int, int, int], int, tuple[_IdentKey, ...], int]


def normalise_channel(value: object) -> str | None:
    """Return *value* as one of :data:`CHANNELS`, or ``None`` if it is not one.

    ``None`` rather than a fallback: a channel the code does not recognise is
    something to tell the owner about, not something to quietly replace with
    ``stable`` and then poll the wrong feed on his behalf.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if candidate in CHANNELS else None


def channel_of_tag(tag: str) -> str:
    """The channel a release *tag* claims to belong to.

    Reads the ``-alpha``/``-beta``/``-rc``/``-dev`` suffix; anything else is
    ``stable``. See the module docstring for why the suffix is the signal.
    """
    match = _TAG_SUFFIX_RE.search(tag or "")
    if match is None:
        return "stable"
    return _SUFFIX_CHANNEL[match.group(1).lower()]


def channel_of_release(tag: str, *, prerelease: bool) -> str:
    """The channel a GitHub release belongs to, from its tag and its flag.

    Args:
        tag: the release's ``tag_name``.
        prerelease: GitHub's ``prerelease`` boolean for that release.

    Returns:
        One of :data:`CHANNELS`. The tag decides; the flag can only veto
        ``stable``, never promote a suffixed tag up to it.
    """
    channel = channel_of_tag(tag)
    if prerelease and channel == "stable":
        return "dev"
    return channel


def accepts(subscribed: str, build: str) -> bool:
    """True if a subscriber to *subscribed* should be offered a *build* build.

    Unknown values are refused rather than guessed at, so a config carrying a
    typo offers nothing instead of offering everything.
    """
    return build in _ACCEPTS.get(subscribed, frozenset())


def _ident_key(ident: str) -> _IdentKey:
    if ident.isdigit():
        return (0, int(ident), "")
    return (1, 0, ident)


def version_key(version: str) -> VersionKey:
    """Sort key for *version* implementing SemVer 2.0.0 §11 precedence.

    Accepts SemVer (``1.2.3``, ``1.2.3-alpha.4``, ``1.2.3+build``) and the
    PEP 440 spellings Python packaging produces (``1.2.3.dev0``, ``1.2.3a4``,
    ``1.2.3rc1``, ``1.2.3.post1``). Build metadata after ``+`` is ignored, as
    SemVer requires.

    Raises:
        ValueError: if *version* is neither.
    """
    raw = (version or "").strip()
    match = _SEMVER_RE.match(raw)
    if match is not None:
        pre = match.group("pre")
        idents = tuple(_ident_key(part) for part in pre.split(".")) if pre else ()
        return (
            (int(match.group("major")), int(match.group("minor")), int(match.group("patch"))),
            0 if idents else 1,
            idents,
            0,
        )

    match = _PEP440_RE.match(raw)
    if match is not None:
        core = (
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
        )
        kind = match.group("kind").lower()
        number = match.group("n") or "0"
        if kind == "post":
            return (core, 1, (), int(number))
        idents = tuple(
            _ident_key(part.format(n=number)) for part in _PEP440_PRE[kind]
        )
        return (core, 0, idents, 0)

    msg = f"invalid version: {version!r}"
    raise ValueError(msg)


def is_newer(candidate: str, current: str) -> bool:
    """True if *candidate* supersedes *current* under SemVer precedence.

    Raises:
        ValueError: if either version is unparseable. Callers must surface
            that rather than swallow it — "I cannot tell which of these is
            newer" is not the same answer as "there is nothing newer".
    """
    return version_key(candidate) > version_key(current)
