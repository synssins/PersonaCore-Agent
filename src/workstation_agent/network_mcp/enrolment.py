"""Receiving the bearer token PersonaCore pushes when a workstation enrols.

The enrolment handshake, as frozen by the core side
---------------------------------------------------
The owner presses "+ Add a workstation" in PersonaCore, which shows a short
pairing code with an expiry. He types that code into the Agent and presses Join.
Then:

1. **Agent → core, over plaintext HTTP:** the pairing code, a display name, this
   endpoint's HTTPS URL, its sha256 certificate fingerprint, versions and its
   tool list. **No token is sent**, deliberately, because that leg is not
   encrypted.
2. **The core mints the bearer token.**
3. **Core → Agent, over *this* endpoint's HTTPS, pinned to the fingerprint just
   supplied:** the core pushes the token to us.
4. The core persists only after that push succeeds.

**This module is step 3's receiver, and only that.** Step 1's outbound call is
not built here: its request shape is not frozen, and building it against a guess
would mean building it twice.

What the core does with our answer, read from its source
--------------------------------------------------------
* It looks at the **status code and nothing else**. Any 2xx is success; any
  non-2xx makes it raise and abort the enrolment. It reads the body only to
  discard it, streamed and capped, so there is no body for us to design. We
  answer ``204 No Content`` — the precise answer against a tolerant reader.
* **3xx is not success and is not followed** — its client has redirects
  disabled. This route therefore never redirects, under any circumstance.
* It allows **5 seconds to connect and 10 to read**. Everything here is bounded
  well inside that, and the uniformity below is bought with constant-time
  comparison rather than with an artificial delay, which would eat that budget
  for exactly the pushes we most want to succeed.
* It **does not retry**. A failed push fails the whole enrolment: the core
  persists nothing and the owner issues a fresh code. So single use here is
  strict, and there is deliberately **no idempotent replay** — a second push
  against a spent code is refused like any other. This endpoint does not carry
  idempotency it does not need.

Why this needs to be its own module
-----------------------------------
``POST /enrol/token`` is the *only* route on this endpoint that is not behind the
bearer gate — it cannot be, because the token it carries is the thing being
established. The endpoint's whole design until now was "answer ``401`` from the
ASGI scope and never read the body" (see ``hardening.py``), so an unauthenticated
route that reads a body is a real change of posture and gets stated in one place
rather than smeared through the middleware.

Six properties carry that change, and each has a test:

===========================  ===========================================================
property                     how it is held
===========================  ===========================================================
reachable only while a Join  :meth:`EnrolmentReceiver.open_join` is the only thing that
is pending                   creates a code; with none, every push is refused
uniform refusal              :meth:`EnrolmentReceiver.redeem` returns a bare ``bool``.
                             It has no vocabulary for *why*, so no caller can leak one.
                             ``hardening`` answers every ``False`` through the same
                             ``_unauthenticated`` helper that every other bearerless
                             request gets: same ``401``, same empty body, same
                             ``WWW-Authenticate``. A push with no Join pending is
                             therefore indistinguishable from a wrong code, and both
                             are indistinguishable from a path that does not exist.
constant-time comparison     :func:`secrets.compare_digest` on **bytes**, run exactly
                             once on *every* path — malformed bodies included — over
                             operands normalised to a fixed 32 bytes by
                             :func:`_digest`, against the pending code's digest or a
                             per-instance random decoy of the same width. Neither the
                             length of the code nor the existence of a Join is
                             observable in the time it takes
single use                   a successful redemption clears the pending Join before it
                             returns, so a second push against a spent code finds no
                             Join and is refused like anything else. Read, compare,
                             apply and clear are serialised by an
                             :class:`asyncio.Lock`, so two concurrent correct pushes
                             produce exactly one enrolment
bounded                      the code, the token and the JSON body all have ceilings;
                             ``hardening`` bounds the wire read and the attempt rate
never logged                 neither the code nor the token appears in any log record,
                             any exception message, or :class:`JoinStatus`
===========================  ===========================================================

The comparison, specifically
---------------------------
This repository has been bitten three times by the same class of bug on exactly
this kind of field (commit ``844a96b``): ``!=`` assumed two comparable strings,
then :func:`secrets.compare_digest` on ``str`` assumed ASCII and raised
``TypeError`` without it, then ``.encode("utf-8")`` assumed well-formed Unicode
and raised ``UnicodeEncodeError`` on an unpaired surrogate that ``json.loads``
accepts happily. So nothing here is trusted until it is safely ``bytes``:
:func:`~workstation_agent.network_mcp.hardening.validate_json_body` rejects a
surrogate before the parse is even looked at, a non-``str`` is refused outright,
and the encode is *still* wrapped. A malformed input is **rejected**, never
substituted with ``errors="replace"`` — a replacement policy maps many different
inputs onto the same bytes, which is the one thing a code comparison must not do.

The Join lives in memory only
-----------------------------
Nothing here touches disk. An Agent restart drops any pending Join, which is the
behaviour we want: a window the owner opened before a crash must not still be
open afterwards. The *token*, once accepted, is persisted by
:class:`~workstation_agent.network_mcp.server.NetworkMCPServer` through
:func:`~workstation_agent.network_mcp.credentials.store_token`, because contract
§11 item 8 requires a restart to bring the endpoint back without the owner
touching PersonaCore.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from workstation_agent.network_mcp.hardening import validate_json_body

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

log = logging.getLogger(__name__)

#: The route the core pushes to. Deliberately *not* under ``/mcp``: the MCP path
#: is the authenticated surface and this one is not, so they do not share a
#: prefix that a future router change could accidentally merge.
ENROL_PATH: Final = "/enrol/token"

#: How long a Join stays open by default.
#:
#: **The core owns the clock. This is only a cleanup for a Join nobody
#: completes.** The core's pairing code carries the authoritative TTL — 300
#: seconds as its default today — and the core shows the owner a live countdown
#: against it. A code is dead when *the core* says so, and this Agent has no
#: opinion about that; the enrolment fails on the core's side, at its deadline,
#: however this value is set.
#:
#: What this value must never do is close first. If it did, the owner would be
#: looking at a code the console still called valid while the Agent had quietly
#: stopped accepting it — a failure with nothing on either screen to explain it.
#: So it sits *above* the core's TTL by the whole of the core's own push budget:
#: 300 seconds of countdown, plus its 5-second connect and 10-second read
#: timeouts, plus margin. 360 is the value the core side suggested.
#:
#: The core's 300 is a default parameter rather than a baked-in constant, so if
#: the owner raises it, raise this with it — the relationship "strictly above
#: the core's TTL plus its timeouts" is the thing to preserve, not the number.
DEFAULT_JOIN_TTL: Final = 360.0

#: Ceiling on the window, whatever a caller asks for. The window is the entire
#: period in which an unauthenticated push can be accepted; it is not something a
#: caller gets to extend arbitrarily.
MAX_JOIN_TTL: Final = 900.0

#: Floor on the pairing code's length. The code is the *whole* authentication for
#: step 3, so a window opened around a four-character code is a window an
#: attacker on the LAN can brute-force: ``hardening``'s rate limit allows on the
#: order of a thousand attempts across a five-minute window, which is a real
#: fraction of a four-digit space. Six characters puts it out of reach.
#:
#: **If the core freezes a shorter code format, this constant is the one place to
#: revisit** — and the answer would be to shorten the window and tighten the rate
#: limit, not simply to lower this.
MIN_CODE_CHARS: Final = 6

#: Ceiling on the pairing code. Nothing a human types at a prompt is longer.
MAX_CODE_CHARS: Final = 128

#: Bounds on the pushed token. The lower bound refuses a token too short to be
#: worth having; the upper bound keeps the value that lands in the token file
#: something the file's readers can hold.
MIN_TOKEN_CHARS: Final = 16
MAX_TOKEN_CHARS: Final = 512

#: Nesting ceiling for the push body. ``{"code": ..., "token": ...}`` is flat;
#: this exists only so a hostile body is refused by structure rather than by luck.
_MAX_JSON_DEPTH: Final = 8

#: Width of a SHA-256 digest, which is the width every comparison operand is
#: normalised to. See :func:`_digest`.
_DIGEST_BYTES: Final = 32

#: The printable-ASCII band a token may use: ``!`` through ``~``. Excludes space
#: and every control character, so the value round-trips through the ASCII token
#: file and through ``Hardening``'s bytes comparison without an encoding step
#: that could raise.
_TOKEN_MIN_ORD: Final = 0x21
_TOKEN_MAX_ORD: Final = 0x7E


class EnrolmentError(Exception):
    """A Join could not be opened.

    The message is written to be shown to the owner verbatim, so it says what to
    do rather than what went wrong internally. It never carries the code.
    """


@dataclass(frozen=True)
class JoinStatus:
    """What may be known about a pending Join.

    Deliberately carries no code and no token: this is what the UI renders and
    what a log line could plausibly be built from, and neither has any business
    holding either value.
    """

    expires_in: float
    """Seconds left in the window, floored at zero."""
    opened_at: dt.datetime
    """Wall-clock time the window was opened, for the page to show."""
    attempts: int
    """Pushes seen against this Join, malformed ones included. A number climbing
    without a success is the owner's signal that something on the LAN is
    guessing."""


@dataclass
class _PendingJoin:
    """The open window.

    Holds a **digest of** the pairing code, never the code. Two reasons, and the
    second is the load-bearing one:

    * the plaintext code stops existing anywhere in this process the moment
      :meth:`EnrolmentReceiver.open_join` returns; and
    * a digest is a fixed 32 bytes, so the comparison in :meth:`redeem` has
      operands of the same width whatever the code's length — and whether or not
      there is a code at all.
    """

    code_digest: bytes
    expires_at: float
    """Monotonic deadline. Monotonic, not wall clock: a window must not be
    extended or closed early by an NTP correction or a daylight-saving jump."""
    opened_at: dt.datetime
    attempts: int = 0


class EnrolmentReceiver:
    """Holds the pending Join and decides whether a push may be accepted.

    Deliberately knows nothing about ASGI, HTTP, sockets or responses.
    :class:`~workstation_agent.network_mcp.hardening.Hardening` owns the wire —
    the byte bound, the read timeout, the attempt rate and the single shape of
    the refusal — and calls :meth:`redeem` with a body it has already bounded.
    Splitting it that way is what keeps *one* refusal response in the codebase
    instead of two that have to be kept identical by hand.

    Args:
        apply_token: Called with an accepted token. Returns ``True`` once the
            token is durably stored **and** in force for subsequent MCP calls.
            Returning ``False`` refuses the push and leaves the Join open, so a
            failure to persist is not reported to the core as a success it will
            then persist against.
        clock: Monotonic time source. Injectable so expiry is testable without
            sleeping.
    """

    def __init__(
        self,
        *,
        apply_token: Callable[[str], bool],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._apply_token = apply_token
        self._clock = clock
        self._pending: _PendingJoin | None = None
        # Fresh per instance and never revealed. Compared against when no Join
        # is pending, purely so that case does the same work as a wrong code. It
        # is 32 random bytes rather than a digest of anything, so no input can
        # produce it, and it is exactly digest-width so the comparison operands
        # match in the no-Join case as well.
        self._decoy_digest = secrets.token_bytes(_DIGEST_BYTES)
        # Stands in for the code a body that would not parse never contained, so
        # the parse-failure path performs the same hash and the same comparison
        # as every other path. Malformed bodies are the cheapest thing for an
        # attacker to send, which makes them the most attractive timing probe.
        self._dummy_code = secrets.token_bytes(_DIGEST_BYTES)
        # Serialises the read-compare-apply sequence in :meth:`redeem`; see the
        # note there for why single use needs it to be a property of this code
        # rather than of how asyncio happens to schedule.
        self._lock = asyncio.Lock()

    @property
    def path(self) -> str:
        """The route this receiver answers on."""
        return ENROL_PATH

    # -- the owner's side ------------------------------------------------

    def open_join(self, code: str, *, ttl_seconds: float = DEFAULT_JOIN_TTL) -> JoinStatus:
        """Open the window the core may push a token into.

        Opening a Join replaces any window already open: the owner mistyping a
        code and typing it again must not leave the first attempt live.

        Args:
            code: The pairing code the owner read off PersonaCore's console.
            ttl_seconds: Window length, clamped to :data:`MAX_JOIN_TTL`.

        Returns:
            The new window's :class:`JoinStatus`.

        Raises:
            EnrolmentError: if *code* is not something that can secure a window.
        """
        if not isinstance(code, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            # The UI hands us a form field, which is always str — but this is the
            # value the window's whole security rests on, so its type is checked
            # here rather than assumed from the caller.
            msg = "The pairing code must be text."
            raise EnrolmentError(msg)

        stripped = code.strip()
        if len(stripped) < MIN_CODE_CHARS:
            msg = (
                f"That pairing code is too short to be safe — it must be at least "
                f"{MIN_CODE_CHARS} characters. Check the code PersonaCore is showing "
                f"and type it again."
            )
            raise EnrolmentError(msg)
        if len(stripped) > MAX_CODE_CHARS:
            msg = (
                f"That pairing code is longer than {MAX_CODE_CHARS} characters, "
                f"which is longer than any code PersonaCore shows."
            )
            raise EnrolmentError(msg)

        try:
            code_bytes = stripped.encode("utf-8")
        except UnicodeEncodeError as exc:
            # Reachable: a paste can carry an unpaired surrogate, which UTF-8
            # cannot represent. Refused rather than substituted.
            msg = "That pairing code contains characters this Agent cannot use."
            raise EnrolmentError(msg) from exc

        ttl = min(max(float(ttl_seconds), 1.0), MAX_JOIN_TTL)
        pending = _PendingJoin(
            # The digest, not the code. The plaintext does not outlive this call.
            code_digest=_digest(code_bytes),
            expires_at=self._clock() + ttl,
            opened_at=dt.datetime.now(dt.UTC),
        )
        self._pending = pending
        # No code, no length, no prefix. A log line is a file on a machine that
        # runs arbitrary commands.
        log.info("network MCP enrolment window opened for %.0f seconds", ttl)
        return JoinStatus(expires_in=ttl, opened_at=pending.opened_at, attempts=0)

    def cancel_join(self) -> None:
        """Close any pending Join. Safe to call when there is none."""
        if self._pending is not None:
            self._pending = None
            log.info("network MCP enrolment window closed by the operator")

    def status(self) -> JoinStatus | None:
        """The pending Join, or ``None`` if there is none or it has expired."""
        pending = self._live_pending()
        if pending is None:
            return None
        return JoinStatus(
            expires_in=max(pending.expires_at - self._clock(), 0.0),
            opened_at=pending.opened_at,
            attempts=pending.attempts,
        )

    # -- the core's side -------------------------------------------------

    async def redeem(self, raw: bytes) -> bool:
        """Decide one ``POST /enrol/token`` body. Returns ``True`` if enrolled.

        Returns a bare ``bool`` on purpose. Every refusal — malformed JSON, a
        missing field, a wrong type, an oversized code, a non-ASCII token, a
        wrong code, an expired window, no Join at all — is the same ``False``,
        so there is no channel through which the caller could learn which one it
        was even if a future edit wanted to tell it.

        **Exactly one comparison runs, over operands of exactly one width, on
        every path through this method.** Both halves of that matter, and each
        was a real defect before it was written this way:

        * *Every path.* An early ``return`` for a body that would not parse
          would refuse it measurably faster than a well-formed body with a wrong
          code — the same disclosure by a different door, and through the
          cheapest probe an attacker has. So a parse failure substitutes a dummy
          code and goes on to hash and compare exactly like everything else.
        * *One width.* :func:`secrets.compare_digest` is constant-time **only
          for equal-length inputs**; the documentation says outright that
          differing lengths can reveal the lengths. Comparing a submitted code
          against a raw pairing code therefore leaked the code's length — and,
          because the no-Join decoy was a different length again, leaked whether
          a Join was pending at all, to anyone willing to sweep the length. Both
          sides are now :func:`_digest`\\ ed first, so every comparison in this
          method is 32 bytes against 32 bytes, pending or not.

        Never raises for any input, and never delays artificially: the core
        allows 10 seconds for the whole exchange, and uniformity here is bought
        with constant-time comparison rather than with a sleep.
        """
        push = _parse_push(raw)
        # Hashed outside the lock: it depends only on the request, and doing the
        # work here keeps the section that must be serialised as short as the
        # invariant needs.
        submitted = _digest(self._dummy_code if push is None else push[0])

        async with self._lock:
            pending = self._live_pending()
            expected = self._decoy_digest if pending is None else pending.code_digest
            if pending is not None:
                pending.attempts += 1
            matched = secrets.compare_digest(submitted, expected)

            if push is None or pending is None or not matched:
                return False
            _code_bytes, token = push

            if not self._apply_token(token):
                # Storing failed. The Join stays open so the owner can have the
                # core push again, and the core is told nothing it would persist
                # against.
                log.warning(
                    "network MCP enrolment: a matching push could not be stored; refused",
                )
                return False

            # Single use, strictly. Cleared *before* returning success, so a
            # replay of this exact body — or a second console pushing this code —
            # finds no Join and is refused like anything else. There is
            # deliberately no idempotent re-presentation: the core does not
            # retry, a failed push fails the whole enrolment, and the owner
            # issues a fresh code.
            #
            # The lock is what makes that true of *concurrent* pushes rather
            # than only of sequential ones. Read-compare-apply-clear must be
            # indivisible: two requests carrying the correct code could
            # otherwise both see the same live Join and both be accepted. Today
            # ``_apply_token`` is synchronous, so this whole section happens
            # between two await points and asyncio serialises it for us — which
            # is exactly the kind of accident that stops being true the first
            # time someone makes the token store awaitable. Single use is a
            # property of this code, not of how the loop happens to schedule.
            self._pending = None

        log.info("network MCP enrolment completed; the endpoint now requires the pushed token")
        return True

    # -- internals -------------------------------------------------------

    def _live_pending(self) -> _PendingJoin | None:
        """The pending Join if it is still inside its window, else ``None``.

        Expiry is applied here rather than on a timer: there is no thread and no
        task to leak, and a window nobody asks about does not need to have been
        reaped on time. Clearing on the way past also means the "window expired"
        line is logged once rather than on every probe.
        """
        pending = self._pending
        if pending is None:
            return None
        if self._clock() >= pending.expires_at:
            self._pending = None
            log.info("network MCP enrolment window expired without a completed enrolment")
            return None
        return pending


def _digest(value: bytes) -> bytes:
    """Normalise *value* to a fixed 32 bytes for comparison.

    Nothing here is about secrecy — the digest never leaves this process and the
    pairing code has far too little entropy for a hash to protect it. It is
    about **width**. :func:`secrets.compare_digest` is constant-time only when
    its operands are the same length, and Python's own documentation says
    differing lengths "could theoretically reveal information about the types
    and lengths" of the operands. Hashing first makes every comparison in
    :meth:`EnrolmentReceiver.redeem` 32 bytes against 32 bytes, so neither the
    length of the owner's code nor the existence of a Join is observable in the
    time the comparison takes.
    """
    return hashlib.sha256(value).digest()


def _acceptable_token(token: str) -> bool:
    """True if *token* is a value this endpoint can hold and compare safely.

    Printable ASCII with no spaces, within bounds. This is not fussiness: the
    token is written to an ASCII file (``credentials.store_token``) and compared
    as pre-encoded bytes (``Hardening._token_ok``), and both of those are only
    exception-free because nothing that reaches them needs a lossy encode. A
    token outside this band is refused at the door instead of raising three
    layers down.
    """
    if not (MIN_TOKEN_CHARS <= len(token) <= MAX_TOKEN_CHARS):
        return False
    return all(_TOKEN_MIN_ORD <= ord(ch) <= _TOKEN_MAX_ORD for ch in token)


def _parse_push(  # noqa: PLR0911 — one return per rejected input class, as validate_json_body
    raw: bytes,
) -> tuple[bytes, str] | None:
    """Structurally validate a push body, returning ``(code_bytes, token)``.

    ``None`` for every rejected input, and it never raises. The heavy lifting is
    :func:`~workstation_agent.network_mcp.hardening.validate_json_body`, reused
    rather than reimplemented: it is the function that already enumerates invalid
    UTF-8, unpaired surrogates and unbounded nesting, and a second parser with
    its own idea of those is how the two drift apart.
    """
    if validate_json_body(raw, max_depth=_MAX_JSON_DEPTH) is not None:
        return None

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError, UnicodeDecodeError):  # pragma: no cover
        # Unreachable through validate_json_body, which has already decoded and
        # parsed this exact body. Kept because "cannot fail" is the assumption
        # that produced three of this repository's four pre-auth crashes.
        return None
    if not isinstance(parsed, dict):
        return None

    code = parsed.get("code")
    token = parsed.get("token")
    if not isinstance(code, str) or not isinstance(token, str):
        return None

    stripped = code.strip()
    if not (MIN_CODE_CHARS <= len(stripped) <= MAX_CODE_CHARS):
        return None
    if not _acceptable_token(token):
        return None

    try:
        code_bytes = stripped.encode("utf-8")
    except UnicodeEncodeError:  # pragma: no cover — validate_json_body got there first
        return None
    return code_bytes, token
