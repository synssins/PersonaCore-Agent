"""Awaitable confirmation primitive for confirmable conditions (contract §7).

``MCPHost.start`` takes ``confirm_cb: Callable[[ConfirmationRequest], Awaitable[bool]]``
but the only presentation surface the agent owns is
:meth:`workstation_agent.ui.notifications.toast.ToastPresenter.show`, which is
**synchronous, returns ``None``, and is callback-based** (``actions`` maps
``action_id -> (label, callback)``).  This module is the adapter between the two.

:class:`ConfirmPresenter` turns one toast into one awaitable ``bool``:

* it shows a toast with **Allow** / **Deny** buttons and speaks the §7 line,
* it resolves ``True`` on Allow and ``False`` on Deny,
* it gives up after :data:`CONFIRM_TIMEOUT_S` seconds with the ``unconfirmed``
  outcome — a value, not an exception,
* it carries a **correlation id** so the prompt can be tied to an audit row,
* and it **fails closed**: every path that is not an explicit Allow click
  denies.

Fail-closed paths — each one denies, none of them raises out of
:meth:`ConfirmPresenter.confirm`:

===================================== ===========================
Failure                               ``ConfirmDecision.reason``
===================================== ===========================
the toast provider raised             ``presenter_error``
no presenter configured (``None``)    ``no_presenter``
presenter has no usable ``show()``    ``presenter_unusable``
``_WINRT_AVAILABLE`` is false, or the
real presenter has no notifier — the
buttons could never be clicked        ``toast_unavailable``
``show()`` raised                     ``toast_failed``
nobody answered within the timeout    ``timeout`` (``unconfirmed``)
anything else raised                  ``internal_error``
===================================== ===========================

The ``_WINRT_AVAILABLE`` row is the important one: ``show()`` merely logs and
returns when winrt is missing (``toast.py:115-121``), so without an explicit
check an absent toast stack would sit out the full timeout and — with any
less careful design — read as an auto-allow.

Usage::

    presenter = ConfirmPresenter(
        toast_provider=lambda: subsystems.toast,
        config_provider=lambda: subsystems.config,
    )
    await host.start(cfg, confirm_cb=presenter, tts_speak=voice)
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Contract constants
# --------------------------------------------------------------------------

#: Confirmation window, contract §7.  An unanswered prompt resolves to
#: :data:`OUTCOME_UNCONFIRMED` once this elapses.
CONFIRM_TIMEOUT_S: Final = 20.0

#: Upper bound on the spoken line.  The toast is already on screen and the
#: button callbacks are already armed before this is awaited, so a wedged TTS
#: backend delays the answer but can never lose it or hang the confirm.
SPEAK_TIMEOUT_S: Final = 10.0

OUTCOME_ALLOWED: Final = "allowed"
OUTCOME_DENIED: Final = "denied"
OUTCOME_UNCONFIRMED: Final = "unconfirmed"

ACTION_ALLOW: Final = "confirm_allow"
ACTION_DENY: Final = "confirm_deny"

TOAST_TITLE: Final = "PersonaCore-Agent"

#: Longest command string echoed back into the prompt.  A tool argument is
#: attacker-influenced text; it is not pasted verbatim into a toast at length.
_MAX_COMMAND_CHARS: Final = 120


# --------------------------------------------------------------------------
# Decision record
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfirmDecision:
    """Outcome of one confirmation prompt.

    ``outcome`` is one of :data:`OUTCOME_ALLOWED`, :data:`OUTCOME_DENIED` or
    :data:`OUTCOME_UNCONFIRMED`.  Only :data:`OUTCOME_ALLOWED` permits the
    call to proceed; ``unconfirmed`` is reported separately from ``denied``
    so the audit row can tell "the user said no" from "nobody answered".
    """

    outcome: str
    correlation_id: str
    reason: str = ""
    spoken: bool = False

    @property
    def allowed(self) -> bool:
        """True only for an explicit Allow."""
        return self.outcome == OUTCOME_ALLOWED


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def command_text(req: Any) -> str:  # noqa: ANN401 — duck-typed ConfirmationRequest
    """Return the ``<command>`` fragment for the §7 prompt.

    Prefers a ``command`` argument when the tool has one, otherwise the tool
    id.  Always returns a short, single-line, non-empty string.
    """
    candidate = ""
    with contextlib.suppress(Exception):
        args = getattr(req, "args", None)
        if isinstance(args, dict):
            raw = args.get("command")
            if isinstance(raw, str) and raw.strip():
                candidate = raw.strip()
    if not candidate:
        with contextlib.suppress(Exception):
            tool_id = getattr(req, "tool_id", "")
            if isinstance(tool_id, str):
                candidate = tool_id.strip()
    if not candidate:
        candidate = "an unnamed command"

    candidate = " ".join(candidate.split())
    if len(candidate) > _MAX_COMMAND_CHARS:
        candidate = candidate[: _MAX_COMMAND_CHARS - 1] + "…"
    return candidate


def prompt_line(req: Any) -> str:  # noqa: ANN401 — duck-typed ConfirmationRequest
    """The exact §7 prompt: spoken aloud and used as the toast body."""
    return f"PersonaCore wants to run {command_text(req)} on this machine. Allow?"


def toast_stack_available(presenter: Any) -> bool:  # noqa: ANN401 — duck-typed
    """False when a toast could be shown but its buttons can never be clicked.

    ``ToastPresenter.show`` logs and returns when winrt is unavailable, which
    would otherwise leave the confirm waiting on a future nothing can ever
    resolve.  Non-``ToastPresenter`` objects (fakes, future presenters) are
    trusted to honour their own contract.
    """
    try:
        from workstation_agent.ui.notifications import toast as toast_mod  # noqa: PLC0415
    except Exception:  # pragma: no cover — the module is import-guarded
        log.exception("confirm: toast module failed to import — denying")
        return False

    presenter_cls = getattr(toast_mod, "ToastPresenter", None)
    if presenter_cls is None or not isinstance(presenter, presenter_cls):
        return True

    # Read through the module object so tests can monkeypatch the flag.
    if not getattr(toast_mod, "_WINRT_AVAILABLE", False):
        return False
    return getattr(presenter, "_notifier", None) is not None


async def _call_speak(voice: Any, text: str) -> None:  # noqa: ANN401 — duck-typed
    """Speak *text* through *voice*, which may be an object or a callable."""
    speak = getattr(voice, "speak", None)
    if speak is None and callable(voice):
        speak = voice
    if speak is None:
        return
    result = speak(text)
    if inspect.isawaitable(result):
        await result


# --------------------------------------------------------------------------
# ConfirmPresenter
# --------------------------------------------------------------------------


class ConfirmPresenter:
    """Toast + voice confirmation prompt exposed as an awaitable ``bool``.

    The instance is itself the ``confirm_cb``: ``await presenter(req)``
    returns ``True`` only for an explicit Allow.

    Parameters
    ----------
    toast_provider:
        Called at prompt time (not construction time) for the shared
        ``ToastPresenter``.  ``app.py`` builds the presenter at step 8, well
        after the MCP host starts at step 3, so this must stay lazy.
    speak:
        Optional voice channel — an object with an ``async speak(text)`` or a
        plain callable.  Usually supplied later by
        :meth:`attach_voice`, which ``MCPHost.start`` calls with its
        ``tts_speak``.
    config_provider:
        Called at prompt time for the :class:`~workstation_agent.config.schema.AgentConfig`
        whose ``notifications.voice_announce_confirmations_enabled`` gates the
        spoken line.  When it is absent, unreadable or false, the toast is
        still shown and nothing is spoken.
    timeout_s:
        Confirmation window; defaults to the §7 value.  Injectable so tests
        do not wait 20 seconds.
    speak_timeout_s:
        Upper bound on the spoken line.

    """

    def __init__(
        self,
        *,
        toast_provider: Callable[[], Any] | None = None,
        speak: Any = None,  # noqa: ANN401 — duck-typed voice channel
        config_provider: Callable[[], Any] | None = None,
        timeout_s: float = CONFIRM_TIMEOUT_S,
        speak_timeout_s: float = SPEAK_TIMEOUT_S,
    ) -> None:
        """Build a presenter; nothing is resolved until a prompt is raised."""
        self._toast_provider = toast_provider
        self._voice = speak
        self._config_provider = config_provider
        self._timeout_s = timeout_s
        self._speak_timeout_s = speak_timeout_s

    # -- wiring ---------------------------------------------------------

    def attach_voice(self, voice: Any) -> None:  # noqa: ANN401 — duck-typed
        """Adopt *voice* as the spoken channel for confirmations.

        ``MCPHost.start`` calls this with the ``tts_speak`` it was handed, so
        the voice the application configures reaches the prompt without
        ``app.py`` having to wire the same object into two places.
        """
        self._voice = voice

    # -- the confirm_cb -------------------------------------------------

    async def __call__(self, req: Any) -> bool:  # noqa: ANN401 — duck-typed
        """Alias for :meth:`confirm` so the instance *is* the callback."""
        return await self.confirm(req)

    async def confirm(self, req: Any) -> bool:  # noqa: ANN401 — duck-typed
        """Return ``True`` only if the operator explicitly allowed *req*."""
        decision = await self.request(req)
        return decision.allowed

    async def request(self, req: Any) -> ConfirmDecision:  # noqa: ANN401 — duck-typed
        """Prompt for *req* and return the full :class:`ConfirmDecision`.

        Never raises except :class:`asyncio.CancelledError`, which is
        re-raised so shutdown still works — and which cannot produce an
        allow either, since the caller is being torn down.
        """
        correlation_id = ""
        with contextlib.suppress(Exception):
            existing = getattr(req, "correlation_id", "")
            if isinstance(existing, str):
                correlation_id = existing
        if not correlation_id:
            correlation_id = uuid.uuid4().hex

        try:
            return await self._request(req, correlation_id)
        except asyncio.CancelledError:
            log.warning("confirm[%s]: cancelled — not allowed", correlation_id)
            raise
        except Exception:
            # Nothing below is allowed to turn into an allow.
            log.exception("confirm[%s]: unexpected failure — denying", correlation_id)
            return ConfirmDecision(OUTCOME_DENIED, correlation_id, "internal_error")

    # -- internals ------------------------------------------------------

    async def _request(self, req: Any, correlation_id: str) -> ConfirmDecision:  # noqa: ANN401
        presenter, reason = self._resolve_presenter()
        if presenter is None:
            log.warning(
                "confirm[%s]: denying %s — %s",
                correlation_id,
                getattr(req, "tool_id", "<unknown>"),
                reason,
            )
            return ConfirmDecision(OUTCOME_DENIED, correlation_id, reason)

        line = prompt_line(req)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bool] = loop.create_future()

        def _resolve(*, answer: bool) -> None:
            """Called from the toast/WinRT thread; hop back onto the loop."""
            def _set() -> None:
                if not future.done():
                    future.set_result(answer)

            try:
                loop.call_soon_threadsafe(_set)
            except RuntimeError:
                # Loop already closed — a click that arrived after the
                # prompt was abandoned.  Dropping it is the safe outcome.
                log.warning("confirm[%s]: late answer dropped", correlation_id)

        def _on_allow() -> None:
            _resolve(answer=True)

        def _on_deny() -> None:
            _resolve(answer=False)

        actions: dict[str, tuple[str, Callable[[], None]]] = {
            ACTION_ALLOW: ("Allow", _on_allow),
            ACTION_DENY: ("Deny", _on_deny),
        }

        try:
            presenter.show(title=TOAST_TITLE, body=line, actions=actions)
        except Exception:
            log.exception("confirm[%s]: toast failed — denying", correlation_id)
            return ConfirmDecision(OUTCOME_DENIED, correlation_id, "toast_failed")

        spoken = await self._announce(line, correlation_id)

        try:
            answer = await asyncio.wait_for(future, self._timeout_s)
        except TimeoutError:
            log.warning(
                "confirm[%s]: no answer in %.1fs — unconfirmed",
                correlation_id,
                self._timeout_s,
            )
            return ConfirmDecision(
                OUTCOME_UNCONFIRMED, correlation_id, "timeout", spoken=spoken,
            )
        finally:
            # wait_for already cancels on timeout; this covers the paths
            # where the caller is cancelled, so a later click is a no-op.
            future.cancel()

        outcome = OUTCOME_ALLOWED if answer is True else OUTCOME_DENIED
        log.info("confirm[%s]: %s", correlation_id, outcome)
        return ConfirmDecision(outcome, correlation_id, "user", spoken=spoken)

    def _resolve_presenter(self) -> tuple[Any, str]:
        """Return ``(presenter, "")`` or ``(None, reason)`` — never raises."""
        if self._toast_provider is None:
            return None, "no_presenter"
        try:
            presenter = self._toast_provider()
        except Exception:
            log.exception("confirm: toast provider raised — denying")
            return None, "presenter_error"

        if presenter is None:
            return None, "no_presenter"
        if not callable(getattr(presenter, "show", None)):
            return None, "presenter_unusable"
        if not toast_stack_available(presenter):
            return None, "toast_unavailable"
        return presenter, ""

    def _voice_enabled(self) -> bool:
        """Read ``notifications.voice_announce_confirmations_enabled``.

        Defaults to *off* whenever the setting cannot be read: an
        unreadable config must not start talking to the room.
        """
        if self._config_provider is None:
            return False
        try:
            cfg = self._config_provider()
        except Exception:
            log.exception("confirm: config provider raised — voice suppressed")
            return False
        notifications = getattr(cfg, "notifications", None)
        return bool(getattr(notifications, "voice_announce_confirmations_enabled", False))

    async def _announce(self, line: str, correlation_id: str) -> bool:
        """Speak *line* when enabled.  Never raises, never blocks forever."""
        if self._voice is None or not self._voice_enabled():
            return False
        try:
            await asyncio.wait_for(_call_speak(self._voice, line), self._speak_timeout_s)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            log.warning("confirm[%s]: spoken line timed out", correlation_id)
            return False
        except Exception:
            log.exception("confirm[%s]: spoken line failed", correlation_id)
            return False
        return True


# --------------------------------------------------------------------------
# §7 confirmation policy — never/always-prompt lists and session memory (B3)
# --------------------------------------------------------------------------
#
# ConfirmPresenter above is the *mechanism*: show one prompt, wait for one
# answer.  This section is the *policy* that decides, for a given tool and a
# gate decision, whether that mechanism gets invoked at all — contract §7's
# operator-editable never-prompt / always-prompt lists, and the per-tool
# "remember for this session" that lets a burst of calls to the same tool
# ask only once.
#
# Name mapping
# ------------
# Contract §7 and ``AgentConfig.confirmation`` spell tool names in the
# underscore ``family_verb`` form (``files_read``, ``jobs_*``) — the same
# spelling the contract text and the settings UI use.  The gate
# (``mcp_host.permissions.evaluate_detailed``) and ``MCPHost.invoke`` work in
# the dotted ``family.verb`` form the plugin manifests declare
# (``filesystem.read``).  :func:`underscore_to_dotted` converts, and
# :func:`tool_matches_pattern` compares case-insensitively, so a hand-typed
# or mis-cased entry (``Files_write``) still matches.  ``jobs_*`` is the one
# family wildcard: it becomes ``jobs.*`` and matches every dotted tool
# *within* the ``jobs`` family (not the bare word ``jobs`` itself, which is
# not a real tool id) — see :func:`tool_matches_pattern`.
#
# A name that still fails to match anything real — a typo the case-fold
# doesn't rescue, a family that has not been built yet — fails *toward* the
# gate's own decision, but that is **not symmetrically safe for both
# lists**: for a never-prompt entry, "matches nothing" means the gate's own
# decision stands, which is at worst an extra prompt. For an always-prompt
# entry, "matches nothing" *also* means the gate's own decision stands —
# and for an action tool the gate often already says "allow" on its own, so
# a broken always-prompt match can silently produce no prompt at all where
# §7 wanted one every time. Treat "fails toward prompting" as a claim about
# the never-prompt list only; case-folding closes the one way this was
# reachable through an ordinary operator typo, but it is not a guarantee
# that every possible mismatch on the always-prompt side is harmless.
#
# What this can and cannot do
# ----------------------------
# * It never runs before the gate and never sees a ``"deny"`` —
#   ``MCPHost.invoke`` only consults it for calls the gate already resolved
#   to ``"confirm"`` or ``"allow"``.  A pre-approved (never-prompt) tool that
#   the gate denies stays denied; this module has no path back to that
#   decision at all, by construction rather than by a check that could be
#   missed.
# * For a gate ``"confirm"``: the policy can only *suppress* the prompt
#   (never-prompt, or an already-remembered tool+session) — the call still
#   had to be "allowed in principle" by the gate first.
# * For a gate ``"allow"``: the policy can *add* a prompt (always-prompt)
#   that the gate itself did not require — contract §7 wants every
#   ``shell_run`` and ``files_write`` confirmed even when the
#   argument-confinement gate has nothing to complain about.
# * If a tool is (mis)configured into both lists, "always" wins: the safe
#   failure direction is more confirmation, not less.


def underscore_to_dotted(name: str) -> str:
    """Convert a §7 tool name to the gate's dotted ``family.verb`` form.

    ``"files_read"`` -> ``"files.read"``.  ``"jobs_*"`` (the one family
    wildcard the contract defines) -> ``"jobs.*"``.  A name with no ``_`` at
    all — already dotted, empty, or just not a recognised shape — is
    returned unchanged, which will not match a real dotted tool id.

    Case is *not* folded here — :func:`tool_matches_pattern` does that on
    both sides at comparison time, once, rather than here and at every call
    site that might otherwise forget to.
    """
    name = name.strip()
    if not name:
        return name
    if name.endswith("_*"):
        family = name[:-2]
        return f"{family}.*" if family else name
    if "_" not in name:
        return name
    family, verb = name.split("_", 1)
    return f"{family}.{verb}"


def tool_matches_pattern(pattern: str, tool_id: str) -> bool:
    """True if dotted *pattern* (from :func:`underscore_to_dotted`) matches *tool_id*.

    Case-folded on both sides before comparing, so an operator- or hand-typed
    entry like ``Files_write`` still matches the gate's (always lower-case)
    ``files.write`` — see the asymmetry note below for why this matters more
    than it looks.

    A trailing ``.*`` matches every tool *within* that family (``jobs.*``
    matches ``jobs.wait``, ``jobs.output``, ... but not the bare name
    ``jobs`` itself, which is not a real dotted tool id and should not be
    swept in just because it shares the family's spelling). Everything else
    is an exact match only — there is no implicit prefix matching, so
    ``files.rea`` never matches ``files.read``.

    Failing to match is **not symmetrically safe**. A never-prompt entry
    that fails to match falls back to the gate's own decision — at worst an
    extra prompt, never a widened permission. An always-prompt entry that
    fails to match (a mis-cased config line, say) falls back to the gate's
    own decision too, but for an action tool the gate often says "allow" on
    its own — so a broken always-prompt match can silently produce *no*
    prompt at all where §7 wanted one every time. Case-folding here removes
    the one way that was reachable through ordinary operator typos.
    """
    if not pattern or not tool_id:
        return False
    pattern = pattern.casefold()
    tool_id = tool_id.casefold()
    if pattern == tool_id:
        return True
    if pattern.endswith(".*"):
        family = pattern[:-2]
        return bool(family) and tool_id.startswith(family + ".")
    return False


class PromptPolicy:
    """Runtime view of contract §7's confirmation policy for one MCPHost.

    See :class:`workstation_agent.mcp_host.host.MCPHost`, which owns one
    instance of this class.  Reads the operator's ``AgentConfig.confirmation``
    lists via
    *config_provider*, called fresh on every query — there is no cached copy
    to go stale, so a setting changed through the UI takes effect on the very
    next call.

    Session memory (:meth:`remember` / :meth:`is_remembered`) is the only
    stateful part of this class, and it is deliberately narrow:

    * **per session AND per tool** — keyed by ``(session_id, tool_id)``, so
      remembering ``serial.write`` for session ``s1`` cannot suppress a
      prompt for ``files.write`` in ``s1``, nor for ``serial.write`` in a
      different session ``s2``;
    * **in memory only** — a plain dict on this instance, never written to
      disk and never shared with another :class:`PromptPolicy`, so it cannot
      outlive the process or leak to another one; and
    * **cleared by** :meth:`reset`, which ``MCPHost.start`` calls on every
      (re)start — "must not survive an Agent restart" is enforced by that
      call always happening, not by a TTL that happens to be short enough.
    """

    def __init__(self, config_provider: Callable[[], Any] | None = None) -> None:
        """Build a policy view; *config_provider* is called lazily, per query."""
        self._config_provider = config_provider
        self._remembered: dict[str, set[str]] = {}

    def reset(self) -> None:
        """Drop all remembered session approvals.  Called by ``MCPHost.start``."""
        self._remembered = {}

    def _policy_config(self) -> Any:  # noqa: ANN401 — duck-typed AgentConfig.confirmation
        if self._config_provider is None:
            return None
        try:
            cfg = self._config_provider()
        except Exception:
            log.exception("confirm policy: config provider raised")
            return None
        if cfg is None:
            return None
        return getattr(cfg, "confirmation", None)

    def classify(self, tool_id: str) -> str | None:
        """Return ``"always"``, ``"never"``, or ``None`` for *tool_id*.

        ``None`` means "the operator has not named this tool" — the caller
        must defer entirely to the gate's own decision.  A tool named in
        both lists resolves to ``"always"`` (see the module docstring).
        """
        policy = self._policy_config()
        if policy is None:
            return None
        always = getattr(policy, "always_prompt", None) or ()
        if any(tool_matches_pattern(underscore_to_dotted(p), tool_id) for p in always):
            return "always"
        never = getattr(policy, "never_prompt", None) or ()
        if any(tool_matches_pattern(underscore_to_dotted(p), tool_id) for p in never):
            return "never"
        return None

    def remember_enabled(self, tool_id: str) -> bool:
        """True if the operator opted *tool_id* into "remember for session"."""
        policy = self._policy_config()
        if policy is None:
            return False
        patterns = getattr(policy, "remember_for_session", None) or ()
        return any(tool_matches_pattern(underscore_to_dotted(p), tool_id) for p in patterns)

    def is_remembered(self, session_id: str | None, tool_id: str) -> bool:
        """True if *tool_id* was already explicitly allowed in *session_id*.

        Always false without a session id — there is nothing to key on, so
        an in-process caller with no transport session is never remembered
        and always goes through the real prompt.

        Trust boundary this rests on: keying by ``session_id`` only isolates
        remembered approvals per session if ``session_id`` itself is
        unguessable and never reused. This class does not mint or validate
        it -- it takes whatever ``MCPHost.invoke`` was handed, which comes
        from ``SessionContext`` (B2), minted per connection with
        ``uuid.uuid4().hex`` in ``mcp_host/mcp_server.py`` at the time this
        was written. If that ever changes to something predictable or
        reused across connections (e.g. derived from a client-supplied
        value, or recycled from a pool), a never-explicitly-approved caller
        could inherit another session's remembered approvals purely by
        presenting its id -- this method has no way to detect that.
        """
        if not session_id:
            return False
        return tool_id in self._remembered.get(session_id, ())

    def remember(self, session_id: str | None, tool_id: str) -> None:
        """Record an explicit Allow for *tool_id* in *session_id*, if enabled.

        A no-op without a session id, and a no-op unless the operator opted
        *tool_id* into remembering (:meth:`remember_enabled`) — remembering
        is never turned on silently just because a prompt happened to
        succeed.
        """
        if not session_id or not self.remember_enabled(tool_id):
            return
        self._remembered.setdefault(session_id, set()).add(tool_id)

    def forget_session(self, session_id: str) -> None:
        """Drop remembered approvals for one session (e.g. on disconnect)."""
        self._remembered.pop(session_id, None)
