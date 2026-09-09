"""Unit tests for workstation_agent.confirm — the awaitable confirm primitive.

The single property under test everywhere below is **fail closed**: the only
path that produces ``True`` is an explicit Allow click.  Every other path —
no presenter, an unusable presenter, an absent winrt toast stack, a raising
``show()``, a raising provider, an unanswered prompt — must deny.
"""
# ruff: noqa: ARG002, FBT001, PLW0108, PT018

from __future__ import annotations

import asyncio

import pytest

from workstation_agent.config.schema import AgentConfig
from workstation_agent.confirm import (
    ACTION_ALLOW,
    ACTION_DENY,
    CONFIRM_TIMEOUT_S,
    OUTCOME_ALLOWED,
    OUTCOME_DENIED,
    OUTCOME_UNCONFIRMED,
    ConfirmDecision,
    ConfirmPresenter,
    PromptPolicy,
    command_text,
    prompt_line,
    toast_stack_available,
    tool_matches_pattern,
    underscore_to_dotted,
)
from workstation_agent.mcp_host.host import ConfirmationRequestImpl
from workstation_agent.ui.notifications import toast as toast_mod

# A timeout short enough that CI never waits for the real 20 s window.
FAST = 0.05


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeToast:
    """Records show() calls.  ``answer`` decides which button 'clicks'.

    The click is fired synchronously from inside ``show()``, exactly like a
    user who answers instantly; the resolver has to cope with being called
    before anything awaits the future.
    """

    def __init__(self, answer: bool | None = None, *, raises: bool = False) -> None:
        self.answer = answer
        self.raises = raises
        self.calls: list[dict] = []

    def show(self, *, title, body, actions=None):
        self.calls.append({"title": title, "body": body, "actions": actions})
        if self.raises:
            msg = "toast stack exploded"
            raise RuntimeError(msg)
        if self.answer is None or not actions:
            return
        action_id = ACTION_ALLOW if self.answer else ACTION_DENY
        actions[action_id][1]()


class ThreadedToast(FakeToast):
    """Fires the button callback from a *different* thread, as WinRT does."""

    def show(self, *, title, body, actions=None):
        self.calls.append({"title": title, "body": body, "actions": actions})
        if self.answer is None or not actions:
            return
        import threading

        action_id = ACTION_ALLOW if self.answer else ACTION_DENY
        threading.Thread(target=actions[action_id][1], daemon=True).start()


class RecordingVoice:
    def __init__(self, *, raises: bool = False, hangs: bool = False) -> None:
        self.spoken: list[str] = []
        self.raises = raises
        self.hangs = hangs

    async def speak(self, text: str) -> None:
        self.spoken.append(text)
        if self.raises:
            msg = "tts is down"
            raise RuntimeError(msg)
        if self.hangs:
            await asyncio.sleep(3600)


def make_req(tool_id="shell.exec", args=None):
    return ConfirmationRequestImpl(
        plugin_id="shell",
        tool_id=tool_id,
        args=args if args is not None else {},
    )


def make_config(*, voice: bool) -> AgentConfig:
    cfg = AgentConfig()
    cfg.notifications.voice_announce_confirmations_enabled = voice
    return cfg


def make_presenter(toast, *, voice=None, config=None, timeout=FAST, speak_timeout=FAST):
    return ConfirmPresenter(
        toast_provider=lambda: toast,
        speak=voice,
        config_provider=(lambda: config) if config is not None else None,
        timeout_s=timeout,
        speak_timeout_s=speak_timeout,
    )


# ---------------------------------------------------------------------------
# Contract surface
# ---------------------------------------------------------------------------


def test_timeout_is_the_contract_value():
    """§7 fixes the confirmation window at 20 s."""
    assert CONFIRM_TIMEOUT_S == 20.0
    assert ConfirmPresenter()._timeout_s == 20.0


def test_prompt_line_matches_section_7():
    assert prompt_line(make_req("shell.exec")) == (
        "PersonaCore wants to run shell.exec on this machine. Allow?"
    )


def test_prompt_line_prefers_the_command_argument():
    req = make_req("shell.exec", {"command": "  dir  C:\\ "})
    assert command_text(req) == "dir C:\\"
    assert "dir C:\\" in prompt_line(req)


def test_command_text_is_bounded_and_single_line():
    req = make_req("shell.exec", {"command": "a" * 500 + "\nrm -rf /"})
    text = command_text(req)
    assert len(text) <= 120
    assert "\n" not in text


def test_command_text_survives_a_malformed_request():
    class Broken:
        @property
        def args(self):
            msg = "no args for you"
            raise RuntimeError(msg)

        @property
        def tool_id(self):
            msg = "no tool id either"
            raise RuntimeError(msg)

    assert command_text(Broken()) == "an unnamed command"


def test_decision_allowed_only_for_allowed_outcome():
    assert ConfirmDecision(OUTCOME_ALLOWED, "cid").allowed
    assert not ConfirmDecision(OUTCOME_DENIED, "cid").allowed
    assert not ConfirmDecision(OUTCOME_UNCONFIRMED, "cid").allowed


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allow_click_resolves_true():
    toast = FakeToast(answer=True)
    decision = await make_presenter(toast).request(make_req())
    assert decision.outcome == OUTCOME_ALLOWED
    assert decision.allowed


@pytest.mark.asyncio
async def test_deny_click_resolves_false():
    toast = FakeToast(answer=False)
    decision = await make_presenter(toast).request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert not decision.allowed


@pytest.mark.asyncio
async def test_toast_carries_allow_and_deny_buttons_and_the_prompt():
    toast = FakeToast(answer=True)
    await make_presenter(toast).confirm(make_req())
    call = toast.calls[0]
    assert set(call["actions"]) == {ACTION_ALLOW, ACTION_DENY}
    assert call["actions"][ACTION_ALLOW][0] == "Allow"
    assert call["actions"][ACTION_DENY][0] == "Deny"
    assert call["body"] == "PersonaCore wants to run shell.exec on this machine. Allow?"


@pytest.mark.asyncio
async def test_answer_from_another_thread_resolves():
    """The real toast fires its callback off-loop; the adapter must cope."""
    toast = ThreadedToast(answer=True)
    presenter = make_presenter(toast, timeout=5.0)
    assert await presenter.confirm(make_req()) is True


@pytest.mark.asyncio
async def test_correlation_id_is_stable_and_echoed():
    toast = FakeToast(answer=True)
    req = make_req()
    req.correlation_id = "abc123"
    decision = await make_presenter(toast).request(req)
    assert decision.correlation_id == "abc123"


@pytest.mark.asyncio
async def test_correlation_id_is_minted_when_absent():
    toast = FakeToast(answer=True)
    d1 = await make_presenter(toast).request(make_req())
    d2 = await make_presenter(toast).request(make_req())
    assert d1.correlation_id
    assert d1.correlation_id != d2.correlation_id


@pytest.mark.asyncio
async def test_presenter_instance_is_the_callback():
    toast = FakeToast(answer=True)
    presenter = make_presenter(toast)
    assert await presenter(make_req()) is True


# ---------------------------------------------------------------------------
# Fail-closed: the timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unanswered_prompt_is_unconfirmed_not_allowed():
    """An unanswered prompt resolves to ``unconfirmed`` — a value, not a raise."""
    toast = FakeToast(answer=None)
    presenter = make_presenter(toast, timeout=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_UNCONFIRMED
    assert decision.reason == "timeout"
    assert not decision.allowed
    assert await presenter.confirm(make_req()) is False


@pytest.mark.asyncio
async def test_timeout_fires_at_the_configured_window():
    """The window is honoured, and only injection keeps CI off the 20 s clock."""
    toast = FakeToast(answer=None)
    loop = asyncio.get_running_loop()
    started = loop.time()
    decision = await make_presenter(toast, timeout=0.25).request(make_req())
    elapsed = loop.time() - started
    assert decision.outcome == OUTCOME_UNCONFIRMED
    assert 0.2 <= elapsed < 5.0


@pytest.mark.asyncio
async def test_click_after_the_timeout_is_harmless():
    """A late Allow must not blow up, and must not retroactively allow."""
    captured: dict = {}

    class LateToast(FakeToast):
        def show(self, *, title, body, actions=None):
            assert actions is not None
            captured["actions"] = actions

    presenter = make_presenter(LateToast(), timeout=FAST)
    assert await presenter.confirm(make_req()) is False
    captured["actions"][ACTION_ALLOW][1]()  # the user clicks Allow, too late
    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# Fail-closed: no presenter / unusable presenter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_toast_provider_denies():
    presenter = ConfirmPresenter(timeout_s=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "no_presenter"


@pytest.mark.asyncio
async def test_provider_returning_none_denies_immediately():
    """A missing presenter denies without burning the confirmation window."""
    presenter = ConfirmPresenter(toast_provider=lambda: None, timeout_s=30.0)
    loop = asyncio.get_running_loop()
    started = loop.time()
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "no_presenter"
    assert loop.time() - started < 1.0


@pytest.mark.asyncio
async def test_provider_raising_denies():
    def _boom():
        msg = "no subsystems yet"
        raise RuntimeError(msg)

    presenter = ConfirmPresenter(toast_provider=_boom, timeout_s=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "presenter_error"


@pytest.mark.asyncio
async def test_presenter_without_show_denies():
    presenter = ConfirmPresenter(toast_provider=lambda: object(), timeout_s=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "presenter_unusable"


@pytest.mark.asyncio
async def test_show_raising_denies():
    """An exception inside the presenter denies rather than propagating."""
    toast = FakeToast(raises=True)
    presenter = make_presenter(toast)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "toast_failed"
    assert await presenter.confirm(make_req()) is False


# ---------------------------------------------------------------------------
# Fail-closed: the winrt toast stack is absent
# ---------------------------------------------------------------------------


def test_toast_stack_available_false_without_winrt(monkeypatch):
    monkeypatch.setattr(toast_mod, "_WINRT_AVAILABLE", False, raising=False)
    real = toast_mod.ToastPresenter(app_id="test")
    assert toast_stack_available(real) is False


def test_toast_stack_available_false_without_notifier(monkeypatch):
    monkeypatch.setattr(toast_mod, "_WINRT_AVAILABLE", True, raising=False)
    real = toast_mod.ToastPresenter(app_id="test")
    real._notifier = None
    assert toast_stack_available(real) is False


def test_toast_stack_available_true_with_a_live_notifier(monkeypatch):
    monkeypatch.setattr(toast_mod, "_WINRT_AVAILABLE", True, raising=False)
    real = toast_mod.ToastPresenter(app_id="test")
    real._notifier = object()
    assert toast_stack_available(real) is True


def test_toast_stack_available_trusts_injected_presenters():
    assert toast_stack_available(FakeToast()) is True


@pytest.mark.asyncio
async def test_absent_toast_stack_denies_and_never_shows(monkeypatch):
    """``show()`` only logs when winrt is missing, so no click can ever arrive.

    Without the explicit availability check this would sit out the whole
    confirmation window; with a less careful design it would auto-allow.
    """
    monkeypatch.setattr(toast_mod, "_WINRT_AVAILABLE", False, raising=False)
    real = toast_mod.ToastPresenter(app_id="test")
    presenter = ConfirmPresenter(toast_provider=lambda: real, timeout_s=30.0)

    loop = asyncio.get_running_loop()
    started = loop.time()
    decision = await presenter.request(make_req())

    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "toast_unavailable"
    assert not decision.allowed
    assert loop.time() - started < 1.0
    assert await presenter.confirm(make_req()) is False


# ---------------------------------------------------------------------------
# Fail-closed: anything else
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_internal_failure_denies(monkeypatch):
    """A defect anywhere below ``request`` still denies."""
    def _explode(_req):
        msg = "unexpected"
        raise RuntimeError(msg)

    monkeypatch.setattr("workstation_agent.confirm.prompt_line", _explode)
    presenter = make_presenter(FakeToast(answer=True))
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "internal_error"


@pytest.mark.asyncio
async def test_confirm_never_raises_for_a_garbage_request():
    presenter = make_presenter(FakeToast(answer=None))
    assert await presenter.confirm(object()) is False


@pytest.mark.asyncio
async def test_cancellation_propagates_and_does_not_allow():
    presenter = make_presenter(FakeToast(answer=None), timeout=30.0)
    task = asyncio.create_task(presenter.confirm(make_req()))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# voice_announce_confirmations_enabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_voice_enabled_speaks_the_section_7_line():
    voice = RecordingVoice()
    toast = FakeToast(answer=True)
    presenter = make_presenter(toast, voice=voice, config=make_config(voice=True))
    decision = await presenter.request(make_req())
    assert decision.spoken is True
    assert voice.spoken == [
        "PersonaCore wants to run shell.exec on this machine. Allow?",
    ]
    assert toast.calls[0]["body"] == voice.spoken[0]


@pytest.mark.asyncio
async def test_voice_disabled_suppresses_speech_but_still_shows_the_toast():
    voice = RecordingVoice()
    toast = FakeToast(answer=True)
    presenter = make_presenter(toast, voice=voice, config=make_config(voice=False))
    decision = await presenter.request(make_req())
    assert voice.spoken == []
    assert decision.spoken is False
    assert len(toast.calls) == 1
    assert decision.allowed


@pytest.mark.asyncio
async def test_voice_defaults_off_without_a_config_provider():
    voice = RecordingVoice()
    presenter = make_presenter(FakeToast(answer=True), voice=voice)
    await presenter.request(make_req())
    assert voice.spoken == []


@pytest.mark.asyncio
async def test_unreadable_config_suppresses_voice_but_not_the_toast():
    def _boom():
        msg = "config not loaded"
        raise RuntimeError(msg)

    voice = RecordingVoice()
    toast = FakeToast(answer=True)
    presenter = ConfirmPresenter(
        toast_provider=lambda: toast,
        speak=voice,
        config_provider=_boom,
        timeout_s=FAST,
    )
    decision = await presenter.request(make_req())
    assert voice.spoken == []
    assert len(toast.calls) == 1
    assert decision.allowed


@pytest.mark.asyncio
async def test_speech_failure_does_not_allow_and_does_not_break_the_prompt():
    voice = RecordingVoice(raises=True)
    toast = FakeToast(answer=None)
    presenter = make_presenter(toast, voice=voice, config=make_config(voice=True))
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_UNCONFIRMED
    assert decision.spoken is False
    assert len(toast.calls) == 1


@pytest.mark.asyncio
async def test_wedged_tts_cannot_hang_the_confirm():
    voice = RecordingVoice(hangs=True)
    toast = FakeToast(answer=True)
    presenter = make_presenter(
        toast, voice=voice, config=make_config(voice=True), speak_timeout=FAST,
    )
    decision = await presenter.request(make_req())
    assert decision.allowed  # the click landed while the TTS was wedged
    assert decision.spoken is False


@pytest.mark.asyncio
async def test_attach_voice_installs_the_channel():
    voice = RecordingVoice()
    presenter = make_presenter(FakeToast(answer=True), config=make_config(voice=True))
    presenter.attach_voice(voice)
    await presenter.request(make_req())
    assert len(voice.spoken) == 1


@pytest.mark.asyncio
async def test_plain_callable_voice_is_supported():
    spoken: list[str] = []

    async def _speak(text: str) -> None:
        spoken.append(text)

    presenter = make_presenter(
        FakeToast(answer=True), voice=_speak, config=make_config(voice=True),
    )
    await presenter.request(make_req())
    assert len(spoken) == 1


@pytest.mark.asyncio
async def test_synchronous_voice_is_supported():
    spoken: list[str] = []

    class SyncVoice:
        def speak(self, text: str) -> None:
            spoken.append(text)

    presenter = make_presenter(
        FakeToast(answer=True), voice=SyncVoice(), config=make_config(voice=True),
    )
    decision = await presenter.request(make_req())
    assert spoken and decision.spoken is True


# ---------------------------------------------------------------------------
# Adversarial presenters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_answer_wins_when_both_buttons_fire():
    """A presenter that fires Deny then Allow must not be talked into an allow."""
    class BothToast:
        def show(self, *, title, body, actions):
            actions[ACTION_DENY][1]()
            actions[ACTION_ALLOW][1]()

    presenter = ConfirmPresenter(toast_provider=BothToast, timeout_s=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED


@pytest.mark.asyncio
async def test_repeated_clicks_are_idempotent():
    class ChattyToast:
        def show(self, *, title, body, actions):
            for _ in range(5):
                actions[ACTION_ALLOW][1]()

    presenter = ConfirmPresenter(toast_provider=ChattyToast, timeout_s=FAST)
    assert await presenter.confirm(make_req()) is True


@pytest.mark.asyncio
async def test_concurrent_prompts_are_independent():
    """One prompt's answer must not resolve another's."""
    p_yes = make_presenter(FakeToast(answer=True), timeout=1.0)
    p_no = make_presenter(FakeToast(answer=None), timeout=FAST)

    yes, no = await asyncio.gather(
        p_yes.confirm(make_req("a.one")),
        p_no.confirm(make_req("b.two")),
    )
    assert yes is True
    assert no is False


@pytest.mark.asyncio
async def test_show_raising_after_a_click_still_denies():
    """Fail-closed beats a click: if show() blew up, the prompt is not trusted."""
    class LateBoomToast:
        def show(self, *, title, body, actions):
            actions[ACTION_ALLOW][1]()
            msg = "raised after firing the callback"
            raise RuntimeError(msg)

    presenter = ConfirmPresenter(toast_provider=LateBoomToast, timeout_s=FAST)
    decision = await presenter.request(make_req())
    assert decision.outcome == OUTCOME_DENIED
    assert decision.reason == "toast_failed"


# ---------------------------------------------------------------------------
# §7 confirmation policy (B3) — name mapping
# ---------------------------------------------------------------------------


class TestUnderscoreToDotted:
    def test_simple_family_verb(self):
        assert underscore_to_dotted("files_read") == "files.read"
        assert underscore_to_dotted("shell_run") == "shell.run"

    def test_family_wildcard(self):
        assert underscore_to_dotted("jobs_*") == "jobs.*"

    def test_no_underscore_returned_unchanged(self):
        """No family separator to find -- returned as-is, matching nothing real."""
        assert underscore_to_dotted("alreadydotted") == "alreadydotted"

    def test_empty_string(self):
        assert underscore_to_dotted("") == ""

    def test_whitespace_is_stripped(self):
        assert underscore_to_dotted("  files_read  ") == "files.read"

    def test_only_first_underscore_splits(self):
        """A verb that itself contains an underscore keeps it (e.g. multi-word verbs)."""
        assert underscore_to_dotted("adb_factory_reset") == "adb.factory_reset"


class TestToolMatchesPattern:
    def test_exact_match(self):
        assert tool_matches_pattern("files.read", "files.read")

    def test_exact_mismatch(self):
        assert not tool_matches_pattern("files.read", "files.write")

    def test_no_partial_prefix_match(self):
        assert not tool_matches_pattern("files.rea", "files.read")

    def test_family_wildcard_matches_every_verb(self):
        assert tool_matches_pattern("jobs.*", "jobs.wait")
        assert tool_matches_pattern("jobs.*", "jobs.output")
        assert tool_matches_pattern("jobs.*", "jobs.list")

    def test_family_wildcard_does_not_match_other_family(self):
        assert not tool_matches_pattern("jobs.*", "adb.devices")

    def test_family_wildcard_does_not_match_the_bare_family_name(self):
        """`jobs.*` matches tools *within* the family, not the word `jobs` itself.

        Rework cycle 1, finding #2: no real tool is named exactly its
        family, but the wildcard should describe "within the family", not
        "starts with the family's spelling".
        """
        assert not tool_matches_pattern("jobs.*", "jobs")

    def test_empty_pattern_or_tool_never_matches(self):
        assert not tool_matches_pattern("", "files.read")
        assert not tool_matches_pattern("files.read", "")

    def test_case_insensitive_exact_match(self):
        """Rework cycle 1, finding #1: a mis-cased pattern must still match.

        `underscore_to_dotted("Files_write")` -> `"Files.write"` (case is not
        folded there by design); the gate's tool id is always lower-case
        (`files.write`). Without folding here, an always-prompt entry typed
        with a capital would silently stop matching -- the unsafe direction.
        """
        assert tool_matches_pattern("Files.write", "files.write")
        assert tool_matches_pattern("files.write", "FILES.WRITE")

    def test_case_insensitive_wildcard_match(self):
        assert tool_matches_pattern("JOBS.*", "jobs.output")
        assert tool_matches_pattern("jobs.*", "JOBS.OUTPUT")


# ---------------------------------------------------------------------------
# §7 confirmation policy (B3) — PromptPolicy
# ---------------------------------------------------------------------------


def _cfg_with_policy(*, never=(), always=(), remember=()) -> AgentConfig:
    cfg = AgentConfig()
    cfg.confirmation.never_prompt = list(never)
    cfg.confirmation.always_prompt = list(always)
    cfg.confirmation.remember_for_session = list(remember)
    return cfg


class TestPromptPolicyClassify:
    def test_no_config_provider_is_neutral(self):
        policy = PromptPolicy(config_provider=None)
        assert policy.classify("files.read") is None

    def test_config_provider_raising_is_neutral(self):
        def _boom():
            msg = "config unavailable"
            raise RuntimeError(msg)

        policy = PromptPolicy(config_provider=_boom)
        assert policy.classify("files.read") is None

    def test_config_without_confirmation_attr_is_neutral(self):
        policy = PromptPolicy(config_provider=lambda: object())
        assert policy.classify("files.read") is None

    def test_never_prompt_classification(self):
        cfg = _cfg_with_policy(never=["files_read"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("files.read") == "never"

    def test_always_prompt_classification(self):
        cfg = _cfg_with_policy(always=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("shell.run") == "always"

    def test_unlisted_tool_is_neutral(self):
        cfg = _cfg_with_policy(never=["files_read"], always=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("clipboard.paste") is None

    def test_wildcard_family_classification(self):
        cfg = _cfg_with_policy(never=["jobs_*"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("jobs.output") == "never"
        assert policy.classify("jobs.wait") == "never"

    def test_capitalised_always_prompt_entry_still_classifies_always(self):
        """Rework cycle 1, finding #1 -- the unsafe direction.

        An always-prompt entry typed (or hand-edited into config.toml) with
        different casing must still classify as "always": if it silently
        stopped matching, an action tool the gate would otherwise "allow"
        on its own could run with no prompt at all.
        """
        cfg = _cfg_with_policy(always=["Shell_Run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("shell.run") == "always"

    def test_listed_in_both_resolves_to_always(self):
        """Misconfiguration (both lists) fails toward more confirmation."""
        cfg = _cfg_with_policy(never=["shell_run"], always=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("shell.run") == "always"

    def test_config_reread_on_every_call(self):
        """No cached copy -- a config swapped mid-flight is picked up live."""
        cfg = _cfg_with_policy()
        policy = PromptPolicy(config_provider=lambda: cfg)
        assert policy.classify("shell.run") is None
        cfg.confirmation.always_prompt = ["shell_run"]
        assert policy.classify("shell.run") == "always"


class TestPromptPolicySessionMemory:
    def test_not_remembered_without_session_id(self):
        cfg = _cfg_with_policy(remember=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember(None, "shell.run")
        assert not policy.is_remembered(None, "shell.run")
        assert not policy.is_remembered("", "shell.run")

    def test_remember_requires_opt_in(self):
        """remember() is a no-op unless the tool is on remember_for_session."""
        cfg = _cfg_with_policy()  # remember list empty
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        assert not policy.is_remembered("s1", "shell.run")

    def test_remember_then_is_remembered(self):
        cfg = _cfg_with_policy(remember=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        assert policy.is_remembered("s1", "shell.run")

    def test_remember_is_per_tool(self):
        """Remembering shell.run must not remember files.write in the same session."""
        cfg = _cfg_with_policy(remember=["shell_run", "files_write"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        assert policy.is_remembered("s1", "shell.run")
        assert not policy.is_remembered("s1", "files.write")

    def test_remember_does_not_leak_across_sessions(self):
        cfg = _cfg_with_policy(remember=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        assert policy.is_remembered("s1", "shell.run")
        assert not policy.is_remembered("s2", "shell.run")

    def test_reset_clears_all_sessions(self):
        """reset() -- called by MCPHost.start on every restart -- forgets everything."""
        cfg = _cfg_with_policy(remember=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        assert policy.is_remembered("s1", "shell.run")
        policy.reset()
        assert not policy.is_remembered("s1", "shell.run")

    def test_forget_session_only_clears_that_session(self):
        cfg = _cfg_with_policy(remember=["shell_run"])
        policy = PromptPolicy(config_provider=lambda: cfg)
        policy.remember("s1", "shell.run")
        policy.remember("s2", "shell.run")
        policy.forget_session("s1")
        assert not policy.is_remembered("s1", "shell.run")
        assert policy.is_remembered("s2", "shell.run")
