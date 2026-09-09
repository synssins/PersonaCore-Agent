"""The composition root actually wires the confirm path (review finding §1).

Before this, ``app.py`` called ``await host.start(cfg)`` with neither
``confirm_cb`` nor ``tts_speak``, so every confirmable condition was silently
denied and no voice ever played.  These tests pin the wiring end to end:
``Application`` -> ``MCPHost.start`` -> ``ConfirmPresenter`` -> ``ToastPresenter``.
"""
# ruff: noqa: FBT001

from __future__ import annotations

import asyncio

import pytest

from workstation_agent.app import Application
from workstation_agent.config.schema import AgentConfig
from workstation_agent.confirm import ACTION_ALLOW, ACTION_DENY, ConfirmPresenter
from workstation_agent.mcp_host import host as host_mod
from workstation_agent.mcp_host.host import ConfirmationRequestImpl, MCPHost
from workstation_agent.mcp_host.loader import PluginManifest, VerifyResult


class CapturingToast:
    def __init__(self, answer: bool | None) -> None:
        self.answer = answer
        self.calls: list[dict] = []

    def show(self, *, title, body, actions=None):
        self.calls.append({"title": title, "body": body, "actions": actions})
        if self.answer is None or not actions:
            return
        actions[ACTION_ALLOW if self.answer else ACTION_DENY][1]()


class CapturingTTS:
    """Stands in for WyomingTTSClient: speak() returns a drainable task."""

    def __init__(self) -> None:
        self.spoken: list[str] = []

    async def speak(self, text: str):
        self.spoken.append(text)
        return object()

    async def audio_chunks(self, _task):
        yield b"\x00\x01"


class CapturingSpeaker:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def enqueue(self, chunk: bytes) -> None:
        self.chunks.append(chunk)


@pytest.fixture
def app_with_stub_host(monkeypatch):
    """An Application whose MCPHost.start records what it was handed."""
    captured: dict = {}

    class StubHost:
        async def start(self, config, confirm_cb=None, tts_speak=None):
            captured["config"] = config
            captured["confirm_cb"] = confirm_cb
            captured["tts_speak"] = tts_speak

    monkeypatch.setattr(host_mod, "MCPHost", StubHost)
    return Application(fake_backends=True, headless=True), captured


@pytest.mark.asyncio
async def test_start_mcp_host_passes_confirm_cb_and_tts_speak(app_with_stub_host):
    app, captured = app_with_stub_host
    cfg = AgentConfig()
    app._subs.config = cfg

    await app._start_mcp_host(cfg)

    assert isinstance(captured["confirm_cb"], ConfirmPresenter)
    assert captured["tts_speak"] is not None
    assert app._subs.started["mcp_host"].ok


@pytest.mark.asyncio
async def test_wired_presenter_resolves_lazily(app_with_stub_host):
    """The presenter is built at step 3 but the toast only exists at step 8."""
    app, captured = app_with_stub_host
    cfg = AgentConfig()
    cfg.notifications.voice_announce_confirmations_enabled = True
    app._subs.config = cfg

    await app._start_mcp_host(cfg)
    presenter: ConfirmPresenter = captured["confirm_cb"]
    presenter._timeout_s = 0.05

    req = ConfirmationRequestImpl(plugin_id="shell", tool_id="shell.exec", args={})

    # Step 3..7: no ToastPresenter yet -> deny, do not wait, do not allow.
    early = await presenter.request(req)
    assert not early.allowed
    assert early.reason == "no_presenter"

    # Step 8: the toast presenter appears; the same object now works.
    toast = CapturingToast(answer=True)
    app._subs.toast = toast
    assert await presenter.confirm(req) is True
    assert toast.calls[0]["body"] == (
        "PersonaCore wants to run shell.exec on this machine. Allow?"
    )


@pytest.mark.asyncio
async def test_wired_voice_speaks_through_tts_and_speaker(app_with_stub_host):
    """host.start hands tts_speak to the presenter; audio reaches the speaker."""
    app, captured = app_with_stub_host
    cfg = AgentConfig()
    cfg.notifications.voice_announce_confirmations_enabled = True
    app._subs.config = cfg

    await app._start_mcp_host(cfg)
    presenter: ConfirmPresenter = captured["confirm_cb"]
    presenter._timeout_s = 0.05

    # MCPHost.start would normally do this; the stub host does not.
    presenter.attach_voice(captured["tts_speak"])

    tts = CapturingTTS()
    speaker = CapturingSpeaker()
    app._subs.tts = tts
    app._subs.speaker = speaker
    app._subs.toast = CapturingToast(answer=True)

    req = ConfirmationRequestImpl(plugin_id="shell", tool_id="shell.exec", args={})
    assert await presenter.confirm(req) is True
    assert tts.spoken == [
        "PersonaCore wants to run shell.exec on this machine. Allow?",
    ]
    assert speaker.chunks == [b"\x00\x01"]


@pytest.mark.asyncio
async def test_wired_voice_is_silent_before_the_tts_exists(app_with_stub_host):
    app, captured = app_with_stub_host
    cfg = AgentConfig()
    cfg.notifications.voice_announce_confirmations_enabled = True
    app._subs.config = cfg

    await app._start_mcp_host(cfg)
    presenter: ConfirmPresenter = captured["confirm_cb"]
    presenter._timeout_s = 0.05
    presenter.attach_voice(captured["tts_speak"])

    toast = CapturingToast(answer=True)
    app._subs.toast = toast

    req = ConfirmationRequestImpl(plugin_id="shell", tool_id="shell.exec", args={})
    assert await presenter.confirm(req) is True
    assert len(toast.calls) == 1


# ---------------------------------------------------------------------------
# Full host path: MCPHost.invoke -> confirm adapter -> toast
# ---------------------------------------------------------------------------


def _confirm_runtime(plugin_id: str, client):
    manifest = PluginManifest(
        id=plugin_id,
        name="Confirmable Plugin",
        version="0.0.1",
        runtime="python",
        entry=[],
        plugin_dir=__import__("pathlib").Path(),
        signature_file=__import__("pathlib").Path("signature.sig"),
        declared_permissions=[
            f"tool:{plugin_id}.write",
            "path:/safe/",
            # Default-deny on absence: the manifest has to say what the
            # tool's arguments are before the confirm branch is reachable.
            f"args:{plugin_id}.write:action:!path=ws_path",
        ],
        confirmable_conditions=["outside_declared_paths"],
    )
    return host_mod._PluginRuntime(
        manifest=manifest,
        verify_result=VerifyResult(status="unsigned"),
        status="running",
        tools=[{"name": f"{plugin_id}.write"}],
        granted_permissions={f"tool:{plugin_id}.write"},
        client=client,
    )


@pytest.fixture(autouse=True)
def isolated_audit_db(tmp_path):
    import workstation_agent.mcp_host.audit as audit_mod

    audit_mod.set_db_path(tmp_path / "audit.db")
    yield
    audit_mod.reset_connection()


@pytest.mark.asyncio
async def test_host_invoke_prompts_through_the_toast_and_proceeds_on_allow():
    from unittest.mock import AsyncMock, patch

    client = AsyncMock()
    client.tools_call = AsyncMock(
        return_value={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    toast = CapturingToast(answer=True)
    presenter = ConfirmPresenter(toast_provider=lambda: toast, timeout_s=0.05)

    host = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await host.start(AgentConfig(), confirm_cb=presenter, tts_speak=None)
    host._runtimes["e2e_allow"] = _confirm_runtime("e2e_allow", client)

    result = await host.invoke("e2e_allow.write", {"path": "/unsafe/x.txt"})
    await host.stop()

    assert not result.is_error
    assert len(toast.calls) == 1
    client.tools_call.assert_awaited_once()


@pytest.mark.asyncio
async def test_host_invoke_denies_when_nobody_answers_the_toast():
    from unittest.mock import AsyncMock, patch

    client = AsyncMock()
    toast = CapturingToast(answer=None)  # toast shown, never clicked
    presenter = ConfirmPresenter(toast_provider=lambda: toast, timeout_s=0.05)

    host = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await host.start(AgentConfig(), confirm_cb=presenter, tts_speak=None)
    host._runtimes["e2e_timeout"] = _confirm_runtime("e2e_timeout", client)

    # B2: the unanswered prompt now comes back as §5.2's `unconfirmed`
    # result rather than a PermissionError — §7: "A refused or unconfirmed
    # call is a normal result (§5.2), not an error".  The load-bearing part
    # of B1's assertion (the tool never ran) is kept and the code is pinned.
    result = await host.invoke("e2e_timeout.write", {"path": "/unsafe/x.txt"})
    await host.stop()

    assert result.ok is False
    assert result.code == "unconfirmed"
    client.tools_call.assert_not_called()


@pytest.mark.asyncio
async def test_host_invoke_denies_when_the_toast_stack_is_absent(monkeypatch):
    """The confirm path with no winrt: denied, and the tool never runs."""
    from unittest.mock import AsyncMock, patch

    from workstation_agent.ui.notifications import toast as toast_mod

    monkeypatch.setattr(toast_mod, "_WINRT_AVAILABLE", False, raising=False)
    real_presenter = toast_mod.ToastPresenter(app_id="test")

    client = AsyncMock()
    presenter = ConfirmPresenter(toast_provider=lambda: real_presenter, timeout_s=30.0)

    host = MCPHost()
    with patch.object(host_mod, "discover", return_value=[]):
        await host.start(AgentConfig(), confirm_cb=presenter, tts_speak=None)
    host._runtimes["e2e_nowinrt"] = _confirm_runtime("e2e_nowinrt", client)

    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await host.invoke("e2e_nowinrt.write", {"path": "/unsafe/x.txt"})
    await host.stop()

    assert result.ok is False
    assert result.code == "unconfirmed"
    assert loop.time() - started < 5.0
    client.tools_call.assert_not_called()
