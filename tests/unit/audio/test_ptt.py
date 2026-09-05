"""Unit tests for PushToTalk via a mocked keyboard module."""
from __future__ import annotations

from unittest.mock import MagicMock

from workstation_agent.audio.ptt import PttConfig, PttEvent, PushToTalk


def _make_keyboard_mock() -> MagicMock:
    """Return a mock that behaves like the keyboard library."""
    kb = MagicMock()
    kb.add_hotkey.return_value = object()  # simulates a handle
    kb.on_release_key.return_value = object()
    return kb


def _make_ptt(config: PttConfig | None = None, **kwargs) -> tuple[PushToTalk, MagicMock, list]:
    events: list[PttEvent] = []
    kb = _make_keyboard_mock()
    cfg = config or PttConfig(hotkey="ctrl+shift+space")
    ptt = PushToTalk(cfg, events.append, keyboard_mod=kb, **kwargs)
    return ptt, kb, events


def test_registers_hotkey_on_init() -> None:
    """PushToTalk should register the hotkey during construction."""
    ptt, kb, _ = _make_ptt()
    kb.add_hotkey.assert_called_once()
    ptt.close()


def test_trigger_fires_callback() -> None:
    """Simulating the hotkey press should invoke callback with PTT event."""
    ptt, kb, events = _make_ptt()

    # Extract the registered callback from add_hotkey call
    call_args = kb.add_hotkey.call_args
    registered_cb = call_args[0][1]  # second positional arg is the callback
    registered_cb()  # simulate key press

    assert len(events) == 1
    assert events[0].model_name == "ptt"
    assert events[0].confidence == 1.0
    ptt.close()


def test_set_hotkey_swaps_hotkey() -> None:
    """set_hotkey should unregister the old hotkey and register the new one."""
    ptt, kb, _ = _make_ptt()

    ptt.set_hotkey("alt+t")

    # remove_hotkey called for old, add_hotkey called twice (init + set)
    assert kb.remove_hotkey.call_count == 1
    assert kb.add_hotkey.call_count == 2
    assert kb.add_hotkey.call_args[0][0] == "alt+t"
    ptt.close()


def test_close_unregisters_hotkey() -> None:
    """close() should call remove_hotkey."""
    ptt, kb, _ = _make_ptt()
    ptt.close()
    kb.remove_hotkey.assert_called_once()


def test_ptt_event_fields() -> None:
    """PttEvent should be a NamedTuple with model_name, confidence, ts_ms."""
    evt = PttEvent(model_name="ptt", confidence=1.0, ts_ms=12345)
    assert evt.model_name == "ptt"
    assert evt.confidence == 1.0
    assert evt.ts_ms == 12345


def test_ptt_config_defaults() -> None:
    """PttConfig default hotkey should be 'ctrl+shift+space'."""
    cfg = PttConfig()
    assert cfg.hotkey == "ctrl+shift+space"
    assert cfg.trigger_on_press is True


def test_trigger_on_release() -> None:
    """When trigger_on_press=False, on_release_key should be used."""
    kb = _make_keyboard_mock()
    events: list[PttEvent] = []
    cfg = PttConfig(hotkey="ctrl+t", trigger_on_press=False)
    ptt = PushToTalk(cfg, events.append, keyboard_mod=kb)

    kb.on_release_key.assert_called_once()
    kb.add_hotkey.assert_not_called()
    ptt.close()
