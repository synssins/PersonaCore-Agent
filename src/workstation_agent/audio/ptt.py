"""Push-to-talk via the ``keyboard`` library.

Provides the same trigger interface as WakeDetector: a callback with
``(source, confidence, ts_ms)`` fields via :class:`PttEvent`.

The hotkey is configurable from :class:`PttConfig` and can be swapped at
runtime via :meth:`PushToTalk.set_hotkey`.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import NamedTuple


class PttEvent(NamedTuple):
    """Trigger event emitted by PushToTalk, mirroring WakeEvent."""

    model_name: str  # always "ptt"
    confidence: float  # always 1.0
    ts_ms: int  # milliseconds since the Unix epoch


PttCallback = Callable[[PttEvent], None]


@dataclass
class PttConfig:
    """Configuration for push-to-talk."""

    hotkey: str = "ctrl+shift+space"
    """Global hotkey string in keyboard-lib notation, e.g. ``'ctrl+shift+space'``."""
    trigger_on_press: bool = field(default=True)
    """If True, callback fires on key press; if False, on release."""


class PushToTalk:
    """Global hotkey listener that fires a callback on press (or release).

    Parameters
    ----------
    config:
        Initial PTT configuration.
    callback:
        Called when the hotkey is triggered.
    keyboard_mod:
        Injectable keyboard module for testing.  In production, ``None`` uses
        the real ``keyboard`` package.
    """

    def __init__(
        self,
        config: PttConfig,
        callback: PttCallback,
        *,
        keyboard_mod: object | None = None,
    ) -> None:
        self._callback = callback
        self._config = config
        self._hotkey_handle: object | None = None

        if keyboard_mod is not None:
            self._keyboard = keyboard_mod
        else:
            import keyboard  # noqa: PLC0415

            self._keyboard = keyboard

        self._register(config.hotkey)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_hotkey(self, hotkey: str) -> None:
        """Swap the hotkey at runtime (hot-swappable)."""
        self._unregister()
        self._config = PttConfig(hotkey=hotkey, trigger_on_press=self._config.trigger_on_press)
        self._register(hotkey)

    def close(self) -> None:
        """Remove the hotkey hook."""
        self._unregister()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _trigger(self) -> None:
        ts_ms = int(time.time() * 1000)
        self._callback(PttEvent(model_name="ptt", confidence=1.0, ts_ms=ts_ms))

    def _register(self, hotkey: str) -> None:
        if self._config.trigger_on_press:
            self._hotkey_handle = self._keyboard.add_hotkey(  # type: ignore[attr-defined]
                hotkey, self._trigger, suppress=False,
            )
        else:
            # on_release_key works per-key; for combos we use on_release
            self._hotkey_handle = self._keyboard.on_release_key(  # type: ignore[attr-defined]
                hotkey, lambda _e: self._trigger(),
            )

    def _unregister(self) -> None:
        if self._hotkey_handle is not None:
            with contextlib.suppress(Exception):
                self._keyboard.remove_hotkey(self._hotkey_handle)  # type: ignore[attr-defined]
            self._hotkey_handle = None
