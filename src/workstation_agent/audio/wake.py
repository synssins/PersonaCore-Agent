"""Wake-word detection using OpenWakeWord with a webrtcvad gate.

The VAD gate (webrtcvad) screens out silent frames before they reach the OWW
model, keeping CPU usage low during long quiet periods.  If webrtcvad is
unavailable the gate is bypassed and every frame is scored.

Model load time is logged once at INFO level during construction.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable
from typing import NamedTuple

import webrtcvad

log = logging.getLogger(__name__)

# VAD aggressiveness: 0 (least) - 3 (most aggressive about filtering non-speech)
_VAD_MODE = 2
_SAMPLE_RATE = 16_000


class WakeEvent(NamedTuple):
    """Emitted when a wake-word is detected above threshold."""

    model_name: str
    confidence: float
    ts_ms: int  # milliseconds since the Unix epoch


WakeCallback = Callable[[WakeEvent], None]


class WakeDetector:
    """Scores audio frames with OpenWakeWord and calls *callback* on detection.

    Parameters
    ----------
    model_names:
        OpenWakeWord model identifiers (e.g. ``"hey_mycroft"``).  Each is
        loaded by OWW at construction time.
    callback:
        Called on the calling thread when confidence >= *threshold*.
    threshold:
        Detection threshold in [0, 1].  Default 0.5.
    model_factory:
        Injectable factory for the OWW Model.  In tests, pass a mock.
    """

    def __init__(
        self,
        model_names: list[str],
        callback: WakeCallback,
        *,
        threshold: float = 0.5,
        model_factory: Callable[..., object] | None = None,
    ) -> None:
        self._callback = callback
        self._threshold = threshold

        t0 = time.monotonic()
        if model_factory is not None:
            self._model = model_factory(wakeword_models=model_names)
        else:
            from openwakeword.model import Model  # noqa: PLC0415

            self._model = Model(wakeword_models=model_names, inference_framework="onnx")
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        log.info("openwakeword_loaded models=%s load_ms=%s", model_names, round(elapsed_ms, 1))

        self._vad: webrtcvad.Vad | None = None
        with contextlib.suppress(Exception):
            self._vad = webrtcvad.Vad(_VAD_MODE)

    def process_frame(self, pcm: bytes, ts_ms: int | None = None) -> None:
        """Score one PCM frame.

        The VAD gate rejects frames classified as silence.  Frames that pass
        the gate are fed to the OWW model; any model whose score meets the
        threshold fires *callback*.

        webrtcvad accepts exactly 10, 20, or 30 ms frames of 16-bit mono
        at 16 kHz: 320, 640, or 960 bytes respectively.
        """
        if ts_ms is None:
            ts_ms = int(time.time() * 1000)

        # VAD gate: only score speech frames
        if self._vad is not None:
            valid_sizes = {(_SAMPLE_RATE * ms // 1000) * 2 for ms in (10, 20, 30)}
            if len(pcm) not in valid_sizes:
                return  # wrong frame size - skip
            is_speech = True  # default: proceed if VAD raises
            with contextlib.suppress(Exception):
                is_speech = self._vad.is_speech(pcm, _SAMPLE_RATE)
            if not is_speech:
                return

        scores: dict[str, float] = self._model.predict(pcm)  # type: ignore[attr-defined]
        for name, score in scores.items():
            if score >= self._threshold:
                self._callback(WakeEvent(model_name=name, confidence=float(score), ts_ms=ts_ms))
