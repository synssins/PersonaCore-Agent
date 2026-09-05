"""Unit tests for WakeDetector.

OpenWakeWord Model.predict is mocked wholesale; no model files are loaded.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from workstation_agent.audio.wake import WakeDetector, WakeEvent

_FRAME_BYTES = (16000 * 10 // 1000) * 2  # 320 bytes for 10ms at 16kHz int16 (valid webrtcvad size)


def _make_fake_model(scores: dict[str, float]) -> MagicMock:
    """Return a mock OWW model whose predict returns *scores*."""
    model = MagicMock()
    model.predict.return_value = scores
    return model


def _model_factory(scores: dict[str, float]):
    """Factory callable matching WakeDetector's model_factory signature."""
    def _factory(**_kwargs):
        return _make_fake_model(scores)
    return _factory


@pytest.fixture
def silence_frame() -> bytes:
    """20 ms of silence (all zeros) at 16 kHz mono int16."""
    return b"\x00" * _FRAME_BYTES


@pytest.fixture
def speech_frame() -> bytes:
    """20 ms of low-level noise that webrtcvad classifies as speech."""
    import math
    import struct

    # Simple 440 Hz sine wave at moderate amplitude - passes webrtcvad gate
    samples = [
        int(4000 * math.sin(2 * math.pi * 440 * i / 16000))
        for i in range(160)
    ]
    return struct.pack("<" + "h" * 160, *samples)


def test_callback_fires_above_threshold(speech_frame: bytes) -> None:
    """Callback must fire when model score >= threshold (speech frame passes VAD)."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.9}),
    )
    detector.process_frame(speech_frame)
    assert len(events) == 1
    assert events[0].model_name == "hey_test"
    assert events[0].confidence == pytest.approx(0.9)


def test_callback_does_not_fire_below_threshold(speech_frame: bytes) -> None:
    """Callback must NOT fire when model score < threshold."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.3}),
    )
    detector.process_frame(speech_frame)
    assert events == []


def test_callback_fires_at_exact_threshold(speech_frame: bytes) -> None:
    """Score == threshold should trigger."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.5}),
    )
    detector.process_frame(speech_frame)
    assert len(events) == 1


def test_multiple_models_independent(speech_frame: bytes) -> None:
    """Each model above threshold fires its own event."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["model_a", "model_b"],
        callback=events.append,
        threshold=0.4,
        model_factory=_model_factory({"model_a": 0.8, "model_b": 0.2}),
    )
    detector.process_frame(speech_frame)
    assert len(events) == 1
    assert events[0].model_name == "model_a"


def test_wrong_frame_size_skips_model() -> None:
    """A frame of unexpected size is dropped (VAD can't process it)."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.9}),
    )
    # Pass a frame that's the wrong size for webrtcvad
    detector.process_frame(b"\x00" * 100)
    assert events == []


def test_ts_ms_populated(speech_frame: bytes) -> None:
    """WakeEvent.ts_ms should be a reasonable Unix timestamp in ms."""
    events: list[WakeEvent] = []
    before = int(time.time() * 1000)
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.99}),
    )
    detector.process_frame(speech_frame)
    after = int(time.time() * 1000)
    assert events
    assert before <= events[0].ts_ms <= after


def test_custom_ts_ms_passed_through(speech_frame: bytes) -> None:
    """If ts_ms is passed explicitly it should appear in the event."""
    events: list[WakeEvent] = []
    detector = WakeDetector(
        model_names=["hey_test"],
        callback=events.append,
        threshold=0.5,
        model_factory=_model_factory({"hey_test": 0.99}),
    )
    detector.process_frame(speech_frame, ts_ms=42000)
    assert events[0].ts_ms == 42000
