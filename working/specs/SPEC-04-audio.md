# SPEC-04 — Audio subsystem skeleton

**Executor tier:** sonnet. **Branch:** `feat/spec-04-audio`. **Worktree:** `../wsa-spec-04/`.
**Depends on:** SPEC-01, SPEC-02.

## Goal

Wire the full listen → transcribe → speak audio path against Wyoming, with wake-word triggering, push-to-talk fallback, barge-in, and a state machine per design §4.11. All tests run against an in-process fake Wyoming server; no real PersonaCore contact.

## Files to create / modify (only these)

- `src/workstation_agent/audio/__init__.py`
- `src/workstation_agent/audio/mic.py`:
  - `MicStream` — captures 16 kHz mono PCM frames from the OS default input device using `sounddevice` (already in `pyproject.toml` per SPEC-01).
  - **Threading contract:** `sounddevice.InputStream` uses a blocking C callback thread that MUST NOT touch the asyncio event loop directly. Bridge via `queue.SimpleQueue` (thread-safe) plus `asyncio.get_running_loop().call_soon_threadsafe` to hand frames into an `asyncio.Queue` consumed by the async iterator. Alternatively, wrap the entire `sounddevice.InputStream.read()` blocking loop in `asyncio.to_thread` and yield frames through an async queue. Document the choice.
  - Async iterator yielding `AudioFrame(pcm: bytes, ts_ms: int)`.
  - `pause()` / `resume()` for mute integration.
- `src/workstation_agent/audio/wake.py`:
  - `WakeDetector` — wraps `openwakeword.Model`, given a list of model names/paths, callback fires with `(model_name, confidence, ts)` when threshold exceeded.
  - VAD gate: only score frames after `webrtcvad` (add to deps if needed) reports voice, to keep CPU low. If dep add is a problem, use OpenWakeWord's own VAD flag.
  - Cold-start log-once: model load time reported at INFO.
- `src/workstation_agent/audio/ptt.py`:
  - `PushToTalk` — global hotkey listener via `keyboard` lib.
  - Same trigger interface as `WakeDetector` (callback with `(source="ptt", confidence=1.0, ts)`).
  - Hotkey configurable from `PttConfig`, hot-swappable at runtime.
- `src/workstation_agent/audio/stt.py`:
  - `WyomingSTTClient` — asyncio TCP client to Wyoming ASR endpoint.
  - `async transcribe(frames: AsyncIterator[AudioFrame]) -> AsyncIterator[str]` — streams `audio-chunk` events, listens for `transcript` events, yields interim + final. Cancellation-safe.
  - Handles reconnect with backoff.
- `src/workstation_agent/audio/tts.py`:
  - `WyomingTTSClient` — asyncio TCP client to Wyoming TTS endpoint. Implements the streaming synthesis protocol (`synthesize-start`, `synthesize-chunk`, `synthesize`, `synthesize-stop`) per PersonaCore's Wyoming client comments — read `C:\Projects\PersonaCore\personacore-gitrepo\src\personacore\wyoming\client.py` for the wire ordering.
  - `async speak(text: str) -> AbortableTask` returns immediately; task runs in background, yields `audio-chunk` bytes to a queue consumed by the sound-output module.
  - `AbortableTask.abort()` cancels the exchange, drops in-flight audio, sends `synthesize-stop`.
- `src/workstation_agent/audio/sink.py`:
  - `Speaker` — plays PCM to OS default output via `sounddevice.OutputStream`. Same threading pattern as `MicStream`: blocking C callback bridged via `call_soon_threadsafe` or `asyncio.to_thread` — never call blocking `sounddevice` operations inline in async code.
  - Fast barge-in cancel: `abort()` sets a flag consumed by the callback thread; drains the pending queue.
  - `mute()` / `unmute()` for the systray mute action (which mutes BOTH mic and speaker per Q10b).
- `src/workstation_agent/audio/session.py`:
  - `AudioSession` state machine per design §4.11. Consumes `WakeDetector` + `PushToTalk` callbacks, drives `WyomingSTTClient`, waits for LLM turn via injected `on_transcribed` callback, plays TTS via `Speaker`, handles barge-in (wake mid-TTS cancels the `AbortableTask`, resets to LISTENING).
  - Emits events via a `Callable[[AudioEvent], None]` for the UI to display state.
- `tests/fakes/fake_wyoming.py`:
  - In-process asyncio TCP server implementing minimal ASR + TTS halves. Configurable canned transcripts + canned TTS audio bytes. Used by every audio test.
- `tests/integration/audio/test_full_pipeline.py`:
  - Fires a canned audio file into a fake `MicStream`, asserts wake detector triggers, STT yields the expected transcript, TTS produces expected audio bytes, barge-in cancels mid-speak.
- `tests/unit/audio/test_session_machine.py`:
  - State transitions per design §4.11, sticky window respected, single_shot doesn't loop, persistent stays in listening after speak-end.
- `tests/unit/audio/test_ptt.py`:
  - Hotkey capture (via mocked `keyboard` lib).
- `tests/unit/audio/test_wake.py`:
  - Mock OpenWakeWord `Model.predict` return values; assert callback fires above threshold, not below.

## Constraints

- No real audio device required for tests: `MicStream` accepts an injectable frame source (in prod: `sounddevice`; in tests: a fake). Same for `Speaker`.
- No real network required: `WyomingSTTClient` and `WyomingTTSClient` accept an injectable connect function (in prod: `asyncio.open_connection`; in tests: an in-process socket pair or the `fake_wyoming` server).
- The session mode logic lives in `AudioSession`, not in `LLMSession` — SPEC-05 just gets called once per user turn.
- All required deps (`sounddevice`, `webrtcvad-wheels`, `openwakeword`, `wyoming`, `keyboard`) are pre-declared by SPEC-01. Do NOT modify `pyproject.toml`.

## Acceptance criteria

- Green ruff/pyright.
- `pytest tests/unit/audio tests/integration/audio -q` green.
- Coverage on `audio/*` >= 80%.

## Executor summary MUST report

Any new deps needed; whether the OpenWakeWord model loaded in the test environment (skip test if no model file present); how you tested barge-in cancellation.
