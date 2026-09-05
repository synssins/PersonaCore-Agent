# SPEC-02 — Security primitives + config store

**Executor tier:** sonnet. **Branch:** `feat/spec-02-security-config`. **Worktree:** `../wsa-spec-02/`.
**Depends on:** SPEC-01 (scaffolding).

## Goal

Land the crypto and config-file primitives every other subsystem uses. No UI, no async, no I/O beyond disk.

## Files to create / modify (only these)

- `src/workstation_agent/security/__init__.py` — one-line docstring only.
- `src/workstation_agent/security/dpapi.py`:
  - `protect(plaintext: bytes, *, entropy: bytes | None = None) -> bytes` wrapping `win32crypt.CryptProtectData` at CurrentUser scope. Return `CryptProtectData`-encoded bytes.
  - `unprotect(blob: bytes, *, entropy: bytes | None = None) -> bytes` calling `CryptUnprotectData`; raise `DpapiError` (custom `Exception` subclass) with the Win32 error code on failure. Never leak the ciphertext or plaintext into the exception message.
  - `redact_key(text: str) -> str` — regex-strips anything looking like an OpenAI-style API key (`sk-[A-Za-z0-9_-]{20,}`) and any 40+ char base64 blob passed via env — used by logging.
- `src/workstation_agent/security/signature.py`:
  - `verify(pubkey: bytes, message: bytes, sig: bytes) -> bool` via `nacl.signing.VerifyKey`. Return `False` on `BadSignatureError`; never raise.
  - `canonical_json(obj: Any) -> bytes` — deterministic JSON: sorted keys, UTF-8, no trailing whitespace, no NaN/Infinity. Used for manifests before signature.
  - `load_public_key(env_var: str = "PC_AGENT_SIGNING_PUBKEY") -> bytes | None` — for build-time bake-in; returns None if unset (test/dev mode).
  - No sign-side code here (private key never touches the agent).
- `src/workstation_agent/config/__init__.py` — docstring only.
- `src/workstation_agent/config/schema.py` — Pydantic v2 models:
  - `AgentConfig` root model with sub-models: `LlmConfig` (base_url, model, api_key_ref, timeout_seconds, streaming_bool), `WyomingConfig` (host, port, tts_voice, asr_model), `WakeConfig` (enabled, model_names[], threshold, mic_device), `PttConfig` (enabled, hotkey), `SessionConfig` (mode: Literal["single_shot","sticky","persistent"], sticky_seconds), `UpdateConfig` (enabled, poll_interval_hours, channel, github_repo), `NotificationsConfig` (toast_enabled, voice_announce_updates_enabled, voice_announce_confirmations_enabled), `UIConfig` (webview_close_to_tray_bool, systray_show_startup_notification_bool), `PluginsConfig` (allow_unsigned_bool, per_plugin: dict[str, PluginConfig] with enabled + granted_permissions).
  - `api_key_ref` is the on-disk NAME of a DPAPI blob; the raw key is never in the TOML.
  - Full validation: URLs are `AnyHttpUrl`, ports 1-65535, positive integers where required.
  - `default() -> AgentConfig` returns a sensible default with `base_url = "http://192.168.1.150:8053/v1"`, `wyoming.host = "192.168.1.150"`, `wyoming.port = 10300`, `wake.model_names = ["hey_jarvis"]`, `ptt.hotkey = "ctrl+alt+space"`, `session.mode = "sticky"`, `session.sticky_seconds = 30`, `update.github_repo = "synssins/PersonaCore-Agent"`.
- `src/workstation_agent/config/store.py`:
  - `paths()` — returns dict of resolved paths (config file, secrets blob, plugins dir, audit db, conversations db, logs dir) using `%APPDATA%\WorkstationAgent\`. Respects `PC_AGENT_APPDATA` env for tests.
  - `load() -> AgentConfig` — reads TOML via `tomlkit`, validates via Pydantic, returns default and writes it if file missing.
  - `save(cfg: AgentConfig) -> None` — atomic write: write to `config.toml.tmp` then `os.replace` to `config.toml`. Preserves comments in existing file where structure unchanged (tomlkit round-trip).
  - `save_secret(name: str, plaintext: bytes) -> None` — protects via DPAPI, writes to `secrets/<name>.dpapi` atomically, then **applies an explicit Windows ACL denying READ/EXECUTE to the Low-integrity mandatory SID** (`S-1-16-4096`) and to `Everyone`, granting only the current user Read+Write. Use `win32security.SetNamedSecurityInfo` with a DACL built from `win32security.ACL()`. This is critical: without it, our Low-IL plugin subprocesses could read the DPAPI blob and decrypt it since DPAPI CurrentUser scope applies to any process in the same user session.
  - `load_secret(name: str) -> bytes` — reads and unprotects; raises `KeyError` if absent (no info leak).
  - `delete_secret(name: str) -> None`.
  - `harden_file(path: Path) -> None` — extracted helper for the ACL work above; also applied by SPEC-08 to the CC MCP token file.
- `tests/unit/security/test_signature.py` — verify against known-good vector (generate an Ed25519 keypair in the test with `nacl`, sign, verify true; flip a byte, verify false; malformed sig returns False not raise).
- `tests/unit/security/test_dpapi.py` — Windows-only (skip on non-Windows via `pytest.mark.skipif`), round-trip a small blob.
- `tests/unit/security/test_redact.py` — redaction table cases including `sk-abc...`, embedded in log lines, multiple keys per string.
- `tests/unit/config/test_schema.py` — default is valid, invalid URL raises, unknown session mode raises, sticky_seconds must be positive.
- `tests/unit/config/test_store.py` — load creates default, save round-trips including comments (write TOML with comments manually, load-save, assert comments preserved), atomic write leaves no `.tmp` on failure (use `unittest.mock` to fake `os.replace` failure), secret round-trip via monkeypatched fake DPAPI (a fake at `tests/fakes/fake_dpapi.py` that just XORs — cross-platform, tests don't care about real crypto).

## Constraints

- Only files listed above may be created/modified. May NOT touch `pyproject.toml` (already has all deps).
- All public functions have type hints.
- No global state; all functions pure or take explicit paths.
- Windows-only code branches guarded by `sys.platform == "win32"` where reasonable; DPAPI module is unashamedly Windows-only, ImportError on non-Windows platforms is fine (tests skip).

## Acceptance criteria

- `ruff check .` green on new files.
- `pyright` green.
- `pytest tests/unit/security tests/unit/config -q` green.
- Coverage on `security/*` and `config/*` >= 90%.

## Executor summary MUST report

Files created, test count, coverage numbers per module. Whether DPAPI tests ran (Windows) or skipped.
