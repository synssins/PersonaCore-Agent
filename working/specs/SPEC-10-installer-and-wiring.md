# SPEC-10 — Installer, main entry wiring, boot check, release workflow

**Executor tier:** opus (per plan-audit — PyInstaller + Inno Setup + GH Actions + boot-check integration is failure-prone at lower tiers). **Branch:** `feat/spec-10-installer`. **Worktree:** `../wsa-spec-10/`.
**Depends on:** ALL previous SPECs (integration layer).

## Goal

Compose all subsystems into a runnable app, produce a working installer, wire the release CI, add a boot-check that exercises the full stack against fakes.

## Files to create / modify (only these)

### Main entry wiring

- `src/workstation_agent/app.py`:
  - `class Application` — composition root.
  - **CRITICAL threading topology** (per plan audit):
    - Main thread runs `pywebview.start()` — blocking, owned by SPEC-07B's `WebviewWindow`.
    - A **dedicated background thread** runs the asyncio event loop hosting: MCP host, audio pipeline, LLM turns, update poller, FastAPI (via `uvicorn`), Claude Code driver, agent's own MCP server.
    - The systray runs on its own thread via `pystray.Icon.run_detached()` — invoked from the asyncio thread during startup.
    - Cross-thread communication: from asyncio → main-thread pywebview via a thread-safe queue polled by pywebview's own `window.evaluate_js` timer; from pywebview/systray → asyncio via `asyncio.run_coroutine_threadsafe`.
  - Startup order (on the asyncio thread, before starting pywebview on the main thread):
    1. Configure logging.
    2. Load config, audit log, session store, secret loader.
    3. Start `MCPHost` (discover + spawn plugins).
    4. Start `WyomingSTTClient`, `WyomingTTSClient`, `MicStream`, `Speaker`, `AudioSession`.
    5. Start `OpenAICompatClient`, wire `LLMTurn`.
    6. Wire `AudioSession.on_transcribed → LLMTurn.run → TTS speak`.
    7. Start FastAPI backend (SPEC-07A) on ephemeral port, write `ui-port` file.
    8. Start `ToastPresenter`, `SystemTray.run_detached()`.
    9. Start `UpdatePoller`, wire `on_update_available` → toast + optional voice.
    10. Start `ClaudeCodeDriver` and the agent's own MCP server on the static named pipe.
    11. Signal main thread: instantiate `WebviewWindow`, if first-run flag missing call `WebviewWindow.open("/first-run")`, then `WebviewWindow.start()` (blocks).
  - `async shutdown()` — reverse order teardown from asyncio thread; signal pywebview to close.
- `src/workstation_agent/__main__.py` — replaces the SPEC-01 placeholder:
  - `argparse` for `--autostart`, `--diag`, `--fake-backends`, `--check-updates`, `--rollback [ver]`.
  - `--diag` prints subsystem readiness table (each subsystem exposes a `health()` method returning `{ok, detail}`; the composition root iterates).
  - `--fake-backends` swaps in-process fakes for Wyoming + OpenAI + Claude SDK — used by boot check.
  - Default (no flags): `Application().run()`.

### Boot check

- `scripts/boot_check.py`:
  - Boots the app with `--fake-backends`.
  - Asserts every subsystem `health() == ok` within 15 s of start.
  - Asserts FastAPI port file exists and `GET /dashboard` returns 200.
  - Asserts systray icon thread is alive.
  - Asserts one round-trip: injects a fake wake trigger + canned STT transcript "what time is it", fake LLM returns text, TTS emits at least one audio-chunk.
  - Exits 0 on success, non-zero + summary on failure.

### Installer

- `installer/setup.iss` — Inno Setup script:
  - Per-user install (default): destination `{userappdata}\..\Local\WorkstationAgent` (i.e. `%LOCALAPPDATA%\WorkstationAgent`), no admin required.
  - Machine-wide install (if user picks): `{pf}\WorkstationAgent`, requires admin.
  - Installs both `Agent.exe` (PyInstaller bundle) and `Updater.exe` (Go binary) into `app\<version>\`, creates junction `current` → `app\<version>\`.
  - Startup registration branches:
    - Per-user: writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WorkstationAgent = "<install>\current\Agent.exe" --autostart`.
    - Machine-wide: creates a Task Scheduler task via `schtasks /create /TN "WorkstationAgent\Startup" /TR ... /SC ONLOGON /RL LIMITED`.
  - Final page: `[✓] Launch WorkstationAgent` checkbox (default checked).
  - Uninstaller: reverse everything, keep `%APPDATA%\WorkstationAgent\` (user's data) intact with a note in the uninstall UI.
- `installer/build.ps1` — builds PyInstaller bundle + Go binary + runs Inno Setup compiler:
  1. `pyinstaller workstation_agent.spec` → `dist\Agent\`.
  2. `cd updater && go build -ldflags "-X main.PublicKeyHex=$env:PC_AGENT_SIGNING_PUBKEY -s -w" -o ..\dist\Updater.exe .`.
  3. `iscc installer\setup.iss /DAppVersion=$version` → `dist\PersonaCore-Agent-Setup-$version.exe`.
- `workstation_agent.spec` at repo root — PyInstaller spec targeting one-folder build with correct data files (`ui/backend/templates`, `ui/backend/static`, `ui/systray/assets`, plugin manifests + signatures + `__main__.py` for each of the six plugin stubs).

### Release workflow

- `.github/workflows/release.yml` — replace the placeholder from SPEC-01 with a real pipeline on tag `v*`:
  1. `windows-latest` runner.
  2. Setup Python 3.12, Go 1.22, install deps.
  3. Run `pytest -q` (does NOT gate publish per PersonaCore's discipline, but result is recorded).
  4. Run `scripts/boot_check.py --fake-backends` — this DOES gate publish.
  5. `installer/build.ps1 -Version $tag_without_v`.
  6. Sign `manifest.json` with Ed25519 (private key from `secrets.PC_AGENT_SIGNING_PRIVATE_KEY`) — signing tool: `scripts/sign_manifest.py`.
  7. Placeholder `signtool.exe` step gated by `if: env.PC_AGENT_CODESIGN_CERT_PATH != ''` — no-ops until Chris provisions a cert.
  8. Create GitHub Release with `agent-<v>-win-x64.zip`, `updater-<v>-win-x64.exe`, `manifest.json`, `manifest.json.sig`, plus `PersonaCore-Agent-Setup-<v>.exe`.

- `scripts/sign_manifest.py` — reads `manifest.json`, canonicalizes via `security.signature.canonical_json`, signs with Ed25519 from an env-supplied hex private key, writes `manifest.json.sig`. Uses `nacl.signing.SigningKey`.

### Diagnostic + smoke tests

- `tests/integration/test_boot_check.py` — runs `scripts/boot_check.py --fake-backends` as a subprocess, asserts exit 0.
- `tests/integration/test_diag.py` — runs `python -m workstation_agent --diag` with `--fake-backends`, asserts every subsystem "OK".

## Constraints

- SPEC-10 owns cross-cutting wiring. Do NOT re-implement any subsystem — import and compose only.
- Boot check must complete in under 30 s.
- Do NOT bake real Ed25519 private keys into the repo.
- Inno Setup script must be lint-clean (Inno's own compile-time warnings zero).
- Release workflow must not have any live `secrets.*` access failures on a dry run.

## Acceptance criteria

- `python -m workstation_agent --diag --fake-backends` → all OK, exit 0.
- `scripts/boot_check.py --fake-backends` → exit 0 in < 30 s.
- Locally-built installer produces a working install into a temp dir (`installer/build.ps1 -Version 0.1.0` then `dist\PersonaCore-Agent-Setup-0.1.0.exe /VERYSILENT /DIR=<tmp>` — Inno's silent flags).
- `pytest -q` green across the whole repo.
- Release workflow YAML validates (`gh workflow view release.yml`) without errors.

## Executor summary MUST report

Total repo test count. Boot check timing. Any surprises composing the subsystems (missing interfaces, protocol drift). Any additions to `pyproject.toml` (only allowed in this SPEC — orchestrator will approve inline).
