=== PLAN.md ===
# Workstation Agent — Framework Build Plan

- **Date:** 2026-09-04
- **Design source:** `docs/superpowers/specs/2026-09-04-workstation-agent-design.md`
- **Scope of this plan:** the **framework**, not the finished product. Every
  subsystem lands as a compile-clean, unit-tested skeleton with the
  interface locked and one or two happy paths wired up. First-party plugins
  are stubbed enough to prove the loader. Real audio round-trips against
  PersonaCore are v0.2, not this plan.
- **Orchestrator:** Fable 5 (never implements — dispatches, integrates, decides).
- **Auditor / verifier:** Antigravity (Gemini 3.1 Pro) — ONE plan audit, ONE
  verify per subtask, per team policy.

## Subtask decomposition

Ten subtasks. Ordering respects the interface dependency graph (later
subtasks import from earlier). Independence within a wave is enforced by
worktree isolation — each subtask runs in its own git worktree branched from
`main`, with an explicit list of files it may create or modify.

### Wave 0 (must land first — blocks everything)

- **SPEC-01 — Project scaffolding** (`haiku`)
  Repo skeleton, `pyproject.toml`, `ruff.toml`, `pytest.ini`, `.gitignore`,
  `README.md`, `LICENSE`, CI workflow skeletons, base `src/workstation_agent/`
  package with `__init__.py` and `__main__.py` stubs, empty subpackage
  directories with docstrings pinning purpose.

### Wave 1 (parallel — five independent subtasks after SPEC-01)

- **SPEC-02 — Security primitives + config store** (`sonnet`)
  `security.dpapi`, `security.signature`, `config.store` (TOML load/save,
  atomic writes, JSON-schema validation). No UI, no I/O beyond disk.
- **SPEC-03 — MCP host: subprocess supervisor + plugin loader + permissions + audit** (`opus`)
  The load-bearing piece. Windows Job Objects, low-integrity spawn,
  discovery via entry-points + folder scan, manifest signature verify (uses
  SPEC-02), install-time perms model, runtime confirmation hooks (callback
  interface — UI wires later), append-only audit SQLite. One canary
  `hello_world` in-tree plugin proves the loader end-to-end.
- **SPEC-04 — Audio subsystem skeleton** (`sonnet`)
  `audio.wake` (OpenWakeWord wrapper — model file path from config, callback
  fires on trigger), `audio.ptt` (global hotkey listener), `audio.stt`
  (Wyoming ASR client — streaming), `audio.tts` (Wyoming TTS client —
  streaming, barge-in interface), `audio.session` (state machine per
  design §4.11). All tested against in-process fake Wyoming server.
- **SPEC-05 — LLM subsystem + session store** (`sonnet`)
  `llm.client` (OpenAI-compat chat with tools, streaming), `llm.tool_bridge`
  (MCP tool descriptors → OpenAI schema, dispatches tool calls to MCP host
  via a callback interface — MCP host itself is SPEC-03), `llm.session_store`
  (SQLite conversation log, three session modes). Tested against in-process
  fake OpenAI-compat server.
- **SPEC-06 — Updater client (Python side) + Go updater binary** (`opus`)
  In-agent: `updater_client` polls GitHub Releases API, verifies Ed25519
  signature (uses SPEC-02), writes `pending_update.json`, spawns
  `Updater.exe`. Go binary in `updater/`: single-file build, `go build`
  target, implements the flow in design §4.7 including `--rollback`. Ships
  Ed25519 public key baked in via `-ldflags -X`. Integration test drives
  the Go binary against a local HTTP fixture serving canned manifest +
  zip.

### Wave 2 (parallel — four subtasks after Wave 1 lands)

- **SPEC-07 — UI: systray + WebView2 + FastAPI backend + toast notifications** (`sonnet`)
  `ui.systray` (pystray icon + full right-click menu including
  mute-mic-and-speaker), `ui.webview` (pywebview window pointed at local
  FastAPI URL), `ui.backend` (FastAPI serving `/first-run`, `/dashboard`,
  `/config`, `/plugins`, `/audit`, `/logs`, `/about` — HTML skeleton with
  functional forms; visual design deferred to `interface-design` skill),
  `ui.notifications` (Windows toast via `winrt`), `observability.logging`
  (structlog + JSONL rotation). This is the biggest surface after SPEC-03.
- **SPEC-08 — Claude Code integration** (`sonnet`)
  `claude_code.driver` — `claude-agent-sdk` wrapper, cross-process presence
  detection (process enum), explicit "ask Claude Code" tool exposed as a
  first-party plugin `plugins/claude_code_bridge`. Agent-side MCP server
  exposing `agent.speak`, `agent.toast`, `agent.status`,
  `agent.last_transcript`, `agent.pause_listening`, `agent.execute_local`
  under `mcp_host.mcp_server`.
- **SPEC-09 — First-party plugin suite (stubs proving the API)** (`haiku`)
  Six stub plugins that load, register their tools, respond to invocations
  with a canned "not yet implemented — but the wire is live" payload:
  `filesystem`, `powershell`, `desktop_control`, `browser`, `screen_vision`,
  `clipboard`. Each ships a signed `plugin.toml` + Python entry.
  **Real implementations are future work** — this proves the loader,
  permission surface, and audit log with real plugin manifests.
- **SPEC-10 — Installer (Inno Setup) + main entry wiring + boot check** (`sonnet`)
  Inno Setup script covering per-user vs machine-wide branching, Launch
  checkbox on final page, Registry Run vs Task Scheduler registration,
  uninstaller. Wires `__main__.py` to compose all subsystems into a
  runnable app. `scripts/boot_check.py` — starts agent against fakes,
  asserts everything comes up. Extends `release.yml` with build + sign +
  publish steps.

## Interfaces between subtasks (the "joints")

- **SPEC-02 → SPEC-03, SPEC-06**: `security.signature.verify(pubkey, msg, sig) -> bool`, `security.dpapi.protect(bytes) -> bytes` / `unprotect(bytes) -> bytes`, `config.store.load(path) -> ConfigModel` / `save(model)`.
- **SPEC-03 → SPEC-05**: `mcp_host.tools_descriptor() -> list[ToolDescriptor]`; `mcp_host.invoke(tool_id, args) -> ToolResult` (async).
- **SPEC-03 → SPEC-07**: `mcp_host.confirmation_callback: Callable[[ConfirmationRequest], Awaitable[bool]]` — the UI subscribes; MCP host calls it for destructive-op prompts. Also `mcp_host.plugins()` and `mcp_host.reload(plugin_id)`.
- **SPEC-04 → SPEC-05**: `audio.session.on_transcribed(text) -> None` → LLM turn.
- **SPEC-05 → SPEC-04**: `audio.tts.speak(text) -> AbortableTask`.
- **SPEC-06 → SPEC-07**: `updater_client.on_update_available: Callable[[Manifest], None]` — the UI wires a toast + optional voice prompt.
- **SPEC-08 → SPEC-04, SPEC-07**: agent's own MCP server needs `audio.tts.speak`, `ui.notifications.toast`, `audio.session.pause()`.
- **SPEC-10 → all**: orchestrates lifecycle order.

Every interface above is a Python `Protocol` in `src/workstation_agent/protocols/`
(SPEC-01 creates the file; each producer subtask defines its half).

## Dependency graph

```
SPEC-01 (scaffold)
  ├─▶ SPEC-02 (security + config)
  │     ├─▶ SPEC-03 (MCP host)
  │     └─▶ SPEC-06 (updater)
  ├─▶ SPEC-04 (audio)
  └─▶ SPEC-05 (LLM)  [needs SPEC-03's ToolDescriptor type — mocked until SPEC-03 lands]

After Wave 1:
  SPEC-07 (UI)          [needs SPEC-02 config, SPEC-03 plugins, SPEC-06 updates]
  SPEC-08 (Claude Code) [needs SPEC-03 MCP host, SPEC-04 audio, SPEC-07 notifications]
  SPEC-09 (plugin stubs) [needs SPEC-03 plugin loader]
  SPEC-10 (installer + wiring) [needs everything]
```

## Execution policy

- Each subtask runs in its own git worktree branched from `main`
  (`worktree/SPEC-NN/`), branch name `feat/spec-NN-<slug>`.
- Executors are FORBIDDEN from editing files outside their allowed-paths
  list. Files that are cross-cutting (`pyproject.toml`, protocols module)
  are edited only by SPEC-01 or by the orchestrator at integration.
- Every subtask ships: implementation + unit tests + integration test
  where interfaces are touched. Coverage floor 80% on
  `mcp_host`, `updater_client`, `security.*`, `llm.session_store`,
  `config.store`.
- Orchestrator merges to `main` sequentially after each subtask passes
  verify. Merge order respects the dependency graph.

## Verify contract (one call per subtask)

Verifier receives: `SPEC-NN.md`, the diff (`git diff main...feat/spec-NN-<slug>`),
and the executor's summary. Returns structured verdict per team protocol:
VERDICT (pass/fail), DEVIATIONS, BUGS, GAPS.

## Rework caps

Per team protocol: one cycle = each currently-failing subtask reworked once
then re-verified once, cycle counter increments regardless of outcome, cap
~3 cycles per wave. After the cap: STOP and ask Chris.

## Integration acceptance for the framework as a whole

- `python -m workstation_agent --diag` prints subsystem status (all "OK"
  against fakes; PersonaCore-connected components print "unreachable" gracefully).
- `pytest -q` green on Windows runner.
- `scripts/boot_check.py --fake-backends` runs without error, exits 0.
- `pyinstaller workstation_agent.spec` produces a runnable one-folder bundle.
- `cd updater && go build ./...` produces `Updater.exe`.
- No cross-subtask file conflicts on merge.

## Explicit deferrals (v0.2, not this plan)

- Real audio round-trip against live PersonaCore (SPEC-04 tests against fakes).
- Real LLM tool-use loop against live PersonaCore (SPEC-05 tests against fakes).
- First-party plugin *implementations* (SPEC-09 is stubs only; the design
  document has the tool inventories per plugin — those become v0.2 subtasks).
- UI visual design (v1 UI is functional-unstyled; `interface-design` skill
  runs after framework lands).
- Authenticode signing (skeleton in `release.yml`; cert provisioning is
  Chris's action).

=== DESIGN SPEC ===
# Workstation Agent — Design Spec

- **Date:** 2026-09-04
- **Status:** approved (Chris, in chat, 2026-09-04)
- **Author role:** orchestrator (Fable 5)
- **Successor artifact:** `working/PLAN.md`

## 1. Purpose

A Windows-first, always-on desktop AI agent that:

- Listens for a wake word (OpenWakeWord) or a global push-to-talk hotkey.
- Transcribes speech via Wyoming STT, sends the turn (with tool schemas) to an
  OpenAI-compatible LLM endpoint, executes any tool calls the LLM returns via
  local MCP-plugin subprocesses, and speaks the reply via Wyoming TTS with
  barge-in support.
- Hosts a plugin surface for full workstation control (filesystem, PowerShell,
  browser via Playwright, desktop automation, screen vision, clipboard, Windows
  toast notifications, Claude Code invocation).
- Interfaces with Claude Code bidirectionally: exposes an MCP server that CC
  can consume, and drives CC itself via the `claude-agent-sdk` with
  voice-mediated tool approval.
- Runs at logon, supports a two-part signed self-update from GitHub Releases,
  and is designed for a public-product ("eventually C") trajectory while
  shipping unsigned initially.

## 2. Non-goals for v1

- Non-Windows hosts (design keeps OS-specific code isolated for later ports).
- Authenticode-signed installer (skeleton present; cert provisioning is a
  post-v1 step).
- Multi-user machine-wide UX polish (installer supports it, admin experience
  is deferred).
- Rich agent memory / RAG. Conversation is per-session + local SQLite log.
- PersonaCore-side changes (no server work in this repo).

## 3. External dependencies (config, not code)

- **PersonaCore** at `192.168.1.150:8053` — OpenAI-compat `/v1/chat/completions`.
- **PersonaCore Wyoming server** at `192.168.1.150:10300` (default port) — both
  ASR and TTS halves on one socket per the shipped Wyoming service.
- **GitHub Releases** on `synssins/workstation-agent` (or user-chosen slug) —
  update manifests + signed artifacts.

The agent MUST NOT hard-code these; they are TOML config, edited only via UI.

## 4. Architecture

### 4.1 Approach

Approach **B** (chosen by user): single-process Python core + WebView2-hosted
native UI + subprocess-per-plugin (MCP stdio) + separate Go updater binary.

### 4.2 Process topology

```
Agent.exe (PyInstaller, Python 3.12+)
├── audio pipeline (thread pool)
├── LLM client (async)
├── MCP host (async supervisor)
│    ├── plugin-A subprocess (MCP stdio)
│    ├── plugin-B subprocess (MCP stdio)
│    └── ...                       (Windows Job Object, Low integrity)
├── Claude Code SDK integration
├── local FastAPI (127.0.0.1:<port>)
├── WebView2 window (pywebview)  ← navigates to local FastAPI
├── systray (pystray)
└── Windows toast bridge (winrt.windows.ui.notifications)

Updater.exe (Go, single-file)  ← launched by Agent on user confirm
```

### 4.3 In-process modules (Python package `workstation_agent`)

| Module | Responsibility |
|---|---|
| `audio.wake` | OpenWakeWord model host, VAD gate, callback on trigger |
| `audio.ptt` | Global hotkey listener (`keyboard` lib), same trigger surface as wake |
| `audio.stt` | Wyoming ASR client (streaming) |
| `audio.tts` | Wyoming TTS client (streaming, barge-in on wake trigger) |
| `audio.session` | Coordinates listening / thinking / speaking state machine |
| `llm.client` | OpenAI-compat chat completions client (tools support, streaming) |
| `llm.tool_bridge` | Converts MCP tool descriptors → OpenAI tool schema; routes tool calls back to MCP host |
| `llm.session_store` | Local SQLite conversation log, three session modes (single/sticky/persistent) |
| `mcp_host.supervisor` | Spawns/monitors plugin subprocesses; Windows Job Objects; Low-integrity spawn |
| `mcp_host.loader` | Discovers plugins via entry-points AND `%APPDATA%\WorkstationAgent\plugins\` folder; verifies manifest signature |
| `mcp_host.permissions` | Install-time coarse permissions + runtime prompts for destructive actions |
| `mcp_host.audit` | Append-only SQLite log of every tool call |
| `mcp_host.mcp_server` | Exposes the agent's own tools (speak, toast, status, execute_local) as an MCP server for Claude Code to consume |
| `claude_code.driver` | `claude-agent-sdk` wrapper; presence detection; voice-mediated tool approvals |
| `updater_client` | Polls GitHub Releases API, verifies Ed25519 manifest signature, writes `pending_update.json`, spawns `Updater.exe` |
| `config.store` | TOML load/save, JSON schema validation, atomic writes |
| `security.dpapi` | DPAPI wrapper for API-key encryption at rest (`win32crypt.CryptProtectData`) |
| `security.signature` | Ed25519 verification of update manifests and plugin manifests |
| `ui.systray` | pystray icon + right-click menu (updates, config, exit, mute mic+speaker) |
| `ui.webview` | pywebview window; opens on demand or on first-run |
| `ui.backend` | FastAPI serving first-run wizard, config editor, plugin browser, audit log viewer, notification history |
| `ui.notifications` | Windows toast bridge (winrt) with action support |
| `observability.logging` | structlog + JSONL rotation |
| `observability.tracing` | Optional OTLP exporter (off by default) |

### 4.4 Plugin API (contract)

Plugins are **MCP servers** (JSON-RPC over stdio). Each ships a `plugin.toml`:

```toml
[plugin]
id = "workstation.filesystem"
name = "Filesystem"
version = "1.0.0"
runtime = "python"        # or "node", "go", "any" (must be self-contained)
entry = "python -m workstation_agent.plugins.filesystem"
signature = "signature.sig"     # Ed25519 sig of manifest bytes + entry file hash

[permissions.declared]
filesystem.read = ["%USERPROFILE%\\Documents", "%USERPROFILE%\\Downloads"]
filesystem.write = ["%USERPROFILE%\\Documents"]

[permissions.confirmable]
# tools that trigger runtime confirmation if invoked outside declared scope
filesystem.write = "outside_declared_paths"

[compat]
agent_min = "0.1.0"
```

The agent verifies the signature at load; if unsigned or mismatched, the plugin
is quarantined and a red badge appears in the plugin UI. User can override with
an explicit "unsigned, I accept the risk" acknowledgment recorded in the audit
log.

### 4.5 Subprocess isolation (Windows-specific)

- Each plugin spawned via `subprocess.Popen(...)` wrapped by:
  - **Job Object** (`CreateJobObject` + `AssignProcessToJobObject`) with
    `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `LIMIT_PROCESS_MEMORY`,
    `LIMIT_JOB_MEMORY`, and `LIMIT_ACTIVE_PROCESS = 1` (no fork bombs).
  - **Low integrity level** via `CreateProcessAsUser` with a token modified by
    `SetTokenInformation(TokenIntegrityLevel)` to `S-1-16-4096`.
  - `CREATE_NEW_PROCESS_GROUP` for clean Ctrl-Break signaling.
- IO via anonymous pipes (MCP stdio).
- No environment variable inheritance except explicit `PATH` and a scoped
  `WSA_PLUGIN_ID`.

### 4.6 Audit log schema

SQLite at `%APPDATA%\WorkstationAgent\audit.sqlite`. WAL mode. Append-only
enforced by triggers rejecting UPDATE/DELETE on the events table.

```sql
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc TEXT NOT NULL,
  plugin_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_summary TEXT NOT NULL,      -- redacted, <= 4KB
  consented TEXT NOT NULL,          -- 'preauth' | 'runtime_yes' | 'runtime_no' | 'auto'
  result_status TEXT NOT NULL,      -- 'ok' | 'error' | 'denied' | 'timeout'
  agent_version TEXT NOT NULL,
  session_id TEXT NOT NULL
);
CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN
  SELECT RAISE(FAIL, 'audit events are immutable'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN
  SELECT RAISE(FAIL, 'audit events are immutable'); END;
```

### 4.7 Updater contract

Release manifest schema (`manifest.json` on each GitHub Release):

```json
{
  "version": "1.2.3",
  "channel": "stable",
  "released_at": "2026-09-15T04:00:00Z",
  "mandatory": false,
  "notes_url": "https://github.com/.../releases/tag/v1.2.3",
  "artifacts": {
    "agent": {
      "url": "https://.../agent-1.2.3-win-x64.zip",
      "sha256": "hex...",
      "size": 152341234
    },
    "updater": {
      "url": "https://.../updater-1.2.3-win-x64.exe",
      "sha256": "hex...",
      "size": 4823123
    }
  },
  "min_updater_version": "1.0.0"
}
```

Sibling `manifest.json.sig` = Ed25519 signature over UTF-8 canonical JSON.

Flow:

1. `updater_client` polls Releases API (startup + every 6h; both configurable
   and disable-able).
2. Latest > installed → download manifest + sig → verify → present toast +
   optional voice announcement (each toggleable).
3. User confirms → write verified `pending_update.json` to
   `%APPDATA%\WorkstationAgent\` → spawn `Updater.exe --update`.
4. `Updater.exe`:
   - Waits for agent PID exit (30s grace → SIGTERM → hard kill).
   - Downloads agent zip to `<install>\_incoming\`, verifies SHA-256.
   - Extracts to `<install>\app\1.2.3\`.
   - Atomically swaps `<install>\current` junction to the new version.
   - Relaunches `<install>\current\Agent.exe`.
   - Retains last 3 versions; prunes older.
   - Logs to `%APPDATA%\WorkstationAgent\logs\updater-YYYYMMDD.log`.
   - `Updater.exe --rollback [version]` also supported.
5. Failure at any step: `current` unchanged, log written, toast fired,
   exit code non-zero, updater exits.

Public key baked into Agent.exe AND Updater.exe at build time from
`SIGNING_PUBLIC_KEY` GitHub Actions env. Private key held only in Actions
secret `SIGNING_PRIVATE_KEY`.

### 4.8 Install layout

Per-user:

```
%LOCALAPPDATA%\WorkstationAgent\
├── app\
│   ├── 1.2.3\
│   │   ├── Agent.exe                (PyInstaller one-folder → single-file wrapper)
│   │   ├── _internal\               (PyInstaller runtime)
│   │   └── Updater.exe
│   ├── 1.2.2\    (previous, retained for rollback)
│   └── 1.2.1\
├── current  → junction → app\1.2.3\
└── uninstall.exe

%APPDATA%\WorkstationAgent\
├── config.toml
├── secrets.dpapi                   (DPAPI blob: {api_key, ...})
├── audit.sqlite
├── conversations.sqlite
├── plugins\                        (drop-in plugin folders)
├── logs\
├── pending_update.json             (transient, deleted by updater)
└── first_run_completed             (flag)
```

Machine-wide replaces `%LOCALAPPDATA%\WorkstationAgent` with
`%PROGRAMFILES%\WorkstationAgent`, keeps per-user `%APPDATA%` for user data.

### 4.9 Startup registration

Per-user install: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value
`WorkstationAgent` = `"C:\Users\<u>\AppData\Local\WorkstationAgent\current\Agent.exe" --autostart`

Machine-wide install: Windows Task Scheduler task
`WorkstationAgent\Startup` triggered `AT LOGON of any user`, action
`"C:\Program Files\WorkstationAgent\current\Agent.exe" --autostart`, run with
user's rights (not SYSTEM).

`--autostart` suppresses first-run wizard auto-open and starts minimized to
tray.

### 4.10 First-run experience

1. Installer's final page: `[✓] Launch WorkstationAgent` (default checked).
2. Agent starts, systray icon appears, WebView2 window opens to
   `http://127.0.0.1:<port>/first-run`.
3. Wizard steps: LLM endpoint URL + key (DPAPI-encrypted on save), Wyoming
   host + port, wake word choice (OWW model dropdown, defaults `hey_jarvis`),
   push-to-talk hotkey, starter plugin selection (each row shows requested
   permissions).
4. On finish: `first_run_completed` flag written, wizard closes, systray
   notification "WorkstationAgent is running. Say '<wake word>' to talk."

### 4.11 Conversational flow (state machine)

```
IDLE  ──(wake word | PTT)──▶ LISTENING
LISTENING ──(silence timeout)──▶ THINKING
LISTENING ──(wake word again)──▶ LISTENING (barge-in, reset transcript)
THINKING ──(LLM streams tool_call)──▶ TOOL_RUNNING
TOOL_RUNNING ──(tool result)──▶ THINKING
THINKING ──(LLM streams text)──▶ SPEAKING
SPEAKING ──(wake word | PTT)──▶ LISTENING (barge-in, cancel TTS)
SPEAKING ──(TTS end)──▶ [sticky window active?]
  ├─ yes ──▶ LISTENING (window: 30s default)
  └─ no  ──▶ IDLE
```

Session modes: `single_shot` skips the sticky branch; `sticky` uses the
window (config-configurable seconds); `persistent` keeps the transcript
forever until user says "new chat" or clicks a UI reset.

### 4.12 UI surfaces

The FastAPI backend exposes these UI routes; the WebView2 window navigates
between them:

- `/first-run` — the wizard
- `/dashboard` — status pill, mute state, current session, last N exchanges
- `/config` — grouped settings (endpoint, audio, notifications, updates,
  session mode, PTT hotkey capture)
- `/plugins` — installed plugins, permissions, signature status, enable/disable,
  reload-pending badge, install-from-file, install-from-registry
- `/audit` — filtered view of `audit.sqlite`
- `/logs` — tailing view of the day's JSONL log
- `/about` — version, update check button, rollback UI

All rendered from HTML/CSS/JS assets under `src/workstation_agent/ui/frontend/`.
The **visual design** of these pages is deferred to the `interface-design`
skill in a follow-up work item; v1 ships with a functional, unstyled
skeleton the design pass replaces.

### 4.13 Security posture summary

| Threat | Mitigation |
|---|---|
| Compromised plugin exfiltrating API key | Plugins are subprocesses; agent secrets never leave main process; LLM calls scoped through `agent.chat` MCP tool |
| Compromised plugin escalating on host | Low-integrity spawn; Job Object CPU/memory/child limits; no admin rights |
| Prompt injection triggering destructive command | Runtime confirmation dialogs for `powershell.exec` outside allowlist and `filesystem.write` outside declared paths; LLM sees `run_command(intent, command)` so mismatch is user-visible |
| Malicious update pushed to GitHub | Ed25519-signed manifest; public key baked into agent + updater at build; sig verified before download; SHA-256 verified after |
| Tampered plugin on disk | Manifest+code hash pinned at install; startup re-verify; refuse to load on mismatch |
| Log exfiltration | API keys never logged (redaction filter in `security.dpapi.redact_key`); transcripts logged only at DEBUG |
| DoS via plugin resource exhaustion | Job Object memory + CPU limits; watchdog kills unresponsive plugin subprocess after N seconds |

## 5. Deferred to later versions (explicit non-scope)

- Authenticode signing of Agent.exe and Updater.exe (skeleton yes, cert no).
- PersonaCore conversation sync (§ 8c "future C" — data model has room, no wire).
- Non-Windows hosts (OS-specific code confined to `os_windows` submodules).
- Custom-trained wake word (OpenWakeWord custom training pipeline). Config
  path exists; ship model files stay defaults.
- LLM provider abstraction beyond OpenAI-compat (design supports it, we ship
  one provider).
- Hot-reload of plugins during a running session (explicit "reload plugins"
  systray action instead).
- Fine-grained network-outbound filtering per plugin (declared + audit-logged
  only in v1; WFP hook is post-v1).

## 6. Testing strategy

- **Unit** (pytest, ruff, pyright strict): every module, no I/O, boundaries
  mocked. Coverage floor 80% on `mcp_host`, `updater_client`, `security.*`,
  `llm.session_store`, `config.store`.
- **Integration**: in-process fake Wyoming server, in-process fake
  OpenAI-compat server (FastAPI fixture), a canary MCP plugin subprocess. End-
  to-end test: canned audio → wake → transcribe → LLM (returning a canned tool
  call) → tool executes → LLM final → TTS bytes.
- **Boot check**: `scripts/boot_check.py` starts agent against fakes, asserts
  systray icon appears, FastAPI is reachable, WebView2 window opens, one
  round-trip completes. Runs on every tag before build publish.
- **CI**: GitHub Actions.
  - `ci.yml`: on push/PR — lint, typecheck, unit + integration on Windows
    runner.
  - `release.yml`: on tag `v*` — boot check → PyInstaller build → Go build
    → sign manifest with Ed25519 → publish GitHub Release.

## 7. Repository layout

```
C:\Projects\GameTest\               # working root, git repo, project name TBD by user
├── CLAUDE.md                       # session guidance
├── README.md
├── LICENSE                         # MIT (Chris to confirm)
├── pyproject.toml
├── ruff.toml
├── pytest.ini
├── .gitignore
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── docs/
│   ├── superpowers/specs/         # this doc lives here
│   └── plugin-authors.md          # written after plugin API is solid
├── working/                        # planning + specs for /team executors (NOT published)
│   ├── PLAN.md
│   └── specs/
│       ├── SPEC-01-*.md
│       └── ...
├── src/
│   └── workstation_agent/
│       ├── __init__.py
│       ├── __main__.py
│       ├── audio/
│       ├── llm/
│       ├── mcp_host/
│       ├── claude_code/
│       ├── updater_client/
│       ├── config/
│       ├── security/
│       ├── ui/
│       │   ├── systray/
│       │   ├── webview/
│       │   ├── backend/
│       │   ├── frontend/
│       │   └── notifications/
│       ├── observability/
│       └── plugins/                # first-party plugin sources
├── updater/                        # Go source for Updater.exe
├── installer/                      # Inno Setup script + assets
└── tests/
    ├── unit/
    ├── integration/
    └── fakes/
```

## 8. Open items requiring Chris's later input

- **Project name / GitHub repo slug** (currently `workstation-agent`; the
  directory `C:\Projects\GameTest` is provisional and to be renamed at Chris's
  convenience).
- **License** (default MIT; confirm on wake).
- **Ed25519 signing key material** — key generation + storage in GitHub
  Actions secrets is Chris's action; agent build reads the public key from an
  env var at CI build time.
- **Ed25519 public key for first-party plugin registry** — same story.
- **Wake word choice**: default `hey_jarvis`; Chris may want another OWW model.
- **PTT hotkey default**: proposed `Ctrl+Alt+Space`.
- **Playwright browser channels**: Chrome + Edge on by default; installing
  the browser binaries adds ~200MB to first-run.

## 9. Change log

| Date | Version | Change |
|---|---|---|
| 2026-09-04 | 1.0 | Initial approved design (Chris in chat) |

=== SPEC-01-scaffolding.md ===
# SPEC-01 — Project scaffolding

**Executor tier:** haiku. **Branch:** `feat/spec-01-scaffolding`. **Worktree:** `../wsa-spec-01/`.

## Goal

Land the skeleton every other subtask builds on: repo files, Python package layout, CI workflow files (skeleton only — they will grow in SPEC-10), and a `protocols` module where every subsystem's cross-cutting interfaces live.

## Files to create (only these — nothing else)

- `pyproject.toml` — Python 3.12, `hatchling` backend, deps split into `dependencies` (runtime) and `[project.optional-dependencies].dev`. Runtime deps to include: `openwakeword`, `wyoming`, `httpx`, `structlog`, `pydantic`, `pystray`, `pywebview`, `fastapi`, `uvicorn`, `keyboard`, `winrt`, `pywin32`, `cryptography`, `pynacl` (Ed25519), `click`, `tomlkit`, `claude-agent-sdk`, `pyautogui`, `pywinauto`, `mss`, `pytesseract`, `playwright`. Dev deps: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `pyright`, `pyinstaller`, `respx`, `dirty-equals`.
- `ruff.toml` — line length 100, target-version py312, all rules on by default, per-file ignores for tests.
- `pytest.ini` — `pythonpath = src`, `asyncio_mode = auto`, `--strict-markers`.
- `.gitignore` — Python, PyInstaller, venvs, `.pytest_cache`, `_incoming/`, `logs/`, `*.dpapi`, `worktree/`, `.vscode/`, `.idea/`, `dist/`, `build/`, `*.egg-info/`, `secrets.dpapi`.
- `README.md` — short "PersonaCore-Agent: Windows-first voice-controlled AI agent. See `docs/superpowers/specs/` for design."
- `LICENSE` — MIT, copyright holder "Chris (synssins)".
- `.github/workflows/ci.yml` — Windows runner, matrix (`3.12`), steps: checkout, setup-python, `pip install -e .[dev]`, `ruff check`, `pyright`, `pytest -q --cov=workstation_agent --cov-report=term-missing --cov-fail-under=80`. Trigger on push + PR to main.
- `.github/workflows/release.yml` — on tag `v*`, placeholder body: echo "release build placeholder — SPEC-10 fills this in". Trigger blocks explicit `workflow_dispatch` too.
- `src/workstation_agent/__init__.py` — `__version__ = "0.1.0.dev0"`.
- `src/workstation_agent/__main__.py` — placeholder that prints "PersonaCore-Agent framework (WIP). SPEC-10 wires the app together." and exits 0. Do NOT import subsystems here yet.
- Empty package dirs, each with an `__init__.py` containing only a one-line docstring pinning its purpose:
  - `audio/` `llm/` `mcp_host/` `claude_code/` `updater_client/` `config/` `security/` `observability/` `plugins/` `ui/` `ui/systray/` `ui/webview/` `ui/backend/` `ui/frontend/` `ui/notifications/`
- `src/workstation_agent/protocols.py` — one module with these `typing.Protocol` classes, only definitions, no implementations. Each carries a docstring naming its producer/consumer SPEC:

  ```python
  class ToolDescriptor(Protocol): ...        # SPEC-03 produces, SPEC-05 consumes
  class ToolResult(Protocol): ...
  class MCPHost(Protocol):                    # SPEC-03 produces, SPEC-05/07/08 consume
      async def tools(self) -> list[ToolDescriptor]: ...
      async def invoke(self, tool_id: str, args: dict) -> ToolResult: ...
      async def plugins(self) -> list["PluginInfo"]: ...
      async def reload(self, plugin_id: str) -> None: ...
  class PluginInfo(Protocol): ...
  class ConfirmationRequest(Protocol): ...    # SPEC-03 produces
  class ConfirmationCallback(Protocol):       # SPEC-07 implements
      async def __call__(self, req: ConfirmationRequest) -> bool: ...
  class AudioSession(Protocol): ...           # SPEC-04
  class AbortableTask(Protocol): ...
  class TTSSpeaker(Protocol): ...             # SPEC-04
      async def speak(self, text: str) -> AbortableTask: ...
  class LLMSession(Protocol): ...             # SPEC-05
  class Updater(Protocol): ...                # SPEC-06
  class ToastPresenter(Protocol): ...         # SPEC-07
  class UpdateAvailableCallback(Protocol): ...
  ```
- `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`, `tests/fakes/__init__.py`.
- `working/README.md` — one line: "planning artifacts; not published to git remote (see `.gitignore`)". **NOTE:** update `.gitignore` to include `working/` before committing anything under it, then force-add `working/README.md` — orchestrator ignores `working/*` from executor branches at merge time. Actually simpler: **leave `working/` OUT of `.gitignore`; executors must not touch `working/`**. The orchestrator alone owns `working/`.
- `CLAUDE.md` at repo root — one page: project name, "this is the framework build; see design spec and PLAN.md for scope", team roster hint, "no worker touches `working/`", "no worker touches files outside its SPEC's allowed-paths list".

## Files this SPEC may NOT touch

Everything not on the list above. In particular: `working/`, `docs/superpowers/specs/`, any Go source, any HTML/CSS/JS.

## Constraints

- No implementations, only stubs and configuration.
- `__main__.py` prints and exits — no subsystem imports.
- `pyproject.toml` MUST declare all runtime deps listed above so downstream SPECs don't fight the lockfile.
- Dependency versions: pin major only (`>=X,<X+1`) for now.

## Acceptance criteria

- `pip install -e .[dev]` succeeds on Windows.
- `ruff check .` green.
- `pyright` green (empty package = trivially typed).
- `pytest -q` runs (zero tests but exit 0).
- `python -m workstation_agent` prints the placeholder and exits 0.
- `git status` shows only files listed above (nothing else created/modified).

## Testing

Add `tests/unit/test_smoke.py` with one test: `def test_package_imports(): import workstation_agent  # noqa`.

## Executor summary MUST report

Files created (count + list). Result of each acceptance command. Any deviations from this SPEC and why.

=== SPEC-02-security-and-config.md ===
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
  - `save_secret(name: str, plaintext: bytes) -> None` — protects via DPAPI, writes to `secrets/<name>.dpapi` atomically.
  - `load_secret(name: str) -> bytes` — reads and unprotects; raises `KeyError` if absent (no info leak).
  - `delete_secret(name: str) -> None`.
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

=== SPEC-03-mcp-host.md ===
# SPEC-03 — MCP host: supervisor + loader + permissions + audit

**Executor tier:** opus. **Branch:** `feat/spec-03-mcp-host`. **Worktree:** `../wsa-spec-03/`.
**Depends on:** SPEC-01, SPEC-02.

## Goal

The load-bearing subsystem. Discover plugins, verify their signatures, spawn each as a Windows-isolated subprocess speaking MCP JSON-RPC over stdio, expose their tools to the LLM subsystem, enforce install-time + runtime permissions, and audit every tool call.

## Files to create / modify (only these)

- `src/workstation_agent/mcp_host/__init__.py`
- `src/workstation_agent/mcp_host/supervisor.py`:
  - `class PluginSupervisor` — spawns a plugin subprocess.
  - `spawn(manifest: PluginManifest, cwd: Path) -> SubprocessHandle` — implements:
    - `subprocess.Popen(...)` with stdin/stdout piped, stderr piped to logger.
    - Windows-only: wraps the process in a **Job Object** via `pywin32` (`win32job.CreateJobObject` + `AssignProcessToJobObject`) with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `LIMIT_PROCESS_MEMORY = 512MB` (config-overridable), `LIMIT_JOB_MEMORY = 768MB`, `LIMIT_ACTIVE_PROCESS = 4`, `LIMIT_JOB_TIME`.
    - **Low integrity** spawn: create a primary token via `win32security.OpenProcessToken`, `DuplicateTokenEx`, `SetTokenInformation(TokenIntegrityLevel, Low SID S-1-16-4096)`, then `win32process.CreateProcessAsUser`. Guarded — if this fails on this Windows edition, fall back to Medium integrity with a WARN log entry (not silent).
    - Environment: only `PATH` and `WSA_PLUGIN_ID=<manifest.id>` passed through.
    - Watchdog: if plugin misses heartbeat (MCP `ping`) for `heartbeat_timeout` seconds (default 30), terminate the job.
  - `terminate(handle: SubprocessHandle, *, hard_after: float = 5.0)` — send graceful `shutdown` MCP method, wait, then close job.
- `src/workstation_agent/mcp_host/mcp_client.py`:
  - Async MCP client using the `mcp` PyPI package if available, else implement JSON-RPC 2.0 over stdio inline (small — ~150 LOC). Prefer the `mcp` package if it works on Windows headless.
  - Supports `initialize`, `tools/list`, `tools/call`, `notifications/*`, and a custom `ping` heartbeat.
- `src/workstation_agent/mcp_host/loader.py`:
  - `discover() -> list[PluginManifest]` — merges results from:
    - Python entry points group `workstation_agent.plugins` (via `importlib.metadata`).
    - Folder scan of `%APPDATA%\WorkstationAgent\plugins\*/plugin.toml`.
    - Bundled first-party plugins in `src/workstation_agent/plugins/*/plugin.toml`.
  - `PluginManifest` dataclass parsed from `plugin.toml` per design §4.4.
  - `verify(manifest: PluginManifest, allow_unsigned: bool) -> VerifyResult` — computes SHA-256 of the entry file + canonical-JSON of the manifest, checks against `signature.sig` using `security.signature.verify`. Missing signature → `VerifyResult(status='unsigned')`. Bad signature → `VerifyResult(status='invalid')`. Good → `VerifyResult(status='valid')`. Returns the result — caller decides whether to quarantine.
- `src/workstation_agent/mcp_host/permissions.py`:
  - `PermissionDecision = Literal["allow", "deny", "confirm"]`.
  - `evaluate(plugin: PluginManifest, tool: str, args: dict, granted: set[str]) -> PermissionDecision`:
    - Match declared permissions against tool's declared capability.
    - Return `"confirm"` when tool is in `[permissions.confirmable]` AND args exceed declared scope (e.g., filesystem write path not under declared roots — implement one built-in checker per named condition string in the manifest; unknown condition → `deny` with a WARN).
    - Return `"deny"` when required capability is absent from `granted`.
- `src/workstation_agent/mcp_host/audit.py`:
  - Opens `audit.sqlite` (path from `config.store.paths()`) in WAL mode.
  - Creates the schema from design §4.6 on first open (idempotent).
  - `log(event: AuditEvent) -> None` — synchronous, small writes, hold the lock briefly.
  - `query(filters: AuditQuery) -> list[AuditEvent]` for the UI.
  - Enforces UPDATE/DELETE triggers via schema DDL.
- `src/workstation_agent/mcp_host/host.py`:
  - `class MCPHost` implementing the `MCPHost` Protocol from SPEC-01:
    - `async start(config: AgentConfig, confirm_cb: ConfirmationCallback | None) -> None` — discover, verify (respecting `config.plugins.allow_unsigned`), spawn each enabled plugin, gather tool lists.
    - `async invoke(tool_id: str, args: dict) -> ToolResult` — resolves plugin, evaluates permissions, calls `confirm_cb` if `"confirm"`, dispatches via MCP client, logs to audit.
    - `async plugins() -> list[PluginInfo]` — returns current state (running, quarantined, reload_pending).
    - `async reload(plugin_id: str)` — terminate + respawn (explicit reload only).
    - `async stop()` — graceful termination of all plugins.
- `src/workstation_agent/plugins/hello_world/plugin.toml` — a canary plugin manifest (signed with a test key generated at test time — see below).
- `src/workstation_agent/plugins/hello_world/__main__.py` — trivial MCP server exposing `hello_world.echo(text: str) -> {text: str}`. Uses the `mcp` package or the inline JSON-RPC helper.
- `tests/integration/mcp_host/test_hello_world.py` — spawns `hello_world` via `MCPHost`, invokes `hello_world.echo`, asserts round-trip; asserts an audit row was written; asserts Job Object kill cleans up the subprocess.
- `tests/unit/mcp_host/test_loader.py` — discovery across entry-points + folder + bundled; signature verify against generated test keypair; unsigned → quarantined when `allow_unsigned=False`.
- `tests/unit/mcp_host/test_permissions.py` — table-driven cases covering allow/deny/confirm for filesystem, powershell, and unknown-condition edge cases.
- `tests/unit/mcp_host/test_audit.py` — schema created, insert succeeds, UPDATE/DELETE raise, query filters work.
- `tests/fakes/fake_plugin/` — a fake plugin for tests (manifest + tiny MCP server) that we can control from the test harness (returns whatever the test asks).
- `tests/fakes/gen_test_keypair.py` — pytest fixture producing a per-session Ed25519 keypair and signing the fake plugins on the fly (so the repo never commits real signatures for test-only plugins).

## Files this SPEC may NOT touch

- `pyproject.toml`, `ruff.toml`, `pytest.ini`, workflow YAML.
- Anything under `src/workstation_agent/` OUTSIDE `mcp_host/` and `plugins/hello_world/`.
- The `protocols.py` file (SPEC-01 owns the shared Protocols; if you need a new one, note it in the executor summary — orchestrator will add).

## Constraints

- Subprocess isolation is required. Do NOT run any plugin code in-process, even for the canary.
- Every audit event must be written before `invoke()` returns.
- When `confirm_cb` is `None` and a tool requires confirmation, treat as deny (with audit entry).
- Job Object cleanup on process exit is critical — verify in tests by inspecting `subprocess.poll()` after `terminate()`.

## Acceptance criteria

- `ruff check`, `pyright`, `pytest tests/unit/mcp_host tests/integration/mcp_host -q` all green.
- Coverage on `mcp_host/*` >= 85% (integration test covers `supervisor.py`).
- The hello_world plugin end-to-end integration test passes.

## Executor summary MUST report

Whether the `mcp` PyPI package worked or you implemented JSON-RPC inline (and why). Windows Job Object + low-integrity spawn behavior observed. Any Protocol additions you needed and where you noted them.

=== SPEC-04-audio.md ===
# SPEC-04 — Audio subsystem skeleton

**Executor tier:** sonnet. **Branch:** `feat/spec-04-audio`. **Worktree:** `../wsa-spec-04/`.
**Depends on:** SPEC-01, SPEC-02.

## Goal

Wire the full listen → transcribe → speak audio path against Wyoming, with wake-word triggering, push-to-talk fallback, barge-in, and a state machine per design §4.11. All tests run against an in-process fake Wyoming server; no real PersonaCore contact.

## Files to create / modify (only these)

- `src/workstation_agent/audio/__init__.py`
- `src/workstation_agent/audio/mic.py`:
  - `MicStream` — captures 16 kHz mono PCM frames from the OS default input device using `sounddevice` (add to `pyproject.toml` deps — flag this in executor summary, orchestrator will amend). Or, if adding a dep is disallowed, use `pyaudiowpatch`. Prefer `sounddevice`.
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
  - `Speaker` — plays PCM to OS default output via `sounddevice`. Barge-in fast-cancel.
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
- If you MUST add `sounddevice` / `webrtcvad` to deps, note it in the executor summary; orchestrator amends `pyproject.toml`.

## Acceptance criteria

- Green ruff/pyright.
- `pytest tests/unit/audio tests/integration/audio -q` green.
- Coverage on `audio/*` >= 80%.

## Executor summary MUST report

Any new deps needed; whether the OpenWakeWord model loaded in the test environment (skip test if no model file present); how you tested barge-in cancellation.

=== SPEC-05-llm-and-session.md ===
# SPEC-05 — LLM client + tool bridge + session store

**Executor tier:** sonnet. **Branch:** `feat/spec-05-llm`. **Worktree:** `../wsa-spec-05/`.
**Depends on:** SPEC-01, SPEC-02. **Consumes:** SPEC-03's `MCPHost` Protocol (mocked for now).

## Goal

OpenAI-compatible chat client with streaming + tool-call loop, MCP-to-OpenAI tool schema bridge, and a SQLite-backed conversation store honoring three session modes (single_shot / sticky / persistent).

## Files to create / modify (only these)

- `src/workstation_agent/llm/__init__.py`
- `src/workstation_agent/llm/client.py`:
  - `OpenAICompatClient` — `httpx.AsyncClient`-based, streaming chat.
  - `async chat(messages, tools, *, stream=True) -> AsyncIterator[ChatDelta]`.
  - `ChatDelta` union: text chunk, tool_call start/args-delta/complete, finish reason.
  - Handles `data: [DONE]` SSE terminator and network reconnect on transient failures (bounded retries).
  - Base URL, model name, API key come from `AgentConfig` + `config.store.load_secret("llm_api_key")`.
- `src/workstation_agent/llm/tool_bridge.py`:
  - `to_openai_schema(descriptors: list[ToolDescriptor]) -> list[dict]` — maps MCP tool descriptors to OpenAI `tools=[{"type":"function","function":{...}}]` format.
  - `class ToolRouter` — receives streamed tool-call from `OpenAICompatClient`, waits for full args, dispatches to `MCPHost.invoke`, formats the result back into an OpenAI `tool` role message.
- `src/workstation_agent/llm/session_store.py`:
  - Opens `conversations.sqlite` (WAL mode).
  - Schema:
    ```sql
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY,        -- uuid
      created_at TEXT NOT NULL,
      last_activity_at TEXT NOT NULL,
      mode TEXT NOT NULL,          -- 'single_shot' | 'sticky' | 'persistent'
      title TEXT
    );
    CREATE TABLE messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL REFERENCES sessions(id),
      role TEXT NOT NULL,          -- 'system' | 'user' | 'assistant' | 'tool'
      content TEXT,                -- text or JSON tool result
      tool_calls_json TEXT,        -- nullable
      tool_call_id TEXT,           -- nullable
      ts_utc TEXT NOT NULL
    );
    ```
  - `class SessionStore`:
    - `start_session(mode: SessionMode) -> SessionId`.
    - `append(session_id, role, content=None, tool_calls=None, tool_call_id=None)`.
    - `history(session_id) -> list[OpenAIMessage]` — returns messages in OpenAI-compatible format.
    - `should_continue(session_id, now: datetime, sticky_seconds: int) -> bool` — for sticky-window logic.
- `src/workstation_agent/llm/turn.py`:
  - `class LLMTurn` — orchestrates one user turn:
    - Takes user text, gets tools from `MCPHost`, calls `OpenAICompatClient.chat`, streams deltas, dispatches tool calls through `ToolRouter`, feeds tool results back into the LLM (multi-round if the LLM makes more tool calls), yields final text chunks to the caller for TTS.
    - Emits progress events (`text_chunk`, `tool_call_started`, `tool_call_done`, `finished`) for the UI.
    - Persists every message to `SessionStore`.
- `tests/fakes/fake_openai.py`:
  - FastAPI ASGI app implementing `/v1/chat/completions` with SSE streaming. Configurable canned responses including tool-call sequences and multi-round loops.
- `tests/unit/llm/test_tool_bridge.py` — MCP descriptor → OpenAI schema conversion table.
- `tests/unit/llm/test_session_store.py` — insert, history round-trip, sticky-window boundary conditions.
- `tests/integration/llm/test_turn_loop.py`:
  - Uses `fake_openai` + a fake `MCPHost` that returns a hardcoded tool result; asserts the multi-round tool loop terminates and the final assistant text is emitted; asserts every message persisted to `SessionStore`.

## Constraints

- Do not import from `mcp_host/` — depend only on the `MCPHost` Protocol from SPEC-01.
- Streaming is required; no non-streaming code path in v1.
- API key never appears in logs or exceptions (use `security.dpapi.redact_key` in `client.py`'s log lines).
- No secrets in error messages ever.

## Acceptance criteria

- Green ruff/pyright/pytest.
- Coverage on `llm/*` >= 85%.

## Executor summary MUST report

Number of round-trips the multi-round tool loop was tested with. Any hiccups implementing SSE parsing. Whether `fake_openai` was reused (or should be reused) across other SPECs.

=== SPEC-06-updater.md ===
# SPEC-06 — Updater client (Python) + Updater.exe (Go)

**Executor tier:** opus. **Branch:** `feat/spec-06-updater`. **Worktree:** `../wsa-spec-06/`.
**Depends on:** SPEC-01, SPEC-02.

## Goal

End-to-end signed self-update flow per design §4.7. In-agent Python side polls Releases, verifies Ed25519, prompts user, hands off. Standalone Go binary performs the swap and relaunch. Rollback command supported.

## Files to create / modify (only these)

- `src/workstation_agent/updater_client/__init__.py`
- `src/workstation_agent/updater_client/manifest.py`:
  - `class UpdateManifest` (Pydantic) — schema exactly matches design §4.7.
  - `fetch(github_repo: str, http: httpx.AsyncClient) -> tuple[UpdateManifest, bytes]` — GET latest release, download `manifest.json` + `manifest.json.sig`, return parsed manifest + raw canonical JSON bytes for verification.
- `src/workstation_agent/updater_client/verifier.py`:
  - `verify(manifest_bytes: bytes, sig_bytes: bytes, pubkey: bytes) -> bool` — thin wrapper on `security.signature.verify`.
- `src/workstation_agent/updater_client/poller.py`:
  - `class UpdatePoller` — async loop, runs `fetch → verify → compare version → notify` on config-driven schedule; can be nudged to poll now via `check_now()`.
  - Emits `on_update_available(manifest)` callback when a verified newer version is found.
- `src/workstation_agent/updater_client/handoff.py`:
  - `stage_pending(manifest: UpdateManifest) -> Path` — writes `pending_update.json` (contains manifest + verified flag + agent's PID) atomically to `%APPDATA%\WorkstationAgent\`.
  - `spawn_updater() -> None` — locates `Updater.exe` next to the current Agent.exe (`<install>\current\Updater.exe`), spawns it with `--update` and detached process flag (`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`), then triggers a clean agent shutdown.
- `updater/go.mod` — module `github.com/synssins/PersonaCore-Agent/updater`, Go 1.22.
- `updater/main.go` — CLI with subcommands via `flag`:
  - `--update` — read `pending_update.json`, wait for agent PID exit (30 s grace, then `TerminateProcess`), download artifact, verify SHA-256 against manifest, extract to `<install>\app\<version>\`, atomically swap `<install>\current` junction (Windows: `mklink /J` semantics via `syscall.CreateSymbolicLink` with directory flag, or `os.Symlink` — junction is preferable, use `golang.org/x/sys/windows` to call `DeviceIoControl` with `FSCTL_SET_REPARSE_POINT` if needed), relaunch `<install>\current\Agent.exe`, prune to last 3 versions, exit 0.
  - `--rollback [version]` — switch `current` junction to the specified older version folder, relaunch, exit 0.
  - `--check` — one-shot: fetch + verify latest release, print to stdout, exit.
- `updater/internal/verify/verify.go`:
  - Ed25519 verification via `crypto/ed25519`. Public key baked in via `-ldflags "-X main.PublicKeyHex=<hex>"`.
- `updater/internal/manifest/manifest.go` — struct matching Python's `UpdateManifest` + canonical JSON serialization (sorted keys, no whitespace) matching `security.signature.canonical_json`.
- `updater/internal/swap/swap.go` — junction manipulation, kill agent, download, extract.
- `updater/internal/prune/prune.go` — retain last N versions.
- `updater/Makefile` (or `build.ps1`) — `go build -ldflags="-X main.PublicKeyHex=$PC_AGENT_SIGNING_PUBKEY -s -w" -o dist/Updater.exe ./`.
- `updater/main_test.go` + `updater/internal/*/*_test.go` — Go unit tests. At minimum: canonical JSON matches Python's byte-for-byte on a fixture, Ed25519 verify with matching / mismatched sig, version comparison edge cases (`1.2.10` > `1.2.9`), prune keeps newest 3.
- `tests/integration/updater/test_end_to_end.py`:
  - Python test that:
    - Generates a test Ed25519 keypair.
    - Builds a fake release: tiny zip, manifest referencing it, signed manifest.
    - Serves them from a `pytest-httpserver` (add dep — flag it).
    - Runs `Updater.exe --update` against a temp install directory pre-populated with a fake "old version" and a mock agent process (a subprocess that just sleeps).
    - Asserts: manifest verified, artifact downloaded, sha256 matched, extraction succeeded, junction swapped, agent relaunched (verified by checking the new mock agent PID exists), old version retained until pruning.
  - The Go binary MUST be built once at the start of the test session and cached.

## Constraints

- Ed25519 canonical serialization MUST byte-match between Python and Go. Include a fixture-based cross-check test.
- Updater is standalone: no Python runtime available to it. It reads only `pending_update.json` + does its work.
- Never overwrite in place — always stage in `_incoming\` and atomic-swap.
- Updater failure MUST leave the previous `current` junction untouched.
- Updater logs to `%APPDATA%\WorkstationAgent\logs\updater-YYYYMMDD.log` (line-oriented, timestamped).
- No admin elevation attempts in v1. Per-user install path only; machine-wide handling comes with SPEC-10.

## Acceptance criteria

- `pytest tests/integration/updater -q` green (builds Go binary as a fixture).
- `go test ./...` green in `updater/`.
- `go build` in `updater/` produces a working binary (~< 10 MB stripped).
- Coverage on `updater_client/*` >= 85%.

## Executor summary MUST report

Windows junction manipulation approach chosen (mklink shell-out vs. syscall). Any dep additions. Whether canonical JSON matched byte-for-byte across languages on first try; if not, what changed.

=== SPEC-07-ui.md ===
# SPEC-07 — UI: systray + WebView2 + FastAPI backend + toast notifications + logging

**Executor tier:** sonnet. **Branch:** `feat/spec-07-ui`. **Worktree:** `../wsa-spec-07/`.
**Depends on:** SPEC-01, SPEC-02, SPEC-03 (MCPHost Protocol), SPEC-06 (update flow surface).

## Goal

Deliver the user-facing surface: systray icon with full menu, WebView2 window pointed at a local FastAPI serving all UI pages, Windows toast notifications with action buttons, structured logging.

Visual **design** of the pages is explicitly out of scope — ship functional-unstyled HTML forms/tables that a follow-up pass with `interface-design` will restyle without changing routes/data contracts.

## Files to create / modify (only these)

- `src/workstation_agent/ui/systray/__init__.py`
- `src/workstation_agent/ui/systray/tray.py`:
  - `class SystemTray` using `pystray`. Icon PNG shipped in `ui/systray/assets/icon.png` (a plain generated 32×32 placeholder — Chris will replace).
  - Right-click menu items:
    - **Open** (double-click default) — opens WebView2 window to `/dashboard`.
    - **Mute agent** (checkbox) — toggles combined mic + speaker mute (calls into audio subsystem via injected callbacks).
    - **Session mode ›** submenu: Single-shot / Sticky / Persistent (radio) — writes to config.
    - **Reload plugins** (badge shows count of pending-reload plugins).
    - **Check for updates now** — triggers `UpdatePoller.check_now()`.
    - **Open config** — WebView2 to `/config`.
    - **Show audit log** — WebView2 to `/audit`.
    - **Show logs folder** — Explorer window at logs dir.
    - **About** — WebView2 to `/about`.
    - **Exit** — clean shutdown.
- `src/workstation_agent/ui/webview/window.py`:
  - `class WebviewWindow` — thin wrapper around `pywebview` (Edge backend on Windows). Runs its own event loop on a dedicated thread; agent stays running when window closes (`close_to_tray` config default true).
  - `open(path: str)` — navigates the window to `http://127.0.0.1:<port>{path}`; creates the window lazily on first call.
  - `close()` — hides but doesn't destroy (fast re-open).
- `src/workstation_agent/ui/backend/__init__.py`
- `src/workstation_agent/ui/backend/app.py`:
  - FastAPI app bound to `127.0.0.1:0` (OS-picked ephemeral port; port written to `%APPDATA%\WorkstationAgent\ui-port` for the WebView2 side to read).
  - Routes:
    - `GET /` → redirect to `/dashboard` (or `/first-run` if `first_run_completed` flag absent).
    - `GET /first-run` — HTML wizard per design §4.10, step navigation via `HX-Trigger` or plain form POSTs. Final POST writes config + creates flag file.
    - `GET /dashboard` — HTML: status pill, mute state, current session id, last N exchanges (calls SPEC-05 `SessionStore` — inject as dep).
    - `GET/POST /config` — form-driven grouped settings. POST validates via Pydantic schema then `config.store.save`.
    - `GET /plugins` — list installed plugins with signature status; enable/disable toggles; per-permission grant checkboxes; install-from-file (POST multipart) and install-from-registry (POST URL).
    - `GET /audit` — filtered table view backed by `mcp_host.audit.query`.
    - `GET /logs` — last N lines of today's JSONL, tail via server-sent events.
    - `GET /about` — version, update check button (POST triggers poller), rollback dropdown (POST spawns `Updater.exe --rollback <ver>`).
  - Auth: **loopback-only**; refuse any connection whose remote host isn't `127.0.0.1`. No token in v1.
  - HTML: minimal semantic markup, one shared `layout.html` + `static/skeleton.css` (dead simple, ~50 lines). NO custom design work. Include a comment banner in every template saying `<!-- SKELETON — replace with interface-design output -->`.
- `src/workstation_agent/ui/backend/templates/*.html` — Jinja2 templates for each route.
- `src/workstation_agent/ui/backend/static/skeleton.css` — placeholder.
- `src/workstation_agent/ui/notifications/__init__.py`
- `src/workstation_agent/ui/notifications/toast.py`:
  - `class ToastPresenter` using `winrt.windows.ui.notifications` — actionable toasts with buttons ("Update now", "Later", "Skip version") wired to callbacks.
  - Fallback: if `winrt` isn't available (dev on non-Windows), no-op with a WARN log.
- `src/workstation_agent/observability/__init__.py`
- `src/workstation_agent/observability/logging.py`:
  - `configure(log_dir: Path, level: str)` — `structlog` with JSON renderer, `RotatingFileHandler` daily rotation, redaction processor applying `security.dpapi.redact_key`.
  - Live level change API (`set_level(level)`) — systray menu (or `/config`) can adjust without restart.
- `src/workstation_agent/observability/tracing.py`:
  - Optional OTLP exporter using `opentelemetry-*` packages IF the deps are already present; else no-op. **Do NOT add these to `pyproject.toml`** in v1 — it's an optional plugin-installable capability. If code needs a stub, `try: import; except ImportError: pass`.
- `tests/unit/ui/test_config_routes.py` — GET/POST /config with fake config store; validation errors render inline.
- `tests/unit/ui/test_plugins_routes.py` — enable/disable toggle updates config; unsigned install requires explicit acknowledgment.
- `tests/unit/ui/test_first_run.py` — wizard flow writes correct config + flag.
- `tests/unit/ui/test_notifications.py` — toast action callback fires (via `winrt` mock).
- `tests/unit/observability/test_logging.py` — JSON output, redaction applied, log rotation triggers.

## Constraints

- Only files listed above may be created/modified.
- All templates carry the SKELETON comment banner.
- WebView2 window lifecycle must not block the main agent event loop (dedicated thread).
- FastAPI bind is loopback-only, port ephemeral, port file atomic-written.
- No secrets in URLs or query strings.

## Acceptance criteria

- `ruff check`, `pyright`, `pytest tests/unit/ui tests/unit/observability -q` green.
- Coverage on `ui/*` and `observability/*` >= 80%.
- Manual boot check (in SPEC-10) will exercise WebView2 window opening.

## Executor summary MUST report

Whether `pywebview` + WebView2 works headless in the test env (probably needs `pywebview.start(gui="edgechromium", headless=True)` or a mock — expect this to be tricky). Any UI dependencies you had to add.

=== SPEC-08-claude-code.md ===
# SPEC-08 — Claude Code integration (both directions)

**Executor tier:** sonnet. **Branch:** `feat/spec-08-claude-code`. **Worktree:** `../wsa-spec-08/`.
**Depends on:** SPEC-01, SPEC-03 (MCPHost), SPEC-04 (audio), SPEC-07 (notifications).

## Goal

Direction 1: Agent exposes its own MCP server so Claude Code (and any other MCP host) can drive it. Direction 2: Agent drives Claude Code via `claude-agent-sdk` with voice-mediated tool-call approvals. Direction 2.5: presence detection + explicit trigger.

## Files to create / modify (only these)

### Direction 1: agent's own MCP server

- `src/workstation_agent/mcp_host/mcp_server.py`:
  - Stdio MCP server exposing:
    - `agent.speak(text: str) -> {ok: bool}` — calls `TTSSpeaker.speak`.
    - `agent.toast(title: str, body: str, actions?: list[str]) -> {ok: bool, action?: str}` — via `ToastPresenter`.
    - `agent.status() -> {state, current_session_id, mute_mic, mute_speaker, plugins_loaded}`.
    - `agent.last_transcript(n?: int) -> {turns: [{role, text, ts}]}`.
    - `agent.pause_listening(seconds: int) -> {ok: bool}`.
    - `agent.execute_local(plugin_id: str, tool: str, args: dict) -> {result}` — proxies through `MCPHost.invoke` with permission checks.
  - Runs on a separate task; can be launched standalone (`python -m workstation_agent.mcp_host.mcp_server`) for CC to add to its `.claude/mcp.json`. The standalone entry connects back to the running agent over a local Unix-socket-equivalent on Windows: named pipe `\\.\pipe\WSA-AGENT-<pid>` — or, simpler, IPC via the local FastAPI on `127.0.0.1:<port>/agent-ipc` with a per-session bearer token. **Pick named pipe** — matches Windows conventions, avoids exposing IPC over HTTP.
  - Token: agent generates a random 32-byte token at startup, writes to `%APPDATA%\WorkstationAgent\mcp-token` (mode 0600 equivalent on Windows: DACL current-user-only). The standalone MCP server reads the token and presents it on the named-pipe handshake.

### Direction 2: driving Claude Code

- `src/workstation_agent/claude_code/__init__.py`
- `src/workstation_agent/claude_code/driver.py`:
  - `class ClaudeCodeDriver` — wraps `claude-agent-sdk`. Spawns a CC subprocess for a user turn, streams events (message, tool_use, tool_result, notification, stop).
  - `async run(prompt: str, cwd: Path | None = None, on_tool_use: ToolUseHook | None = None) -> AsyncIterator[CCEvent]`.
  - `on_tool_use` hook is where **voice-mediated approval** happens: when CC wants to use a tool, we speak a challenge ("Claude Code wants to run: <tool>. Say yes to approve, no to deny."), wait for STT reply through the audio session, decide.
- `src/workstation_agent/claude_code/presence.py`:
  - `is_running() -> bool` — enumerate processes, look for `claude.exe` or `node.exe` running Claude Code, or check for a lockfile CC writes.
  - `active_project() -> Path | None` — from running CC's cwd if we can read it (via `psutil.Process.cwd()`), else `None`.
- `src/workstation_agent/plugins/claude_code_bridge/plugin.toml` — a first-party plugin manifest.
- `src/workstation_agent/plugins/claude_code_bridge/__main__.py` — an MCP server (subprocess like every other plugin) exposing:
  - `claude_code.invoke(prompt: str, cwd?: str, voice_approval: bool = true) -> {events}` — proxies to `ClaudeCodeDriver.run`, streams events back as MCP notifications.
  - `claude_code.presence() -> {running: bool, cwd?: str}`.
  - `claude_code.list_recent_sessions(limit?: int) -> {sessions}` — from `~/.claude/projects/*/`.
- `tests/fakes/fake_claude_sdk.py` — stub that emits a canned event stream, used in tests since real CC binary won't run in CI.
- `tests/unit/claude_code/test_driver.py` — voice approval loop: tool_use event → challenge spoken → fake yes → approved; fake no → denied and CC session terminated.
- `tests/unit/claude_code/test_presence.py` — mocked process enum; running / not running.
- `tests/integration/claude_code/test_bridge_plugin.py` — the plugin subprocess loaded via `MCPHost`; `claude_code.invoke` returns events via the fake SDK.
- `tests/unit/mcp_host/test_agent_mcp_server.py` — spawns the agent's own MCP server standalone, connects a fake MCP client via named pipe, calls `agent.status`, asserts response and that a bad token is rejected.

## Constraints

- `claude-agent-sdk` version pinned in `pyproject.toml` (**tell orchestrator the exact pin in the executor summary** — this SPEC does not modify pyproject).
- Voice approval MUST time out (config default 20 s) → treat as deny.
- Named pipe DACL restricts to CurrentUser only.
- Token file readable only by CurrentUser (Windows DACL, not just filesystem mode).

## Acceptance criteria

- Green ruff/pyright/pytest for `claude_code/*` and the plugin.
- Coverage on `claude_code/*` >= 80%.
- Named-pipe MCP server integration test round-trips one call.

## Executor summary MUST report

Which SDK version worked. Any Windows named-pipe quirks. Whether real `claude` process detection needed heuristics beyond a simple process scan.

=== SPEC-09-plugin-stubs.md ===
# SPEC-09 — First-party plugin stubs (six)

**Executor tier:** haiku. **Branch:** `feat/spec-09-plugin-stubs`. **Worktree:** `../wsa-spec-09/`.
**Depends on:** SPEC-01, SPEC-03 (plugin loader interface).

## Goal

Ship six signed first-party plugin **stubs** that load, register their real tool inventories, respond to invocations with structured "not_implemented" results, and prove the loader + permission surface + audit log against realistic manifests. Real implementations land as v0.2 subtasks per plugin.

## Files to create / modify (only these)

Each plugin under `src/workstation_agent/plugins/<name>/`:

- `plugin.toml` (per design §4.4 format, with correct capabilities declared).
- `__main__.py` — MCP server exposing the tools with `not_implemented` results.
- `signature.sig` — Ed25519 signature of canonical manifest + `__main__.py` hash. Signed with the **first-party plugin signing key** — a fixed Ed25519 keypair generated by SPEC-01's test infrastructure. Public key baked into agent for first-party trust. **Executor generates the signing keypair as part of this SPEC**, writes:
  - `working/signing/first_party.pub.hex` — the public key hex (orchestrator will move this into `pyproject.toml`'s data files and bake into build).
  - `working/signing/first_party.priv.hex` — **NOT COMMITTED** (executor MUST add to `.gitignore` and confirm in summary that it did not land in the tree).

Plugins (all with stub tool bodies):

- **`filesystem`** — tools: `filesystem.list(path)`, `filesystem.read(path)`, `filesystem.write(path, content)`, `filesystem.delete(path)`. Declared perms: `filesystem.read` + `filesystem.write` with scoped paths from manifest.
- **`powershell`** — tools: `powershell.run(intent, command, timeout_s?)`. Declared perms: `powershell.exec` + confirmable "any command outside allowlist". Manifest carries an empty regex allowlist by default.
- **`desktop_control`** — tools: `desktop.click(x, y)`, `desktop.type(text)`, `desktop.key(combo)`, `desktop.list_windows()`, `desktop.focus_window(title_pattern)`. Declared perm: `desktop.control`.
- **`browser`** — tools: `browser.open(url)`, `browser.screenshot()`, `browser.click(selector)`, `browser.type(selector, text)`, `browser.eval(js)`. Declared perms: `browser.navigate` (allowlisted domains empty by default = anywhere blocked until user grants) + `browser.script` for `eval`.
- **`screen_vision`** — tools: `screen.capture(monitor?, region?)` returning base64 image, `screen.capture_ocr(monitor?, region?)` returning `{regions: [{bbox, text}]}`, `screen.list_monitors()`. Declared perm: `screen.capture`. **Both modes exposed** per Q5.
- **`clipboard`** — tools: `clipboard.get()`, `clipboard.set(text)`, `clipboard.clear()`. Declared perms: `clipboard.read`, `clipboard.write`.

Every stub tool returns:
```json
{"status": "not_implemented", "plugin": "<id>", "tool": "<name>", "note": "framework stub — implementation lands in v0.2"}
```

## Constraints

- Real implementations are OUT OF SCOPE. Do NOT try to make `filesystem.read` actually read files, `powershell.run` actually run PowerShell, etc.
- Each plugin's `__main__.py` is a real MCP server, not a mock — loader must be able to spawn it and get tools/list back.
- Signatures MUST verify against the first-party pubkey when loaded by SPEC-03's loader.
- Manifests declare the **real** tool schemas the v0.2 implementations will honor, so the LLM tool bridge (SPEC-05) sees a correct surface today.

## Acceptance criteria

- All six plugins load via `MCPHost.start()` (integration test).
- Each plugin's tools appear in `MCPHost.tools()` output with correct schemas.
- Invoking any tool returns the `not_implemented` payload.
- Signature verify passes for all six.
- Coverage on plugin `__main__.py` files >= 60% (they are thin).

## Executor summary MUST report

The generated first-party public key hex (for orchestrator to bake into build). Confirmation that the private key file is `.gitignore`d and not committed. Any tool-schema decisions worth flagging for the v0.2 implementation.

=== SPEC-10-installer-and-wiring.md ===
# SPEC-10 — Installer, main entry wiring, boot check, release workflow

**Executor tier:** sonnet. **Branch:** `feat/spec-10-installer`. **Worktree:** `../wsa-spec-10/`.
**Depends on:** ALL previous SPECs (integration layer).

## Goal

Compose all subsystems into a runnable app, produce a working installer, wire the release CI, add a boot-check that exercises the full stack against fakes.

## Files to create / modify (only these)

### Main entry wiring

- `src/workstation_agent/app.py`:
  - `class Application` — composition root. Order:
    1. Configure logging (`observability.logging.configure`).
    2. Load config (`config.store.load`).
    3. Instantiate audit log, session store, secret loader.
    4. Instantiate `MCPHost`, start it (discover + spawn plugins).
    5. Instantiate `WyomingSTTClient`, `WyomingTTSClient`, `MicStream`, `Speaker`, `AudioSession`.
    6. Instantiate `OpenAICompatClient`, `LLMTurn`.
    7. Wire `AudioSession.on_transcribed → LLMTurn.run → TTS speak`.
    8. Instantiate `ToastPresenter`, `SystemTray`, `WebviewWindow`, `FastAPIApp`.
    9. Instantiate `UpdatePoller`, wire `on_update_available` → toast + optional voice.
    10. Instantiate `ClaudeCodeDriver` and start the agent's own MCP server.
    11. On first-run flag missing: `WebviewWindow.open("/first-run")`.
  - `async run()` — sets up signal handlers, joins the systray thread, waits for exit.
  - `async shutdown()` — graceful teardown in reverse order.
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
