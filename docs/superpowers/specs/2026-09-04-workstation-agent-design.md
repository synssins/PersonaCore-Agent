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
