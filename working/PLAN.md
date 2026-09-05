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
