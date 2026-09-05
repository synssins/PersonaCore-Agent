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
