# SPEC-03A — Subprocess supervisor + MCP stdio client

**Executor tier:** opus. **Branch:** `feat/spec-03a-supervisor`. **Worktree:** `../wsa-spec-03a/`.
**Depends on:** SPEC-01, SPEC-02.

## Goal

The low-level plumbing SPEC-03B builds on: spawn a plugin subprocess with proper Windows isolation, wire MCP JSON-RPC over stdio, health-check via ping, terminate cleanly.

## Files to create / modify (only these)

- `src/workstation_agent/mcp_host/__init__.py` — one-line docstring only.
- `src/workstation_agent/mcp_host/supervisor.py`:
  - `class PluginSupervisor` — spawns a plugin subprocess.
  - `spawn(entry_cmd: list[str], cwd: Path, plugin_id: str, resource_limits: ResourceLimits) -> SubprocessHandle`:
    - `subprocess.Popen(...)` stdin/stdout piped, stderr → logger.
    - **Environment**: pass through **ONLY these OS variables** — `SYSTEMROOT`, `SYSTEMDRIVE`, `WINDIR`, `USERPROFILE`, `USERNAME`, `USERDOMAIN`, `TEMP`, `TMP`, `APPDATA`, `LOCALAPPDATA`, `PROGRAMDATA`, `PATHEXT`, `PATH`, `COMSPEC`, `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`, plus the plugin-specific `WSA_PLUGIN_ID=<plugin_id>`. No other env inheritance. (Passing only `PATH` breaks Python `%TEMP%`-dependent imports, tempfile creation, and every Windows API that needs `%SYSTEMROOT%`.)
    - **Windows Job Object** wrapping via `pywin32` (`win32job.CreateJobObject` + `AssignProcessToJobObject`): `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `LIMIT_PROCESS_MEMORY = resource_limits.max_memory_mb * MB` (default 512 MB), `LIMIT_JOB_MEMORY = 768 MB`, `LIMIT_ACTIVE_PROCESS = 4`, `LIMIT_JOB_TIME` optional.
    - **Low integrity** spawn: `win32security.OpenProcessToken(current) → DuplicateTokenEx → SetTokenInformation(TokenIntegrityLevel, S-1-16-4096) → win32process.CreateProcessAsUser`. If the token duplication or IL set fails on this Windows edition (rare, but not impossible on Home SKUs), fall back to spawning at the parent's integrity level with a **WARN log entry** (not silent) and set a `SubprocessHandle.integrity = "medium"` flag so SPEC-03B / UI can badge those plugins as "reduced isolation".
    - Also set `CREATE_NEW_PROCESS_GROUP` for clean Ctrl-Break signaling.
    - Return `SubprocessHandle` with `pid`, `job_handle`, `integrity`, plus `stdin`/`stdout` streams.
  - `terminate(handle: SubprocessHandle, *, hard_after: float = 5.0)`:
    - Attempt graceful MCP `shutdown` request via the client.
    - Wait `hard_after` seconds; if still running, close the Job Object (kills whole tree).
    - Ensure `job_handle` closed after.
- `src/workstation_agent/mcp_host/mcp_client.py`:
  - Async MCP client. Prefer the `mcp` PyPI package's stdio client. If it doesn't work headless on Windows, implement JSON-RPC 2.0 over stdio inline (~150 LOC).
  - Supports: `initialize`, `tools/list`, `tools/call`, `notifications/*`, and a custom `ping` heartbeat.
  - Async iterator for incoming server-initiated notifications.
  - Timeout + cancellation-safe.
  - `class MCPStdioClient`: `connect(stdin, stdout)`, `initialize()`, `tools_list()`, `tools_call(tool, args)`, `ping()`, `shutdown()`, `notifications()`.
- `src/workstation_agent/mcp_host/watchdog.py`:
  - `class HeartbeatWatchdog` — periodic MCP `ping` (every 10 s default); if a plugin misses `heartbeat_timeout` seconds (default 30), terminate it via `PluginSupervisor.terminate`. Emits `on_plugin_died` events for SPEC-03B to reload / mark quarantined.
- `tests/fakes/echo_plugin/__main__.py` — the tiniest possible MCP server (echoes `hello.echo(text)`). Used by both SPEC-03A and SPEC-03B tests.
- `tests/unit/mcp_host/test_supervisor.py` — spawn `echo_plugin`, assert PID + Job Object exist; terminate, assert both cleared; env passthrough limited to whitelist (spawn a helper that dumps its env, assert only whitelisted vars present); IL fallback path exercised via monkeypatched `SetTokenInformation` raising.
- `tests/unit/mcp_host/test_mcp_client.py` — round-trip `initialize`, `tools/list`, `tools/call`, `ping`, `shutdown` against `echo_plugin`.
- `tests/unit/mcp_host/test_watchdog.py` — inject a fake client that ignores ping; watchdog terminates after timeout; ping success resets the timer.

## Files this SPEC may NOT touch

- Anything outside `src/workstation_agent/mcp_host/{__init__,supervisor,mcp_client,watchdog}.py`.
- `pyproject.toml`, `ruff.toml`, `pytest.ini`.
- `protocols.py` (if you need a new Protocol, note it in the executor summary).

## Acceptance criteria

- `pytest tests/unit/mcp_host -q` green.
- Coverage on `supervisor.py`, `mcp_client.py`, `watchdog.py` >= 85%.
- The env-whitelist assertion passes: only the listed variables leak into the subprocess.

## Executor summary MUST report

Whether `mcp` PyPI package worked or inline JSON-RPC needed. Whether low-integrity spawn succeeded on the test host. Observed subprocess memory for `echo_plugin` (sanity check for Job Object limits).
