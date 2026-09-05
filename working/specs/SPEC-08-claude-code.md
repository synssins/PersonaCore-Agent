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
  - Runs on a separate task; can be launched standalone (`python -m workstation_agent.mcp_host.mcp_server`) for CC to add to its `.claude/mcp.json`.
  - **Static named pipe** (audit finding): the standalone entry connects back to the running agent over `\\.\pipe\PC-Agent-MCP` — a fixed name so CC's `.claude/mcp.json` doesn't need updating when the agent restarts with a new PID. Only one agent instance can bind this pipe at a time (enforced by `CreateNamedPipe` returning `ERROR_PIPE_BUSY` on the second attempt); the second instance logs "another agent instance is already running" and exits with a non-zero code.
  - **Token**: agent generates a random 32-byte token at startup, writes to `%APPDATA%\WorkstationAgent\mcp-token` and immediately calls `security.harden_file(path)` from SPEC-02 to apply the DACL that denies Low-integrity SID read + Everyone read, granting only current user. The standalone MCP server reads the token and presents it on the named-pipe handshake.

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
