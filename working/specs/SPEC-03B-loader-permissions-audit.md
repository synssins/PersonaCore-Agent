# SPEC-03B — Plugin loader + permissions + audit + host facade

**Executor tier:** sonnet. **Branch:** `feat/spec-03b-loader`. **Worktree:** `../wsa-spec-03b/`.
**Depends on:** SPEC-01, SPEC-02, SPEC-03A (supervisor + MCP client).

## Goal

Discovery, manifest signature verification, install-time + runtime permissions, append-only audit log, and the `MCPHost` facade every other subsystem consumes.

## Files to create / modify (only these)

- `src/workstation_agent/mcp_host/loader.py`:
  - `discover() -> list[PluginManifest]` — merges:
    - Python entry points group `workstation_agent.plugins` (via `importlib.metadata.entry_points`).
    - Folder scan of `%APPDATA%\WorkstationAgent\plugins\*/plugin.toml`.
    - Bundled first-party plugins in `src/workstation_agent/plugins/*/plugin.toml`.
  - `PluginManifest` dataclass — parse `plugin.toml` per design §4.4; includes `id`, `name`, `version`, `runtime`, `entry` (arg list), `signature_file`, `declared_permissions`, `confirmable_conditions`, `compat`.
  - `verify(manifest: PluginManifest, pubkeys: list[bytes], allow_unsigned: bool) -> VerifyResult`:
    - Compute canonical-JSON of the manifest (via `security.signature.canonical_json`) + SHA-256 of every code file listed by the manifest's `entry`.
    - Try each pubkey in `pubkeys` (first-party + user-added trusted publishers) against `signature.sig`.
    - Return `VerifyResult(status='valid'|'unsigned'|'invalid'|'quarantined', reason, pubkey_id)`.
- `src/workstation_agent/mcp_host/permissions.py`:
  - `PermissionDecision = Literal["allow", "deny", "confirm"]`.
  - Built-in condition checkers (registered in a dict `{"outside_declared_paths": fn, "command_outside_allowlist": fn, "domain_outside_allowlist": fn}`). Unknown condition → deny + WARN.
  - `evaluate(plugin: PluginManifest, tool: str, args: dict, granted: set[str]) -> PermissionDecision`.
- `src/workstation_agent/mcp_host/audit.py`:
  - Opens `audit.sqlite` (WAL mode) at `config.store.paths()['audit_db']`.
  - Schema per design §4.6 with UPDATE/DELETE-rejecting triggers.
  - `log(event: AuditEvent) -> None`.
  - `query(filters: AuditQuery) -> list[AuditEvent]`.
- `src/workstation_agent/mcp_host/host.py`:
  - `class MCPHost` implementing the `MCPHost` Protocol from SPEC-01:
    - `async start(config, confirm_cb, tts_speak=None)` — discover, verify, spawn every enabled plugin via `PluginSupervisor` (SPEC-03A), attach `HeartbeatWatchdog`, collect tool inventories.
    - `async invoke(tool_id, args) -> ToolResult` — resolve plugin, evaluate permissions, call `confirm_cb` if `"confirm"` (with optional voice challenge via `tts_speak` if provided), dispatch via `MCPStdioClient.tools_call`, write audit row.
    - `async plugins() -> list[PluginInfo]` — running / quarantined / reload_pending / integrity.
    - `async reload(plugin_id)` — terminate + respawn (explicit only).
    - `async stop()` — graceful shutdown of every plugin.
  - `PluginInfo` dataclass includes signature status, granted permissions, resource-limit config.
- `src/workstation_agent/plugins/hello_world/plugin.toml` — a canary plugin manifest.
- `src/workstation_agent/plugins/hello_world/__main__.py` — trivial MCP server exposing `hello_world.echo(text: str) -> {text: str}`.
- `src/workstation_agent/plugins/hello_world/signature.sig` — generated at test-fixture time from the first-party key.
- `tests/fakes/gen_test_keypair.py` — pytest session fixture: generate Ed25519 keypair, sign the fake and hello_world plugins on the fly, patch the loader's known-pubkeys list to include the test key.
- `tests/integration/mcp_host/test_hello_world.py` — spawn `hello_world` via `MCPHost.start`, call `hello_world.echo`, assert round-trip; assert audit row written; assert `MCPHost.stop` cleans up.
- `tests/unit/mcp_host/test_loader.py` — discovery across the three sources; signature verify against fixture key; unsigned+allow_unsigned=False → quarantined.
- `tests/unit/mcp_host/test_permissions.py` — table-driven allow/deny/confirm cases.
- `tests/unit/mcp_host/test_audit.py` — schema created, INSERT succeeds, UPDATE/DELETE raise, query filters work.

## Files this SPEC may NOT touch

- SPEC-03A files (`supervisor.py`, `mcp_client.py`, `watchdog.py`) — import only.
- Anything outside `src/workstation_agent/mcp_host/{loader,permissions,audit,host}.py` and `plugins/hello_world/`.
- `pyproject.toml`, `ruff.toml`, `pytest.ini`.

## Acceptance criteria

- Green pytest for `mcp_host` + hello_world integration.
- Coverage on `loader.py`, `permissions.py`, `audit.py`, `host.py` >= 85%.

## Executor summary MUST report

Whether the loader correctly finds plugins across all three discovery sources. Any deviations from SPEC-03A's `SubprocessHandle` API you had to work around.
