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
  - **CRITICAL — self-lock avoidance:** the updater invoked by the running agent is `<install>\current\Updater.exe`. Attempting to swap the `current` junction while `Updater.exe` is running from inside it will fail with sharing-violation errors. Therefore: on `--update` entry, **the updater first copies itself to `%TEMP%\PC-Agent-Updater-<version>.exe` and re-execs from that copy** (via `os.StartProcess` + `os.Exit`), so the on-disk `current\Updater.exe` is no longer held open when the junction swap happens. The temp copy self-deletes after successful completion (schedule via `MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT` or write a `.bat` self-deleter — the classic approach).
  - `--rollback [version]` — same self-copy pattern, then switch `current` junction to the specified older version folder, relaunch, exit 0.
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
