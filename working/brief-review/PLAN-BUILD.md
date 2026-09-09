# PLAN — Build the workstation plugin v1 (A1–A5)

**Follows:** the review in `REVIEW-SUMMARY.md`, `R1/REPORT.md`, `R2/REPORT.md`.
**Contract:** `C:\Projects\PersonaCore\working\contracts\workstation.md`
**Brief:** `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md`
**Orchestrator:** this session. **Date:** 2026-09-08.

## Standing assumptions (stated, not guessed silently)

Three questions were raised with the PersonaCore side in `REVIEW-SUMMARY.md` §3. We build on
these defaults rather than blocking; each is cheap to change if they answer differently, and
each is the safer reading of their own constraints.

- **A1 tool scoping:** a **static families-only allowlist**. `agent.*` internal tools are never
  served on the network endpoint. The exported registration is generated from that same list, so
  the served set and the registration cannot drift.
- **Confirm vs the 25 s budget:** clamp the post-confirm wait to
  `min(wait_s, 25 - prompt_duration)` and return the job envelope early.
- **A6/§11 item 9:** treat the audit-row requirement as **in scope for A5**, since A5 owns
  `audit.db` regardless of where the done-condition draws its line.

## Scope

**A1–A5 only.** A6 (hands-on acceptance) is **externally blocked**: all seven of its items need
the PersonaCore-side §3 core change first, and items 2–3 need physical hardware nobody has been
asked to supply. A6 is not planned here; it becomes a task when the core change lands.

**B0 is new and comes first** — it is not in the brief. It fixes two live defects the review
found in the existing named-pipe server, which A1 would otherwise inherit or paper over.

## Subtasks

| ID | Title | Class | Executor | Depends on |
|----|-------|-------|----------|------------|
| B0 | Fix the two live `mcp_server.py` defects + de-mock their tests | default | sonnet | — |
| B1 | Confirm primitive: awaitable, timeout, fail-closed | hard | opus | B0 |
| B2 | Gate core: §5.2 envelope, §5.6 stripping, `audit.db` migration for §5.7 | hard | opus | B1 |
| B3 | Pre-approved list + "remember for this session" + UI surface | default | sonnet | B2 |
| B4 | Network MCP endpoint: TLS, token, bind, `401` | hard | opus | B0 |
| B5 | `export-registration` + console entry point + registration/served-set symmetry | default | sonnet | B4 |
| B6 | `shell` / `files` / `jobs` families | hard | opus | B2 |
| B7 | `devices` / `adb` families | hard | opus | B2 |
| B8 | `serial` family + `pyserial` licence record | default | sonnet | B2 |

**A-mapping:** A5 = B1+B2+B3. A1 = B4+B5. A2 = B6. A3 = B7. A4 = B8.

**Ordering rationale — corrected after the build-plan audit.** An earlier draft justified this as
"A5 before A1" on the grounds that A1 would inherit a gate covering one tool in six. The plan
auditor showed that reasoning is wrong: under our families-only scoping, A1 serves *only* family
tools, and those already route through `host.invoke()`, which is gated. The ungated five are
`agent.*` internals the endpoint never serves.

The real constraint is narrower and still holds: **no family is built before the gate**, because
every family built pre-gate gets retrofitted. B4 is *not* blocked on the gate and runs concurrently
with B1. What B4 must not do is land after B2 changes the §5.2 result shape without B2 having
updated the pipe — see B2's pipe-compatibility criterion.

**Parallelism:** B0 alone → then B1 and B4 concurrently → B2 and B5 concurrently → then B3, B6,
B7, B8 all concurrent (four executors; separate worktrees, disjoint path lists).

**`app.py` is a shared composition root — the one real collision, caught by the plan auditor.**
B1 and B4 would both edit `app.py`'s startup sequence and conflict. Resolution: **B1 exclusively
owns `app.py`.** B4 delivers its server as a self-contained module exposing a start/stop interface
and edits no application wiring; B5 performs the one-line wiring into `app.py` after B1 has landed.
`app.py` appears in exactly one subtask's allowed-paths list at a time.

## Per-subtask acceptance criteria

**B0.** `mcp_server.py:334` `self._toast.present(...)` → a real `ToastPresenter` call; `:315`
`json.dumps` gains a `default=` that serialises `ToolResultImpl`. `test_agent_mcp_server.py`
stops mocking the toast presenter and the result serialiser for these paths, so both defects
would have failed the suite. Regression test proving a *successful* `agent.execute_local` returns
`isError: False` with the payload intact.

**B1.** An awaitable confirm primitive returning `bool`, with a 20 s timeout (§7) resolving to
`unconfirmed`, a correlation id, and toast + spoken line. **Fail-closed**: `_WINRT_AVAILABLE`
false, no presenter, or any exception denies. `app.py:441` passes `confirm_cb` and `tts_speak`.
`NotificationsConfig.voice_announce_confirmations_enabled` (`schema.py:84`) is actually read.
Test: an unanswered prompt returns `unconfirmed` at ~20 s; an absent toast stack denies.

**B2.** Every tool result conforms to §5.2 shapes and codes. §5.6 special-token stripping applied.
`audit_log` migrated to satisfy §5.7 — duration column, request-id column, `args_json` truncated
at 200 chars — with append-only still trigger-enforced. **The read/action split**: permission
checkers stop discarding their `tool` argument, so `filesystem.read` outside roots returns
`denied` (§11 item 6), never `confirm`. Test that a read outside roots is denied and never prompts.

**B2 additions from the plan audit (all three are required, not optional):**

- **The read/action split must short-circuit to `deny`, never merely fail to confirm.** This is a
  live trap: `evaluate` ends at `return "allow"` (`permissions.py:214`), and the hard-guard loop
  skips any guard the plugin declares as a confirmable condition (`:201-203`). `filesystem`
  declares `outside_declared_paths` (`plugins/filesystem/plugin.toml:14`). So "fixing" reads by
  making that checker return `False` skips both the confirm *and* the hard guard and lands on
  **allow** — converting a prompt-on-read into a silent out-of-roots read. Test must assert
  `denied`, and separately assert it is not `allow`.
- **Pipe compatibility.** Changing `host.invoke()`'s result to the §5.2 envelope breaks the
  existing named-pipe `agent.execute_local` call site. B2 updates that call site in the same change
  and keeps a test proving the local pipe integration still works end to end.
- **Session-context plumbing.** `host.invoke()` currently accepts no session identifier and B4's
  HTTP endpoint is stateless, so B3's "remember for this session" is unimplementable without it.
  B2 plumbs a session/connection identifier from the transport down into the permissions evaluator.
  Without this, B3's acceptance criteria cannot be met.

**B3.** §7's pre-approved and always-prompt lists as an Agent setting with those defaults, the
operator able to move any tool between them, and per-tool "remember for this session". UI surface
for the list. Test: a tool on the never-prompt list does not prompt; "remember" suppresses a
second prompt in-session and does not survive restart.

**B4.** Streamable-HTTP MCP at `https://<iface>:<port>/mcp`. Self-signed cert, SAN = hostname +
LAN IP, **persisted and reused across restarts** (else the pinned fingerprint changes and §11
item 8 fails). 32-byte random bearer token. `401` on bad or missing token. Binds an
operator-chosen interface, **never `0.0.0.0` by default, never plain HTTP**. Token and cert
fingerprint shown once in the UI with copy buttons. The `mcp`-package-vs-inline decision is the
executor's, recorded with its reason in the repo. `cryptography>=41.0` is already declared
(`pyproject.toml:27`) and currently unused, so cert generation needs no new dependency.
`mcp_client.py:49` `_DEFAULT_TIMEOUT = 10.0` raised deliberately above the 20 s prompt window.
**Hostile-input hardening of the JSON-RPC framing layer is B4's, inherited from B0.** B0 was
rescoped by the owner after four verification rounds each uncovered a new remote pre-auth crash
in the same transport code: `!=` token comparison, `compare_digest` on `str`, `.encode()` on an
unpaired surrogate, and a long line overrunning asyncio's 64 KiB `readline()` buffer. B0 landed
the individual crash fixes and deliberately left the *policy* to B4, which is the subtask that
actually puts this transport on a network. B4 must therefore:

- Choose and justify a pre-auth line bound. B0 restored asyncio's 64 KiB default after a 64 MiB
  limit was rejected as trading a crash for memory exhaustion — an unauthenticated client could
  hold 64 MB per connection. Anything larger than the default needs a stated reason.
- Reject oversized input early rather than buffering it to reply politely.
- Cover the hostile-input space systematically rather than case by case, since case-by-case is
  precisely what took B0 four rounds: at minimum unpaired surrogates, invalid UTF-8 on the wire
  (as distinct from inside a JSON string), deeply nested JSON (`RecursionError`), a line with no
  separator, an empty line, and oversized lines — each asserting the handler returns rather than
  raises and the connection survives or closes cleanly.
- Consider per-connection limits and connection caps, which B0 was explicitly forbidden from
  adding. An unauthenticated network peer is a different threat model from a local named pipe.

**Token comparison uses `secrets.compare_digest`** — the existing pipe compares with `!=`, which is
acceptable for local IPC but leaves a 32-byte token open to a timing attack once it is on a LAN.
B0 fixes the pipe's comparison too, since it is in that file already.

**B5.** `export-registration` writes `workstation-registration.zip` (§2). Requires a console
entry point — `workstation_agent.spec:93` sets `console=False` and `__main__.py:103-115` has no
subcommands, so this needs a separate console binary or a documented console-attach. Tool names
carry §2's `family.verb`→`family_verb` translation; a test asserts all exported names match
`^[a-z][a-z0-9-]{1,63}$` after `_`→`-`. **A test asserts the served set equals the exported set**
— the symmetry bullet 2 forbids breaking.

**Tool-name spelling for the gate declaration — a verified fact, not a choice (B2b).** Every
family must declare `args:files.read:...` with the DOTTED name, never `args:files_read:...`.
`host.invoke` receives the dotted `family.verb` form on every call path that exists:
`network_mcp/server.py:431` passes `tool.internal_name` (the underscore wire name is translated
at the endpoint boundary and never reaches the gate), `mcp_host/mcp_server.py:532/534` builds
`f"{plugin_id}.{tool}"`, and all eight bundled plugins advertise dotted names. The underscore
spellings in older gate tests were test-only fictions from the deleted heuristic. Under
default-deny, the wrong spelling produces a tool nobody can call — the shipped-manifest symmetry
tests in `test_argument_declarations.py` catch it on first run.

**Declaring arguments is now mandatory for every family.** A tool with no `args:` entry in its
signed `plugin.toml`, or a call carrying an argument the entry does not name, is REFUSED. Classes
are `ws_path`, `ws_command`, `web_target`, `foreign`, `opaque`; a leading `!` marks an argument
required. Transcribe from `network_mcp/tools.py`'s schemas. Editing a manifest invalidates its
signature — re-sign it and say so, and the orchestrator will verify.

**Known trap for every family — the path-ish key heuristic, from B2.** `_key_is_pathish` in
`permissions.py` matches argument names by SUBSTRING, and its fragment list includes `name`. So
an argument called `username`, `display_name` or `profile_name` is treated as a path candidate,
found to be relative, and DENIED. No current plugin hits it; the first family to ship such an
argument will. It fails in the safe direction (over-denial, never a bypass), so it was left
alone deliberately rather than widened under time pressure. If your family needs such an
argument, tighten the fragment list rather than working around it.

Related, and already fixed by B2 after it bit twice: arguments that live in a FOREIGN namespace
— a phone path, a phone command, a serial payload — must not be judged against the workstation's
roots or command allowlist. `foreign_args(tool)` in `permissions.py` is an allowlist of EXEMPT
argument names, deliberately not a list of checked ones, so an unrecognised argument stays
checked and the failure mode is a visible over-denial rather than a silent bypass. `serial_`
payloads are already listed pre-emptively. If you add a tool whose argument is not a workstation
path, add it there — do not work around the gate.

**Binding on B6, B7 and B8 alike — result sanitisation, raised by the B4 verifier.** Contract
§5.3: binary never travels in v1; a result over the cap or not valid UTF-8 is `ok: false`,
`code: "error"`, with the size and "binary transfer is not available yet". The brief's own
forbidden list adds stack traces, absolute paths outside the roots, and the token. Four tools
are specifically at risk and each must enforce this at its own boundary, not assume the
transport will:

- `shell_run` and `jobs_output` capture raw stdout/stderr — `type image.png` returns binary, and
  a crashing command returns a stack trace.
- `adb_logcat` streams Android system logs, which by design carry crash stack traces and
  authorisation tokens from logged requests.
- `serial_read` reads arbitrary device bytes, which are not text.

Each family owns the check for its own tools. A test per tool must prove non-UTF-8 output is
refused rather than mangled or passed through.

**B6.** **First, the evaluation the brief mandates and an earlier draft of this plan dropped:**
A2 says "Desktop Commander may be hosted behind the gate instead if it proves mature — evaluate
first, decide, record." B6 begins with that evaluation, records the decision and its reasoning in
the repo, and only then implements. Do not skip to a custom implementation by default.

Then: `shell`, `files`, `jobs` real. Job model per §5.4: in-memory, die with the Agent,
`jobs_wait`/`jobs_output`/`jobs_list`/`jobs_kill`. **`supervisor.py:101`
`max_active_processes = 4` must rise to at least 8** or §5.4's eight concurrent jobs is
physically impossible. Declared roots for files; no absolute path outside the roots ever returned.
Text-only — binary is `ok: false` per §5.3.

**B7.** `devices_list` via **ctypes into `setupapi.dll`** (`pywin32` provides no SetupAPI wrapper —
verified), plus `adb devices -l` and `serial.tools.list_ports`. §6.1's `present_since` cannot come
from WMI alone. `adb_*` as subprocesses over an `adb` binary whose path is a setting. `adb_shell`
job-capable. `adb_pull` is text-only in v1 (§10 defers binary).

**B8.** `pyserial` sessions per §5.5. New dependency: named, reasoned and licence-recorded
(BSD-3) in the repo's dependency record.

## Constraints binding every subtask

- **Venv is mandatory** (CLAUDE.md). Every command runs through `.venv\Scripts\python.exe`.
  Never `pip install` against system Python — it has clobbered PersonaCore's `mcp` before.
- Implementation + unit tests + integration tests where interfaces are touched.
- `ruff check`, `pyright`, and `pytest` clean before any subtask reports done.
- No worker touches `working/`. No worker touches paths outside its own allowed list.
- No worker runs git write commands; only the orchestrator commits.
- Nothing under `C:\Projects\PersonaCore\` is ever modified — read-only reference.
- **Never return** binary, a stack trace, an absolute path outside the roots, or the token.
- Every new tool goes through permissions → confirmable conditions → `audit.db`.

## Verification

Each subtask verified by the non-Anthropic verifier against its spec and diff, per roster. B1, B2
and B4 additionally get a security-focused verify pass: B4 puts this machine on the LAN, and B2
owns the read/action split that decides whether reads can be prompted.
