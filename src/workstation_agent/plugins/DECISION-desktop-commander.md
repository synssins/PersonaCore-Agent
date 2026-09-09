# Decision — host Desktop Commander behind the gate, or implement `shell`/`files`/`jobs` natively?

**Date:** 2026-09-08
**Subtask:** B6 (contract §5.2–§5.4, §6, §6.1; brief A2)
**Decision:** **Implement natively.** Desktop Commander is not hosted in v1.
**Revisit:** v2, and only for a `code` family (`edit_block`-style structured editing and
indexed search), which is where its surface is genuinely ahead of anything this repo will
build. See "What would change the answer" below.

---

## Why this document exists

The brief (A2) says, in as many words:

> Desktop Commander may be hosted behind the gate instead if it proves mature — **evaluate
> first, decide, record.**

Contract §5.8 says the same thing more generally:

> Where mature third-party MCP servers exist for a family (shell and files: Desktop Commander
> is the candidate), the Agent may host them behind its gate instead of reimplementing; the
> gate is the Agent's per tool, never the hosted server's.

So "we wrote our own" is only an acceptable outcome if it is the *conclusion* of an
evaluation rather than the *default* that happens when nobody does one. This is the
evaluation.

## What was evaluated

`@wonderwhy-er/desktop-commander` (repo `wonderwhy-er/DesktopCommanderMCP`), MIT licensed, a
stdio MCP server. Node.js runtime (a Docker image is offered as the no-Node alternative).
Roughly 25 tools in five groups: terminal (`start_process`, `interact_with_process`,
`read_process_output`, `force_terminate`, `list_sessions`, …), filesystem (`read_file`,
`write_file`, `start_search`, `move_file`, `list_directory`, …), editing (`edit_block`),
config (`get_config`, `set_config_value`), and analytics (`get_usage_stats`,
`get_recent_tool_calls`, `give_feedback_to_desktop_commander`).

Maturity is not in question. It is widely deployed, actively maintained, MIT licensed, and
its process-interaction model (start a REPL, talk to it, read incrementally) is better than
what this subtask builds. The question is whether hosting it behind this Agent's gate is
cheaper and safer than implementing the three families the contract actually specifies.

## Findings

### 1. The tool surface is a different shape from the contract, not a superset of it

This is the decisive finding, and it is not a matter of taste. Contract §6.1 pins **exact
result keys**, and §11 makes a missing listed key a defect. §5.4 pins a **job** model:

| Contract §5.4 / §6.1 | Desktop Commander |
|---|---|
| `wait_s` (default 20, max 25) on the *first* call | no equivalent; start and read are always two calls |
| finished inside `wait_s` → `job_id: null` **and the real result** | never; always a session handle then a read |
| `jobs_wait` / `jobs_output` / `jobs_list` / `jobs_kill` | `read_process_output` / `list_sessions` / `force_terminate`; no wait-with-deadline |
| **at most 8** concurrent jobs, ninth refused with `code: "error"` | no documented concurrency cap |
| finished jobs retained **30 minutes** | session lifetime is not on that contract |
| output paged with `from_byte` / `max_bytes ≤ 60000` | offset/length paging, but stored output is capped at ~4 KiB per record |
| `{"ok": …, "code": …, "reason": …}` on every result (§5.2) | free-form text/JSON, no `ok`/`code`/`reason` |
| `files_read` → `path`, `from_byte`, `bytes`, `total_bytes`, `content`, `truncated` | `read_file` returns content, different keys |

Every row is a translation. Hosting therefore does **not** avoid writing the family — it
means writing a full bidirectional shim for ten tools *plus* carrying a Node process, and the
shim is where all of §5.2/§5.3/§5.4's rules would have to be enforced anyway. The shim is
roughly the size of the implementation, and unlike the implementation it can drift when the
upstream tool surface changes under it. The registration the core loads is frozen at export
time and a mismatch between it and the served list is a **terminal load failure** (contract
§2), so upstream drift is not a cosmetic risk here.

### 2. It can widen its own confinement at runtime, and its own docs say the confinement is partial

`set_config_value` can change `allowedDirectories` while the server is running, and the
project's own documentation warns that

> `allowedDirectories` setting currently only restricts filesystem operations, not terminal
> commands.

Contract §5.8 anticipates exactly this and answers it — "the gate is the Agent's per tool,
never the hosted server's" — and the Agent's gate would in fact still hold: root confinement
comes from `path:` in the *signed* `plugin.toml`, and commit `4f28d81` made it a hard
property that nothing a plugin says about itself at runtime reaches the gate. So this is not
a hole we would be inheriting.

It is still a real cost. It means `set_config_value`, `get_config`, and the three analytics
tools must be denied at the gate and never advertised, which is another four entries the shim
has to get right and keep right; and it means the hosted server's own security model
contributes nothing, so we would be paying for a dependency whose safety properties we then
have to ignore entirely.

### 3. Telemetry is on by default

Desktop Commander collects usage analytics by default. The opt-out is a config value
(`telemetryEnabled: false`) — that is, a value reachable by the same `set_config_value` tool
described above. The project states it does not collect file contents, paths, or command
arguments, and there is no reason to doubt that.

It is still the wrong default for this product. This Agent is a thing the owner installs to
get *local* control of their own workstation; the contract's entire transport section (§3) is
about keeping the surface on the LAN behind a token. Shipping a component that phones home by
default, whose off switch lives in mutable runtime config, is a policy change the owner did
not ask for and would have to be told about.

### 4. A Node runtime is a new install-time dependency for a Python/PyInstaller product

The Agent ships as a single Windows installer built from `workstation_agent.spec`. Hosting
Desktop Commander means bundling Node 18+ (or Docker) into that installer, or requiring the
owner to install it. That is a large addition to the install story and to the update story,
for three families that the standard library already covers.

### 5. It was not built for this sandbox, and this sandbox is unusually strict

Every plugin here is spawned by `mcp_host/supervisor.py` with a **low-integrity primary
token**, inside a **Job Object** (kill-on-close, memory and active-process limits), with a
**16-variable environment allow-list**. Desktop Commander writes its own `config.json` beside
itself and expects an ordinary user environment; at low integrity it cannot write there, and
with sixteen environment variables Node's own resolution (`NODE_PATH`, `npm` prefixes,
`APPDATA`-derived caches) is on thin ice. Making it work would mean either widening the
sandbox for it — weakening the isolation for every plugin — or maintaining a patched launch
path. The native implementation, by contrast, is the thing that gets *designed* against the
sandbox: this is why `files.write`'s writable root is `%USERPROFILE%\AppData\LocalLow\…` and
not `Documents`, which a low-integrity process cannot write to at all.

### 6. What we give up by not hosting it

Honestly: quite a lot, but none of it is in v1's scope.

* `edit_block` — surgical search/replace editing with fuzzy match reporting. Genuinely better
  than `files_write`, and nothing in contract §6 asks for it.
* `start_search` — indexed, streaming content and filename search. Contract §6 has no search
  tool.
* `interact_with_process` — a live REPL you can converse with. Contract §5.5 reserves the
  *session* concept for serial devices (B8) and deliberately gives shell a *job* model instead.

None of these are contract v1 tools, so hosting would buy capability the core cannot call and
the registration must not advertise (§2's served/exported symmetry).

## Decision and reasoning, in one paragraph

Hosting Desktop Commander would add a Node runtime, a telemetry default we would have to
document and disable, five tools we would have to deny, a sandbox it was not designed for,
and a translation shim for ten tools — and after all of that the contract's job model
(`wait_s`, `job_id: null`, eight concurrent, thirty-minute retention, byte-offset paging)
still would not exist and would still have to be built in the shim. The saving does not
materialise: what the contract specifies is not what this server does, and the gap is the
whole of the work. `shell`, `files` and `jobs` as specified are `subprocess`, `pathlib` and a
dictionary of job records — the standard library, in one signed plugin, designed against the
low-integrity sandbox from the start. **Implement natively.**

## What would change the answer

* A v2 `code` family whose tools *are* `edit_block`-shaped and indexed-search-shaped. There
  the contract would be written around what the server does, the shim shrinks to almost
  nothing, and the argument flips.
* Desktop Commander growing a telemetry-off-by-default build and a way to freeze
  `allowedDirectories` at start-up.
* The Agent gaining a Node runtime for some other reason, which would remove finding 4.

Recorded per brief A2 and contract §5.8 so that the next person to ask this question starts
from the evidence rather than from scratch.
