# R2 — Buildability review of AGENT-BRIEF.md work items A1–A6

Reviewed 2026-09-08 against the tree at `C:\Projects\GameTest`.
Brief: `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md`.
Contract: `C:\Projects\PersonaCore\working\contracts\workstation.md`.
Factual baseline: `working/brief-review/R1/REPORT.md` (cited, not re-derived).

I record no disagreement with any R1 verdict. Where I extend R1 I say so.

---

## Revisions 2 and 3 — what changed after verification

This report was independently verified by Gemini 3.1 Pro (a different model family)
across two rounds. Round 1 returned VERDICT: fail with one false positive and two
overstatements; round 2 accepted every correction, independently endorsed the
A5-over-A1 ranking, and caught one remaining error. The orchestrator adjudicated
each against the contract text and the code. Four corrections were upheld and are
applied here:

1. **The 25 s timing finding was overstated (was Problem #1; the largest change).**
   I treated §7's "20 s, then `unconfirmed`" as a fixed cost. It is a **timeout**,
   not a fixed cost — the owner normally answers in a few seconds. §11 items 2, 4
   and 7 all work under a sane implementation. The residue is real but narrow: the
   contract does not say whether the confirmation window counts against §5.3's
   25 s budget, so the implementer needs a documented clamping rule. This is **not**
   "A5 is unbuildable, blocked on an owner decision". Rewritten in Part 2 bullet 4
   and re-ranked in Part 3.
2. **"Prompting for reads is already violated" was overstated in the present
   tense.** The architectural finding is confirmed — the checkers discard their
   `tool` argument (`permissions.py:39,62,83`), so `filesystem.read` outside the
   roots resolves to `confirm`. But today the confirm callback is unwired, so the
   observable behaviour is a **silent denial**, not a prompt. The violation is
   **latent** and fires the moment A5 wires the callback. Reframed as a trap A5
   must avoid. Part 2 bullet 6.
3. **`agent.speak` was wrongly included in the LAN-exposure finding.** A1 is
   scoped to "every tool the loaded **families** expose"; the `agent.*` tools are
   internal pipe tools, not family tools, so a strict reading does not put them on
   the endpoint. Removed from Part 2b, Part 3 and the SUMMARY. The core
   finding — `screen.*`, `clipboard.*`, `desktop.*`, `browser.*` are loaded
   families and are explicitly v2/v3 in §10 — is untouched.
4. **Residue 2 of Part 2 bullet 4 repeated the same error the headline finding
   had already been corrected for (revision 3).** I wrote that an answer at ~19 s
   on an always-prompt, non-job-capable tool leaves "no legal envelope to return".
   The arithmetic is simply wrong: ~19 s of a 25 s budget leaves ~6 s, and
   `serial_open`, `serial_write` and a typical `files_write` finish in
   milliseconds, so the call returns an ordinary success envelope at ~19.1 s. A
   success envelope is a legal envelope, and §5.4 already routes work that "may
   outlive 20 s" to a job. Restated as what it honestly is: a one-sentence
   documentation gap covering the corner where prompt_duration plus the actual
   work exceeds 25 s. Downstream text updated in A5's ambiguity list, Part 2
   bullet 4's closing paragraph, Part 3 problem 1 and the SUMMARY.

**Recorded plainly, because it is more useful to the PersonaCore side than a
clean-looking report: the verifier caught the same reasoning error twice** — once
in the headline 25 s finding (correction 1) and again, surviving, in that
finding's own residue (correction 4). Both came from treating §7's 20 s as a
duration that gets consumed rather than as a ceiling that is usually not reached.
Any further reading of this report should check its timing claims against that
assumption specifically.

Three findings the verifier independently **confirmed**, and which are unchanged:
the tool-name regex analysis (31/31 fail verbatim, 31/31 pass after §2's
`family.verb`→`family_verb` translation, which the brief never mentions);
`pywin32` provides no SetupAPI wrapper; and `max_active_processes = 4`
(`supervisor.py:101`) feeding `ActiveProcessLimit` (`supervisor.py:162`) against
§5.4's requirement of 8 concurrent jobs.

---

## 0. Two facts established here that most findings below depend on

**(0a) The named pipe does not gate what the brief thinks it gates.**
A1 says "The endpoint serves every tool the loaded families expose, gated exactly
like the named pipe does today." The named pipe serves **six** tools and none of
them is a family tool: `_TOOLS` at `mcp_server.py:121-179` is `agent.speak`,
`agent.toast`, `agent.status`, `agent.last_transcript`, `agent.pause_listening`,
`agent.execute_local`. Family tools are reachable only *through*
`agent.execute_local`, which forwards to `MCPHost.invoke` at `mcp_server.py:363`.
The other five are dispatched in `_invoke_tool` (`mcp_server.py:322-367`) with no
call to `permissions.evaluate`, no confirm, and no `audit_log` — grep-verified:
`mcp_server.py` never imports `permissions` or `audit`. So "gated exactly like the
named pipe" describes a gate that today covers **one of six** exposed tools.

**(0b) The one gated pipe tool is broken in production, and its tests hide it.**
- `mcp_server.py:334` calls `await self._toast.present(...)`. `ToastPresenter`
  has no `present` — only `show` (`ui/notifications/toast.py:92`) and the
  module function `show_update_toast` (`toast.py:207`). `app.py:785` passes the
  real `ToastPresenter` in as `toast=`. `agent.toast` therefore raises
  `AttributeError` in production.
- `mcp_server.py:315` does `json.dumps(result)` with no `default=`. For
  `agent.execute_local`, `result` is `{"result": <ToolResultImpl>}` — a plain
  dataclass (`host.py:58-64`) — so `json.dumps` raises `TypeError`, caught at
  `mcp_server.py:317` and returned as `isError: True`. Every *successful*
  `agent.execute_local` call fails.
- Both are green in tests because the tests mock the collaborators:
  `tests/unit/mcp_host/test_agent_mcp_server.py:529-530` sets
  `_toast.present = AsyncMock(...)` on a `MagicMock` (which invents the method),
  and `:568` sets `mock_host.invoke = AsyncMock(return_value={...})` — a dict,
  not a `ToolResultImpl`.

This matters because A1's stated design is "do what the pipe does, over HTTPS."
Copying the pipe path copies both defects and copies the missing gate.

---

## Part 1 — Per work item

### A1. Network MCP endpoint — brief says "(hard)"

**Exists**
- Inline JSON-RPC 2.0, both directions: client `mcp_host/mcp_client.py`
  (R1 claim 8), server `mcp_host/mcp_server.py` — full `initialize` /
  `tools/list` / `tools/call` / `ping` / `shutdown` dispatch at
  `mcp_server.py:251-289`.
- A 32-byte token generator with DPAPI/DACL hardening already written:
  `mcp_server.py:66-84` (`secrets.token_hex(32)`, `harden_file`) — R1 claim 1.
  Reusable verbatim for the bearer token.
- Token compare is `!=` on `str` (`mcp_server.py:294`), not
  `hmac.compare_digest`.
- A FastAPI + uvicorn stack is already a runtime dependency and already
  programmatically configured (`app.py:627-640`), so a second uvicorn instance
  with `ssl_certfile` / `ssl_keyfile` is available without a new dependency.
- `cryptography>=41.0,<42.0` is already declared (`pyproject.toml:27`) and is
  referenced **nowhere** in `src/`, `tests/`, `installer/` or
  `workstation_agent.spec` (grep, zero hits). Self-signed X.509 generation needs
  no new dependency and no licence record. It will need a `hiddenimports` entry
  in `workstation_agent.spec:38-54`, which currently lists none of it.
- A TCP variant of the same server already exists for tests:
  `mcp_server.py:488-518` (`run_tcp_server`, default `host="127.0.0.1"`).

**Missing**
- No TLS anywhere. Grep for `x509`, `ssl.`, `SSLContext`, `certfile`, `keyfile`,
  `self-signed` across `src/` returns zero hits.
- No streamable-HTTP framing (SSE / `Mcp-Session-Id`); the inline transport is
  newline-delimited JSON over a byte stream (`mcp_server.py:98-114`).
- No `export-registration` path of any kind. `__main__.py:103-115` builds a
  flag-only `argparse` parser (`--autostart`, `--diag`, `--fake-backends`,
  `--check-updates`, `--rollback`); a positional subcommand would be rejected
  today. There is no TOML *writer* for a manifest either (`tomlkit` is a
  dependency but is used only by `config/store.py`).
- No network config at all: `config/schema.py:108-120` has ten sections and none
  is a server/endpoint section. No bind interface, no port, no cert path, no
  fingerprint, no token reference.
- No UI surface for "shown once with copy buttons". The eight templates are
  `about/audit/config/dashboard/first_run/layout/logs/plugins.html`; the wizard
  (`routers/first_run.py`) is a three-field LLM/audio setup. There is nowhere for
  this today — it is a new page or a new wizard step, plus clipboard JS (the
  static tree is a single `skeleton.css`, no JS file at all).

**Undefined / ambiguous**
1. **Which interface list, and what happens when the IP changes.** The brief says
   "bind to an operator-chosen interface" but names no enumeration source, and the
   cert's SAN is fixed at generation ("SAN = its hostname and LAN IP", contract
   §3). A DHCP lease change silently invalidates the SAN. Contract §3 also says
   the client "verifies **this** instead of the system trust store" — it does not
   say whether hostname/SAN verification is also skipped, so it is undecidable
   from this side whether an IP change breaks the connection or is harmless. This
   must be answered before the cert is generated, not after.
2. **Cert lifetime across restarts.** The brief says "generated on first run".
   Contract §11 item 8 requires "starting the Agent brings it back without a core
   restart" — which is only true if the cert (and thus the pinned fingerprint) is
   *persisted and reused*, never regenerated. The brief never says so, and there
   is no cert store location defined.
3. **`Agent.exe export-registration` cannot report anything.** `Agent.exe` is
   built with `console=False` (`workstation_agent.spec:93`), i.e. a windowed
   binary; `__main__.py:43-67` exists precisely because `sys.stdout`/`stderr` are
   `None` in that build. A CLI subcommand run from a terminal will detach and
   print neither the output path nor an error. The brief specifies a console verb
   on a GUI executable and does not say where the zip is written.
4. **Where the tool-name mapping happens.** The brief forbids dots but never
   states the translation. Only contract §2 does: "The Agent's internal
   `family.verb` names are exposed as `family_verb`." An implementer reading only
   the brief would not know a translation layer is required. See Part 2 bullet 1.
5. **What the endpoint serves.** "every tool the loaded families expose" is a
   moving target — see the contract conflict below.
6. **`401` scope.** The brief says `401` on bad/missing token. It does not say
   whether an unauthenticated `initialize` is also `401` (the pipe returns a
   JSON-RPC `-32000`, `mcp_server.py:295`), i.e. whether auth is HTTP-layer or
   protocol-layer. These produce different health rows on the core side.

**Contract conflicts**
- **A1 vs contract §2, the big one.** A1: "The endpoint serves every tool the
  loaded families expose." Contract §2: "The tool list in the manifest and the
  tool list the Agent serves are reconciled at load and **a mismatch is a
  terminal load failure**". The set of loaded families is *dynamic* in this tree
  in three independent ways: `loader.discover()` (`loader.py:200-218`) merges
  bundled plugins, entry-point plugins **and a user folder**
  (`%APPDATA%\WorkstationAgent\plugins`, `config/store.py:47`); `host.start`
  skips any plugin disabled in config (`host.py:132-136`); and a plugin that
  fails signature verification is quarantined and serves nothing
  (`host.py:149-157`, R1 claim 5). Any of the three silently changes the served
  tool set without an Agent release, and contract §2 assumes the opposite ("the
  registration is regenerated on every Agent release that changes a tool").
  Following A1 literally guarantees the failure mode the brief's own bullet 2
  forbids.
- **A1 vs contract §6 and the "Not yours" section.** Eight plugins are discovered
  today (`plugins/`: browser, claude_code_bridge, clipboard, desktop_control,
  filesystem, hello_world, powershell, screen_vision). Contract §6's family table
  names seven families, none of which is browser, clipboard, desktop or screen.
  "Every tool the loaded families expose" therefore puts `screen.capture`,
  `screen.capture_ocr`, `clipboard.get`, `desktop.click`, `browser.eval` etc. on
  the LAN endpoint and into the registration — directly against the brief's own
  "Not yours: … screenshots the model can see". See Part 2b.

**Difficulty: hard.** Agree with the brief's label, and it is harder than stated:
TLS + streamable-HTTP framing + a cert/token lifecycle + a new config section +
a new UI surface + a manifest writer + a CLI subcommand on a windowed exe + a
tool-name translation layer, none of which exists in any form.

---

### A2. `shell`, `files`, `jobs` — brief says "(default)"

**Exists**
- `powershell` and `filesystem` plugins with declared tools, manifests,
  signatures, and a stdio JSON-RPC loop each — all returning `not_implemented`
  (R1 claim 2: `plugins/powershell/__main__.py:86`,
  `plugins/filesystem/__main__.py:112`). The scaffolding to replace is real.
- `filesystem/plugin.toml:11-12` already declares two roots
  (`path:%USERPROFILE%\Documents`, `path:%USERPROFILE%\Downloads`) and
  `permissions.py:37-57` (`_outside_declared_paths`) already enforces a
  prefix check against them.
- Windows Job Objects with kill-on-close already exist for process-tree
  termination (`supervisor.py:149-181`; `_close_job` docstring: "Closing kills
  the tree (KILL_ON_JOB_CLOSE)") — reusable for `jobs_kill`.

**Missing**
- Every actual implementation. No job registry, no `job_id`, no `wait_s`, no
  output paging, no 60,000-char cap, no `ok`/`code` result envelope anywhere
  (grep for `"unknown_job"`, `"unconfirmed"`, `jobs_output`: zero hits in `src/`).
- Roots are per-plugin manifest constants, not an operator setting. Contract §6
  says `files_*`, `adb_push` and `adb_install` are "all of them … confined to the
  declared roots" — a *shared* root set across families. Today each plugin
  declares its own and there is no config field for roots
  (`config/schema.py` has none).

**Undefined / ambiguous**
1. **Root semantics.** `_outside_declared_paths` (`permissions.py:53-54`) is a
   raw `startswith` on a slash-normalised string with no `%USERPROFILE%`
   expansion, no `..` normalisation, no case folding, no symlink/8.3 resolution.
   `C:/Users/me/Documents/../../Windows/win.ini` passes it. The brief says
   "declared roots for files" and defines none of this.
2. **Where roots are configured** and whether they are per-plugin or global.
3. **Whether the confirmation window counts against `wait_s`** — see the 25 s
   analysis in Part 2 bullet 4. This needs a documented clamping rule in the job
   design; it is not a blocker.
4. **Desktop Commander**: see below.

**Contract conflicts**
- **§5.4 "at most 8 concurrent jobs" vs the sandbox.** `MCPHost._spawn` hard-codes
  `limits = ResourceLimits()` (`host.py:184`), whose `max_active_processes` is
  `4` (`supervisor.py:101`), applied as the Job Object's `ActiveProcessLimit`
  (`supervisor.py:162`). The plugin process itself counts, so a `shell` family
  implemented as a plugin can hold **three** child processes, not eight. The
  whole tree also shares `max_job_memory_mb = 768` (`supervisor.py:100`,
  `:170`). §5.4's cap is unreachable without changing the supervisor, and no work
  item mentions the supervisor.
- **§5.3's 25 s vs the stdio client's 10 s default.** `MCPStdioClient` takes
  `default_timeout: float = _DEFAULT_TIMEOUT` where `_DEFAULT_TIMEOUT = 10.0`
  (`mcp_client.py:49`, constructor at `:69`); `host.py:192` constructs
  `MCPStdioClient()` with no argument, and `MCPHost.invoke` calls
  `tools_call(tool_id, args)` with no per-call override (`host.py:337`), though
  `tools_call` accepts one (`mcp_client.py:245`). This is a **constructor
  default, not a hard cap** — it is overridable in one line. But as wired today
  it sits below §5.4's default `wait_s` of 20, so A2 must raise or override it
  deliberately rather than discover it.
- **Low integrity.** `PluginSupervisor.spawn` launches every plugin under a
  low-integrity token by default, falling back to medium only if that fails
  (`supervisor.py:239-276`), with a whitelisted environment of 16 variables
  (`supervisor.py:63-80`; `build_child_env` at `:128-141`). Contract §5.8 fixes
  families as Agent plugins, so `files_write` into `%USERPROFILE%\Documents` —
  the plugin's own declared root, a medium-integrity object — is a write a
  low-IL process cannot perform. The same applies to anything `shell_run` spawns.
  The brief says "Real implementations replacing the stubs" as if the stubs' host
  environment were neutral; it is not, and no work item addresses it. Worse, the
  fallback at `supervisor.py:251-262` makes the integrity level machine-dependent,
  so this will behave differently on the dev box and the target.

**The Desktop Commander fork in the road: a distraction, and I would cut it.**
Reasons, all from this tree and the contract:
- Contract §5.8 permits it ("the Agent may host them behind its gate instead of
  reimplementing") but binds the gate to the Agent "per tool, never the hosted
  server's". This repo's gate keys on `tool:<name>` in a *signed* `plugin.toml`
  (`permissions.py:134-144`; `loader.py:221-232` — `declared_permissions` is
  inside the signed manifest dict). Hosting a third-party server means either
  hand-maintaining a signed manifest that mirrors its tool list (and re-signing
  on every upstream release), or setting `allow_unsigned` (`schema.py:104`,
  R1 claim 5) — which discards the Ed25519 guarantee the brief itself lists as an
  existing strength.
- Every one of its tools would have to be renamed to `family_verb` to pass the
  §2 regex, and its result shapes rewritten to §6.1's exact keys ("missing listed
  keys are a defect"). At that point almost nothing of the upstream surface
  survives.
- It is a Node/npm process, which the supervisor cannot spawn as designed
  (`_resolve_entry`, `host.py:469-477`, assumes `sys.executable -m <module>` for
  anything non-absolute) and which would inherit the low-IL + 4-process Job
  Object anyway.
The evaluation is not free — it is a day of work that ends in "no" for reasons
already determinable from the contract. Recommend the brief drop it or convert it
to a one-line "decided: no, reason recorded".

**Difficulty: hard**, not "default". The implementations themselves are ordinary;
the job model, the roots model, the 25 s/10 s reconciliation and the low-IL
sandbox are not.

---

### A3. `devices` and `adb` — brief says "(default)"

**Exists**
- Nothing. R1 claim 7: zero ADB, serial or USB references in `src/`, `tests/`,
  `docs/` or `pyproject.toml`.
- Indirectly: `pywin32` is a dependency (`pyproject.toml:26`) and `win32com`
  imports fine in the venv, so WMI via `win32com.client` is available.

**Missing** — the whole family, plus an `adb` path setting (no config field
exists), plus job capability for `adb_shell` (depends on A2's job model).

**Undefined / ambiguous**
1. **"SetupAPI/WMI via `pywin32`" names an API `pywin32` does not provide.**
   Verified in this repo's venv: `import win32setupapi` and `import setupapi`
   both raise `ModuleNotFoundError`, and there is no `setup*` module in the
   `win32` package directory. `pywin32` wraps no SetupAPI. The implementer must
   either `ctypes` into `setupapi.dll` or use WMI (`Win32_PnPEntity`) only. The
   brief names a package that does not do half of what it is named for.
2. **`present_since` is not obtainable from a WMI snapshot.** Contract §6.1
   requires `"present_since": "ISO-8601"` per USB device. `Win32_PnPEntity` has
   no arrival timestamp; the value lives in `DEVPKEY_Device_LastArrivalDate`,
   reachable only through `SetupDiGetDevicePropertyW` (i.e. ctypes, per point 1)
   — or by the Agent keeping its own watcher, which is the hotplug capability the
   brief puts out of scope. See Part 2b.
3. **`adb_pull` is text-only** per contract §6 ("→ text ≤ cap") and §5.3
   ("Binary never travels in v1"), and §10 explicitly names "`adb_pull` of an
   APK" as out of v1. A3 says only "`adb_*` as subprocesses" and does not
   mention the restriction, so the obvious implementation is wrong.
4. `serial` optional "when exactly one device is attached" (§6) — the brief does
   not repeat it and does not say what error code applies when two are attached
   (`error`? `not_found`?).

**Contract conflicts**
- `adb install` / `adb push` write to `%TEMP%` and spawn an ADB server; under the
  low-IL Job Object of `supervisor.py:239-276` with `ActiveProcessLimit = 4`
  (`supervisor.py:101`) neither is safe to assume. Same root cause as A2.

**Difficulty: hard** for `devices_list` (ctypes SetupAPI + `present_since`),
**default** for the `adb_*` subprocess wrappers. Net: hard. The brief's
"(default)" is the single most optimistic label in it.

---

### A4. `serial` — brief says "(default)"

**Exists** — nothing (R1 claim 7).

**Missing** — `pyserial` is not in `pyproject.toml:14-40`; the session model
(§5.5: `session_id`, 10-minute idle close, ≤ 4 per family) has no analogue in the
tree; `unknown_session` does not exist.

**Undefined / ambiguous**
1. **"licence it in the repo's own record" — there is no such record.** No
   `NOTICE`, `THIRD-PARTY` or dependency-licence file exists at the repo root
   (only `LICENSE`, the project's own MIT). `docs/` contains exactly one
   document, `docs/superpowers/specs/2026-09-04-workstation-agent-design.md`. The
   only precedent for recording a dependency decision is the free-text comment at
   `pyproject.toml:41-45`. The brief instructs the implementer to write to a
   record that does not exist and does not say to create one.
2. Sessions are per-*family* (§5.5 "At most **4** open sessions per family") but
   the Agent's lifetime unit is the plugin process. Nothing says whether the
   session registry lives in the plugin or in `MCPHost` — which decides whether
   `sessions_open` in `workstation_status` (§6.1) is even knowable by the host.

**Contract conflicts**
- Same low-integrity issue: opening `\\.\COMn` from a low-IL process is a write
  to a default-medium device object. This needs testing before A4 is scheduled;
  if it fails, A4 is blocked on a supervisor change, not on `pyserial`.

**Difficulty: default**, conditional on the low-IL question being answered. The
`pyserial` work itself is the most ordinary thing in the brief.

---

### A5. Gate wiring — brief says "(default)"

**Exists**
- `permissions.evaluate` returning `allow`/`deny`/`confirm` with a genuine
  default-deny fallthrough (`permissions.py:161-214`; R1 claim 3).
- A confirm branch in `MCPHost.invoke` (`host.py:320-331`) and a
  `_do_confirm` with a TTS announcement hook (`host.py:375-395`).
- An append-only, trigger-enforced `audit.db` (`audit.py:59-71`; R1 claim 6) and
  `audit_log` calls already on the deny / confirm-rejected / error / success
  paths (`host.py:310, 323, 339, 354`).
- A `ToastPresenter` that already renders action buttons with callbacks
  (`toast.py:92-205`).
- A config field that reads as if it were already wired:
  `NotificationsConfig.voice_announce_confirmations_enabled = True`
  (`schema.py:84`) — grep-verified as **read nowhere** in `src/`.

**Missing** — and this is the headline
- **The confirm path is dead in production.** Per R1 claim 4, confirmed
  independently here: `app.py:441` is `await host.start(cfg)` with neither
  `confirm_cb` nor `tts_speak`, so `host.py:393-395` falls through to
  `return False`. Every confirmable-condition call is denied, silently, with no
  toast, no voice, and no prompt. Toast is not on the confirm path at all —
  `mcp_host/host.py` contains no reference to toast (grep, zero hits).
- No pre-approved list, no "remember for this session", no per-tool
  read/action distinction (grep for `pre_approved`, `preapproved`,
  `remember_for_session`: zero hits).
- No §5.2 result envelope. `MCPHost.invoke` signals denial by **raising**
  (`PermissionError`, `host.py:318` and `:331`; `KeyError`, `host.py:300`). There
  is no `ok`/`reason`/`code` anywhere and no mapping to `denied` / `unconfirmed`
  / `unknown_job` / `unknown_session` / `not_found` / `timeout` / `error`.
- No §5.6 special-token stripping. Grep for `im_start`, `eot_id`, `[INST]`,
  `defang`, `untrusted` across `src/`: zero hits.
- **The audit schema cannot hold what §5.7 requires.** `audit_log` columns are
  `ts, event, plugin_id, tool_id, args_json, result, decision, detail`
  (`audit.py:45-57`). §5.7 requires "the tool, the arguments (with `data` fields
  … truncated to 200 characters), the outcome code, the duration, and the MCP
  request id" — no duration column, no request-id column, and `log()`
  (`audit.py:157-186`) writes `args_json` **untruncated**. Because the table is
  created with `CREATE TABLE IF NOT EXISTS`, existing installs need an explicit
  `ALTER TABLE` migration; the append-only triggers do not block that, but
  nothing in the module does migrations today.
- Granted permissions are snapshotted at `host.start` (`host.py:141`) and
  `reload()` never refreshes them (`host.py:423-466`), so the UI grant route
  (`ui/backend/routers/plugins_routes.py:78-93`) does not take effect until the
  Agent restarts. Since `PluginsConfig.per_plugin` defaults to `{}`
  (`schema.py:105`), a fresh install denies **every** tool until the operator
  grants and restarts.

**Undefined / ambiguous**
1. Whether the pre-approved list is keyed by tool or by condition — the contract
   keys it by tool (§7), the tree keys it by condition (`permissions.py:183-199`).
   These are not interchangeable; see Part 2 bullet 6.
2. Whether the 20 s prompt window counts against §5.3's 25 s budget — see Part 2
   bullet 4. A5 needs a documented clamping rule (bound the post-confirm wait to
   25 s − prompt_duration, return the job envelope early). A minor documentation
   gap sits alongside it: the contract does not define the corner where
   prompt_duration plus the actual work exceeds 25 s on an always-prompt tool
   that is not job-capable (`serial_open`, `serial_write`, `files_write`) — those
   operations are sub-second in practice, so this is wording, not behaviour.
3. What "remember for this session" is scoped to: the Agent process, the MCP
   connection, or the PersonaCore chat turn. The Agent cannot see the third.
4. Who owns the toast when the endpoint is remote — the prompt is on the
   workstation but the requester is over HTTPS. Nothing says what happens to a
   second concurrent prompt (the toast API is a single fire-and-callback,
   `toast.py:92-130`, with no queue and no timeout).

**Contract conflicts** — see Part 2 bullets 3, 4 and 6, which are all A5's.

**Difficulty: hard**, not "default". The brief's label appears to assume the
confirm/toast/voice path is wired and needs extending. It is not wired at all
(R1 claim 4), and A5 additionally owns: the §5.2 envelope (a change to every
call site of `MCPHost.invoke`), §5.6 stripping, an `audit.db` schema migration,
the pre-approved list and its UI, session-scoped remembering, and the clamping
rule for §7's prompt window inside §5.3's 25 s budget.

---

### A6. Hands-on — brief gives no label

**Exists** — the Agent runs end to end today (`app.py` composition root, boot
check at `app.py:824-830`); the `--diag` readiness table (`__main__.py:118`)
is a usable smoke-test harness.

**Missing** — everything A1–A5 produce, plus a way to observe the PersonaCore
side.

**Are §11 items 1–7 testable from this side? Mostly no, and the split is uneven.**

| item | testable from `GameTest` alone? |
|---|---|
| 1 `devices_list` | Agent-side logic yes; the phrasing "From PersonaCore chat" no |
| 2 `adb_shell` + prompt + Allow | needs a real phone **and** a live core connection |
| 3 serial round-trip | needs real serial hardware |
| 4 40 s job | Agent-side yes, via a local MCP client |
| 5 stale `job_id` after restart | Agent-side yes |
| 6 `files_read` outside roots → `denied` | Agent-side yes |
| 7 20 s unanswered prompt → `unconfirmed` | Agent-side yes |

So 4, 5, 6, 7 are honest Agent-side integration tests. 1, 2, 3 need PersonaCore
running **and** physical hardware (an ADB phone, a serial device) that no work
item asks anyone to procure. More seriously: items 1–7 all traverse the HTTP
plugin connection, which requires the **core-side** contract 2.1→2.2 change of
§3 (`auth_secret`, `tls_fingerprint`) to have landed. A6's done-condition is
therefore not achievable by this repository alone, and the brief presents it as
this repository's work item without naming the external dependency.

**Contract conflict — A6's scoping of §11. My verdict: a gap, not a clean
hand-over boundary.**
Contract §11 has ten items. A6 names 1–7. Taking the other three in turn:
- **Item 8** ("With the Agent stopped, the Plugins page shows the plugin
  unhealthy … and starting the Agent brings it back without a core restart") is
  *observed* on the Plugins page, so excluding it from the done-condition is
  defensible — but its Agent-side precondition is not trivial: it requires the
  certificate and token to **persist across restarts and be reused**, or the
  pinned fingerprint changes and reconnection fails. A1 says "generated on first
  run" and says nothing about persistence. Excluding item 8 hides that
  requirement rather than handing it over.
- **Item 9** ("Every one of the above is a row in the Agent's audit database and
  in the core's trace") is **half squarely ours** — the audit half is the
  Agent's alone, is named in A5's own scope ("and `audit.db`"), and as shown
  above the current schema cannot satisfy §5.7. There is no reason of
  observability to exclude it: the Agent's own `audit.db` is the most easily
  checked artefact in the whole list. Excluding it means the one §11 item that
  A5 is explicitly building toward is not in anyone's done-condition.
- **Item 10** ("A registration with a wrong token or a wrong fingerprint never
  connects, and the Plugins page says which of the two it was") is half ours too
  — the "wrong token never connects" half is exactly A1's `401` requirement.
  Only the "Plugins page says which" half is PersonaCore's.

So the 1–7 cut does not follow the repository boundary. It follows *where the
result is displayed*. Items 8 and 10 are legitimately observed elsewhere, but
each has an unstated Agent-side precondition; item 9 has no such excuse. **A6
should be items 1–7 plus 9, with the Agent-side halves of 8 and 10 stated as
requirements on A1.**

**Difficulty: default as an exercise, but externally blocked.** It cannot start
until the PersonaCore core change of §3 exists, and items 1–3 additionally need
hardware nobody has been asked to supply.

---

## Part 2 — "Things that would be wrong" (seven bullets)

### 1. "A tool name with a dot. PersonaCore's regex is `^[a-z][a-z0-9-]{1,63}$` after `_`→`-`."

**Current code violates it — every single name.** Enumerated from
`tools/list` in each plugin's `__main__.py` plus `_TOOLS` in `mcp_server.py`,
and tested against the regex with `.venv\Scripts\python.exe`:

31 names, **31 FAIL** when taken verbatim, all for the same reason — the dot.
The full list, grouped:
- `agent.speak`, `agent.toast`, `agent.status`, `agent.last_transcript`,
  `agent.pause_listening`, `agent.execute_local`
  (`mcp_server.py:123,132,145,150,158,167`)
- `browser.open/.screenshot/.click/.type/.eval`
  (`plugins/browser/__main__.py:30,39,44,53,65`)
- `claude_code.invoke/.presence/.list_recent_sessions`
  (`plugins/claude_code_bridge/__main__.py:43,64,69`)
- `clipboard.get/.set/.clear` (`plugins/clipboard/__main__.py:30,35,44`)
- `desktop.click/.type/.key/.list_windows/.focus_window`
  (`plugins/desktop_control/__main__.py:30,42,51,62,67`)
- `filesystem.list/.read/.write/.delete`
  (`plugins/filesystem/__main__.py:30,39,48,60`)
- `hello_world.echo` (`plugins/hello_world/__main__.py:30`)
- `powershell.run` (`plugins/powershell/__main__.py:30`)
- `screen.capture/.capture_ocr/.list_monitors`
  (`plugins/screen_vision/__main__.py:30,42,54`)

Applying the §2 rule the brief omits (`family.verb` → `family_verb`, then
`_`→`-`), **all 31 PASS**: shortest is `desktop-key` (11 chars), longest is
`claude-code-list-recent-sessions` (32). **No name is too short** — the 2-char
minimum is not at risk anywhere, now or under contract §6's proposed names (all
21 of which I also tested: all PASS).

Finding: the violation is total but mechanical, and the fix is a translation
layer the brief never asks for. **The brief states the prohibition without
stating the remedy**, and an implementer who takes A1's "serves every tool the
loaded families expose" literally ships 31 rejected names.

### 2. "A tool the endpoint serves that the exported registration does not list, or the reverse."

**At risk, structurally, and nothing today guarantees anything.**
- **No export path exists at all.** `__main__.py:103-115` has no subcommand;
  grep for `export-registration` / `export_registration` / `manifest.toml`
  across `src/` returns zero hits. Answer to the SPEC's question: there is no
  registration path today, and therefore nothing guarantees a match.
- Three runtime mechanisms can change the served set without a release, all
  cited under A1's contract conflicts: user-folder discovery
  (`loader.py:200-218`), per-plugin `enabled` (`host.py:132-136`), and
  quarantine on a bad signature (`host.py:149-157`). A single operator toggle on
  the Plugins page therefore produces a terminal load failure on the core.
- A fourth, subtler one: `MCPHost._resolve_tool` (`host.py:365-373`) returns the
  **first** running plugin whose `tools` contain a matching name, in dict
  insertion order. Two plugins exposing the same name is resolved silently, and
  the duplicate is not deduped by the inventory in `tools()`
  (`host.py:278-293`) — so the registration would list a name twice and the
  endpoint would serve one of them.
Recommendation for the build plan: `export-registration` must derive from the
*same* function the endpoint's `tools/list` uses, and the endpoint must serve a
fixed §6 allowlist rather than "whatever loaded".

### 3. "Anything rated other than `safe` in the registration: PersonaCore refuses `confirm` tools today."

**Clear today** (nothing rates anything — there is no registration), and I find
**no contradiction in the risk label itself**. What residual risk there is here is
about timing rather than rating — see bullet 4. In short: `risk` is a *core-side
manifest field* saying who gates; contract §4 states plainly that the Agent is the gate
and that "This is weaker than the spec's risk model and it is written down as
such". An unconfirmed call comes back as a normal §5.2 result
(`{"ok": false, "code": "unconfirmed"}`), which the core reads as an ordinary
tool result. `risk = "safe"` and an Agent-side confirmation prompt are compatible
by construction.

### 4. "A call that can take longer than 25 s without being a job."

**At risk in two specific places — but not the blanket contradiction I claimed in
revision 1.** This is the safe-vs-confirm tension, derived from the sections named.

The texts, verbatim:
- §5.3: "A tool call must answer within **25 s** of wall clock. The core's read
  timeout is 30 s … anything that may take longer is a job (§5.4)."
- §5.4: "Any tool that may outlive 20 s takes `wait_s` (default 20, max 25)."
- §7: "Prompt: the Agent's existing toast plus spoken line … **20 s**, then
  `unconfirmed`." and "**Always prompt:** `shell_run`, `adb_shell`, `adb_push`,
  `adb_install`, `files_write`, `serial_open`, `serial_write`."
- §11 item 2: "Run `adb shell getprop ro.product.model` on the phone" prompts on
  the workstation, and after Allow returns the model name."
- §11 item 7: "A prompt left unanswered for 20 s comes back as 'nobody confirmed
  this on the workstation'."

**The key reading.** §7's 20 s is a **timeout, not a fixed cost**. The prompt
window closes as soon as the owner answers, which is normally a few seconds; the
20 s is only the ceiling before the call gives up and returns `unconfirmed`. My
revision-1 arithmetic ("prompt inside `wait_s` leaves 0 s of work time, so §11
item 2 can never return the model name") assumed the window is always fully
consumed. That assumption is wrong, and the finding that rested on it is
withdrawn. Worked through, §11's own cases all fit inside 25 s:
- **§11 item 2** (`adb_shell getprop`, prompt then return the model name): owner
  answers in ~3 s, `adb shell getprop` takes < 1 s against a warm server, so the
  call returns directly, well inside 25 s. **Works.**
- **§11 item 7** (prompt left unanswered): the window expires at 20 s and the call
  returns `{"ok": false, "code": "unconfirmed"}` at ~20 s, inside the 25 s cap.
  **Works.**
- **§11 item 4** (40 s `shell_run`): prompt, then the work exceeds the remaining
  budget, so the call returns the §5.4 `{"state": "running"}` job envelope and the
  caller polls. **Works.**

**What actually survives — the implementer needs a clamping rule.** The contract
does not state whether the confirmation window counts against §5.3's 25 s budget,
and neither §5.3, §5.4 nor §7 says when `wait_s`'s clock starts. The rule that
makes every case above come out right, and which should be written down rather
than guessed at per family, is: *the post-confirm wait is bounded by
25 s − prompt_duration; if that leaves too little time, return the job envelope
early rather than overrunning.* That is an implementation detail with a documented
answer, not an owner decision — but it must be documented, because two families
guessing differently produce different overrun behaviour.

**Two residues.**
1. **The inner client's 10 s default.** `MCPStdioClient`'s `default_timeout` is
   `_DEFAULT_TIMEOUT = 10.0` (`mcp_client.py:49`, constructor `:69`) and
   `host.py:192` constructs it bare, so as wired the host's own inner client
   expires below the 20 s prompt window. It is a constructor default and
   `tools_call` takes a per-call override (`mcp_client.py:245`), so this is one
   line to fix — but it must be fixed deliberately, not discovered.
2. **A one-sentence documentation gap, not a risk.** §7's always-prompt list
   includes `serial_open`, `serial_write` and `files_write`, none of which §6
   gives a `wait_s` or a job envelope. In the ordinary case there is nothing to
   resolve: these operations complete in milliseconds, so even a slow answer at
   ~19 s is followed by a normal success envelope at ~19.1 s, comfortably inside
   the 25 s cap — a success envelope being a perfectly legal envelope — and §5.4
   already routes anything that "may outlive 20 s" to a job. What the contract
   does not define is the residual corner where `prompt_duration` plus the actual
   work exceeds 25 s on a tool that is always-prompt and not job-capable (a very
   large `files_write` after a slow answer). That is one sentence the contract
   should add for completeness; it is not an overrun to expect and not an owner
   decision.

**Operations that can exceed 25 s today or as planned**, named as the SPEC asks:
`shell_run` (arbitrary command — §11 item 4's own example is 40 s),
`adb_shell`, `adb_install` (APK install is routinely > 25 s),
`adb_push` of a large file, `adb_logcat` (bounded at ≤ 20 s by §6, so a slow
confirmation on top of it can cross the cap), `serial_read` (bounded at ≤ 20 s,
same arithmetic), `files_write` of a very large body (always-prompt and not
job-capable — the undefined corner of residue 2 above), and
`devices_list` — which is *not* job-capable in §6, is pre-approved so never
prompts, but calls SetupAPI/WMI enumeration plus `adb devices -l`; `adb devices`
on a cold ADB server starts the daemon and can take tens of seconds.
**`devices_list` is the one that the brief's job model does not cover at all**:
§5.4's model is opt-in per tool via `wait_s`, and §6 gives `devices_list()` no
arguments. §11 item 1 is the first thing the owner will try.

Does §5.4's model (in-memory, ≤ 8, dies with the Agent) cover the rest? For
`shell_run` / `adb_shell` yes, once the clamping rule is written down. Not for
`devices_list`. The three always-prompt non-job tools of residue 2 are covered in
practice — their work is sub-second, so they return normally inside the cap —
leaving only the undefined wording corner noted there. And the ≤ 8 figure is
unreachable under the current Job Object anyway (see A2).

### 5. "Returning binary, a stack trace, an absolute path outside the roots, or the token."

**Mostly clear today; two live risks.**
- **Stack traces: clear but fragile.** `mcp_server.py:317-318` catches `Exception`
  and returns `str(exc)`, not a traceback. But the messages themselves are
  internal: `host.py:299` `f"no running plugin owns tool {tool_id!r}"`,
  `host.py:317` `f"tool {tool_id!r} denied by permissions model"`,
  `host.py:334` `f"plugin {runtime.manifest.id!r} has no client"`. These are
  developer strings, not §5.2's "one plain-English sentence for the model and the
  person". Converting `invoke` from raising to returning the §5.2 envelope
  (A5's job) fixes this; leaving it as-is ships internal identifiers.
- **Absolute paths: at risk.** `Health(detail=...)` values are absolute paths —
  e.g. `app.py:433` sets the session-store health detail to `str(db_path)`.
  These reach `agent.status` only if a `state_getter` is supplied; the production
  wiring at `app.py:781-787` passes only `tts`, `toast` and `mcp_host`, so
  `agent.status` returns `{"state": "unknown"}` (`mcp_server.py:343`) and nothing
  leaks **today**. A1 wiring `workstation_status` to the same `started` dict is
  the obvious implementation and would leak immediately. Flag it in A1's spec.
- **The token: clear today, at risk under A5.** `audit.log` serialises the full
  argument dict with no truncation and no redaction (`audit.py:162-167`), against
  §5.7's "`data` fields of serial and file writes truncated to 200 characters".
  `audit.db` is not a tool result, so this is not a bullet-5 violation as such —
  but any A5 work that surfaces audit rows through a tool (or the audit UI at
  `routers/audit_routes.py`) would carry whatever an argument contained.
- **Binary: clear.** Every tool currently returns `not_implemented` (R1 claim 2).
  Note `screen.capture` and `browser.screenshot` are the natural producers, and
  they are out of scope — see Part 2b.

### 6. "Prompting for reads. The pre-approved list exists so an absent owner blocks actions only."

**The violation is architectural and latent — it is a trap A5 must avoid, not a
defect visible today.**
This repo's gate does **not** distinguish reads from actions anywhere. Answer to
the SPEC's question: no, and that is the finding. The distinction matters for how
it is written up: today nothing prompts, because the confirm callback is unwired
(R1 claim 4), so the path produces a *silent denial*. The moment A5 wires the
callback — which is A5's whole job — the same path starts prompting on reads.

`permissions.evaluate` (`permissions.py:161-214`) makes the confirm decision from
the plugin's `confirmable_conditions` list, never from the tool name — the
`tool` parameter is passed to each checker and every built-in checker discards it
(`permissions.py:39, 62, 83`, each `tool: str,  # noqa: ARG001`). The filesystem
plugin declares `confirmable_conditions = ["outside_declared_paths"]`
(`plugins/filesystem/plugin.toml:14`), and `_outside_declared_paths`
(`permissions.py:37-57`) fires on **any** string argument containing a slash that
falls outside the roots. So `filesystem.read` of a path outside the roots returns
`"confirm"` (`permissions.py:192-199`) — a prompt, on a read.

Once the callback is wired, that resolution is wrong three times over:
- against the brief's bullet 6, verbatim: "Prompting for reads."
- against contract §7, which puts `files_read` and `files_list` in the
  **"Never prompt (pre-approved)"** list;
- against contract §6 — "under declared roots only; a path outside is `denied`"
  — and §11 item 6, "`files_read` of a path outside the declared roots is
  `denied` in plain English". The contract wants `denied`; the code produces
  `confirm`.

And today, because `_do_confirm` returns `False` unconditionally (`host.py:395`,
R1 claim 4), the observable behaviour is a *silent* denial — which happens to
match §11 item 6's outcome by accident, for entirely the wrong reason, with no
`reason` string. So the prompt-on-read defect is **latent, not present-tense**:
wiring the confirm callback both fixes A5's headline defect and, in the same
stroke, converts §11 item 6 from an accidental pass into a prompt-on-a-read
failure. That is the trap, and it is why the two changes must land together.

Consequence for the build plan: A5 cannot extend the condition model, it has to
add a **tool-keyed** pre-approved list layered above it, and it has to change
`outside_declared_paths` from confirm-triggering to deny-triggering for the
`files`/`adb` families. The brief describes A5 as adding a setting to an existing
mechanism; it is a change of mechanism.

### 7. "Listening on `0.0.0.0` by default, or plain HTTP."

**Clear today for the bind address; at risk for HTTP, via precedent.**
- Grep for `0.0.0.0` across `src/`: **zero hits**. Everything binds loopback:
  the UI at `app.py:629` `host="127.0.0.1"`, the MCP test server's default at
  `mcp_server.py:490` `host: str = "127.0.0.1"`, and a positive middleware guard
  at `ui/backend/app.py:135-143` that 403s any non-`127.0.0.1` client. No config
  field, schema default or test would push an implementer toward `0.0.0.0` —
  because no bind-address config field exists at all (`config/schema.py:108-120`).
- **Plain HTTP is the house style, and the first-run wizard cannot express
  https.** `LlmConfig.base_url` defaults to
  `AnyHttpUrl("http://192.168.1.150:8053/v1")` (`schema.py:13`), and the wizard's
  only URL builder hard-codes the scheme: `first_run.py:46-48`,
  `return f"http://{host}:{port}/v1"`. The webview, systray and boot check all
  build `f"http://127.0.0.1:{port}"` (`webview/window.py:222-224`,
  `systray/tray.py:270-272`, `app.py:829`). An implementer adding the endpoint's
  fields to the existing wizard will reuse `_build_base_url` and get `http://`.
  That is the concrete risk; it is a precedent risk, not a current violation.
- Also missing and unmentioned: nothing opens a Windows Firewall rule, and
  nothing warns that binding a LAN interface needs one. A1 will appear to work on
  the dev box and fail from the container.

---

## Part 2b — "Not yours"

The brief: "Hotplug events, screenshots the model can see, binary into the
workspace, voice on the workstation: all v2+".

### Hotplug events
- **Does A1–A6 require it?** *A3 comes within one field of it.* Contract §6.1
  requires `devices_list` to return `"present_since": "ISO-8601"` per USB device.
  A stateless enumeration cannot produce that from `Win32_PnPEntity`; it needs
  either `DEVPKEY_Device_LastArrivalDate` via ctypes/SetupAPI (not in `pywin32`,
  verified above) or a background watcher — which *is* hotplug monitoring, minus
  the event publication. The brief's out-of-scope line draws the boundary at
  "events", and §10's own wording agrees ("Agent publishes
  `…/device_attached` to the broker"), so this is a **near miss, not a defect** —
  but the implementer needs telling that `present_since` means "last arrival
  time from the device property", not "since the Agent noticed it".
- **Already in the tree?** No (R1 claim 7).

### Screenshots the model can see
- **Does A1–A6 require it?** No — but **A1 as written exposes the capability.**
  `screen_vision` declares `screen.capture` and `screen.capture_ocr`
  (`plugins/screen_vision/__main__.py:30,42`) with `tool:screen.capture` in its
  signed manifest (`plugins/screen_vision/plugin.toml:7-8`). A1 says the endpoint
  "serves every tool the loaded families expose", so these go on the LAN and into
  the registration. **This is the clearest place where the brief's scope line and
  the tree disagree.** The same is true of `clipboard.*`, `desktop.*` and
  `browser.*` — four families the contract's §6 table does not contain.
- **Already in the tree?** Yes: `mss` and `pytesseract` are dependencies
  (`pyproject.toml:34-35`), the plugin is bundled, signed and discovered. It
  returns `not_implemented` today (R1 claim 2c), so nothing *works*, but it is
  reachable and would be advertised.
- Fix belongs in A1: the endpoint must serve a **§6 allowlist**, not "loaded
  families". Say so explicitly, because the default reading is the opposite.

### Binary into the workspace
- **Does A1–A6 require it?** **A2's `files` does not** — §5.3 already defines the
  non-UTF-8 case as `ok: false, code: "error"`, so a text-only `files_read` is
  complete and buildable. **A3's `adb_pull` does**, if read naively: pulling an
  APK is the canonical use and is named in §10's out-of-v1 row. A3's one-line
  description does not carry §6's "→ text ≤ cap" restriction. Not a blocking
  defect, but A3's spec must repeat it or it will be built wrong.
- **Already in the tree?** Partly: `clipboard.get` and `screen.capture` are the
  natural binary producers and are stubs; nothing returns binary today.

### Voice on the workstation
- **Does A1–A6 require it?** **A5 requires local speech, and the scope line reads
  as if it forbids it.** Contract §7 specifies the prompt as "the Agent's
  existing toast plus spoken line", A5 cites §7, and §11 item 7 exercises it.
  Reading §8 resolves it: "voice on the workstation" there means *the persona*
  speaking (either `workstation_say` or streamed persona audio), which is a
  different thing from the Agent's own TTS announcing a confirmation. So **not a
  real conflict — but the brief's four-word list is genuinely ambiguous** and an
  implementer could reasonably read it as "don't wire TTS", which would gut A5.
  One clarifying clause in the brief fixes it.
- **Already in the tree?** Yes, and fully: `audio/tts.py` (Wyoming TTS),
  `audio/stt.py`, `audio/wake.py`, `audio/mic.py`; `sounddevice`,
  `openwakeword`, `wyoming` and `webrtcvad-wheels` are dependencies. The Agent
  already speaks. A `workstation_say` tool would be a thin wrapper — which is
  precisely why it must **not** be added to the endpoint before §8 is decided.
  `agent.speak` (`mcp_server.py:123`) already is that tool on the pipe, ungated
  (see §0a) — but it is an internal `agent.*` tool, **not** a family tool, and
  A1 is scoped to "every tool the loaded **families** expose". On a strict
  reading it is therefore not on the endpoint, and I do not count it as a
  LAN-exposure finding. The only caution worth recording: A1 also says "gated
  exactly like the named pipe does today", so an implementer who mirrors the
  pipe's `_TOOLS` list rather than the families' would carry it across. One
  clause in A1 ("families only, per the §6 allowlist") closes that off.

---

## Part 2c — What contract §12's asymmetry predicts

§12 is a twelve-row claim-check table. Eleven rows cite `file:line`
(`mcp_client.py:816-837`, `contracts/manifest.py:16,470-478`,
`config/secrets.py:404`, and so on). The twelfth — the only row about **this**
repository — bundles four claims ("Agent: named-pipe MCP, stubs, no ADB/serial,
gate layers") behind three bare directory names
(`C:\Projects\GameTest\src\workstation_agent\{mcp_host,plugins,security}`).

That asymmetry turns out to be predictive rather than cosmetic. Of the four
bundled claims, three are exact (R1 claims 1, 2, 7). The fourth — "gate layers" —
is the one R1 could only mark PARTLY TRUE (claim 4), and it is the same claim
under which I found two further inaccuracies here: five of the six pipe tools are
ungated and unaudited (§0a), and the sole gated one is broken (§0b).

The practical consequence for the build plan: every brief assertion that rests on
that row should be treated as unverified until checked. Concretely, these are:
- A1's "gated exactly like the named pipe does today" — **wrong**, §0a.
- A1's "The endpoint serves every tool the loaded families expose" — assumes a
  static, §6-shaped tool set; the tree has a dynamic, eight-plugin one.
- §7's "the Agent's **existing** toast plus spoken line" — the word "existing"
  is doing work it cannot support; neither is on the confirm path (R1 claim 4).
- A2's "Real implementations replacing the stubs" — assumes the stubs' host
  environment is neutral; it is a low-integrity Job Object with a 4-process cap.
- A5's "(default)" difficulty — derived from the same assumption.
By contrast, the brief's claims that trace to a `file:line` row in §12 (the
regex, the 30 s timeout, the confirm/restricted refusal, the blob dropping) are
the ones I found no fault with.

---

## Part 3 — Overall

### The three most serious problems, ranked

**1. A5 is labelled "default" but is five unbuilt subsystems on top of a confirm
path that is dead in production — and wiring it up exposes a read-prompt trap.**
Evidence: `app.py:441` passes neither `confirm_cb` nor `tts_speak`, so
`host.py:393-395` returns `False` and every confirmable call is silently denied,
with no toast (grep: `mcp_host/host.py` never mentions toast) and no voice (R1
claim 4). On top of that dead path A5 owns, none of which exists in any form:
the §5.2 result envelope (today `MCPHost.invoke` signals denial by *raising* —
`host.py:300,318,331` — so this is a change at every call site), §5.6
special-token stripping (grep: zero hits), an `audit.db` schema migration
(`audit.py:45-57` has no duration and no request-id column and writes `args_json`
untruncated, against §5.7), the tool-keyed pre-approved list and its UI, and
session-scoped remembering. And the checkers discard their `tool` argument
(`permissions.py:39,62,83`), so the instant the confirm callback is wired,
`filesystem.read` outside the roots starts **prompting on a read** — against the
brief's own bullet 6, §7's pre-approved list and §11 item 6. That trap is latent
today only because nothing prompts at all.
*Cost if unresolved:* work on A2/A3/A4 lands on a gate that denies everything it
is asked to confirm, and the failure is silent, so it surfaces at the hands-on
demo rather than in a test. Converting those families to §5.2 envelopes
afterwards is rework proportional to the number of tools. §11 items 2, 6, 7 and 9
all sit on this.
*Not a blocker, but must be written down:* the contract does not say whether the
confirmation window counts against §5.3's 25 s budget. A5 needs a documented
clamping rule (bound the post-confirm wait to 25 s − prompt_duration and return
the job envelope early). A one-sentence documentation gap sits beside it — the
contract does not define the corner where prompt_duration plus the actual work
exceeds 25 s on an always-prompt, non-job-capable tool (Part 2 bullet 4,
residue 2). No owner decision is required for either.

**2. A1's "serves every tool the loaded families expose" simultaneously
guarantees the registration mismatch the brief forbids and ships four
out-of-scope families onto the LAN.**
Evidence: eight plugins are discovered (`loader.py:200-218`, including a
user-writable `%APPDATA%\WorkstationAgent\plugins` folder); contract §6's table
names none of browser, clipboard, desktop or screen; contract §2 makes any
manifest/served mismatch "a terminal load failure"; and three runtime mechanisms
(user-folder discovery, per-plugin `enabled` at `host.py:132-136`, quarantine at
`host.py:149-157`) change the served set with no release. Separately, all 31
current tool names fail the §2 regex verbatim, and the brief never states the
`family.verb`→`family_verb` translation that fixes them.
*Cost if unresolved:* the plugin never loads at all — the failure is terminal, not
degraded — and a single operator toggling a plugin off on the Plugins page
re-breaks it after it works. Meanwhile `screen.capture` and `screen.capture_ocr`
(explicitly v3 in §10), `clipboard.get`, `desktop.click` and `browser.eval` are
advertised over the network.

**3. Every family runs low-integrity in a 4-process Job Object with a
16-variable environment whitelist, and no work item acknowledges it.**
Evidence: `supervisor.py:239-276` spawns every plugin with a low-integrity token
(medium only as a silent fallback, `:251-262`); `host.py:184` hard-codes
`ResourceLimits()` whose `max_active_processes = 4` (`supervisor.py:101`) becomes
the Job Object's `ActiveProcessLimit` (`supervisor.py:162`);
`build_child_env` (`supervisor.py:128-141`) passes 16 whitelisted variables plus
`WSA_PLUGIN_ID`. Contract §5.8 fixes families as Agent plugins. A low-IL process
cannot write to `%USERPROFILE%\Documents` — the `filesystem` plugin's own
declared root (`plugins/filesystem/plugin.toml:11`) — nor to `%TEMP%`, which
`adb install` needs; §5.4's "at most 8" concurrent jobs is unreachable under a
4-process cap; and there is no channel for delivering settings (the `adb` path,
the roots, the pre-approved list) into a plugin at all.
*Cost if unresolved:* A2, A3 and A4 are each written, tested against mocks, and
then fail on real hardware for reasons that look like unrelated Windows
permission errors. Because the integrity fallback is silent, they may pass on the
dev machine and fail on the target. Discovering this during A6 means reopening
the supervisor, which is upstream of all three.

### What the brief does not mention that this repo's own rules require

From `CLAUDE.md`:
- **The mandatory `.venv`.** A1's central decision — "the `mcp` package in the
  Agent's own venv (it is in its own venv now…)" — depends entirely on this rule,
  and the brief states it as a fact about the tree rather than as a constraint the
  implementer must honour. Anyone installing `mcp` with a bare `pip install`
  reproduces exactly the incident `CLAUDE.md` records ("you will clobber the
  system's `mcp` … That specifically has happened; do not repeat it").
- **Hatchling / `pyproject.toml` as the only dependency record.** A4 says
  "licence it in the repo's own record"; no such record exists (no NOTICE, no
  THIRD-PARTY; `docs/` holds one design document). The only precedent is the
  comment at `pyproject.toml:41-45`.
- **Windows-only.** Unstated but load-bearing: `mcp_server.py:380-382` already
  refuses non-Windows, and A3/A4 are Windows-API-bound.
- **"Every subtask ships implementation + unit tests + integration tests where
  interfaces are touched."** The brief says nothing about tests, and A6 says "QA
  and security run after the hand-over", which reads as permission to skip them.
  It is not — and §0b shows exactly what mock-only unit tests buy: two broken
  production paths, both green.
- **Worker path isolation** and "No worker touches `working/`" — the brief hands
  over six work items with no allowed-paths split. A1 (mcp_host + ui + config +
  `__main__` + spec file) and A5 (mcp_host + ui + config) overlap heavily, so
  they cannot run as parallel workers under this repo's process.
- **PyInstaller packaging.** New plugin families are shipped as *data* files by
  `workstation_agent.spec:27-36` and new imports need `hiddenimports`
  (`:38-54`). Every new family and `cryptography` need spec edits. Unmentioned.

### Is A1→A6 the right order?

Mostly, with two real defects.

- **A5 is in the wrong place.** It is listed fifth, after three families that all
  depend on it: A2's `files` needs the roots-to-`denied` change (bullet 6), A2/A3
  need the §5.2 result envelope for `unknown_job`/`timeout`, and every
  always-prompt tool needs the clamping rule of bullet 4. Building A2–A4 against
  `MCPHost.invoke`'s current raise-on-denial contract (`host.py:300,318,331`) and
  then converting all of them to §5.2 envelopes is rework proportional to the
  number of tools. **The §5.2 envelope, the confirm wiring and the pre-approved
  list should be a prerequisite of A2, not a successor of A4.** Only the UI
  polish (per-tool toggles, "remember for this session") belongs late.
- **A1 before everything is right but incomplete as a first step.** Shipping the
  HTTPS endpoint first, with the confirm branch hard-denying (`host.py:395`),
  exposes the whole loaded tool set on the LAN with a gate whose confirm arm is
  dead. Sequenced as written, the least-safe intermediate state is the longest
  one. A1 should carry an explicit "serve the §6 allowlist only, empty until A2"
  clause.
- **A3 and A4 are correctly ordered relative to each other** and are genuinely
  independent — they are the two items that could run in parallel, which is worth
  saying since nothing else in the brief can.
- **A6 is gated on a PersonaCore deliverable** (the §3 contract 2.1→2.2 core
  change) and on physical hardware. It cannot be scheduled as though it followed
  A5 in this repo's calendar.

---

## SUMMARY

**Per work item**

| item | brief's label | my call | reason in one line |
|---|---|---|---|
| A1 Network MCP endpoint | hard | **hard** | no TLS, no HTTP framing, no config section, no UI surface, no manifest writer, no CLI subcommand — and a windowed `Agent.exe` cannot host `export-registration` as specified |
| A2 shell / files / jobs | default | **hard** | the job model collides with a 4-process Job Object (and with the inner client's 10 s default timeout, which is overridable but currently unset), and `files_write` targets a root a low-integrity plugin cannot write to |
| A3 devices / adb | default | **hard** | `pywin32` wraps no SetupAPI (verified), `present_since` needs a device property the brief's named APIs do not expose, and `adb_pull` is text-only in a way A3 never says |
| A4 serial | default | **default** | ordinary `pyserial` work; the only risks are low-integrity COM access and a licence "record" that does not exist |
| A5 gate wiring | default | **hard** | the confirm path is dead in production, there is no §5.2 envelope, no §5.6 stripping, the audit schema cannot hold §5.7, and wiring the callback turns a read into a prompt |
| A6 hands-on | (none) | **default, externally blocked** | 4 of 7 items are Agent-testable; all 7 need the PersonaCore §3 core change first, and items 2–3 need hardware nobody was asked to supply |

**The three ranked problems**

1. **A5 is mislabelled "default": five unbuilt subsystems on a confirm path that
   is dead in production.** The confirm/toast/voice path is unwired
   (`app.py:441` → `host.py:395`), and A5 additionally owns the §5.2 envelope
   (a change at every `MCPHost.invoke` call site, which today *raises*), §5.6
   stripping, an `audit.db` migration for §5.7, the pre-approved list and its UI,
   and session-scoped remembering. Wiring the callback also trips a latent trap:
   the checkers discard `tool` (`permissions.py:39,62,83`), so `files_read`
   outside the roots begins prompting on a read. *Cost:* every family is built on
   a gate that silently denies, and the rework to §5.2 envelopes scales with the
   number of tools. Separately, the prompt-window-vs-25 s budget needs a
   documented clamping rule, and the contract should add one sentence covering
   the corner where prompt_duration plus the work exceeds 25 s on an
   always-prompt, non-job-capable tool. Neither needs an owner ruling.
2. **A1's "serves every tool the loaded families expose"** guarantees the
   registration mismatch bullet 2 forbids (three runtime mechanisms change the
   served set without a release) and puts four out-of-scope families —
   `screen.*`, `clipboard.*`, `desktop.*`, `browser.*` — on the LAN; all 31
   current tool names also fail the §2 regex verbatim, and the brief never states
   the `family.verb`→`family_verb` translation that fixes them. *Cost:* a terminal
   load failure on the core, i.e. nothing works at all, plus v2/v3 capabilities
   shipped in v1.
3. **Every family runs low-integrity in a 4-process Job Object with a
   16-variable environment whitelist**, unacknowledged anywhere in the brief.
   *Cost:* A2/A3/A4 pass their mocks and fail on real hardware, possibly only on
   the target machine, forcing a supervisor change upstream of all three.
