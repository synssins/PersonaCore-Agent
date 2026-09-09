# R1 -- Verification of AGENT-BRIEF.md's factual claims

Verified against the tree at C:\Projects\GameTest as of 2026-09-08.
Brief under test: C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md.

---

## Claim 1 -- "MCP server is a named pipe with a token" (mcp_host/mcp_server.py)

**Verdict: TRUE**

- Static pipe name: src/workstation_agent/mcp_host/mcp_server.py:51
  PIPE_NAME = r"\.\pipe\PC-Agent-MCP", bound via win32pipe.CreateNamedPipe at
  mcp_server.py:396-405.
- Token generated with secrets.token_hex(32) at mcp_server.py:73 (32 random bytes,
  hex-encoded), written to %APPDATA%\WorkstationAgent\mcp-token
  (mcp_server.py:54-55, 74), hardened via security.dpapi.harden_file
  (mcp_server.py:77-79).
- Every request other than initialize/shutdown/ping is gated on
  self._authenticated (mcp_server.py:273-277); _handle_initialize compares
  params.token to the stored token with != and rejects with JSON-RPC error -32000
  on mismatch (mcp_server.py:291-299).

## Claim 2 -- powershell / filesystem / screen / clipboard / desktop / browser all return not_implemented

**Verdict: TRUE for all six families (per-family breakdown below).** Every one of the six
plugins has exactly one tools/call branch and it is unconditional -- tool_name is read
only to echo it back in the response payload, never branched on, so every tool in every
family returns not_implemented with no exceptions.

- powershell -- TRUE. src/workstation_agent/plugins/powershell/__main__.py:73-96:
  the tools/call handler ignores tool_name and always replies
  status=not_implemented (line 86). Only tool declared is powershell.run
  (lines 28-41).
- filesystem -- TRUE. plugins/filesystem/__main__.py:99-123, same unconditional
  reply (line 112). Four tools declared (list/read/write/delete, lines 28-67), all hit the
  same unconditional branch.
- screen (screen_vision) -- TRUE. plugins/screen_vision/__main__.py:89-113,
  unconditional reply (line 102). Three tools declared (capture/capture_ocr/list_monitors,
  lines 28-58).
- clipboard -- TRUE. plugins/clipboard/__main__.py:79-103, unconditional reply
  (line 92). Three tools declared (get/set/clear, lines 28-48).
- desktop (desktop_control) -- TRUE. plugins/desktop_control/__main__.py:108-132,
  unconditional reply (line 121). Five tools declared (click/type/key/list_windows/
  focus_window, lines 28-77).
- browser -- TRUE. plugins/browser/__main__.py:104-128, unconditional reply
  (line 117). Five tools declared (open/screenshot/click/type/eval, lines 28-73).

No exceptions found in any of the six files -- none of them special-case any tool name.

## Claim 3 -- "Permissions are default-deny"

**Verdict: TRUE**

src/workstation_agent/mcp_host/permissions.py:

- _check_tool_permission (lines 110-158): a plugin with no declared_permissions
  returns "deny" (lines 128-133); a plugin that declares nothing tool-scoped returns
  "deny" (lines 138-143); declared-but-not-granted returns "deny" (lines 146-151);
  granted-but-not-declared also returns "deny" (lines 152-157). The docstring's decision
  table (lines 122-126) states explicitly: "only cell 1 permits the call to proceed" --
  i.e. three of four cells deny, and the un-listed/unknown case denies.
- evaluate() (lines 161-214): an unrecognised entry in plugin.confirmable_conditions
  (a condition name not in CONDITION_CHECKERS) causes an explicit "deny" at
  lines 184-191 ("unknown confirmable_condition=%r ... denying") rather than being
  silently skipped/allowed.
- The only path to "allow" is the fallthrough at line 214, reached only after the
  tool-identity gate passed and no confirmable/hard-guard condition fired.

This is a real default-deny fallthrough, not merely a filename/docstring claim.

## Claim 4 -- "Confirmable conditions with toast and voice"

**Verdict: PARTLY TRUE** -- the confirmable-conditions mechanism is real, but the
"toast and voice" notification claim is not actually wired into the running application.

- The "confirm" decision and confirm flow are real:
  mcp_host/permissions.py can return "confirm" (e.g. lines 192-199), and
  mcp_host/host.py handles it -- invoke-side check at host.py:320-330, dispatching
  to _do_confirm at host.py:375-395.
- Voice: host.py:388-391 -- inside _do_confirm, if self._tts_speak is not None,
  it calls await self._tts_speak.speak(msg) announcing the pending tool call. This is
  wired to the confirm flow structurally. But self._tts_speak is populated only from
  the tts_speak parameter passed to MCPHost.start() (host.py:117-126), and the only
  production call site, src/workstation_agent/app.py:441 (await host.start(cfg)),
  passes neither confirm_cb nor tts_speak -- confirmed by grepping all of src for
  "host.start(" and "MCPHost()" (only hits: app.py:439,441 and the docstring example
  at host.py:9-10). So in the actual running Application, self._tts_speak is always
  None and the voice announcement code path never executes.
- Toast: there is no toast call anywhere in the confirm path. ToastPresenter
  (src/workstation_agent/ui/notifications/toast.py) is used exactly once in
  production, for update-available notifications (app.py:705-710, toast.py:207-243
  show_update_toast) -- nothing in mcp_host/host.py references "toast" or
  "ToastPresenter" at all (grepped; zero hits).
- Confirm callback itself: self._confirm_cb is also None in production (same call
  site), so _do_confirm falls through to return False at host.py:395 -- every
  confirmable-condition tool call is unconditionally denied today, silently, with no
  UI prompt of any kind reaching the user.

What the tree actually does instead: the confirm mechanism and a voice-announcement hook
exist and are unit/integration-tested (tests/unit/mcp_host/test_host.py,
tests/integration/mcp_host/test_first_party_plugins.py), but the composition root
(app.py) never supplies confirm_cb or tts_speak, and toast is never connected to
confirm at all -- only to update notifications. This affects work item A5 ("Gate
wiring... confirmable conditions... pre-approved list... 'remember for this session'"):
A5 needs to build the actual UI-facing confirm prompt and its toast/voice presentation
from scratch, not just extend an existing wired path -- none of it is connected today.

## Claim 5 -- "Plugins are Ed25519-signed"

**Verdict: TRUE, with an explicit, config-gated bypass**

- Verification: src/workstation_agent/security/signature.py:12-30, verify() uses
  nacl.signing.VerifyKey.verify (PyNaCl, Ed25519).
- Enforcement on load: src/workstation_agent/mcp_host/host.py:138 calls
  verify(manifest, TRUSTED_PUBKEYS, allow_unsigned=allow_unsigned) for every discovered
  manifest during MCPHost.start(); host.py:149-157 -- if vresult.status is
  "quarantined" or "invalid", the plugin is marked quarantined, an audit event is
  logged, and continue skips _spawn() entirely -- the plugin subprocess is never
  started. This is real enforcement at load, not merely a check whose result is ignored.
- All six framework plugins (plus hello_world and claude_code_bridge) ship a
  signature.sig file alongside their plugin.toml (confirmed via directory listing --
  e.g. src/workstation_agent/plugins/powershell/signature.sig).
- Bypass exists and is real: mcp_host/loader.py:328-363 verify() takes
  allow_unsigned: bool = False. When True, a missing/empty/sentinel signature file
  returns status="unsigned" instead of "quarantined" (loader.py:350-361), and
  "unsigned" is NOT in the {"quarantined", "invalid"} block set at host.py:149,
  so an unsigned plugin proceeds straight to _spawn(). This flag is driven by
  config.plugins.allow_unsigned (host.py:129), whose schema default is
  allow_unsigned: bool = False (src/workstation_agent/config/schema.py:104) -- i.e.
  signing is enforced by default, but a config toggle turns it off. The brief does not
  mention this bypass; it is real and operators can flip it (e.g. for local dev), so any
  build relying on "signed-only, no exceptions" should note this setting exists.

## Claim 6 -- "Append-only audit.db"

**Verdict: TRUE**

- The store exists: src/workstation_agent/mcp_host/audit.py, SQLite file located at
  root / "audit.db" (src/workstation_agent/config/store.py:48).
- Append-only-ness is enforced by SQL triggers, not merely code discipline:
  audit.py:59-71 defines audit_log_no_update (BEFORE UPDATE ... RAISE(ABORT, ...))
  and audit_log_no_delete (BEFORE DELETE ... RAISE(ABORT, ...)), executed via
  conn.executescript(_CREATE_TABLE + _CREATE_TRIGGERS) at connection time
  (audit.py:130). Any UPDATE/DELETE against audit_log -- whether from this
  module's own code or any other code that opens the same DB file -- is aborted by
  SQLite itself. This is a schema-level guarantee, not something that depends on every
  caller being well-behaved.
- The module's public surface (log() at audit.py:157-193, query() at
  audit.py:196-244) only ever executes INSERT and SELECT, consistent with the
  triggers.
- WAL mode is set (audit.py:73, 129) for concurrent readers, which is orthogonal to
  the append-only guarantee but noted since the module docstring bundles both.

## Claim 7 -- "No ADB, serial or USB code"

Search performed: case-insensitive grep -rniI across the entire tree (excluding
.git, .venv, __pycache__, .ruff_cache, .pytest_cache), plus an explicit check of
pyproject.toml dependencies and mcp-style import scans reused for other patterns.

- ADB -- TRUE (no hits). grep -rniI '\badb\b' . (excludes above) returns exactly
  3 matches, all three inside this review's own artifacts:
  working/brief-review/PLAN.md:68 and working/brief-review/R1/SPEC.md:31,58 -- these
  are the review team's restatement of the claim being verified, not project code. Zero
  hits in src/, tests/, docs/, installer/, scripts/, updater/, or pyproject.toml.
- Serial -- TRUE (no hits, once false positives are excluded). grep -rniI
  'serial' . returns 90 matches project-wide, but every one of them is the English word
  "serialise/serialisation/serialization" (canonical-JSON / Ed25519 signing code, e.g.
  security/signature.py:1,47, mcp_host/loader.py:222, updater_client/manifest.py,
  and copies of the same text in working/VERIFY-*.diff bundles) or, again, this
  review's own SPEC/PLAN files. Zero hits for hardware/serial-port concepts
  (pyserial, serial.tools.list_ports, COM port, etc.) anywhere in src/,
  pyproject.toml, or tests/.
- USB -- TRUE (no hits). grep -rniI '\busb\b' . returns exactly 3 matches, the
  same three review-artifact lines as the ADB search
  (working/brief-review/PLAN.md:68, working/brief-review/R1/SPEC.md:31,58). Zero
  hits elsewhere.

No dependency, stub, setting, or doc-level reference to ADB, serial ports, or USB exists
in the actual project tree (pyproject.toml's dependency list was read in full --
pyproject.toml:14-38 -- and contains no pyserial, pyusb, adb-related package).

## Claim 8 -- "mcp PyPI package dropped on purpose; JSON-RPC is inline"

**Verdict: TRUE**

- mcp is absent from dependencies: pyproject.toml:14-38 lists all 25 runtime
  dependencies; none is mcp. grep -rn for import mcp / from mcp across src/ and
  tests/ returns zero hits -- no code imports the mcp package anywhere.
- The decision is recorded in-repo in three places:
  - pyproject.toml:41-45 -- an explicit comment: "the mcp PyPI package was
    intentionally dropped. SPEC-03A implements the MCP JSON-RPC stdio protocol inline
    (see src/workstation_agent/mcp_host/mcp_client.py) because the mcp package's
    stdio_client bypasses our subprocess env-whitelist + Job Object isolation... it
    will conflict with system tools (e.g. PersonaCore's pinned mcp 2.x)."
  - src/workstation_agent/mcp_host/mcp_client.py:6-12 -- module docstring: "The mcp
    PyPI package's stdio_client was evaluated first but rejected for SPEC-03A: it
    wants to spawn the subprocess itself... and inherits get_default_environment(),
    which bypasses both our Job Object wrapping and our environment whitelist... a
    ~150 LOC inline implementation is cleaner, matches the SPEC-03A fallback
    allowance."
  - working/specs/SPEC-03A-supervisor.md:27,53 -- the original spec instruction that
    allowed the fallback ("If it doesn't work headless on Windows, implement
    JSON-RPC 2.0 over stdio inline") and the completion-report field asking which
    path was taken.
- The inline JSON-RPC implementation is in-tree: mcp_client.py implements a full
  async line-delimited JSON-RPC 2.0 client (initialize, tools/list, tools/call,
  ping, shutdown, notifications/* -- docstring lines 14-21) using only asyncio,
  json, itertools, contextlib (imports at mcp_client.py:36-41) -- no mcp
  dependency. The MCP server side (mcp_host/mcp_server.py) and every plugin's own
  stdio server (plugins/*/__main__.py) likewise hand-roll JSON-RPC with plain json
  and sys.stdin/sys.stdout, no mcp package involved.

This matches the PersonaCore brief's own framing exactly (A1 says "the earlier clash
with PersonaCore's mcp 2.x was a shared-interpreter problem") -- both sides of the
decision are consistent and recorded.

---

## STOP-CLAUSE

Does any wrong claim rise to the level where the brief's "stop and say so if one is
wrong" instruction is triggered? No.

Reasoning: seven of the eight claims verify as fully TRUE against real mechanisms (named
pipe + token, all six plugin families uniformly stubbed, real default-deny permission
fallthrough, real Ed25519 enforcement-on-load with a config-gated bypass, real
trigger-enforced append-only audit log, genuine absence of ADB/serial/USB code, and a
well-documented, genuinely-inline JSON-RPC replacing mcp). The one claim that is only
partly true -- claim 4, "confirmable conditions with toast and voice" -- is imprecise
but not build-invalidating: the brief's own work item A5 ("Gate wiring... confirmable
conditions... audit.db") already treats gate wiring as something this build must do,
not something already finished, so discovering that voice/toast aren't actually wired to
confirm yet doesn't change what A1-A6 direct the implementer to build -- it only
sharpens scope already assigned to A5 (build the real confirm UI/notification path;
don't assume one exists to extend). Nothing in the eight claims, if corrected, would
change the architecture A1-A6 describes, redirect which package to use, or invalidate a
"things that would be wrong" item. The Ed25519 bypass flag (claim 5) is also worth the
builder's attention but doesn't change what gets built either -- it's a pre-existing
config knob, default-off, outside A1-A6's scope.

---

## SUMMARY

| Claim | Subject | Verdict |
|---|---|---|
| 1 | MCP server = named pipe + token | TRUE |
| 2a | powershell tools -> not_implemented | TRUE |
| 2b | filesystem tools -> not_implemented | TRUE |
| 2c | screen tools -> not_implemented | TRUE |
| 2d | clipboard tools -> not_implemented | TRUE |
| 2e | desktop tools -> not_implemented | TRUE |
| 2f | browser tools -> not_implemented | TRUE |
| 3 | Permissions default-deny | TRUE |
| 4 | Confirmable conditions with toast and voice | PARTLY TRUE |
| 5 | Plugins Ed25519-signed | TRUE (config-gated bypass exists, off by default) |
| 6 | Append-only audit.db | TRUE |
| 7a | No ADB code | TRUE (no hits) |
| 7b | No serial code | TRUE (no hits; only serialise/serialization false positives) |
| 7c | No USB code | TRUE (no hits) |
| 8 | mcp dropped on purpose; JSON-RPC inline | TRUE |

Stop-clause: does not fire. One claim (4) is only partly true, but its inaccuracy
sharpens rather than invalidates the brief's own work-item A5; nothing here would change
what gets built under A1-A6.
