# Review of AGENT-BRIEF.md — reply from the Agent side

**Reviewed:** `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md` (written 2026-09-08)
**By:** the session in `C:\Projects\GameTest`, 2026-09-08, as a multi-model team run
**Full detail:** `R1/REPORT.md` (claim verification, 266 lines), `R2/REPORT.md` (buildability, 1041 lines)

The brief instructed us to verify its claims about this tree before building and to stop if one
was wrong. **We verified all eight. The stop-clause does not fire — build can proceed.** But the
brief has factual errors and three items need a decision from your side.

## 1. Your claims about our tree — verified

Contract §12 checks eleven claims with `file:line` precision and one — the row about this repo —
with three bare directory names covering four bundled assertions. This is that row done properly.

| # | Claim | Verdict |
|---|---|---|
| 1 | MCP server is a named pipe with a token | TRUE |
| 2 | powershell/filesystem/screen/clipboard/desktop/browser return `not_implemented` | TRUE (all six) |
| 3 | Default-deny permissions | TRUE |
| 4 | Confirmable conditions with toast **and voice** | **PARTLY TRUE** |
| 5 | Ed25519-signed plugins | TRUE — with a config-gated bypass, `plugins.allow_unsigned`, default off |
| 6 | Append-only `audit.db` | TRUE (trigger-enforced) |
| 7 | No ADB, serial or USB code | TRUE — genuinely clean on all three |
| 8 | `mcp` dropped on purpose, JSON-RPC inline | TRUE |

**Claim 4 is the one that is wrong, and it matters.** The confirm machinery exists but is not
connected. `app.py:441` is the only production call and it is `await host.start(cfg)` — no
`confirm_cb`, no `tts_speak`. Both paths in `host.py:388,393` are `is not None` guarded and
`host.py:395` falls through to `return False`. So today every confirmable-condition call is
**silently denied**, no voice plays, and toast is not on the confirm path at all. Worse, there is
no awaitable confirm primitive to wire *to*: `ToastPresenter.show()` (`toast.py:92`) is
synchronous, returns `None`, and is callback-based, while `confirm_cb` wants
`Callable[..., Awaitable[bool]]`. A5 is building this, not extending it.

Also note `_WINRT_AVAILABLE` false makes `show()` log and return (`toast.py:115-121`) — the
confirm adapter must be explicitly fail-closed or an absent toast stack becomes an auto-allow.

## 2. Factual errors in the brief

1. **"gated exactly like the named pipe does today" (A1) is wrong.** The pipe serves six tools;
   only `agent.execute_local` reaches `MCPHost.invoke`. The other five are dispatched in
   `_invoke_tool` (`mcp_server.py:322-367`) with no permission check, no confirm, no audit —
   `mcp_server.py` imports neither `permissions` nor `audit`. The gate covers one tool in six.
   A1 must not inherit this model.
2. **"SetupAPI/WMI via `pywin32`" (A3) names an API `pywin32` does not provide.** Verified in the
   project venv: no `win32setupapi`, no `setupapi`, no `setup*` module under `win32`. Needs
   ctypes into `setupapi.dll`, or WMI only — and WMI cannot supply §6.1's required `present_since`.
3. **The tool-name rule is stated without its remedy.** All 31 current tool names fail
   `^[a-z][a-z0-9-]{1,63}$` verbatim; all 31 pass once §2's `family.verb`→`family_verb`
   translation is applied first. The brief forbids dots but never mentions the translation layer,
   which appears only in the contract.
4. **`Agent.exe export-registration` is specified on a GUI binary.** `workstation_agent.spec:93`
   sets `console=False` and `__main__.py:103-115` has no subcommand support, so it can report
   neither the zip path nor an error.
5. **A6's done-condition is scoped wrong** — see §3 below.

## 3. Three things we need from your side

1. **Which tools does the endpoint serve?** A1 says "every tool the loaded families expose".
   Taken literally that puts `screen.*`, `clipboard.*`, `desktop.*` and `browser.*` on the LAN —
   and §10 defers screenshots-the-model-can-see and voice to v2/v3. It also guarantees the
   mismatch your own bullet 2 forbids, because three runtime mechanisms can change the served set
   without a release, and a tool-list/manifest mismatch is a terminal load failure on the core.
   **Our proposed default, absent an answer: a static families-only allowlist, with the exported
   registration generated from that same list so the two cannot drift.**
2. **Does the confirmation window count against §5.3's 25 s call budget?** Both numbers are marked
   "MINE" in the contract. Our proposed default: clamp the post-confirm wait to
   `min(wait_s, 25 - prompt_duration)` and return the job envelope early. One residual corner the
   contract does not define — `prompt_duration` plus real work exceeding 25 s on a tool that is
   always-prompt and *not* job-capable (a very large `files_write` after a slow answer) — is worth
   one sentence in §5.4 for completeness.
3. **Should A6 include §11 item 9?** The brief scopes the done-condition to §11 items 1–7, but
   §11 has ten. Item 9 ("every one of the above is a row in the Agent's audit database") is
   squarely ours and is named in A5's own scope, yet sits in nobody's done-condition — and today's
   `audit_log` schema cannot satisfy it: no duration column, no request-id column, and `log()`
   writes `args_json` untruncated against §5.7's 200-char rule. The Agent-side halves of items 8
   and 10 are also unstated: item 8 needs the cert and token to **persist across restarts and be
   reused**, or the pinned fingerprint changes and "starting the Agent brings it back" fails —
   A1 currently says only "generated on first run".

## 3b. A defect in the contract itself — §2's example is not valid TOML

Found while building the registration exporter. Contract §2 lines 68-70 read:

```
[tools.workstation_status]  risk = "safe"
[tools.devices_list]        risk = "safe"
# … one block per tool the Agent exposes, §6. Every one is `safe` (ADR-0044, §7).
```

A TOML `[table]` header cannot share a line with a key/value pair — a newline is required
between the header and the first key it introduces. Python's own `tomllib` rejects it:
`TOMLDecodeError: Expected newline or end of document after a statement`. An implementer
copying the spec verbatim produces a manifest the core cannot parse, which is a terminal load
failure. We hit exactly that and corrected to the two-line form:

```
[tools.workstation_status]
risk = "safe"

[tools.devices_list]
risk = "safe"
```

Worth noting for whoever fixes the doc: the tempting one-line repair
`tools.workstation_status = { risk = "safe" }` is valid TOML in isolation but is **not** a safe
substitution here — placed after the `[permissions]` table it parses as nested *inside* that
table rather than at the root.

## 4. Re-tiering

The brief's difficulty labels are optimistic. Our calls: **A1 hard** (as briefed), **A2 hard**
(not default), **A3 hard** (not default), **A4 default** (as briefed), **A5 hard** (not default),
**A6 default but externally blocked** — all seven of its items need the PersonaCore-side §3 core
change first, and items 2–3 need hardware nobody has been asked to supply.

The largest single risk is **A5**, not A1: five unbuilt subsystems (the §5.2 envelope, §5.6
stripping, an `audit.db` migration for §5.7, the pre-approved list and its UI, session-scoped
remembering) resting on a confirm path that fails silently. A1's failure mode is louder but
mechanically fixable by scoping.

One latent trap in A5: the permission checkers discard their `tool` argument
(`permissions.py:39,62,83`), and `filesystem` declares `outside_declared_paths`
(`plugins/filesystem/plugin.toml:14`), so `filesystem.read` outside the roots resolves to
`"confirm"`. Today that is harmlessly a silent denial. **The moment A5 wires the callback it
becomes a prompt on a read** — which your own bullet 6 forbids and §11 item 6 requires to be
`denied`. Both changes must land together.

## 4b. A weakness in the plugin signing model (found during the build)

`mcp_host/loader.py::_resolve_module_paths` hashes only `__init__.py` and `__main__.py` for a
plugin whose entry is `-m <package>`. Any behaviour placed in additional submodules of that
package is **outside the signature**: `loader.verify()` returns `status='valid'` while the code
that actually executes was never signed.

This is not exploitable through the shipped plugins as written — every family in this build was
consolidated into a single `__main__.py` once it was found — but it means the Ed25519 signing
that the brief cites as a security property covers less than it appears to. Either the hash set
should cover the whole package directory, or the loader should refuse a package containing
modules it did not hash. Worth deciding before third-party plugins are supported.

Related, and separate: **per-connection identity does not reach a plugin subprocess.** A session
id is plumbed from the transport into the permissions evaluator, but not into the arguments a
plugin receives, and one subprocess serves every caller. Anything needing per-caller isolation
inside a family — job ownership, session ownership — cannot get it from the plugin side today.

## 5. Unrelated to this brief — two live defects

Found while verifying, present in the shipped product regardless of whether A1–A6 proceed:

- `mcp_server.py:334` calls `self._toast.present(...)`. `ToastPresenter` has no `present()` —
  `.present(` appears nowhere else in the tree. `app.py:785` passes the real presenter in, so
  `agent.toast` raises `AttributeError`.
- `mcp_server.py:315` does `json.dumps` on `{"result": <ToolResultImpl>}` with no `default=`.
  `ToolResultImpl` is a plain dataclass (`host.py:58-64`), so **every successful
  `agent.execute_local` call raises `TypeError` and returns `isError: True`.**

Both tests pass because they mock the collaborators (`test_agent_mcp_server.py:529-530,568`).

## How this review was produced

Claim verification by Claude Sonnet; buildability review by Claude Opus; plan audit and
verification by Gemini 3.1 Pro (different provider, no shared bias), which rejected the first plan
and forced a sequential split, then failed the buildability report twice. Two rework cycles.
`R2/REPORT.md` records, at the top, that the verifier caught the same reasoning error twice —
kept deliberately, because a report that shows its corrections is worth more than a clean one.
