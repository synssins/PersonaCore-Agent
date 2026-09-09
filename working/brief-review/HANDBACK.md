# Workstation plugin — reply to AGENT-BRIEF.md, and the state of the build

**From:** the Agent side (`C:\Projects\GameTest`)
**Re:** `working/team/workstation/AGENT-BRIEF.md`, written 2026-09-08
**Contract:** `working/contracts/workstation.md`
**Date:** 2026-09-08

Your brief told us to verify its claims about our tree before building and to stop if one was
wrong. **We verified all eight. The stop-clause did not fire, and A1–A5 are built.**

**Status after the PersonaCore reply of 2026-09-08:** the four brief errors accepted; both contract
defects fixed in the contract the same day; all three of our defaults approved and recorded in
contract §0, along with the two items from §8. **Our claim that A6 was blocked was wrong — see §6,
corrected.** Code stays in this repository; only `workstation-registration.zip` crosses over, as an
install rather than a commit.

---

## 1. Your claims about our tree — verified

Contract §12 checks eleven claims with `file:line` precision. The twelfth row — the one about our
repo — cites three bare directory names covering four bundled assertions. This is that row done
properly.

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

**Claim 4 was the one that was wrong.** The confirm machinery existed but was never connected.
`app.py:441` was the only production call and it passed neither `confirm_cb` nor `tts_speak`, so
every confirmable-condition call was **silently denied**, no voice ever played, and toast was not
on the confirm path at all. There was also no awaitable primitive to wire *to*:
`ToastPresenter.show()` is synchronous, returns `None` and is callback-based, while the host
wanted `Callable[..., Awaitable[bool]]`. A5 built that, it did not extend it.

---

## 2. Four factual errors in the brief

1. **"gated exactly like the named pipe does today" (A1).** The pipe served six tools; only
   `agent.execute_local` reached the gate. The other five — including `agent.speak`, your own
   §10 v2 voice capability — were dispatched with no permission check, no confirm and no audit.
   The gate covered one tool in six. A1 does not inherit that model.
2. **"SetupAPI/WMI via `pywin32`" (A3) names an API `pywin32` does not provide.** Verified: no
   `win32setupapi`, no `setupapi`, no `setup*` module under `win32`. We used ctypes into
   `setupapi.dll`. We did **not** add a WMI fallback: `Win32_PnPEntity` returns `InstallDate`
   NULL for every USB device here and carries no other timestamp, so WMI cannot supply §6.1's
   `present_since` and would emit `null` for every row — a §6.1 defect indistinguishable from a
   working one.
3. **The tool-name rule is stated without its remedy.** All 31 of our tool names fail
   `^[a-z][a-z0-9-]{1,63}$` verbatim and all 31 pass once §2's `family.verb`→`family_verb`
   translation is applied. The brief forbids dots but never mentions the translation, which
   appears only in the contract.
4. **`Agent.exe export-registration` is specified on a GUI binary.** `console=False`, and
   `__main__.py` had no subcommands, so it could report neither the zip path nor an error. Solved
   with a gated `AttachConsole(ATTACH_PARENT_PROCESS)`.

---

## 3. Two defects in the contract itself

**§2's example is not valid TOML.** Lines 68-70:

```
[tools.workstation_status]  risk = "safe"
[tools.devices_list]        risk = "safe"
```

A `[table]` header cannot share a line with a key/value pair. `tomllib` rejects it:
`Expected newline or end of document after a statement`. An implementer copying the spec verbatim
produces a manifest your core cannot parse — a terminal load failure. We hit exactly that. The
correct form is a two-line block per tool. Note the tempting one-line repair
`tools.workstation_status = { risk = "safe" }` is valid TOML in isolation but **not** a safe
substitution: placed after `[permissions]` it parses as nested inside that table rather than at
the root.

**§11's done-condition is scoped inconsistently by the brief.** A6 names items 1–7; §11 has ten.
Item 9 ("every one of the above is a row in the Agent's audit database") is squarely ours, is
named in A5's own scope, and sat in nobody's done-condition. We built it anyway. The Agent-side
halves of items 8 and 10 were also unstated — item 8 needs the certificate and token to **persist
and be reused across restarts**, or the pinned fingerprint changes and "starting the Agent brings
it back" fails. A1 said only "generated on first run". We persist them.

---

## 4. Three decisions we need from you

We built on stated defaults rather than blocking. Each is cheap to change.

1. **Which tools does the endpoint serve?** A1 says "every tool the loaded families expose". Taken
   literally that puts `screen.*`, `clipboard.*`, `desktop.*` and `browser.*` on the LAN, and §10
   defers screenshots-the-model-can-see and voice to v2/v3. It also guarantees the mismatch your
   own bullet 2 forbids, since three runtime mechanisms can change the served set without a
   release.
   **Our default: a static families-only allowlist, with the registration generated from that same
   list so the two cannot drift.** `agent.*` internals are never served.
2. **Does the confirmation window count against §5.3's 25 s call budget?** Both numbers are marked
   "MINE". **Our default: clamp the post-confirm wait to `min(wait_s, 25 - prompt_duration)` and
   return the job envelope early.** One corner the contract does not define is worth a sentence in
   §5.4: `prompt_duration` plus real work exceeding 25 s on a tool that is always-prompt and not
   job-capable.
3. **Confirm the tool-name spelling at the boundary.** We serve underscore wire names and
   translate at the endpoint; the gate sees dotted `family.verb`. Registration and served set are
   generated from one list and a test asserts they are equal in both directions.

---

## 5. What is built

| Item | State |
|---|---|
| A1 — network MCP endpoint + registration export | **Done** |
| A2 — `shell` / `files` / `jobs` | **Done** |
| A3 — `devices` / `adb` | **Done** |
| A4 — `serial` | **Done** |
| A5 — gate wiring | **Done** |
| A6 — hands-on acceptance | **Not blocked** — operator steps + hardware for two items (§6) |

13 commits, ~29,700 lines, **2,290 tests passing**, ruff and pyright clean.

The endpoint is HTTPS-only with no code path serving plain HTTP, binds an operator-chosen
interface and **refuses a wildcard bind outright**, answers `401` from the ASGI scope without ever
reading an unauthenticated body, and pins `mcp>=2.1.1,<2.2` — an upper bound, not a floor, because
§12 records twice that your core runs 2.1.1 and "the same SDK on both ends" is the reason we
adopted the dependency at all.

The gate is default-deny by **signed** per-tool argument declaration: a tool with no declaration,
or a call carrying an argument the declaration does not name, is refused. Declarations live in
`declared_permissions` in the signed `plugin.toml` — never a tool's self-reported schema, or a
hostile plugin would declare its own path argument out of confinement.

---

## 6. A6 — CORRECTED 2026-09-08 after the PersonaCore reply

**This section was wrong when written, and the error was ours.** It claimed A6 was blocked because
"your core is stdio, our endpoint is streamable-HTTP" and nothing was callable until the §3 core
change shipped. Both halves were out of date. Verified against the core on receipt of the reply:

- `plugins/mcp_client.py:1006` `_connect_http`, called at `:938`, with
  `streamable_http_client` imported at `:62`.
- `plugins/discovery.py:11,57` — `plugins-http.d/` registrations load like any plugin.
- The §3 bearer-token and pinned-certificate change shipped in `v0.17.0-alpha.26`, and the
  owner's server runs `alpha.27` (`/health` reports `"contract": "2.2"`).

**The two ends already speak the same protocol with the same auth, and `mcp` is 2.1.1 on both
sides.** A6 was never blocked on the core. What remains is operator configuration plus hardware
for two of the ten items.

We should have verified this against the core rather than inferring it from the brief's framing.
The brief described the change as pending; it had already landed. The lesson is the same one this
review was commissioned to apply in the other direction — check the claim against the tree, do not
trust the document.

### What actually remains for A6

Operator steps, on the workstation: enable `[network_mcp]` in `config.toml` with the LAN IP and a
port, start the Agent, open the Network MCP page once and copy the URL, fingerprint and token
(shown once by design), then `Agent.exe export-registration -o <folder>`.

On PersonaCore: add the token as the secret `workstation_token` scoped to plugin `workstation`,
then install the zip. The review screen should name the secret and the pinned fingerprint. A
`waiting_for_secrets` health row means the secret step was skipped; two fingerprints named means
the registration's `tls_fingerprint` does not match the endpoint's.

Then §11 items 1, 4, 5, 6 and 7 need no hardware. Items 2 and 3 wait for a phone and a serial
board.

**One thing to expect when a phone is first attached.** Plugins run low-integrity, and `adb` writes
its auth key to `%USERPROFILE%\.android`, which a low-integrity process cannot write. Without that
key every device reports `unauthorized` forever. We probe candidate locations at runtime and report
a named cause when none work, so it fails legibly — that legible failure is the expected first
outcome, not a surprise.

## 7. Defects we found in our own tree, that bear on your integration

Four of these were pre-existing and would have shipped. Listed because they change what you can
assume about the Agent, not as an apology.

- **A deadlock that scaled with the machine.** Each plugin's stdout reader parked a worker of the
  event loop's default thread pool for that plugin's entire life. The pool is
  `min(32, cpu_count + 4)` — 12 here. The twelfth plugin took the last worker and startup
  deadlocked. A 4-core CI box would have failed at eight plugins.
- **Plugin signature validity depended on the checkout's git line-ending configuration.** A clone
  with `core.autocrlf=false` would have invalidated every shipped plugin, with `allow_unsigned`
  off by default — no working plugins, and an error mentioning nothing about line endings. The
  digest now normalises newlines for Python source, so validity is a property of the plugin.
- **Signatures covered `.py` only.** A planted `.pyd`, `.so` or sourceless `.pyc` was loaded
  natively by the import machinery and hashed by nothing — arbitrary native code execution with
  `verify()` returning `valid`. The covered set is now every importable file in the package tree,
  and digests are bound to their paths so renames cannot preserve a signature.
- **`agent.execute_local` returned `isError: true` on every *successful* call**, and `agent.toast`
  called a method that did not exist. Both were masked by tests that mocked the collaborators.
- **A §5.6 token could splice across two JSON fields** and destroy the result envelope — reachable
  deliberately by any tool controlling two output streams. Stripping now rebuilds the envelope
  rather than editing its rendered text.

---

## 8. Two things worth deciding on your side

- **`jobs_*` is cross-plugin and unresolved.** `shell_run` and `adb_shell` are both job-capable but
  live in different plugin processes. We scoped `jobs_*` to the shell family, made the boundary
  visible (`jobs_list` reports its scope; a foreign job id is answered by naming the owning family,
  never `unknown_job`, which means "died with the Agent" and would be undebuggable), and namespaced
  ids so prefix routing is a later change rather than a rewrite. **§11 item 4 therefore holds for
  `shell_run` and not for `adb_shell`** until routing lands.
- **Per-connection identity does not reach a plugin subprocess.** A session id is plumbed from the
  transport into the permissions evaluator, but not into the arguments a plugin receives, and one
  subprocess serves every caller. Anything needing per-caller isolation inside a family — job
  ownership, serial session ownership — cannot get it from the plugin side today.
