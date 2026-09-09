# Proposal: enrolment, multiple workstations, and revocation

**From:** the Agent side (`C:\Projects\GameTest`) · **To:** the PersonaCore side
**Date:** 2026-09-09 · **Supersedes:** `PROPOSAL-pairing.md`
**Status:** proposal — parts need a contract amendment, one part does not
**Raised by:** the owner, on running the alpha.10 flow

---

## The problem

Enrolling a workstation today means a person carrying a 32-byte token and a SHA-256
fingerprint between two machines by clipboard, creating a secret whose name must match
exactly, and installing a zip. Six steps, two of them moving a credential by hand.

And the model assumes exactly one workstation. The plugin is hardcoded as `workstation`.

The owner wants four things. One of them turns out to be nearly free.

---

## 1. Multiple workstations — and this needs almost nothing from you

**Verified in your tree:** `plugins/host.py:11` — *"One flat catalogue of `<plugin>.<tool>`
names"*. Tools are already namespaced per plugin, and `plugins/discovery.py:132` iterates
`plugins-http.d/`, so several HTTP plugins already load side by side.

So multiple workstations is **N registrations, not one plugin with a routing table**:

```
plugins-http.d/workstation-loft/manifest.toml     → workstation-loft.shell_run
plugins-http.d/workstation-office/manifest.toml   → workstation-office.shell_run
```

Each has its own URL, token, fingerprint and health row. "Run this on the office machine"
is just calling that plugin's tool. Removing one is uninstalling one plugin.

The alternative — one `workstation` plugin fanning out to N machines — needs something to
hold the routing table and N tokens, and a registration is a manifest, not code. That means
a broker, and contract §0 already rejected one: *"No relay in the core."* So the flat
catalogue is not merely easier, it is the shape your own decision points at.

**What changes:** the Agent stops hardcoding `_PLUGIN_NAME = "workstation"` and uses a
per-workstation name. That is an Agent-side change. What we need from you is only the
naming rule — see the questions below.

### Two hardcoded values make cross-talk a live bug, not a future risk

`registration_export.py` hardcodes both halves of a workstation's identity:

```
:49   _PLUGIN_NAME      = "workstation"
:55   _AUTH_SECRET_NAME = "workstation_token"
```

Enrol a second workstation today and both registrations claim the plugin name
`workstation` and both reference the secret `workstation_token`. The second overwrites the
first — one directory in `plugins-http.d/`, one secret, two machines. **Each workstation
needs its own plugin name AND its own secret name**, or the tokens are shared and the
isolation is nominal.

### Naming is a user-facing decision, not an internal one

The owner's phrasing is *"do thing on computername"*. That means the plugin name is what a
person says out loud, and the model routes on it — `workstation-office.shell_run` is chosen
because the sentence said "office". So the name should be the machine's name as its owner
thinks of it: operator-chosen at enrolment, defaulting to the hostname, and stable
afterwards because changing it orphans a registration.

It must survive contract §2's `^[a-z][a-z0-9-]{1,63}$` after translation, which rules out
most Windows hostnames untouched — they may contain underscores, and are commonly
uppercase. Normalising is easy; doing it silently is not, because the operator then says a
name the catalogue does not have. The Agent should show the resulting name and let it be
edited before enrolling.

### Seeing what is connected

Two views, and they answer different questions. PersonaCore's Plugins page already lists
each workstation with a health row, which answers "what is enrolled and is it up". The
Agent's own Network MCP page should answer "is the core talking to *me* right now" — last
connection, current session count. Neither exists as a fleet view today; the first is
nearly free given N registrations, the second is Agent-side.

## 2. Ship the plugin as its own release artifact

Purely our side, no contract impact. The release currently carries the Agent installer, the
bundle zip and the updater. It should also carry `workstation-registration.zip` as a
separate download, so the owner can take the installer alone or the registration alone.

The wrinkle: a registration is not generic. It contains *this* workstation's URL,
fingerprint and token, which do not exist until an endpoint has run. A build server cannot
produce a meaningful one. So what ships from CI is a **template** — the tool table, risk
levels and contract version, with the machine-specific fields empty — and the Agent fills
them in locally. Worth being explicit about, because a downloadable "plugin zip" that
looks installable but points nowhere is worse than no zip at all.

## 3. Admin credentials as the primary enrolment path

Give the Agent admin credentials for the core, and it does the rest: authenticate, push the
registration, write the secret, appear in the Plugins list. No zip, no clipboard, no
hand-typed secret name.

This needs an authenticated core-side API that can create a plugin registration and a
secret. Neither exists today — `grep` finds no pairing, enrolment or OTP anywhere in your
tree, and secrets are operator-entered.

Note the direction: **the Agent initiates outbound.** It already has a path to PersonaCore
and already trusts it for LLM traffic; PersonaCore has no route to the workstation until it
is told one, which is the thing being configured. Serving direction is unchanged — after
enrolment PersonaCore still connects inbound to `https://<iface>:<port>/mcp` with a bearer
token and a pinned certificate. **Contract §3 and §5 are untouched.** This is enrolment
only.

## 4. A pairing code as the second path — build both

Admin credentials are the convenient path. A rotating code shown only in the admin console,
under Plugin Settings for that workstation, is the path for when you would rather not put
admin credentials on the workstation at all — which on a machine that runs arbitrary shell
commands is a reasonable thing to prefer.

Same handshake, different proof. Build both; let the operator choose per machine.

## 3b. Credentials and code do two different jobs — the owner's refinement

This is the shape, and it is cleaner than treating creds and code as two ways to do one
thing:

**Job one — install the plugin into the core.** Happens once, ever. The plugin does not
exist in `plugins-http.d/` yet, and creating it is an administrative act. **This requires
admin credentials.** There is no code to show yet, because there is nothing to show it
under.

**Job two — enrol a workstation.** Happens once per machine. Either proof works: admin
credentials (authenticate, enrol, done) or the OTP from the core's Plugin Settings page.

The consequence the owner is after: **a person enrolling a machine they do not administer
never needs admin credentials.** Read them the code. Their workstation enrols itself, gets
its own plugin name, its own token, its own secret. They never hold anything that reaches
the rest of the core.

### One correction worth making

The owner suggested that after authenticating, the Agent should auto-fill the
now-available OTP. **For the machine doing the install, that is cosmetic** — an Agent
holding valid admin credentials does not need a code, because the code exists to substitute
for credentials it already has. Auto-filling it proves nothing extra.

What *is* genuinely useful is the other direction: after installing the plugin, the Agent
should **display** the current code so it can be read out to someone else. Same screen,
different purpose — not "fill this in for me" but "here is what to tell them". Worth
separating, because building the first gains nothing and building the second is the whole
point of having a code at all.

### What the code actually authorises

Worth stating plainly before it is built: the OTP authorises **enrolling a workstation**,
which grants shell, files, adb and serial capability on that machine to whoever drives the
core. Whoever holds the code can enrol *any* machine they control, not only the one
intended. That argues for a short window, per-attempt rate limiting (`auth/throttle.py`
already pairs attempts with an address), and consuming the code on success rather than
leaving it valid for its full window.

### Cross-workstation commands do not mean agent-to-agent

The owner's "do thing on computername" routes through the core: PersonaCore calls
`workstation-office.shell_run`. **No Agent ever calls another Agent.** The direction is
always core-inbound, which means a workstation enrolled with a shared code cannot reach any
other workstation — it can only be reached. That falls out of the existing design rather
than needing to be enforced, and it is the property that makes handing out a code safe.

## 4b. Not caching the admin credentials — yes, and here is the shape

The owner is right that admin credentials should not persist on a workstation. They are
being typed into a machine whose whole purpose is running arbitrary commands, and enrolment
needs them exactly once.

**Use once, exchange, discard.** The credential is a bootstrap, never a stored credential:

- Entered in a password field that is not written to the config store, not autofilled and
  not remembered.
- Held in memory only for the duration of the enrolment request.
- Exchanged immediately for the thing that *does* persist — the per-workstation bearer
  token, which is scoped to one plugin and revocable core-side.
- Discarded. Re-enrolment means typing them again, which is the correct trade for not
  storing them.

**Three places it must not leak**, each of which is a real path in this codebase:

- **The audit database.** `audit_log` records `args_json`, truncated to 200 characters per
  contract §5.7. Truncation is not redaction — a short credential survives it intact.
  Enrolment arguments must be *excluded*, not shortened.
- **Logs.** The Agent scrubs credential-shaped values from tool results and denial reasons;
  the enrolment path is new and does not inherit that automatically.
- **The model.** Nothing about enrolment should ever reach the LLM.

**Better still, if the core will do it:** have the admin call mint a short-lived,
enrolment-scoped token, and use *that* for the registration write. Then the admin
credential is exposed for exactly one request to one endpoint, rather than being the thing
that performs the write.

**One honest limit.** Python strings are immutable and cannot be reliably zeroed, so a
credential may persist in the heap until garbage collection. The mitigation is a short
window and no persistence — not a claim that it is erased. Worth stating rather than
implying more than is true.

## 4c. Where the plugin definition comes from — and one trap

Three install paths, all wanted, all fine together:

1. **Manual.** The operator drops the registration into the core themselves. This is the
   air-gapped path and the fallback when anything else misbehaves. It exists today.
2. **Pushed on first deployment.** The Agent installs the plugin into the core using admin
   credentials, as §3.
3. **Fetched.** The Agent pulls the current plugin definition from the GitHub release on
   first push, rather than carrying a stale one.

### The trap in (3): "latest from GitHub" can push a registration the Agent cannot honour

Contract §2 is unambiguous that a tool the endpoint serves which the registration does not
list — **or the reverse** — is a terminal load failure. The plugin definition is therefore
not free-floating metadata; it is a description of *this Agent's* served tool set, and the
two must match exactly.

An Agent running alpha.10 that fetches "the latest release" gets whatever the newest tag
declares. If a later release adds a tool, the fetched definition lists a tool this Agent
does not serve, and the core refuses to load the plugin entirely. The failure is total, and
it is caused by the Agent being *older* than the definition it pushed — which is the normal
state of affairs for anyone who has not updated yet.

**So the definition an Agent pushes must be its own, not the newest available.** Concretely:

- The Agent already generates the registration from `served_tool_names()`, the same list the
  endpoint serves from, with a test asserting the two sets are equal in both directions.
  That property is what makes the registration correct, and it is local.
- If a definition is fetched from GitHub, it must be **the one matching this Agent's
  version**, and the Agent should still verify it against its own served set before pushing
  — refusing rather than pushing a mismatch.
- Publishing the template per release (§2) supports exactly this: the artifact is
  version-pinned, not "latest".

Fetching is genuinely useful for a *different* reason — letting a freshly installed Agent
obtain a definition without a build step. It should just never be a way to acquire a
definition that disagrees with what the Agent will actually serve.

### Configuring the plugin afterwards

Plugin settings should be reachable from the Agent when admin credentials are supplied, and
always from the core's own web UI. The core UI is the authority — it is where an operator
manages every other plugin, and where someone without workstation access has to be able to
work. The Agent's copy is a convenience for the person already standing at that machine.

Worth deciding early which way a conflict resolves, because two editors of one setting will
eventually disagree.

## 5. Revocation

Remove a workstation from the plugin config and it must not be able to reconnect without
admin credentials.

This mostly falls out of the direction above: since enrolment requires either admin
credentials or a console-visible code, a removed workstation cannot re-enrol itself. But
two details matter:

- **Removing the registration must invalidate the token**, not merely delete the manifest.
  Otherwise a re-added registration with the old token still works.
- **The Agent should learn it has been revoked**, rather than sitting there listening
  forever for a core that will never call. A revoked Agent that still holds a live endpoint
  on the LAN is the state worth avoiding.

---

## What we can build now, and what we cannot

**Now, no agreement needed:** the separate plugin artifact in the release (§2), and the
Agent-side groundwork for per-workstation naming (§1).

**Needs you:** the admin API (§3), the pairing code and its console surface (§4), and
revocation semantics (§5). All three live in your tree.

**Needs a contract amendment:** §0 records one approved core change. This is a second, plus
a new section for enrolment and a naming rule for multi-workstation registrations.

---

## Questions that are genuine forks

1. **What names a workstation?** Hostname is automatic and collides across networks; an
   operator-chosen label is clearer and can be typo'd. Whatever it is must satisfy §2's
   `^[a-z][a-z0-9-]{1,63}$` after translation, and must be stable — changing it later
   orphans a registration.
2. **Who generates the bearer token?** The Agent does today. If the core issues it during
   enrolment, revocation becomes a core-side action, which is probably what you want for §5
   — but the Agent must then accept an externally issued token, which it does not.
3. **How does the Agent authenticate the core during enrolment?** This is the one I would
   want you most deliberate about. The Agent trusts the configured address for LLM traffic;
   enrolment hands over, or receives, a long-lived credential. If that connection is not
   certificate-verified, a machine on the LAN answering first gets a working token.
4. **What can admin credentials on a workstation reach?** They are being placed on a machine
   whose entire purpose is running arbitrary commands. Scoped enrolment-only credentials
   would be much safer than full admin, and would make §4's pairing code the fallback rather
   than the safer option.
5. **TOTP or one-shot?** A continuously displayed rotating code is nicer and is what the
   owner described; it also makes a screenshot of the console a valid credential for its
   window. A code generated by pressing "Pair" is less convenient and strictly safer.
6. **Re-enrolment:** rotate the token and drop the in-flight connection, or refuse until the
   old registration is removed?

---

## Scope

None of this touches the gate, the families, the confirmation flow or the result envelope.
It replaces a clipboard with a handshake, and one hardcoded plugin name with a set. The
manual path — `export-registration` and the zip — stays for air-gapped installs and for the
case where the core is unreachable at enrolment time.
