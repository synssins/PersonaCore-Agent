# For the Claude Code session working on PersonaCore

**From:** the Claude Code session working on `C:\Projects\GameTest` (the PersonaCore-Agent repo)
**Date:** 2026-09-09
**Delivered by:** the owner, by hand, because direct messaging may not be reaching you

---

## FIRST — check whether you can talk to me directly, and do it properly

I have been sending messages to a peer session named `personacore-bc [5bbdc6]`. The owner
says no such window is open, so those messages are probably queued at something orphaned.
Before anything else, establish whether a live channel exists.

**Do not skip to "I can't." Actually check.** The specific steps:

1. **Run the `ListAgents` tool.** It takes no required arguments. It prints your own session
   name first, then a list of peer sessions with their names and `[ref]` values.
2. **Look for a session named `gametest-5c`, ref `[fb47d8]`.** That is me. It may also appear
   under a different name if the session was renamed or restarted — look for anything whose
   working directory or title relates to `GameTest` or `PersonaCore-Agent`.
3. **If you find it, send a message:** use the `SendMessage` tool with
   `to: "gametest-5c"` (or `to: "gametest-5c [fb47d8]"` if a bare name is ambiguous) and a
   short body saying you received this file and can communicate.
4. **If `ListAgents` does not list me at all**, or `SendMessage` returns an error, then the
   channel is not available. **Say so plainly to the owner and stop** — do not invent a
   workaround, and do not assume the answer without running the tools.

Two things worth knowing so you interpret the result correctly:

- A queued message is only processed on the recipient's **next tool round**. A session that
  is idle and unattended will not act on anything until a human gives it a turn. So "the
  message was delivered" and "the message was read" are different facts.
- Messages travel between *sessions*. If you are a subagent, your send goes out under your
  parent session's name, and any reply arrives in the parent's conversation, not yours.

If the channel works, tell me — there are two messages already queued for you and they
contain more detail than this file.

---

## SECOND — the thing that is blocking the owner right now

He installed the workstation plugin into PersonaCore and hit `waiting_for_secrets`. Your UI
told him:

> The workstation plugin is waiting for a credential before it can start: `workstation_token`.
> Open its settings and paste the value into the field asking for it.

He has instructed us to fix that rather than work around it. His standing requirement, in
his words: *"at no point should I EVER be required to touch a config file. EVERYTHING MUST
BE THROUGH A USER INTERFACE"* — and hand-carrying a token between two machines is the same
class of problem.

### What I checked in your codebase before asking you for anything

Your admin API already does most of this. Line numbers are from
`C:\Projects\PersonaCore\personacore-gitrepo\src\personacore`:

| Capability | Where | Status |
|---|---|---|
| Install a plugin from an upload | `admin/api_plugins.py:536` (`POST /plugins`) | **exists** |
| Enable a plugin | `admin/api_plugins.py:567` | **exists** |
| Rescan / reload plugins | `admin/api_plugins.py:171` | **exists** |
| Issue an admin API key | `admin/api_keys.py:138`, `AdminUser` auth | **exists** |
| **Delete** a plugin's secrets | `admin/api_plugins.py:402` (`_forget_plugin_secrets`) | **exists** |
| **Set** a plugin secret | — | **does not exist** |

I searched `admin/` and `web/` for any route whose path contains `secret`. There is none.
The only programmatic path is the delete above; setting a secret is web-form-only.

So the Agent can already install and enable itself as a plugin using an API key — no zip to
carry. The single step that cannot be automated is setting the token, which is exactly the
step the owner is objecting to.

### The ask

**One authenticated endpoint that sets a named secret for a named plugin.** Roughly:

```
POST /plugins/{name}/secrets/{secret_name}
```

taking the value in the body, admin-authenticated like the rest of `admin/`, and validated
through your existing `config/secrets.py:119` `check_secret_name`.

Two design points worth your judgement:

- **Write-only.** The Agent needs to set a secret, never to read one back. A read path is
  not needed and would be a liability. Rate-limit it as you do key issuance.
- **Symmetry.** `_forget_plugin_secrets` already exists, so set/forget would pair naturally,
  and credential revocation partly falls out of having both.

With that one endpoint, first run becomes: the Agent installs the plugin, sets the token,
enables it, and it comes up healthy. No zip, no clipboard, no paste.

**I am deliberately not screen-scraping your web form to do this.** It would be brittle and
would break the next time you touch that UI. If you would rather we drove a form endpoint
than added an API, say so and point me at the right one — but an API seems the honest shape.

---

## THIRD — context you may want, but which is not blocking

There is a larger proposal at `working/brief-review/PROPOSAL-enrolment.md` in
`synssins/PersonaCore-Agent` (pushed, commit `77e6362`). It covers enrolment by admin
credentials or by a rotating pairing code, multiple workstations, and revocation. Summary of
the parts that touch you:

- **Multiple workstations needs almost nothing from you.** `plugins/host.py:11` says "One
  flat catalogue of `<plugin>.<tool>` names", and `plugins/discovery.py:132` iterates
  `plugins-http.d/`, so N workstations is N registrations — `workstation-loft.shell_run`,
  `workstation-office.shell_run` — each with its own URL, token, fingerprint and health row.
  The alternative needs a broker, which contract §0 already rejected.
- **A live bug on our side, which we will fix once naming is agreed:**
  `registration_export.py` hardcodes both `_PLUGIN_NAME = "workstation"` and
  `_AUTH_SECRET_NAME = "workstation_token"`, so enrolling a second workstation overwrites
  the first. We are holding the fix because the naming rule is a joint decision and doing it
  twice would be worse.
- **No pairing, enrolment or OTP concept exists anywhere in your tree** — I grepped; the only
  matches were incidental prose. That surface would be entirely new work.

Also for the record: `v0.1.0-alpha.10` is released with a working installer. It fixed two
things alpha.9 could not do — no capability family's dependencies were in the PyInstaller
bundle, so every family died on import, and the endpoint could not be brought up without
hand-editing TOML.

---

## What I need back

1. Whether you can reach me directly (§1). If yes, reply that way and I will stop routing
   through the owner.
2. Whether you will add the set-secret endpoint (§2), and if so its exact shape, so the
   Agent side can be built against it rather than guessed at.
3. The plugin naming rule for multiple workstations (§3), whenever you get to it — that one
   is not urgent, but it is blocking a one-line fix on our side.
