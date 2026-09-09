# SPEC R1 — Verify AGENT-BRIEF.md's factual claims about this tree

## Goal

The brief at `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md` makes eight
factual assertions about the repository you are standing in (`C:\Projects\GameTest`, the
`workstation_agent` package). It instructs the reader to verify them before building and to
stop and say so if one is wrong.

Produce a claim-by-claim verdict, backed by evidence from the actual code.

## The claims

Verify each independently:

1. **MCP server is a named pipe with a token**, in `mcp_host/mcp_server.py`.
   Confirm the transport really is a Windows named pipe, confirm a token is required, and
   note the pipe name and how the token is generated/stored/compared.
2. **The plugin tools for powershell, filesystem, screen, clipboard, desktop and browser
   return `not_implemented`.** Check all six families. Report per family whether *every*
   tool returns `not_implemented` or only some do — a family with real behaviour in some
   tools makes the claim partly true, and that matters for work item A2.
3. **Permissions are default-deny.** Find the permission check and confirm that an unlisted
   or unknown tool/permission is denied rather than allowed.
4. **Confirmable conditions with toast and voice.** Confirm both notification paths exist
   and are wired to the confirm flow, not merely present as unused modules.
5. **Plugins are Ed25519-signed.** Confirm signature verification exists and is actually
   enforced on load (and note whether it can be bypassed, e.g. a dev/unsigned mode).
6. **Append-only `audit.db`.** Confirm the audit store exists and identify what enforces
   append-only-ness (schema, triggers, code discipline, or nothing).
7. **No ADB, serial or USB code.** Search the whole tree. Any hit — including a dependency,
   a stub, a setting or a doc-level reference — is reported.
8. **The `mcp` PyPI package was dropped on purpose and JSON-RPC is inline.** Confirm `mcp`
   is absent from `pyproject.toml` and imports, confirm the JSON-RPC implementation is
   in-tree, and find whatever record exists of the decision (docs, specs under
   `docs/superpowers/specs/`, `working/`, or git history).

## Constraints

- **Read-only.** Do not modify, create or delete any file anywhere except your one output
  file named below. No `git` commands that write (no commit, checkout, stash, restore).
- Do not modify anything under `C:\Projects\PersonaCore\` — read only.
- Do not touch `working/` other than your own output file.
- Do not implement anything. If you notice a bug, report it; do not fix it.
- Do not install packages or run `pip`. If you need to run Python, use
  `.venv\Scripts\python.exe` per CLAUDE.md — but you should not need to run anything;
  reading and grepping is enough.

## Acceptance criteria

- All eight claims have a verdict of exactly one of: **TRUE**, **FALSE**, **PARTLY TRUE**.
- Every verdict cites concrete evidence as `path/to/file.py:LINE` (a line number, not just a
  filename) or, for absence claims like #7, the exact search performed and its null result.
- For any **FALSE** or **PARTLY TRUE** verdict, state precisely what the tree actually does
  instead, and say in one line what it means for the brief (which work item it affects).
- Claim 2 is broken out per family (powershell, filesystem, screen, clipboard, desktop,
  browser) — six sub-verdicts, not one.
- Claim 7 covers all three of ADB, serial, USB separately.
- A closing section, **STOP-CLAUSE**, answering: does any wrong claim rise to the level where
  the brief's own "stop and say so if one is wrong" instruction is triggered? Yes/no with
  reasoning. Be honest — a trivially imprecise claim is not a stop; a claim whose wrongness
  would change what gets built is.
- No claim is marked TRUE on the strength of a filename alone. Open the file.

## How to test

There is nothing to run. Self-check before finishing: re-read each verdict and confirm the
cited line actually says what you claim it says. Cited line numbers that don't match the
content are the main failure mode here.

## Output

Write your report to `working/brief-review/R1/REPORT.md`. That is the only file you create.

End your report with a **SUMMARY** section: a table of claim number → verdict, and one
sentence stating whether the stop-clause fires.
