# PLAN — Review of AGENT-BRIEF.md (workstation plugin v1)

**Task:** Review `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md`.
**Orchestrator:** this session (Opus 5, 1M context), in `C:\Projects\GameTest`.
**Date:** 2026-09-08

## Context

The brief was written 2026-09-08 by the PersonaCore side and is addressed to the session
running in `C:\Projects\GameTest` (this repo — the Agent / `workstation_agent` package).
The brief's governing contract is `C:\Projects\PersonaCore\working\contracts\workstation.md`.

The brief contains an explicit, non-optional instruction to the reader:

> **Verify this brief's claims about your own tree before building. Stop and say so if one
> is wrong.**

So this is not an open-ended "what do you think" review. It has a hard deliverable: a
claim-by-claim verdict on the brief's eight factual assertions about this tree, with
evidence, plus a judgement on whether the work it describes is buildable as specified.

**This is a REVIEW ONLY.** No implementation of A1–A6 happens in this task. No source file
in `src/` is modified. The output is a report.

## Deliverable

A single review report covering:
1. Each of the brief's factual claims about this tree: TRUE / FALSE / PARTLY TRUE, with
   `file:line` evidence.
2. Whether any claim being wrong triggers the brief's own "stop and say so" clause.
3. Gaps, ambiguities and contradictions in the work items A1–A6, checked against the
   contract and against what this repo actually contains today.
4. Whether the "Things that would be wrong" constraints are already violated by, or are in
   tension with, existing code.

## Subtasks

| ID | Title | Class | Executor | Depends on |
|----|-------|-------|----------|------------|
| R1 | Verify the brief's 8 factual claims about this tree | default | sonnet | — |
| R2 | Gap / feasibility review of A1–A6 + the constraint list, against the contract | hard | opus | R1 |

**R1 and R2 run SEQUENTIALLY, not in parallel** (revision 2, on the plan auditor's finding).
Two reasons, both accepted from the audit:

1. The brief's "stop and say so if one is wrong" is a *gate*, not a reporting detail. If R1
   finds a claim false in a way that invalidates a work item's premise, R2's buildability
   analysis of that item would be reasoning from a false baseline. The orchestrator reads
   `R1/REPORT.md` and decides whether the stop-clause fires **before** dispatching R2.
2. R2's "what already exists" analysis would otherwise re-run exactly the searches R1 does
   for claims 2, 7 and 8. Feeding `R1/REPORT.md` into R2 as a verified baseline removes the
   duplication.

Both subtasks are strictly read-only; each writes only its own report file under
`working/brief-review/<ID>/`. No git worktree is needed because neither writes tracked source.

### R1 — Claim verification

The brief asserts eight things about this tree. Each is verified against the actual code:

1. The MCP server is a named pipe with a token (`mcp_host/mcp_server.py`).
2. The plugin tools for powershell, filesystem, screen, clipboard, desktop and browser
   return `not_implemented`.
3. Permissions are default-deny.
4. There are confirmable conditions with toast and voice.
5. Plugins are Ed25519-signed.
6. There is an append-only `audit.db`.
7. There is no ADB, serial or USB code.
8. The `mcp` PyPI package was dropped on purpose and JSON-RPC is inline.

### R2 — Buildability review

Takes `R1/REPORT.md` as a verified input: R2 does not re-derive what exists in the tree for
anything R1 already established, and treats R1's verdicts as its factual baseline.

For each work item A1–A6: what already exists, what is missing, what the brief leaves
undefined, and where it conflicts with the contract or with this repo's own rules
(CLAUDE.md: venv-mandatory, Hatchling, Windows-first, tests required). Also checks each
"Things that would be wrong" bullet against current behaviour — in particular the tool-name
regex `^[a-z][a-z0-9-]{1,63}$` after `_`→`-`, the registration/endpoint tool-set symmetry,
the `safe`-only rating rule, and the 25 s / job boundary.

## Tiering rationale

**R1 — default (sonnet).** Careful reading and grepping over a known tree against a fixed
eight-item checklist. It needs judgement about what counts as a claim being satisfied, but
no architectural synthesis. Not trivial (haiku would rubber-stamp filenames); not hard.

**R2 — hard (opus).** Raised from the originally-proposed sonnet on the plan auditor's
recommendation, which I accept. R2 cross-references the brief against nine sections of the
contract, weighs an architectural trade-off (the `mcp` package versus the existing inline
JSON-RPC), and has to resolve a logical tension the auditor and I both expect to be the real
problem in the brief — that PersonaCore refuses `confirm`-rated tools while this repo is
built around confirm flows. That is system-design evaluation, not lookup.

## Verification

The completed reports go to the verifier (non-Anthropic, per roster) with the brief, the
contract and the reports attached, asking whether the claim verdicts are supported by the
evidence cited and whether the review missed anything material in the brief.

## Out of scope

- Implementing A1–A6 or any part of them.
- Editing `src/`, `tests/`, `installer/`, `updater/`.
- Changing anything in `C:\Projects\PersonaCore\` (read-only from here).
- Deciding the `mcp`-package-vs-inline-JSON-RPC question of A1 — the brief leaves that to
  the implementer at build time; the review only flags what each choice would cost.
