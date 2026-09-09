# SPEC R2 — Buildability review of AGENT-BRIEF.md work items A1–A6

## Goal

The brief at `C:\Projects\PersonaCore\working\team\workstation\AGENT-BRIEF.md` describes six
work items (A1–A6) that this repository (`C:\Projects\GameTest`, the `workstation_agent`
package) must deliver, plus a list of "Things that would be wrong". Its governing contract is
`C:\Projects\PersonaCore\working\contracts\workstation.md`.

Assess whether the brief is buildable **as written**: what already exists here, what is
missing, what the brief leaves undefined, and where it conflicts with the contract or with
this repo's own rules.

You are reviewing the brief, not the codebase in general. Findings must trace back to
something the brief asks for or forbids.

## Inputs

- The brief (path above).
- The contract (path above) — read the sections the brief cites: §2, §3, §5.2, §5.4, §5.5,
  §5.6, §7, §10, §11.
- This repo: `src/workstation_agent/`, `pyproject.toml`, `CLAUDE.md`, `docs/`, `tests/`.
- **`working/brief-review/R1/REPORT.md`** — the completed, orchestrator-reviewed verification
  of the brief's eight factual claims about this tree. **Treat it as your factual baseline.**
  Do not re-derive what R1 already established; cite it. If your own reading contradicts an
  R1 verdict, say so explicitly and show the evidence — do not silently override it.

## What to produce

**Part 1 — Per work item (A1 through A6):**
- What already exists in this tree that A<n> can build on (`file:line`).
- What is missing.
- What the brief leaves **undefined or ambiguous** — a question the implementer would have
  to answer or guess. Be specific; "needs more detail" is not a finding, "the brief does not
  say which interface list the operator chooses from, or what happens when the chosen NIC's
  IP changes" is.
- Contract conflicts: anything where the brief and the contract disagree, or where the brief
  cites a contract section that does not say what the brief implies. Quote both.
- A difficulty call: **trivial / default / hard**, with a reason. This feeds the eventual
  build plan's tiering.

Pay particular attention to:
- **A1**: the `mcp`-package-vs-inline-JSON-RPC choice. Do *not* decide it. Lay out what each
  option costs given what is in the tree today (the existing inline JSON-RPC, the venv
  situation described in CLAUDE.md, the earlier `mcp` clash the brief mentions). Also: cert
  generation with SAN = hostname + LAN IP, showing token/cert once with copy buttons in the
  existing UI, `401` handling, and interface binding — does the existing UI have anywhere
  for this to live?
- **A2**: the "Desktop Commander may be hosted behind the gate instead" option. Is that a
  real fork in the road or a distraction? Say which and why.
- **A6**: contract §11 items 1–7 are the done-condition. Are they actually testable from
  this side, or do some require PersonaCore to be running?

**Part 2 — "Things that would be wrong":**
The brief lists **seven** bullets in that section. For each of the seven, state whether current code already violates it, is at risk of
violating it, or is clear. Cite evidence. Specifically check:
- Tool names against `^[a-z][a-z0-9-]{1,63}$` after `_`→`-`. Enumerate the tool names this
  repo currently exposes and test them against that regex. Report any that fail — including
  names that are too short (the regex requires 2–64 characters total).
- Whether an export/registration path exists at all today (`Agent.exe export-registration`),
  and whether anything currently guarantees the endpoint's tool set matches it.
- The `safe`-only rating rule versus the confirmable-conditions machinery this repo already
  has: the brief says PersonaCore refuses `confirm` tools today, but the repo is built around
  confirm flows. Is that a contradiction? Analyse it — it is the most likely real problem in
  the brief.
- Anything in the current code that could return an absolute path outside the roots, a stack
  trace, or the token in a tool result.
- **The 25 s boundary.** Which currently-planned or currently-existing operations can exceed
  25 s, and does the brief's job model (contract §5.4: in-memory, ≤ 8, die with the Agent)
  actually cover them? Name the operations.
- **"Prompting for reads."** The brief forbids it: the pre-approved list exists so that an
  absent owner blocks *actions* only. Does this repo's current confirm/permission flow
  distinguish reads from actions at all? If not, that is a finding.
- **`0.0.0.0` and plain HTTP.** Check what the existing server binds to and whether any
  current default, setting, config schema or test would lead an implementer to bind all
  interfaces or serve plain HTTP.

**Part 2b — The "Not yours" section:**
The brief ends by putting four things out of scope for v1 (hotplug events, screenshots the
model can see, binary into the workspace, voice on the workstation), each waiting on a
PersonaCore-side decision per contract §10. For each:
- Does any of A1–A6, as written, implicitly *require* it? (E.g. does `devices_list` in A3
  edge into hotplug; does A2's `files` edge into binary-into-workspace.) A work item that
  cannot be completed without an out-of-scope capability is a serious brief defect — say so.
- Does the capability already exist in this tree today? This repo has screen/vision, clipboard
  and audio code. If an out-of-scope capability is already present and reachable through the
  new endpoint, that is a finding: the brief's scope line and the tree disagree.

**Part 3 — Overall:**
- The three most serious problems with the brief, ranked, each with what it would cost if not
  resolved before building.
- Anything the brief does not mention that this repo's own rules require (CLAUDE.md: mandatory
  `.venv`, Hatchling, Windows-only, unit + integration tests per subtask, worker path
  isolation).
- Whether the dependency order A1→A6 is actually the right order, or whether something is
  mis-ordered.

## Constraints

- **Read-only.** Do not modify, create or delete any file anywhere except your one output
  file named below. No writing `git` commands.
- Do not modify anything under `C:\Projects\PersonaCore\` — read only.
- Do not implement anything, not even a stub or a one-line fix. Report only.
- Do not install packages or run `pip`. If you must run Python use `.venv\Scripts\python.exe`
  per CLAUDE.md.

## Acceptance criteria

- All six work items A1–A6 covered, each with all five headings (exists / missing /
  undefined / contract conflicts / difficulty).
- All **seven** "Things that would be wrong" bullets addressed individually.
- The tool-name regex check is done by actually enumerating this repo's tool names and
  testing them, not by assertion.
- The `safe`-vs-`confirm` tension is analysed, not just noted.
- Every finding cites either a `file:line` in this repo or a quoted line from the brief or
  the contract. No unsupported assertions.
- All four "Not yours" items addressed, both directions (does A1–A6 need it / does the tree
  already have it and expose it).
- Where a finding rests on something R1 established, R1 is cited rather than re-derived; any
  disagreement with an R1 verdict is stated openly with evidence.
- Part 3 ranks exactly three top problems, with consequences.
- Findings are about the brief's buildability. General code-quality gripes unrelated to
  A1–A6 are out of scope — omit them.

## How to test

Nothing to run. Self-check: every `file:line` you cite must actually contain what you say it
does, and every contract quote must be verbatim.

## Output

Write your report to `working/brief-review/R2/REPORT.md`. That is the only file you create.

End with a **SUMMARY** section: one line per work item giving its difficulty call, then the
three ranked problems as one line each.
