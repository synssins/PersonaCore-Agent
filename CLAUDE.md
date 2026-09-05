# PersonaCore-Agent Framework Build

This repository contains the scaffolding and skeletal implementations for **PersonaCore-Agent**, a Windows-first voice-controlled AI agent.

## Overview

This is the **framework build**, not the finished product. Every subsystem is structured as a compile-clean, unit-tested skeleton with the interface locked. Real audio and LLM integrations are deferred to v0.2.

See `/docs/superpowers/specs/` for the complete design specification and `working/PLAN.md` for the breakdown of all subtasks.

## Team Rules

1. **No worker touches `working/`** — the orchestrator owns all planning artifacts.
2. **No worker touches files outside their SPEC's allowed-paths list** — isolation prevents conflicts.
3. Every subtask ships implementation + unit tests + integration tests where interfaces are touched.

## Build Information

- **Build system:** Hatchling
- **Python:** 3.12+
- **Development dependencies:** ruff, pyright, pytest, pytest-asyncio, pytest-cov
- **Windows-only target**

## Virtual environment — MANDATORY

**This project MUST run from its own venv at `.venv/`.** Never `pip install` against system Python — you will clobber the system's `mcp` (and other) packages that PersonaCore, Vesmark, and other projects on this workstation depend on. That specifically has happened; do not repeat it.

First-time setup (one command):

```bash
C:\Python314\python.exe -m venv .venv
.venv\Scripts\python.exe -m pip install -e .[dev]
```

From then on, every project command runs through `.venv\Scripts\python.exe`:

```bash
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m pyright
.venv\Scripts\python.exe -m workstation_agent
```

Or activate the venv once per shell (`.venv\Scripts\activate`) and drop the prefix. Either works; the point is that `python`, `pip`, `pytest` etc. must resolve to the venv, not `C:\Python314\python.exe` directly.

If a subagent's SPEC or executor instructions say "run `pip install -e .[dev]`" without the venv path, it means "run it inside the venv." Never run bare `pip install` against system Python from this project.
