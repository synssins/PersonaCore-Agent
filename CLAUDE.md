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

To install locally:

```bash
pip install -e .[dev]
```

To run tests:

```bash
pytest -q
```

To check code quality:

```bash
ruff check .
pyright
```

To run the agent placeholder:

```bash
python -m workstation_agent
```
