"""Shared fixtures for SPEC-03A unit tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the repo root is importable so ``python -m tests.fakes.echo_plugin``
# works when spawned as a subprocess by the supervisor.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture
def repo_root() -> Path:
    return _REPO_ROOT


@pytest.fixture
def echo_plugin_cmd() -> list[str]:
    """Command line that spawns the echo plugin as an MCP stdio server."""
    return [sys.executable, "-u", "-m", "tests.fakes.echo_plugin"]
