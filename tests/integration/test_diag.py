"""Runs ``python -m workstation_agent --diag --fake-backends`` as a subprocess.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""
# ruff: noqa: T201

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_diag_reports_every_subsystem_ok(tmp_path: Path) -> None:
    """--diag must exit 0 and print an OK line per subsystem."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PC_AGENT_APPDATA"] = str(tmp_path / "appdata")
    env["PC_AGENT_SKIP_MCP_PIPE"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "workstation_agent", "--diag", "--fake-backends"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

    assert result.returncode == 0
    assert "OK" in result.stdout
    # Every subsystem row prints Status=OK or FAIL.  Assert no FAIL line.
    assert "FAIL" not in result.stdout
