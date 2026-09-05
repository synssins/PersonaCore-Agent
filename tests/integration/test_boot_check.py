"""Runs scripts/boot_check.py as a subprocess with --fake-backends.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""
# ruff: noqa: T201, S603

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BOOT_CHECK = _REPO_ROOT / "scripts" / "boot_check.py"

_BOOT_TIMEOUT_S = 60  # boot_check itself budgets 30s; give the subprocess headroom


def test_boot_check_exits_zero(tmp_path: Path) -> None:
    """Boot check subprocess must exit 0 within budget."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PC_AGENT_APPDATA"] = str(tmp_path / "appdata")
    env["PC_AGENT_SKIP_MCP_PIPE"] = "1"

    result = subprocess.run(
        [sys.executable, str(_BOOT_CHECK), "--fake-backends"],
        env=env,
        capture_output=True,
        text=True,
        timeout=_BOOT_TIMEOUT_S,
        check=False,
    )
    if result.returncode != 0:
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
    assert result.returncode == 0
