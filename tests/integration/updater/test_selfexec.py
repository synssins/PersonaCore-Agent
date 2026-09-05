# ruff: noqa: S101, S603, PLW1510
r"""Integration test for the SPEC-06 self-copy relay dance.

The Go updater is designed to break the ERROR_SHARING_VIOLATION that
would otherwise occur when it swaps the `current` junction that its own
image was loaded from. Concretely:

1. First invocation (env sentinel unset) -> updater copies itself to
   ``%TEMP%\PC-Agent-Updater-<ver>.exe`` and spawns that copy with
   ``PC_AGENT_UPDATER_SELF_RELAY`` set. Parent exits, releasing the
   file handle on the original binary.
2. Second invocation (env sentinel set) -> updater proceeds in-process
   without another copy.

We assert the observable difference by inspecting %TEMP% before and
after the two runs. We do NOT need the update to succeed — ``--check``
fails fast when required flags are missing, but that failure happens
AFTER the relay has (or hasn't) fired, which is exactly the signal we
want. Using ``--check`` avoids needing a signed manifest or install
root just to drive the relay code path.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="self-copy relay is Windows-only",
)


def _list_updater_copies(temp_dir: Path) -> list[Path]:
    """All ``PC-Agent-Updater-*.exe`` files under a temp dir."""
    return sorted(temp_dir.glob("PC-Agent-Updater-*.exe"))


def test_selfexec_first_call_copies_then_second_call_passes_through(
    tmp_path: Path,
    updater_binary: Path,
) -> None:
    """First run makes a copy; second run (sentinel set) does not.

    We isolate the temp directory used by the child process by
    exporting ``TEMP`` and ``TMP`` for the subprocess. Then we can
    inspect that directory directly for the presence (or absence) of a
    ``PC-Agent-Updater-*.exe`` file.

    We drive the relay via ``--rollback`` (not ``--update``) because
    ``cmdRollback`` relays FIRST, before any file I/O — so a bogus
    install root still exercises the relay code path deterministically.
    ``cmdUpdate`` reads pending_update.json before relaying, so a
    missing pending file short-circuits the relay entirely.
    """
    scratch_temp = tmp_path / "scratch-temp"
    scratch_temp.mkdir()

    # --- Baseline: no copies exist yet.
    assert _list_updater_copies(scratch_temp) == []

    # --- Run 1: sentinel unset -> updater SHOULD copy itself.
    env_first = {
        **os.environ,
        "TEMP": str(scratch_temp),
        "TMP": str(scratch_temp),
    }
    env_first.pop("PC_AGENT_UPDATER_SELF_RELAY", None)
    result_first = subprocess.run(
        [
            str(updater_binary),
            "--rollback",
            "0.0.9-relaytest",
            "--install-root",
            str(tmp_path / "install"),
            "--logs-dir",
            str(tmp_path / "logs1"),
        ],
        capture_output=True,
        text=True,
        env=env_first,
        timeout=60,
    )
    copies_after_first = _list_updater_copies(scratch_temp)
    assert copies_after_first, (
        f"expected a PC-Agent-Updater-*.exe under {scratch_temp} after first "
        f"invocation; nothing found. Parent exit={result_first.returncode} "
        f"stdout={result_first.stdout!r} stderr={result_first.stderr!r}"
    )
    copy_path = copies_after_first[0]
    assert copy_path.stat().st_size > 0, "copy should be a non-empty binary"

    # --- Run 2: sentinel SET -> updater must NOT copy again.
    env_second = {
        **os.environ,
        "TEMP": str(scratch_temp),
        "TMP": str(scratch_temp),
        "PC_AGENT_UPDATER_SELF_RELAY": str(updater_binary),
    }
    subprocess.run(
        [
            str(updater_binary),
            "--rollback",
            "0.0.9-relaytest",
            "--install-root",
            str(tmp_path / "install"),
            "--logs-dir",
            str(tmp_path / "logs2"),
        ],
        capture_output=True,
        text=True,
        env=env_second,
        timeout=60,
    )
    copies_after_second = _list_updater_copies(scratch_temp)
    # No NEW copies should have appeared (the same file may still be
    # there from run 1, but the count must not have grown).
    assert len(copies_after_second) == len(copies_after_first), (
        f"sentinel-set run should not create a new copy; "
        f"before={copies_after_first}, after={copies_after_second}"
    )


def test_selfexec_copy_name_encodes_version(
    tmp_path: Path,
    updater_binary: Path,
) -> None:
    """The %TEMP% copy filename includes the version we're relaying for.

    We can't easily set the "version" from outside because it comes
    from the pending file; but for --update with a missing pending file
    the code path fails BEFORE relay in the update handler — the relay
    for --update is gated on loading pending. For --rollback the version
    comes from the CLI flag directly. Use that.
    """
    scratch_temp = tmp_path / "scratch-temp"
    scratch_temp.mkdir()
    env = {
        **os.environ,
        "TEMP": str(scratch_temp),
        "TMP": str(scratch_temp),
    }
    env.pop("PC_AGENT_UPDATER_SELF_RELAY", None)
    subprocess.run(
        [
            str(updater_binary),
            "--rollback",
            "1.2.3-testrelay",
            "--install-root",
            str(tmp_path / "no-such-install"),
            "--logs-dir",
            str(tmp_path / "logs"),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    copies = _list_updater_copies(scratch_temp)
    assert copies, "expected a relay copy after --rollback"
    # Version substring must appear in the filename.
    matched = [c for c in copies if "1.2.3-testrelay" in c.name]
    assert matched, (
        f"expected a copy with '1.2.3-testrelay' in the name; got {[c.name for c in copies]}"
    )
