"""A fake ``adb`` binary that is a real executable, not a mock.

There is no phone attached to this workstation and no ``adb`` installed on it,
so every ADB test needs a stand-in.  Patching ``subprocess.run`` would be the
easy stand-in and the wrong one: the brief's warning is precisely that an
implementation which passes its mocks fails on real hardware, and the parts
most likely to fail — argv construction, byte-level capture, the timeout path,
a non-zero exit code, output that is not valid UTF-8 — are exactly the parts a
patched ``subprocess.run`` never exercises.

So the fake is a ``.bat`` shim that runs a Python script under the venv
interpreter.  ``run_adb`` spawns it through the ordinary ``subprocess.run`` code
path, with real argv, real pipes, real bytes and a real exit code.  The script
decides what to emit from a JSON script file, including raw non-UTF-8 bytes,
which a ``.bat`` alone cannot produce.
"""

from __future__ import annotations

import json
import os
import sys

# Both imports are used in runtime fixture annotations, which pytest reads at
# collection time; moving them into a TYPE_CHECKING block breaks collection.
from collections.abc import Iterator  # noqa: TC003
from pathlib import Path  # noqa: TC003

import pytest

_RUNNER = r"""
import json, os, sys, time

spec = json.loads(open(os.environ["FAKE_ADB_SPEC"], "r", encoding="utf-8").read())
argv = sys.argv[1:]

# Record the argv every invocation was given, so a test can assert on what
# `run_adb` actually built rather than on what it meant to build.
with open(os.environ["FAKE_ADB_CALLS"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(argv) + "\n")

rule = None
for candidate in spec.get("rules", []):
    if all(token in argv for token in candidate.get("match", [])):
        rule = candidate
        break
if rule is None:
    rule = spec.get("default", {})

if rule.get("sleep"):
    time.sleep(float(rule["sleep"]))

out = rule.get("stdout", "")
if isinstance(out, str):
    sys.stdout.buffer.write(out.encode("utf-8"))
else:
    sys.stdout.buffer.write(bytes(out))
err = rule.get("stderr", "")
if isinstance(err, str):
    sys.stderr.buffer.write(err.encode("utf-8"))
else:
    sys.stderr.buffer.write(bytes(err))
sys.stdout.buffer.flush()
sys.stderr.buffer.flush()
sys.exit(int(rule.get("returncode", 0)))
"""


class FakeAdb:
    """Handle onto a scripted fake ``adb`` executable."""

    def __init__(self, path: Path, spec_file: Path, calls_file: Path) -> None:
        self.path = str(path)
        self._spec_file = spec_file
        self._calls_file = calls_file

    def script(self, rules: list[dict], default: dict | None = None) -> None:
        """Set what the fake emits.

        Each rule matches when every token in ``match`` appears in argv, so a
        rule can key on ``["shell", "getprop"]`` without caring where the
        ``-s <serial>`` prefix landed.
        """
        payload = {"rules": rules, "default": default or {"stdout": "", "returncode": 0}}
        self._spec_file.write_text(json.dumps(payload), encoding="utf-8")

    def devices(self, listing: str, *, returncode: int = 0) -> dict:
        """Convenience rule for ``adb devices -l``."""
        return {"match": ["devices"], "stdout": listing, "returncode": returncode}

    @property
    def calls(self) -> list[list[str]]:
        """Every argv the fake was invoked with, in order."""
        if not self._calls_file.exists():
            return []
        return [
            json.loads(line)
            for line in self._calls_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


ONE_DEVICE = (
    "List of devices attached\n"
    "R58N12ABCDE            device product:beyond1lte model:SM_G973F "
    "device:beyond1lte transport_id:1\n"
)
NO_DEVICES = "List of devices attached\n"
TWO_DEVICES = (
    "List of devices attached\n"
    "R58N12ABCDE            device product:beyond1lte model:SM_G973F transport_id:1\n"
    "emulator-5554          device product:sdk_gphone model:Pixel_6 transport_id:2\n"
)
UNAUTHORISED = (
    "List of devices attached\n"
    "R58N12ABCDE            unauthorized usb:1-3\n"
)


@pytest.fixture
def fake_adb(tmp_path: Path) -> Iterator[FakeAdb]:
    """Yield a scripted fake ``adb`` that really executes."""
    runner = tmp_path / "fake_adb_runner.py"
    runner.write_text(_RUNNER, encoding="utf-8")
    spec_file = tmp_path / "fake_adb_spec.json"
    calls_file = tmp_path / "fake_adb_calls.jsonl"

    shim = tmp_path / "adb.bat"
    shim.write_text(
        f'@echo off\r\n"{sys.executable}" "{runner}" %*\r\n',
        encoding="utf-8",
    )
    os.environ["FAKE_ADB_SPEC"] = str(spec_file)
    os.environ["FAKE_ADB_CALLS"] = str(calls_file)

    fake = FakeAdb(shim, spec_file, calls_file)
    fake.script([], default={"stdout": "", "returncode": 0})
    try:
        yield fake
    finally:
        os.environ.pop("FAKE_ADB_SPEC", None)
        os.environ.pop("FAKE_ADB_CALLS", None)


@pytest.fixture
def one_device(fake_adb: FakeAdb) -> FakeAdb:
    """A fake ``adb`` reporting exactly one attached, authorised device."""
    fake_adb.script([fake_adb.devices(ONE_DEVICE)])
    return fake_adb
