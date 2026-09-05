# ruff: noqa: S101, S603
"""Shared fixtures for the updater integration test.

Builds the Go binary exactly once per session, with a fresh Ed25519
keypair whose public half is baked in via ``-ldflags -X``. Tests then
sign fixtures with the matching private key and hand them to the
freshly-built ``Updater.exe``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

REPO_ROOT = Path(__file__).resolve().parents[3]
UPDATER_SRC = REPO_ROOT / "updater"


@pytest.fixture(scope="session")
def signing_keypair() -> tuple[SigningKey, bytes]:
    """Return (SigningKey, 32-byte verify_key_bytes)."""
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key)


@pytest.fixture(scope="session")
def updater_binary(tmp_path_factory: pytest.TempPathFactory,
                   signing_keypair: tuple[SigningKey, bytes]) -> Path:
    """Build Updater.exe once per session with the test pubkey baked in."""
    _, pub = signing_keypair
    pubhex = pub.hex()

    go_exe = _resolve_go()
    if go_exe is None:
        pytest.skip("Go toolchain not available (needed to build Updater.exe)")

    outdir = tmp_path_factory.mktemp("updater-build")
    binary = outdir / "Updater.exe"

    ldflags = f"-X main.PublicKeyHex={pubhex} -X main.UpdaterVersion=0.0.0-test"
    cmd = [
        go_exe,
        "build",
        "-ldflags",
        ldflags,
        "-o",
        str(binary),
        ".",
    ]
    result = subprocess.run(
        cmd,
        cwd=UPDATER_SRC,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"go build failed (exit {result.returncode})\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )
    assert binary.exists(), f"expected binary at {binary}"
    return binary


def _resolve_go() -> str | None:
    """Find `go` on PATH or in the default Windows install location."""
    from_path = shutil.which("go")
    if from_path:
        return from_path
    if sys.platform == "win32":
        candidate = Path("C:/Program Files/Go/bin/go.exe")
        if candidate.exists():
            return str(candidate)
    return None
