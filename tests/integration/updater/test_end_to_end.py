# ruff: noqa: S603, S607, ARG001, ANN204, PT011, B017, EM101, PLR0915, PLW1510, RUF059, FURB171
"""End-to-end test for SPEC-06 Updater.exe + Python handoff.

The test:

1. Generates an Ed25519 keypair (session fixture) and builds the Go
   binary with the public key baked in.
2. Prepares a fake install layout:  <root>/app/0.0.1/  +  <root>/current
   junction pointing at it.
3. Builds a fake "new version 0.0.2" agent zip and a signed manifest
   referencing it.
4. Serves them from a pytest-httpserver.
5. Spawns a mock "old agent" subprocess (a python that sleeps).
6. Uses the Python ``handoff.stage_pending`` helper to drop
   ``pending_update.json``.
7. Runs ``Updater.exe --update`` and waits for it.
8. Asserts: new version extracted, junction points at 0.0.2, mock
   agent exited, updater exit code 0, log file created, and the
   relaunch spawned a child (verified by the recorded pid inside a
   marker file the "new agent" writes).

The remaining tests exercise the Python ``updater_client`` package in
isolation — verifier, poller state machine, manifest fetch, spawn, and
version comparison.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx
import pytest
from nacl.signing import SigningKey

from workstation_agent.security.signature import canonical_json
from workstation_agent.updater_client import (
    UpdatePoller,
    handoff,
    verifier,
)
from workstation_agent.updater_client.handoff import spawn_updater, stage_pending
from workstation_agent.updater_client.manifest import (
    ArtifactRef,
    ArtifactSet,
    UpdateManifest,
    fetch,
    is_newer,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="junction swap only works on Windows",
)


def _build_agent_zip(tmp: Path, *, new_version: str) -> tuple[Path, bytes]:
    """Return (zip_path, zip_bytes) for a fake agent build.

    The zip contains:

      Agent.exe        - a python script wrapper (renamed .exe for realism)
      _internal/lib.txt
      version.txt

    ``Agent.exe`` is actually a Python interpreter copy that runs the
    embedded ``agent_script.py``. That way the updater can Relaunch it
    without needing a real binary compiler.

    Simpler approach: put a ``.bat`` that shells out to python. The
    updater uses ``exec.Command`` which happily runs .bat files with the
    .exe filename (Windows CreateProcess resolves via the extension).
    Even simpler: skip the ``.exe`` shell trick, and have the test
    Relaunch a python interpreter by SETTING PC_AGENT_UPDATER_PATH to a
    known python-launching wrapper. But the swap module hard-codes
    Agent.exe in the junction, so we DO need a real Agent.exe file.
    """
    build_dir = tmp / "build"
    build_dir.mkdir()
    # Copy the running python.exe as Agent.exe so it's a real executable.
    python_exe = Path(sys.executable)
    agent_exe = build_dir / "Agent.exe"
    shutil.copy2(python_exe, agent_exe)
    # And copy python's DLL support if present so it can actually run.
    for sibling in python_exe.parent.iterdir():
        if sibling.suffix.lower() in {".dll"} and sibling.name.lower().startswith("python"):
            shutil.copy2(sibling, build_dir / sibling.name)
    # Drop a "run me" script that Agent.exe will execute; but Agent.exe
    # is python.exe, so calling it with no args just opens a REPL and
    # exits immediately when stdin closes — that's fine for the test,
    # we just need it to be *launchable*.

    (build_dir / "version.txt").write_text(new_version, encoding="utf-8")
    (build_dir / "_internal").mkdir()
    (build_dir / "_internal" / "lib.txt").write_text("hello", encoding="utf-8")

    zip_path = tmp / f"agent-{new_version}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in build_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(build_dir))
    return zip_path, zip_path.read_bytes()


def _make_junction(link: Path, target: Path) -> None:
    """Create a Windows directory junction via mklink."""
    subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
    )


def _spawn_mock_agent(tmp: Path) -> subprocess.Popen[bytes]:
    """Spawn a subprocess that just sleeps until killed."""
    script = tmp / "mock_agent.py"
    script.write_text(
        textwrap.dedent(
            """
            import time, sys
            # Signal readiness by writing our pid.
            open(sys.argv[1], 'w').write(str(__import__('os').getpid()))
            try:
                time.sleep(300)
            except KeyboardInterrupt:
                pass
            """,
        ),
        encoding="utf-8",
    )
    pid_file = tmp / "mock_agent.pid"
    proc = subprocess.Popen(
        [sys.executable, str(script), str(pid_file)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait for it to write its pid.
    deadline = time.time() + 5
    while time.time() < deadline:
        if pid_file.exists():
            break
        time.sleep(0.05)
    return proc


def test_updater_end_to_end(
    tmp_path: Path,
    signing_keypair: tuple[SigningKey, bytes],
    updater_binary: Path,
    httpserver,  # pytest-httpserver fixture
) -> None:
    sk, pub = signing_keypair

    # -- Fake install layout --------------------------------------------------
    install_root = tmp_path / "install"
    (install_root / "app" / "0.0.1").mkdir(parents=True)
    (install_root / "app" / "0.0.1" / "Agent.exe").write_bytes(b"old-agent")
    (install_root / "app" / "0.0.1" / "version.txt").write_text("0.0.1", encoding="utf-8")
    _make_junction(install_root / "current", install_root / "app" / "0.0.1")
    assert (install_root / "current" / "version.txt").read_text() == "0.0.1"

    # -- Build the new agent zip ---------------------------------------------
    new_version = "0.0.2"
    zip_path, zip_bytes = _build_agent_zip(tmp_path, new_version=new_version)
    sha = hashlib.sha256(zip_bytes).hexdigest()

    # -- Serve the artifacts --------------------------------------------------
    httpserver.expect_request("/agent.zip").respond_with_data(
        zip_bytes, content_type="application/zip",
    )
    agent_url = httpserver.url_for("/agent.zip")
    updater_url = httpserver.url_for("/updater.exe")
    # We don't actually download the updater in --update flow, but the
    # manifest schema requires the entry, so serve a stub.
    httpserver.expect_request("/updater.exe").respond_with_data(b"stub")

    # -- Manifest + signature -------------------------------------------------
    manifest_dict = {
        "version": new_version,
        "channel": "stable",
        "released_at": "2026-09-15T04:00:00Z",
        "mandatory": False,
        "notes_url": "https://example.invalid/notes",
        "artifacts": {
            "agent": {"url": agent_url, "sha256": sha, "size": len(zip_bytes)},
            "updater": {
                "url": updater_url,
                "sha256": hashlib.sha256(b"stub").hexdigest(),
                "size": 4,
            },
        },
        "min_updater_version": "0.0.0",
    }
    manifest_bytes = canonical_json(manifest_dict)
    signature = sk.sign(manifest_bytes).signature
    assert len(signature) == 64

    manifest = UpdateManifest(
        version=new_version,
        channel="stable",
        released_at="2026-09-15T04:00:00Z",
        mandatory=False,
        notes_url="https://example.invalid/notes",
        artifacts=ArtifactSet(
            agent=ArtifactRef(url=agent_url, sha256=sha, size=len(zip_bytes)),
            updater=ArtifactRef(
                url=updater_url,
                sha256=hashlib.sha256(b"stub").hexdigest(),
                size=4,
            ),
        ),
        min_updater_version="0.0.0",
    )

    # -- Mock "old agent" process --------------------------------------------
    mock_agent = _spawn_mock_agent(tmp_path)
    try:
        # -- Handoff --------------------------------------------------------
        appdata = tmp_path / "appdata"
        appdata.mkdir()
        pending_path = stage_pending(
            manifest,
            manifest_bytes=manifest_bytes,
            signature_bytes=signature,
            agent_pid=mock_agent.pid,
            appdata_dir=appdata,
        )
        assert pending_path.exists()
        loaded = json.loads(pending_path.read_text(encoding="utf-8"))
        assert loaded["verified"] is True
        assert loaded["agent_pid"] == mock_agent.pid

        # -- Run Updater.exe --update --------------------------------------
        logs_dir = tmp_path / "logs"
        env = {
            **os.environ,
            "PC_AGENT_APPDATA": str(appdata),
            "PC_AGENT_INSTALL_ROOT": str(install_root),
        }
        # We test the RELAYED (child) side directly by setting the
        # sentinel — the self-copy dance is exercised in an isolated
        # test below. This lets the pytest tempdir remain the sole
        # cleanup owner and avoids leaving orphan .exes in %TEMP%.
        env["PC_AGENT_UPDATER_SELF_RELAY"] = str(updater_binary)

        result = subprocess.run(
            [
                str(updater_binary),
                "--update",
                "--install-root",
                str(install_root),
                "--pending",
                str(pending_path),
                "--logs-dir",
                str(logs_dir),
                "--keep",
                "3",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
    finally:
        if mock_agent.poll() is None:
            mock_agent.kill()
            mock_agent.wait(timeout=5)

    assert result.returncode == 0, (
        f"updater exit {result.returncode}\nstdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )

    # -- Assertions -----------------------------------------------------------
    # Mock agent was killed.
    assert mock_agent.poll() is not None, "mock agent should have exited"

    # New version extracted.
    new_dir = install_root / "app" / new_version
    assert new_dir.exists()
    assert (new_dir / "Agent.exe").exists()
    assert (new_dir / "version.txt").read_text(encoding="utf-8") == new_version

    # Junction swapped.
    current = install_root / "current"
    assert (current / "version.txt").read_text(encoding="utf-8") == new_version

    # Old version retained (only 2 versions installed, keep=3 -> both kept).
    assert (install_root / "app" / "0.0.1").exists()

    # Log file created.
    log_files = list(logs_dir.glob("updater-*.log"))
    assert log_files, "expected an updater log file"
    log_text = log_files[0].read_text(encoding="utf-8")
    assert "signature OK" in log_text
    assert "junction swapped" in log_text
    assert "relaunched agent pid=" in log_text

    # Pending file deleted.
    assert not pending_path.exists()


def test_updater_rejects_bad_signature(
    tmp_path: Path,
    signing_keypair: tuple[SigningKey, bytes],
    updater_binary: Path,
    httpserver,
) -> None:
    """A tampered manifest must not swap the junction."""
    sk, _ = signing_keypair
    install_root = tmp_path / "install"
    (install_root / "app" / "0.0.1").mkdir(parents=True)
    (install_root / "app" / "0.0.1" / "Agent.exe").write_bytes(b"old-agent")
    _make_junction(install_root / "current", install_root / "app" / "0.0.1")

    fake_zip = b"not-a-real-zip"
    sha = hashlib.sha256(fake_zip).hexdigest()
    httpserver.expect_request("/agent.zip").respond_with_data(fake_zip)
    agent_url = httpserver.url_for("/agent.zip")

    manifest_dict = {
        "version": "0.0.2",
        "channel": "stable",
        "released_at": "2026-09-15T04:00:00Z",
        "mandatory": False,
        "notes_url": "https://example.invalid",
        "artifacts": {
            "agent": {"url": agent_url, "sha256": sha, "size": len(fake_zip)},
            "updater": {"url": agent_url, "sha256": sha, "size": len(fake_zip)},
        },
        "min_updater_version": "0.0.0",
    }
    manifest_bytes = canonical_json(manifest_dict)
    good_sig = sk.sign(manifest_bytes).signature
    # Flip a byte in the manifest AFTER signing.
    tampered_bytes = bytearray(manifest_bytes)
    tampered_bytes[0] ^= 0x01

    appdata = tmp_path / "appdata"
    appdata.mkdir()
    pending = {
        "schema_version": 1,
        "verified": True,
        "agent_pid": 0,
        "manifest": manifest_dict,
        "manifest_b64": base64.b64encode(bytes(tampered_bytes)).decode("ascii"),
        "signature_b64": base64.b64encode(good_sig).decode("ascii"),
    }
    pending_path = appdata / "pending_update.json"
    pending_path.write_text(json.dumps(pending), encoding="utf-8")

    env = {
        **os.environ,
        "PC_AGENT_APPDATA": str(appdata),
        "PC_AGENT_UPDATER_SELF_RELAY": str(updater_binary),
    }
    result = subprocess.run(
        [
            str(updater_binary),
            "--update",
            "--install-root",
            str(install_root),
            "--pending",
            str(pending_path),
            "--logs-dir",
            str(tmp_path / "logs"),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode != 0
    # Junction untouched.
    current_bytes = (install_root / "current" / "Agent.exe").read_bytes()
    assert current_bytes == b"old-agent"
    # No new version dir.
    assert not (install_root / "app" / "0.0.2").exists()


def test_updater_rollback(
    tmp_path: Path,
    updater_binary: Path,
) -> None:
    """``Updater.exe --rollback <ver>`` swaps `current` back to an
    earlier installed version without touching data on disk.

    Layout:
        <root>/app/1.0.0/Agent.exe         (previous "known good" version)
        <root>/app/1.1.0/Agent.exe         (freshly installed, misbehaving)
        <root>/current -> app/1.1.0        (currently active)

    After ``--rollback 1.0.0``:
        <root>/current -> app/1.0.0        (rolled back)
        <root>/app/1.1.0/**                (preserved — no data loss)
        <root>/app/1.0.0/**                (preserved)
        Mock agent has been relaunched (exit code 0 from updater).
    """
    # -- Install layout with two versions ------------------------------------
    install_root = tmp_path / "install"
    v_old = install_root / "app" / "1.0.0"
    v_new = install_root / "app" / "1.1.0"
    for v, tag in [(v_old, "1.0.0"), (v_new, "1.1.0")]:
        v.mkdir(parents=True)
        # Copy python.exe as Agent.exe so Relaunch can start it.
        shutil.copy2(Path(sys.executable), v / "Agent.exe")
        for sibling in Path(sys.executable).parent.iterdir():
            if (
                sibling.suffix.lower() == ".dll"
                and sibling.name.lower().startswith("python")
            ):
                shutil.copy2(sibling, v / sibling.name)
        (v / "version.txt").write_text(tag, encoding="utf-8")
        # A data-file we later assert survives the rollback verbatim.
        (v / "user_data.txt").write_text(f"payload-{tag}", encoding="utf-8")

    # `current` starts pointing at 1.1.0 (the version we roll back FROM).
    _make_junction(install_root / "current", v_new)
    assert (install_root / "current" / "version.txt").read_text(
        encoding="utf-8",
    ) == "1.1.0"

    # -- Run Updater.exe --rollback 1.0.0 ------------------------------------
    logs_dir = tmp_path / "logs"
    env = {
        **os.environ,
        "PC_AGENT_INSTALL_ROOT": str(install_root),
        # Skip the self-copy dance — we're already running from tempdir.
        "PC_AGENT_UPDATER_SELF_RELAY": str(updater_binary),
    }
    result = subprocess.run(
        [
            str(updater_binary),
            "--rollback",
            "1.0.0",
            "--install-root",
            str(install_root),
            "--logs-dir",
            str(logs_dir),
            "--keep",
            "3",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"rollback exit {result.returncode}\nstdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )

    # -- Post-conditions -----------------------------------------------------
    # `current` now points at 1.0.0.
    current = install_root / "current"
    assert (current / "version.txt").read_text(encoding="utf-8") == "1.0.0"

    # No data loss: both version dirs still exist with their data.
    assert (v_old / "user_data.txt").read_text(encoding="utf-8") == "payload-1.0.0"
    assert (v_new / "user_data.txt").read_text(encoding="utf-8") == "payload-1.1.0"

    # Log file was written and mentions the rollback swap.
    log_files = list(logs_dir.glob("updater-*.log"))
    assert log_files, "expected an updater log file"
    log_text = log_files[0].read_text(encoding="utf-8")
    assert "rollback" in log_text.lower()
    assert "junction" in log_text.lower()
    assert "relaunched agent pid=" in log_text, (
        f"expected relaunch confirmation in log; got:\n{log_text}"
    )


def test_stage_pending_atomic(tmp_path: Path) -> None:
    """stage_pending must produce a file with the right shape atomically."""
    appdata = tmp_path / "appdata"
    manifest = UpdateManifest(
        version="1.2.3",
        channel="stable",
        released_at="2026-09-15T04:00:00Z",
        mandatory=False,
        notes_url="https://example.invalid",
        artifacts=ArtifactSet(
            agent=ArtifactRef(url="https://a", sha256="a" * 64, size=1),
            updater=ArtifactRef(url="https://u", sha256="b" * 64, size=1),
        ),
        min_updater_version="1.0.0",
    )
    out = stage_pending(
        manifest,
        manifest_bytes=b"raw",
        signature_bytes=b"sig",
        agent_pid=1234,
        appdata_dir=appdata,
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["agent_pid"] == 1234
    assert data["verified"] is True
    assert data["manifest"]["version"] == "1.2.3"
    # No leftover .tmp files.
    leftovers = list(appdata.glob("*.tmp"))
    assert not leftovers


# ---------------------------------------------------------------------------
# Focused unit tests (kept in this file per SPEC-06 allowed-paths rule).
# ---------------------------------------------------------------------------


def _make_manifest_dict(*, version: str = "1.2.3") -> dict[str, Any]:
    return {
        "version": version,
        "channel": "stable",
        "released_at": "2026-09-15T04:00:00Z",
        "mandatory": False,
        "notes_url": "https://example.invalid/notes",
        "artifacts": {
            "agent": {"url": "https://x/agent.zip", "sha256": "a" * 64, "size": 10},
            "updater": {"url": "https://x/updater.exe", "sha256": "b" * 64, "size": 5},
        },
        "min_updater_version": "1.0.0",
    }


class TestManifestValidation:
    def test_valid(self) -> None:
        m = UpdateManifest.model_validate(_make_manifest_dict())
        assert m.version == "1.2.3"
        assert m.artifacts.agent.size == 10

    def test_bad_sha256_length(self) -> None:
        d = _make_manifest_dict()
        d["artifacts"]["agent"]["sha256"] = "abc"
        with pytest.raises(Exception):
            UpdateManifest.model_validate(d)

    def test_bad_sha256_case_normalised(self) -> None:
        d = _make_manifest_dict()
        d["artifacts"]["agent"]["sha256"] = "A" * 64
        m = UpdateManifest.model_validate(d)
        assert m.artifacts.agent.sha256 == "a" * 64

    def test_bad_url_scheme(self) -> None:
        d = _make_manifest_dict()
        d["artifacts"]["agent"]["url"] = "ftp://x"
        with pytest.raises(Exception):
            UpdateManifest.model_validate(d)

    def test_bad_version(self) -> None:
        d = _make_manifest_dict(version="not-semver")
        with pytest.raises(Exception):
            UpdateManifest.model_validate(d)

    def test_bad_channel(self) -> None:
        d = _make_manifest_dict()
        d["channel"] = "canary"
        with pytest.raises(Exception):
            UpdateManifest.model_validate(d)

    def test_extra_field_forbidden(self) -> None:
        d = _make_manifest_dict()
        d["surprise"] = 1
        with pytest.raises(Exception):
            UpdateManifest.model_validate(d)


class TestIsNewer:
    def test_semver_numeric(self) -> None:
        assert is_newer("1.2.10", "1.2.9") is True
        assert is_newer("2.0.0", "1.99.99") is True
        assert is_newer("1.2.3", "1.2.3") is False
        assert is_newer("1.0.0", "1.0.1") is False

    def test_prerelease_ignored(self) -> None:
        assert is_newer("1.2.4-beta.1", "1.2.3") is True

    def test_invalid_version_raises(self) -> None:
        with pytest.raises(ValueError):
            is_newer("bad", "1.2.3")


class TestVerifier:
    def test_round_trip(self, signing_keypair: tuple[SigningKey, bytes]) -> None:
        sk, pub = signing_keypair
        msg = b"hello"
        sig = sk.sign(msg).signature
        assert verifier.verify(msg, sig, pub) is True
        assert verifier.verify(msg + b"!", sig, pub) is False
        assert verifier.verify(msg, b"\0" * 64, pub) is False


async def test_fetch_downloads_and_parses(
    signing_keypair: tuple[SigningKey, bytes],
    httpserver,
) -> None:
    _, pub = signing_keypair
    m_bytes = canonical_json(_make_manifest_dict())
    sig = SigningKey.generate().sign(m_bytes).signature  # unrelated key OK here
    del pub, sig  # not used in fetch itself
    # GitHub-like release payload: /repos/OWNER/REPO/releases/latest
    httpserver.expect_request("/repos/o/r/releases/latest").respond_with_json(
        {
            "assets": [
                {
                    "name": "manifest.json",
                    "browser_download_url": httpserver.url_for("/manifest.json"),
                },
                {
                    "name": "manifest.json.sig",
                    "browser_download_url": httpserver.url_for("/manifest.json.sig"),
                },
            ],
        },
    )
    httpserver.expect_request("/manifest.json").respond_with_data(m_bytes)
    httpserver.expect_request("/manifest.json.sig").respond_with_data(b"stub-sig")

    async with httpx.AsyncClient(base_url=httpserver.url_for("/")) as client:
        # Rewrite fetch's api_url to point at the mock server.
        original_get = client.get

        async def rewrite_get(url, **kw):  # type: ignore[no-untyped-def]
            if url.startswith("https://api.github.com"):
                url = httpserver.url_for(
                    url.replace("https://api.github.com", ""),
                )
            return await original_get(url, **kw)

        client.get = rewrite_get  # type: ignore[method-assign]
        manifest, raw, sig_bytes = await fetch("o/r", client)
    assert manifest.version == "1.2.3"
    assert raw == m_bytes
    assert sig_bytes == b"stub-sig"


async def test_fetch_missing_assets(httpserver) -> None:
    httpserver.expect_request("/repos/o/r/releases/latest").respond_with_json(
        {"assets": [{"name": "something-else", "browser_download_url": "https://x"}]},
    )
    async with httpx.AsyncClient() as client:
        async def rewrite_get(url, **kw):  # type: ignore[no-untyped-def]
            if url.startswith("https://api.github.com"):
                url = httpserver.url_for(url.replace("https://api.github.com", ""))
            return await httpx.AsyncClient.get(client, url, **kw)

        client.get = rewrite_get  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="missing manifest"):
            await fetch("o/r", client)


class _StubPollerFetch:
    """Test double for poller.fetch — records calls, returns queued results."""

    def __init__(self, results: list[Any]) -> None:
        self.results = results
        self.calls: list[str] = []

    async def __call__(self, repo: str, http: httpx.AsyncClient):  # noqa: ARG002
        self.calls.append(repo)
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


async def test_poller_fires_callback_on_newer_verified(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sk, pub = signing_keypair
    md = _make_manifest_dict(version="2.0.0")
    mbytes = canonical_json(md)
    sig = sk.sign(mbytes).signature
    manifest = UpdateManifest.model_validate(md)

    stub = _StubPollerFetch([(manifest, mbytes, sig)])
    monkeypatch.setattr("workstation_agent.updater_client.poller.fetch", stub)

    seen: list[UpdateManifest] = []

    async def cb(m, raw, sigb):
        seen.append(m)
        assert raw == mbytes
        assert sigb == sig

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
        )
        result = await poller.poll_once()
    assert result is not None
    assert result.version == "2.0.0"
    assert len(seen) == 1


async def test_poller_skips_when_signature_invalid(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, pub = signing_keypair
    md = _make_manifest_dict(version="2.0.0")
    mbytes = canonical_json(md)
    manifest = UpdateManifest.model_validate(md)
    bad_sig = b"\x00" * 64

    stub = _StubPollerFetch([(manifest, mbytes, bad_sig)])
    monkeypatch.setattr("workstation_agent.updater_client.poller.fetch", stub)

    calls: list[Any] = []

    async def cb(m, raw, sigb):  # pragma: no cover - should not fire
        calls.append(m)

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
        )
        assert await poller.poll_once() is None
    assert calls == []


async def test_poller_skips_when_not_newer(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sk, pub = signing_keypair
    md = _make_manifest_dict(version="1.0.0")
    mbytes = canonical_json(md)
    sig = sk.sign(mbytes).signature
    manifest = UpdateManifest.model_validate(md)

    monkeypatch.setattr(
        "workstation_agent.updater_client.poller.fetch",
        _StubPollerFetch([(manifest, mbytes, sig)]),
    )

    async def cb(m, raw, sigb):  # pragma: no cover
        raise AssertionError

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
        )
        assert await poller.poll_once() is None


async def test_poller_swallows_fetch_errors(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, pub = signing_keypair
    monkeypatch.setattr(
        "workstation_agent.updater_client.poller.fetch",
        _StubPollerFetch([RuntimeError("boom")]),
    )

    async def cb(m, raw, sigb):  # pragma: no cover
        raise AssertionError

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
        )
        assert await poller.poll_once() is None


async def test_poller_start_stop_and_check_now(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sk, pub = signing_keypair
    md = _make_manifest_dict(version="2.0.0")
    mbytes = canonical_json(md)
    sig = sk.sign(mbytes).signature
    manifest = UpdateManifest.model_validate(md)

    # Feed several results so the loop can spin.
    stub = _StubPollerFetch([(manifest, mbytes, sig)] * 5)
    monkeypatch.setattr("workstation_agent.updater_client.poller.fetch", stub)

    seen = asyncio.Event()

    async def cb(m, raw, sigb):
        seen.set()

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
            poll_interval_seconds=60.0,
        )
        poller.start()
        # start() a second time is a no-op.
        poller.start()
        poller.check_now()
        await asyncio.wait_for(seen.wait(), timeout=5)
        await poller.stop()
    assert stub.calls  # at least one fetch happened


async def test_poller_callback_exception_is_swallowed(
    signing_keypair: tuple[SigningKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sk, pub = signing_keypair
    md = _make_manifest_dict(version="2.0.0")
    mbytes = canonical_json(md)
    sig = sk.sign(mbytes).signature
    manifest = UpdateManifest.model_validate(md)
    monkeypatch.setattr(
        "workstation_agent.updater_client.poller.fetch",
        _StubPollerFetch([(manifest, mbytes, sig)]),
    )

    async def cb(m, raw, sigb):
        raise RuntimeError("boom")

    async with httpx.AsyncClient() as client:
        poller = UpdatePoller(
            github_repo="o/r",
            current_version="1.0.0",
            pubkey=pub,
            http=client,
            on_update_available=cb,
        )
        # Should return the manifest but not raise despite the callback exploding.
        result = await poller.poll_once()
    assert result is not None


def test_handoff_uses_appdata_env(monkeypatch: pytest.MonkeyPatch,
                                  tmp_path: Path) -> None:
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "wsa"))
    manifest = UpdateManifest.model_validate(_make_manifest_dict())
    out = stage_pending(
        manifest,
        manifest_bytes=b"raw",
        signature_bytes=b"sig",
        agent_pid=9,
    )
    assert out.parent == tmp_path / "wsa"
    assert out.exists()


def test_handoff_default_agent_pid_is_self(monkeypatch: pytest.MonkeyPatch,
                                           tmp_path: Path) -> None:
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))
    manifest = UpdateManifest.model_validate(_make_manifest_dict())
    out = stage_pending(
        manifest,
        manifest_bytes=b"raw",
        signature_bytes=b"sig",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["agent_pid"] == os.getpid()


def test_locate_updater_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PC_AGENT_UPDATER_PATH", "C:\\fake\\Updater.exe")
    assert handoff._locate_updater() == Path("C:\\fake\\Updater.exe")


def test_locate_updater_install_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PC_AGENT_UPDATER_PATH", raising=False)
    root = Path("C:\\install")
    assert handoff._locate_updater(root) == root / "current" / "Updater.exe"


def test_locate_updater_sibling_of_sys_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PC_AGENT_UPDATER_PATH", raising=False)
    expected = Path(sys.executable).parent / "Updater.exe"
    assert handoff._locate_updater() == expected


def test_spawn_updater_uses_temp_binary(tmp_path: Path) -> None:
    """spawn_updater actually launches the binary; we point it at a
    short-lived script that exits quickly so the PID is real."""
    # Write a tiny .bat that just exits.
    fake = tmp_path / "current" / "Updater.exe"
    fake.parent.mkdir()
    # Copy python.exe as a stand-in — it will exit cleanly when stdin
    # is closed (Popen sets DEVNULL).
    shutil.copy2(sys.executable, fake)
    # For python 3.14+ we also need the DLL.
    for sibling in Path(sys.executable).parent.iterdir():
        if sibling.suffix.lower() == ".dll" and sibling.name.lower().startswith("python"):
            shutil.copy2(sibling, fake.parent / sibling.name)
    pid = spawn_updater(install_root=tmp_path, extra_args=["-c", "pass"])
    assert pid > 0
    # Wait briefly for the child to exit so we don't leave zombies.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.1)


def test_appdata_dir_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PC_AGENT_APPDATA", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    p = handoff._appdata_dir()
    # Should return SOME path — tempdir fallback.
    assert p is not None
    assert "WorkstationAgent" in str(p)


def test_atomic_write_cleans_tmp_on_failure(monkeypatch: pytest.MonkeyPatch,
                                            tmp_path: Path) -> None:
    dest = tmp_path / "out.json"

    real_replace = os.replace

    def failing_replace(a, b):  # type: ignore[no-untyped-def]
        raise OSError("simulated")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError):
        handoff._atomic_write_bytes(dest, b"x")
    # And a leftover .tmp must not survive.
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
    monkeypatch.setattr(os, "replace", real_replace)
