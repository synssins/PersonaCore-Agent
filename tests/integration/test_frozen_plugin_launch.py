"""Launch every bundled plugin out of a real PyInstaller build.

A passing unit suite proves nothing about the packaged app: this venv has
``pyserial``, which is exactly why ``No module named 'serial'`` reached a
user.  The only test that can settle the question runs the **frozen** exe.

This module spawns each plugin the way
``mcp_host.supervisor.PluginSupervisor.spawn`` does — ``Agent.exe -u -m
workstation_agent.plugins.<id>``, from the plugin's own directory, with the
supervisor's environment allow-list — and speaks the plugin's line-delimited
JSON-RPC to it.  A plugin that dies on an import never answers
``initialize``; that is precisely the failure the field report described.

It is **opt-in**, because it needs an artefact ``pytest -q`` has no business
building::

    ./installer/build.ps1 -Version 0.1.0-alpha.9
    $env:WSA_FROZEN_DIST = "dist\\Agent"
    .venv\\Scripts\\python.exe -m pytest tests/integration/test_frozen_plugin_launch.py -q

Without ``WSA_FROZEN_DIST`` every test here skips.
"""
# ruff: noqa: ANN401

from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import IO, Any

import pytest

from workstation_agent.mcp_host.supervisor import build_child_env

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS_SRC = REPO_ROOT / "src" / "workstation_agent" / "plugins"

#: Seconds to wait for one JSON-RPC reply from a freshly spawned plugin.
REPLY_TIMEOUT = 30.0

#: The four files the bundle must carry for each plugin.
PLUGIN_FILES = ("__init__.py", "__main__.py", "plugin.toml", "signature.sig")


def _bundled_plugin_ids() -> list[str]:
    return sorted(
        p.name
        for p in PLUGINS_SRC.iterdir()
        if p.is_dir() and not p.name.startswith("__") and (p / "__init__.py").exists()
    )


PLUGIN_IDS = _bundled_plugin_ids()


class _Plugin:
    """A spawned frozen plugin plus a timeout-safe reader for its stdout."""

    def __init__(self, exe: Path, plugin_id: str, cwd: Path) -> None:
        self.plugin_id = plugin_id
        self.proc = subprocess.Popen(  # noqa: S603 — cmd is a fixed template
            [str(exe), "-u", "-m", f"workstation_agent.plugins.{plugin_id}"],
            cwd=str(cwd),
            env=build_child_env(plugin_id),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self.stderr_chunks: list[bytes] = []
        self._start(self._pump_stdout, self.proc.stdout)
        self._start(self._pump_stderr, self.proc.stderr)

    @staticmethod
    def _start(target: Any, stream: IO[bytes] | None) -> None:
        if stream is not None:
            threading.Thread(target=target, args=(stream,), daemon=True).start()

    def _pump_stdout(self, stream: IO[bytes]) -> None:
        try:
            for line in stream:
                self._lines.put(line)
        finally:
            self._lines.put(None)

    def _pump_stderr(self, stream: IO[bytes]) -> None:
        with contextlib.suppress(OSError, ValueError):
            self.stderr_chunks.append(stream.read())

    @property
    def stderr_text(self) -> str:
        return b"".join(self.stderr_chunks).decode("utf-8", "replace").strip()

    def request(self, method: str, request_id: int) -> dict[str, Any]:
        """Send one request and return its reply, skipping notifications."""
        msg = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}}
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

        while True:
            try:
                line = self._lines.get(timeout=REPLY_TIMEOUT)
            except queue.Empty:
                line = None
            if line is None:
                self.proc.poll()
                pytest.fail(
                    f"{self.plugin_id}: no reply to {method!r} "
                    f"(exit code {self.proc.returncode}). stderr:\n{self.stderr_text}",
                )
            try:
                reply = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if reply.get("id") == request_id:
                return reply

    def close(self) -> None:
        if self.proc.stdin is not None:
            with contextlib.suppress(OSError):
                self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


def _frozen_dist() -> Path | None:
    raw = os.environ.get("WSA_FROZEN_DIST")
    if not raw:
        return None
    dist = Path(raw)
    return dist if dist.is_absolute() else REPO_ROOT / dist


@pytest.fixture(scope="module")
def agent_exe() -> Path:
    dist = _frozen_dist()
    if dist is None:
        pytest.skip("set WSA_FROZEN_DIST=dist\\Agent to run the frozen-build tests")
    exe = dist / "Agent.exe"
    if not exe.exists():
        pytest.skip(f"no frozen build at {exe}")
    return exe


@pytest.mark.parametrize("plugin_id", PLUGIN_IDS)
def test_frozen_plugin_starts_and_answers(agent_exe: Path, plugin_id: str) -> None:
    """The plugin subprocess must initialize and list its tools.

    This is the assertion the ``serial`` defect failed: with ``pyserial``
    absent from the bundle, ``Agent.exe -m workstation_agent.plugins.serial``
    raised ``ModuleNotFoundError`` before writing a byte to stdout.
    """
    plugin_dir = (
        agent_exe.parent / "_internal" / "workstation_agent" / "plugins" / plugin_id
    )
    assert plugin_dir.is_dir(), (
        f"{plugin_id} was not shipped to {plugin_dir}; the on-disk copy is what "
        "the plugin's signature is verified against"
    )

    plugin = _Plugin(agent_exe, plugin_id, plugin_dir)
    try:
        init = plugin.request("initialize", 1)
        assert "result" in init, f"{plugin_id} initialize failed: {init}"

        tools = plugin.request("tools/list", 2)
        assert "result" in tools, f"{plugin_id} tools/list failed: {tools}"
        assert tools["result"]["tools"], f"{plugin_id} advertised no tools"

        plugin.request("shutdown", 3)
    finally:
        plugin.close()


def _pyz_module_names(agent_exe: Path) -> set[str]:
    """Every module name inside the exe's embedded PYZ archive.

    ``CArchiveReader.toc`` maps a name to
    ``(offset, length, uncompressed_length, compression_flag, typecode)``;
    ``'z'`` is the PYZ entry.
    """
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    carchive = CArchiveReader(str(agent_exe))
    names: set[str] = set()
    for entry_name, entry in carchive.toc.items():
        if entry[4] != "z":
            continue
        tmp = Path(tempfile.gettempdir()) / f"wsa_pyz_{os.getpid()}_{entry_name}"
        tmp.write_bytes(carchive.extract(entry_name))
        try:
            names |= set(ZlibArchiveReader(str(tmp)).toc)
        finally:
            tmp.unlink(missing_ok=True)
    return names


def test_no_plugin_is_embedded_in_the_pyz(agent_exe: Path) -> None:
    """Exactly one copy of each plugin ships, and it is the on-disk one.

    PyInstaller's frozen importer sits ahead of the filesystem path finder on
    ``sys.meta_path``, so a plugin module embedded in the PYZ would be
    executed while ``mcp_host.loader.verify`` went on hashing the on-disk copy
    in ``_internal/``.  The two would then be free to diverge, which is a
    signature bypass.  ``workstation_agent.spec`` strips the plugin modules
    out of ``a.pure`` after Analysis precisely so this set is empty.
    """
    embedded = _pyz_module_names(agent_exe)
    assert embedded, "could not read the exe's PYZ archive"

    leaked = sorted(
        name
        for name in embedded
        if name == "workstation_agent.plugins"
        or name.startswith("workstation_agent.plugins.")
    )
    assert not leaked, (
        "these plugin modules are embedded in the PYZ and would be imported in "
        f"preference to the on-disk copy the signature covers: {leaked}"
    )
    # The point of naming the plugins to Analysis at all: their dependencies.
    assert "serial" in embedded
    assert "serial.tools.list_ports" in embedded


@pytest.mark.parametrize("plugin_id", PLUGIN_IDS)
def test_frozen_plugin_matches_the_source_it_was_signed_from(
    agent_exe: Path,
    plugin_id: str,
) -> None:
    """The bundled copy must be byte-identical to the signed source.

    ``mcp_host.loader.signing_message`` digests the files under
    ``_internal/workstation_agent/plugins/<id>/``.  Any difference from the
    tree the signature was made over quarantines the plugin.
    """
    plugin_dir = (
        agent_exe.parent / "_internal" / "workstation_agent" / "plugins" / plugin_id
    )
    for name in PLUGIN_FILES:
        src = PLUGINS_SRC / plugin_id / name
        if not src.exists():
            continue
        shipped = plugin_dir / name
        assert shipped.exists(), f"{plugin_id}/{name} missing from the bundle"
        assert shipped.read_bytes() == src.read_bytes(), (
            f"{plugin_id}/{name} in the bundle differs from the source tree; "
            "its signature will not verify"
        )
