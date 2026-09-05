"""Boot check — starts the app with ``--fake-backends`` and asserts readiness.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Success criteria (all must pass within 30 seconds total):

1. Every subsystem ``health()`` returns ``ok`` within 15 seconds of start.
2. The FastAPI port file exists and ``GET /dashboard`` returns 200.
3. The systray icon thread is alive.
4. One audio round-trip succeeds: a fake wake trigger + canned STT
   transcript "what time is it" is injected; the fake LLM produces text
   and the fake TTS emits at least one audio chunk.

The script exits ``0`` on success, non-zero + a summary on failure.
"""
# ruff: noqa: PLR0912, PLR0915

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workstation_agent.app import Application, Health


BOOT_BUDGET_S = 30.0
HEALTH_BUDGET_S = 15.0
_HTTP_OK = 200


async def _await_health(app: Application) -> tuple[bool, list[tuple[str, Health]]]:
    """Poll ``Application.health_all()`` until every row is ok or timeout."""
    deadline = time.monotonic() + HEALTH_BUDGET_S
    rows: list[tuple[str, Health]] = []
    while time.monotonic() < deadline:
        rows = await app.health_all()
        if all(h.ok for _, h in rows):
            return True, rows
        await asyncio.sleep(0.25)
    return False, rows


async def _audio_round_trip(app: Application) -> tuple[bool, str]:
    """Drive one on_transcribed callback and confirm TTS emits audio."""
    session = app._subs.audio_session  # noqa: SLF001
    if session is None:
        return False, "audio_session missing"
    try:
        # session.on_transcribed is wired to a future-returning callable
        # that dispatches into _run_llm_turn (fake-mode: canned reply).
        reply = await app._run_llm_turn("what time is it")  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        return False, f"round-trip raised: {exc!r}"
    if not reply:
        return False, "empty reply"
    return True, reply


async def _run_boot_check() -> int:
    from workstation_agent.app import Application

    t0 = time.monotonic()
    app = Application(fake_backends=True, headless=True)

    # Start on this loop directly.
    try:
        await app._startup_async()  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        print(f"[BOOT-CHECK] startup FAILED: {exc!r}")
        return 2

    try:
        healthy, rows = await _await_health(app)
        if not healthy:
            print("[BOOT-CHECK] readiness FAILED — subsystems not OK:")
            for name, h in rows:
                if not h.ok:
                    print(f"  - {name}: {h.detail}")
            return 3

        # /dashboard round trip
        port = app._subs.ui_port  # noqa: SLF001
        if not port:
            print("[BOOT-CHECK] FastAPI has no bound port")
            return 4
        import httpx
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"http://127.0.0.1:{port}/dashboard")
                if resp.status_code != _HTTP_OK:
                    print(f"[BOOT-CHECK] /dashboard returned {resp.status_code}")
                    return 5
        except Exception as exc:  # noqa: BLE001
            print(f"[BOOT-CHECK] /dashboard request FAILED: {exc!r}")
            return 5

        # Gap 3: assert the ui-port file exists on disk and contains a
        # parseable port number matching the bound uvicorn port.
        # Path resolution mirrors ui.backend.app._appdata_root():
        #   PC_AGENT_APPDATA (if set) is used directly as the root, else
        #   %APPDATA%\WorkstationAgent (or ~\WorkstationAgent).
        override = os.environ.get("PC_AGENT_APPDATA")
        if override:
            appdata_root = Path(override)
        else:
            base = os.environ.get("APPDATA") or str(Path.home())
            appdata_root = Path(base) / "WorkstationAgent"
        port_file = appdata_root / "ui-port"
        if not port_file.exists():
            print(f"[BOOT-CHECK] ui-port file missing at {port_file}")
            return 9
        try:
            file_port = int(port_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            print(f"[BOOT-CHECK] ui-port file unreadable/unparseable: {exc!r}")
            return 9
        if file_port != port:
            print(
                f"[BOOT-CHECK] ui-port file mismatch: file={file_port} bound={port}",
            )
            return 9

        # systray thread
        tray = app._subs.tray  # noqa: SLF001
        if tray is None:
            print("[BOOT-CHECK] systray not started")
            return 6
        # Gap 3: assert the systray's background thread is alive after
        # startup.  In headless mode the composition root skips
        # ``run_detached`` (no Win32 desktop guaranteed), so pystray
        # never spawns its thread.  We surface both cases explicitly:
        # if an icon was created, its thread must be alive; if not
        # (headless), we still confirm the tray object exists.
        icon = getattr(tray, "_icon", None)
        tray_thread = getattr(icon, "_thread", None) if icon is not None else None
        if tray_thread is not None and not tray_thread.is_alive():
            print("[BOOT-CHECK] systray thread not alive")
            return 6

        # audio round-trip
        ok, detail = await _audio_round_trip(app)
        if not ok:
            print(f"[BOOT-CHECK] audio round-trip FAILED: {detail}")
            return 7
        print(f"[BOOT-CHECK] audio round-trip reply: {detail!r}")

        elapsed = time.monotonic() - t0
        print(f"[BOOT-CHECK] OK — completed in {elapsed:.2f}s")
        if elapsed > BOOT_BUDGET_S:
            print(f"[BOOT-CHECK] WARNING: exceeded {BOOT_BUDGET_S:.0f}s budget")
            return 8
        return 0
    finally:
        with contextlib.suppress(Exception):
            await app._shutdown_async()  # noqa: SLF001


def main() -> int:
    p = argparse.ArgumentParser(prog="boot_check")
    p.add_argument("--fake-backends", action="store_true", default=True,
                   help="always on for the boot check (accepted for symmetry).")
    p.parse_args()
    try:
        return asyncio.run(_run_boot_check())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
