"""Entry point for PersonaCore-Agent.

SPEC-10 composition-root wiring.  The default (no args) runs the full
:class:`~workstation_agent.app.Application`.  Flags:

* ``--autostart`` — informational; toggles the audit note "started at logon".
* ``--diag`` — print a subsystem-readiness table then exit.
* ``--fake-backends`` — swap in-process fakes for Wyoming / OpenAI /
  Claude SDK. Used by the boot check and by ``--diag``.
* ``--check-updates`` — nudge the updater to poll immediately then exit.
* ``--rollback [ver]`` — spawn ``Updater.exe --rollback <ver>`` and exit.
"""
# ruff: noqa: FBT001, PLC0415, E501

from __future__ import annotations

import argparse
import asyncio
import logging
import runpy
import sys


def _maybe_run_as_python(argv: list[str]) -> int | None:
    """Detect ``[-u] -m <module>`` invocation and act as a Python module runner.

    Under PyInstaller, ``sys.executable`` is ``Agent.exe`` (not ``python.exe``),
    so the MCP-host supervisor's ``[sys.executable, "-u", "-m", "plugin.mod"]``
    spawn command re-invokes Agent.exe with those args. Without this hook,
    argparse would reject ``-u -m ...`` as unrecognized and the plugin
    subprocess would exit before its stdout produced anything, which the
    supervisor logs as ``plugin stdout closed``.

    Returns:
        The exit code if we ran a module (caller should exit with it), or
        ``None`` to indicate normal argparse dispatch should proceed.
    """
    # Strip a leading -u (unbuffered stdio) if present.
    args = list(argv[1:])
    if args and args[0] == "-u":
        args = args[1:]
    if not (len(args) >= 2 and args[0] == "-m"):
        return None
    module = args[1]
    # Shift sys.argv so the target module sees a normal argv.
    sys.argv = [module, *args[2:]]
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 0 if code is None else 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="workstation-agent")
    p.add_argument("--autostart", action="store_true",
                   help="Started at logon by the OS.")
    p.add_argument("--diag", action="store_true",
                   help="Run subsystem readiness check and exit.")
    p.add_argument("--fake-backends", action="store_true",
                   help="Swap in-process fakes for Wyoming/OpenAI/Claude SDK.")
    p.add_argument("--check-updates", action="store_true",
                   help="Poll for updates immediately and exit.")
    p.add_argument("--rollback", metavar="VERSION", nargs="?", const="",
                   help="Roll back to the specified version and exit.")
    return p


def _cmd_diag(fake_backends: bool) -> int:
    """Run :meth:`Application.diag` and print the readiness table."""
    from workstation_agent.app import Application

    app = Application(fake_backends=fake_backends, headless=True)
    rows = asyncio.run(app.diag())

    all_ok = True
    name_w = max(len(name) for name, _ in rows) if rows else 0
    print(f"{'Subsystem':<{name_w}}  Status  Detail")
    print("-" * (name_w + 30))
    for name, h in rows:
        status = "OK" if h.ok else "FAIL"
        print(f"{name:<{name_w}}  {status:<6}  {h.detail}")
        if not h.ok:
            all_ok = False
    return 0 if all_ok else 1


def _cmd_check_updates() -> int:
    """Nudge the update poller to run immediately then exit."""
    from workstation_agent.app import Application

    async def _once() -> None:
        app = Application(headless=True)
        try:
            await app._startup_async()  # noqa: SLF001
            poller = app._subs.update_poller  # noqa: SLF001
            if poller is not None:
                poller.check_now()
                # Give it a moment to run.
                await asyncio.sleep(1.0)
        finally:
            await app._shutdown_async()  # noqa: SLF001

    asyncio.run(_once())
    return 0


def _cmd_rollback(version: str) -> int:
    """Spawn ``Updater.exe --rollback <ver>``."""
    from workstation_agent.updater_client import handoff

    args = ["--rollback", version] if version else ["--rollback"]
    pid = handoff.spawn_updater(extra_args=args)
    print(f"spawned updater pid={pid}")
    return 0


def main() -> int:
    """Parse args and dispatch to the requested command."""
    # Under PyInstaller, this same EXE is used by the MCP-host supervisor to
    # spawn plugin subprocesses (``sys.executable == Agent.exe``). Detect the
    # ``-u -m <module>`` pattern before argparse and act as a Python runner.
    rc = _maybe_run_as_python(sys.argv)
    if rc is not None:
        return rc

    args = _build_parser().parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.diag:
        return _cmd_diag(fake_backends=args.fake_backends)
    if args.check_updates:
        return _cmd_check_updates()
    if args.rollback is not None:
        return _cmd_rollback(args.rollback)

    from workstation_agent.app import Application

    app = Application(
        fake_backends=args.fake_backends,
        autostart=args.autostart,
    )
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
