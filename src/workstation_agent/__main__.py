"""Entry point for PersonaCore-Agent.

SPEC-10 composition-root wiring.  The default (no args) runs the full
:class:`~workstation_agent.app.Application`.  Flags:

* ``--autostart`` — informational; toggles the audit note "started at logon".
* ``--diag`` — print a subsystem-readiness table then exit.
* ``--fake-backends`` — swap in-process fakes for Wyoming / OpenAI /
  Claude SDK. Used by the boot check and by ``--diag``.
* ``--check-updates`` — nudge the updater to poll immediately then exit.
* ``--rollback [ver]`` — spawn ``Updater.exe --rollback <ver>`` and exit.

Subcommand:

* ``export-registration [-o DIR]`` — write ``workstation-registration.zip``
  (contract §2) and exit. See :func:`_attach_console` for how this reports
  its result from a ``console=False`` (``workstation_agent.spec:93``) build.
"""
# ruff: noqa: FBT001, PLC0415, E501

from __future__ import annotations

import argparse
import asyncio
import io
import logging
import os
import runpy
import sys
from pathlib import Path


def _startup_log_path() -> Path:
    """Return the file path where windowed-EXE startup output is captured."""
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home()
    log_dir = base / "WorkstationAgent"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "startup.log"


def _startup_write(msg: str) -> None:
    """Best-effort write to the startup log — never raises."""
    try:
        with open(_startup_log_path(), "a", encoding="utf-8") as f:  # noqa: PTH123
            f.write(msg)
    except OSError:
        pass


def _ensure_std_streams() -> None:
    """PyInstaller windowed builds (--noconsole) set sys.stdout/stderr to None.

    Uvicorn's default log config instantiates ``ColourizedFormatter`` which
    calls ``sys.stdout.isatty()`` — that blows up with
    ``AttributeError: 'NoneType' object has no attribute 'isatty'`` and
    prevents the agent from starting.

    Rather than pipe to /dev/null (which hides real crashes), redirect both
    streams to ``%APPDATA%\\WorkstationAgent\\startup.log`` so any traceback
    at startup is captured to a file the user can send us. Falls back to
    devnull if the log dir can't be written.
    """
    if sys.stdout is None or sys.stderr is None:
        try:
            log = open(_startup_log_path(), "a", encoding="utf-8", buffering=1)  # noqa: SIM115, PTH123
            log.write(f"\n=== startup {os.getpid()} ===\n")
        except OSError:
            log = open(os.devnull, "w", encoding="utf-8", buffering=1)  # noqa: SIM115, PTH123
        if sys.stdout is None:
            sys.stdout = log
        if sys.stderr is None:
            sys.stderr = log
    if sys.stdin is None:
        sys.stdin = io.StringIO("")


#: Tokens that mean "run one thing, print a result or an error, and exit" —
#: as opposed to the default no-args invocation, which starts the windowed
#: app and must stay silent (no console flash).
_CLI_REPORT_TOKENS: tuple[str, ...] = (
    "--diag", "--check-updates", "--rollback", "export-registration",
)


def _wants_console(argv: list[str]) -> bool:
    """True if *argv* asks for one of the report-and-exit commands."""
    return any(token in argv for token in _CLI_REPORT_TOKENS)


def _attach_console() -> None:
    """Attach this process to whatever console launched it, or allocate one.

    The console-binary problem: ``workstation_agent.spec:93`` builds
    ``Agent.exe`` with ``console=False`` — right for the windowed app, which
    lives in the tray and must never flash a terminal — but it means a
    report-and-exit command like ``Agent.exe export-registration`` has
    nowhere to print its output path or an error. PyInstaller's windowed
    bootloader leaves ``sys.stdout``/``sys.stderr`` as ``None``
    (:func:`_ensure_std_streams` below papers over that for uvicorn's
    logging, but a papered-over ``None`` still can't report a CLI result to
    the person who ran the command).

    The fix used here is a documented console-attach rather than a second
    build target: ``AttachConsole(ATTACH_PARENT_PROCESS)`` lets a
    GUI-subsystem executable reattach to the console of whatever process
    launched it — ``console=False`` only means this process does not
    allocate its *own* console window at start, not that it can never talk
    to one. Run from an existing ``cmd``/PowerShell prompt (the normal way
    to run ``export-registration``), this makes ``print()`` land in that
    same window. If there is no parent console at all — double-clicked, or
    launched by a scheduler with no terminal — ``AllocConsole`` opens a
    fresh one so the message is not simply lost.

    A second console-only binary was rejected: it would need its own
    PyInstaller target kept in lockstep with ``Agent.exe`` (same
    hiddenimports, same datas, same version), doubles the artifact PyInstaller
    produces and Inno Setup ships, and buys nothing a single attach call
    does not already give the one CLI command that needs it.

    Interpreter runs (tests, ``python -m workstation_agent``) already have a
    real terminal and are left alone; this only fires for a frozen Windows
    build whose stdout is ``None``.
    """
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return
    if sys.stdout is not None:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        attach_parent_process = -1
        if not kernel32.AttachConsole(attach_parent_process):
            kernel32.AllocConsole()
        sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115, PTH123
        sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115, PTH123
        sys.stdin = open("CONIN$", encoding="utf-8")  # noqa: SIM115, PTH123
    except OSError:
        # Attaching failed (e.g. genuinely no console anywhere reachable).
        # _ensure_std_streams' log-file fallback still runs after this, so a
        # startup failure is at least captured there rather than lost twice.
        pass


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
    min_module_args = 2  # "-m" plus the module name
    # Strip a leading -u (unbuffered stdio) if present.
    args = list(argv[1:])
    if args and args[0] == "-u":
        args = args[1:]
    if not (len(args) >= min_module_args and args[0] == "-m"):
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

    sub = p.add_subparsers(dest="command")
    export_p = sub.add_parser(
        "export-registration",
        help="Write workstation-registration.zip (contract §2) and exit.",
    )
    export_p.add_argument(
        "-o", "--output", metavar="DIR", default=None,
        help="Directory to write workstation-registration.zip into. "
             "Defaults to the current directory.",
    )
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


def _cmd_export_registration(output: str | None) -> int:
    """Write ``workstation-registration.zip`` (contract §2) and report where.

    Reports its output path on success and a real error on failure — the
    problem the console-attach in :func:`_attach_console` exists to solve.
    """
    from workstation_agent.config import store as _cfg_store
    from workstation_agent.registration_export import export_registration

    try:
        cfg = _cfg_store.load()
        result = export_registration(
            cfg.network_mcp,
            output_dir=Path(output) if output else None,
        )
    except Exception as exc:  # noqa: BLE001 — a CLI command reports any failure, never crashes
        print(f"error: could not export the workstation registration: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {result.path} ({len(result.tool_names)} tools, {result.url})")
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
    # A report-and-exit command (export-registration, --diag, ...) needs a
    # real console to report to; the windowed app must stay silent. Decide
    # which this is from the raw argv, before argparse and before
    # _ensure_std_streams() would otherwise paper over stdout with the
    # startup log file.
    if _wants_console(sys.argv[1:]):
        _attach_console()

    # PyInstaller windowed builds leave stdout/stderr as None; give uvicorn +
    # anything else that calls .isatty() something real to talk to.
    _ensure_std_streams()

    # Under PyInstaller, this same EXE is used by the MCP-host supervisor to
    # spawn plugin subprocesses (``sys.executable == Agent.exe``). Detect the
    # ``-u -m <module>`` pattern before argparse and act as a Python runner.
    rc = _maybe_run_as_python(sys.argv)
    if rc is not None:
        return rc

    args = _build_parser().parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if getattr(args, "command", None) == "export-registration":
        return _cmd_export_registration(args.output)
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
    # Log a heartbeat BEFORE anything else so we can confirm Agent.exe ran
    # at all, then wrap main() so any exception at startup lands in
    # %APPDATA%\WorkstationAgent\startup.log — including uvicorn's log-config
    # crash, missing DLL fallout, etc.
    import datetime as _dt
    _startup_write(
        f"\n=== agent boot pid={os.getpid()} at={_dt.datetime.now(_dt.UTC).isoformat()} "
        f"argv={sys.argv!r} frozen={getattr(sys, 'frozen', False)} "
        f"executable={sys.executable!r} ===\n",
    )
    try:
        rc = main()
        _startup_write(f"=== agent exit rc={rc} ===\n")
        sys.exit(rc)
    except SystemExit:
        raise
    except BaseException:
        import traceback
        _startup_write("\n=== unhandled exception at startup ===\n")
        try:
            with open(_startup_log_path(), "a", encoding="utf-8") as f:  # noqa: PTH123
                traceback.print_exc(file=f)
        except OSError:
            pass
        raise
