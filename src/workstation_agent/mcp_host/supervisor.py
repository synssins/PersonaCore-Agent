"""Plugin subprocess supervisor.

Spawns MCP plugin subprocesses on Windows with:

* an explicit environment allow-list (no accidental credential leakage),
* a Windows Job Object wrapping the child (kill-on-close, memory + active
  process limits) via ``pywin32``,
* a low-integrity primary token when the OS + SKU permits it — otherwise the
  parent's integrity level with a WARN log and ``integrity="medium"`` on the
  returned handle so callers / UI can badge the plugin as "reduced isolation".

Only the SPEC-03A files (``supervisor.py``, ``mcp_client.py``, ``watchdog.py``)
in ``mcp_host/`` are affected by this module; higher-level plugin discovery,
signature verification, permissions and audit live in SPEC-03B.
"""
# ruff: noqa: S101, ANN401
# S101: internal-invariant asserts (mypy narrowing) are intentional.
# ANN401: pywin32 has no type stubs; ``Any`` is unavoidable for handles.
#
# pyright: reportAttributeAccessIssue=false, reportArgumentType=false
# The pywin32 type stubs model PyHANDLE as ``int`` but the runtime object is
# a rich wrapper with ``.Close()`` / ``.Detach()`` methods and accepts ``None``
# for optional SECURITY_ATTRIBUTES arguments. Every one of these two error
# categories in this module is a stub artefact, not a real bug.

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import msvcrt
import os
import subprocess
import threading
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, Any

import win32api
import win32con
import win32job
import win32pipe
import win32process
import win32security

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from collections.abc import Awaitable, Callable
    from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MB = 1024 * 1024

#: Exact list of OS environment variables that a plugin subprocess is allowed
#: to inherit. Passing only ``PATH`` breaks Python ``%TEMP%``-dependent
#: imports, ``tempfile`` creation, and every Windows API that needs
#: ``%SYSTEMROOT%``. Passing everything is a credential-leak vector. This
#: whitelist is the compromise SPEC-03A pins.
ENV_WHITELIST: tuple[str, ...] = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PATHEXT",
    "PATH",
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)

#: SID string for low integrity level.
_LOW_INTEGRITY_SID = "S-1-16-4096"

#: CreateProcess flag we always want in the spawn: gives the child its own
#: process group so a Ctrl-Break signal only hits the plugin tree.
_CREATE_NEW_PROCESS_GROUP = 0x00000200


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceLimits:
    """Job Object resource limits for a spawned plugin."""

    max_memory_mb: int = 512
    max_job_memory_mb: int = 768
    max_active_processes: int = 4
    #: Optional per-job user-mode time limit in 100-ns units (LIMIT_JOB_TIME).
    #: ``None`` means "unlimited"; supervisor doesn't set the flag.
    job_user_time_100ns: int | None = None


@dataclass
class SubprocessHandle:
    """Everything needed to talk to / tear down a spawned plugin."""

    pid: int
    process: subprocess.Popen[bytes]
    job_handle: Any  # PyHANDLE; typed as Any because pywin32 stubs are absent.
    integrity: str  # "low" or "medium"
    stdin: IO[bytes]
    stdout: IO[bytes]
    plugin_id: str
    resource_limits: ResourceLimits
    #: True once ``terminate`` has run to completion; used by tests + watchdog.
    closed: bool = field(default=False)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def build_child_env(plugin_id: str) -> dict[str, str]:
    """Assemble the child environment from ``ENV_WHITELIST`` + ``WSA_PLUGIN_ID``.

    Values missing from the parent environment are simply skipped — we never
    inject empty strings for variables like ``USERDOMAIN`` that may be absent
    on domain-less machines.
    """
    env: dict[str, str] = {}
    for name in ENV_WHITELIST:
        val = os.environ.get(name)
        if val is not None:
            env[name] = val
    env["WSA_PLUGIN_ID"] = plugin_id
    return env


# ---------------------------------------------------------------------------
# Job Object helpers (pywin32)
# ---------------------------------------------------------------------------


def _create_job_object(limits: ResourceLimits) -> Any:
    """Create a Windows Job Object with the SPEC-03A limits applied."""
    job = win32job.CreateJobObject(None, "")  # type: ignore[arg-type]
    info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)

    flags = (
        win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
        | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    )
    basic = info["BasicLimitInformation"]
    basic["LimitFlags"] = flags
    basic["ActiveProcessLimit"] = limits.max_active_processes

    if limits.job_user_time_100ns is not None:
        basic["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_JOB_TIME
        basic["PerJobUserTimeLimit"] = limits.job_user_time_100ns

    info["BasicLimitInformation"] = basic
    info["ProcessMemoryLimit"] = limits.max_memory_mb * _MB
    info["JobMemoryLimit"] = limits.max_job_memory_mb * _MB

    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
    return job


def _assign_process_to_job(job: Any, process_handle: Any) -> None:
    win32job.AssignProcessToJobObject(job, process_handle)


def _close_job(job: Any) -> None:
    """Close a job handle. Closing kills the tree (KILL_ON_JOB_CLOSE)."""
    try:
        win32api.CloseHandle(job)
    except Exception:
        log.exception("failed to close job object")


# ---------------------------------------------------------------------------
# Low-integrity token / spawn
# ---------------------------------------------------------------------------


def _make_low_integrity_token() -> Any:
    """Duplicate the current process token, set integrity to low, return it.

    Raises on any failure; caller decides whether to fall back.
    """
    current = win32api.GetCurrentProcess()
    src_token = win32security.OpenProcessToken(
        current,
        win32con.TOKEN_DUPLICATE
        | win32con.TOKEN_ADJUST_DEFAULT
        | win32con.TOKEN_QUERY
        | win32con.TOKEN_ASSIGN_PRIMARY,
    )
    dup = win32security.DuplicateTokenEx(
        src_token,
        win32security.SecurityImpersonation,
        win32con.MAXIMUM_ALLOWED,
        win32security.TokenPrimary,
    )
    sid = win32security.ConvertStringSidToSid(_LOW_INTEGRITY_SID)
    til = (sid, win32security.SE_GROUP_INTEGRITY)
    win32security.SetTokenInformation(dup, win32security.TokenIntegrityLevel, til)
    return dup


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------


class PluginSupervisor:
    """Spawn / terminate plugin subprocesses with Windows isolation."""

    def __init__(self) -> None:
        self._handles: dict[int, SubprocessHandle] = {}
        self._lock = threading.Lock()

    # -- spawn ----------------------------------------------------------------

    def spawn(
        self,
        entry_cmd: list[str],
        cwd: Path,
        plugin_id: str,
        resource_limits: ResourceLimits | None = None,
    ) -> SubprocessHandle:
        """Spawn ``entry_cmd`` under a Job Object with a low-integrity token."""
        limits = resource_limits or ResourceLimits()
        env = build_child_env(plugin_id)

        job = _create_job_object(limits)

        # Try the low-integrity path first. Any failure -> fall back to a
        # plain ``subprocess.Popen`` at parent integrity, log a WARN, and
        # tag the handle so higher layers can badge the plugin.
        integrity: str = "low"
        token: Any | None = None
        try:
            token = _make_low_integrity_token()
        except Exception as exc:  # noqa: BLE001 - we WANT the broad catch
            log.warning(
                "low-integrity token unavailable (plugin_id=%s): %s - falling back "
                "to parent integrity; SubprocessHandle.integrity='medium'",
                plugin_id,
                exc,
            )
            integrity = "medium"
            token = None

        popen: subprocess.Popen[bytes]
        if token is not None:
            try:
                popen = self._spawn_low_integrity(entry_cmd, cwd, env, token)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "low-integrity spawn failed (plugin_id=%s): %s - falling back "
                    "to parent integrity; SubprocessHandle.integrity='medium'",
                    plugin_id,
                    exc,
                )
                integrity = "medium"
                popen = self._spawn_medium_integrity(entry_cmd, cwd, env)
        else:
            popen = self._spawn_medium_integrity(entry_cmd, cwd, env)

        # Assign to Job Object AFTER spawn so KILL_ON_JOB_CLOSE covers the
        # tree. On Windows 8+ nested jobs are allowed; we rely on that.
        try:
            self._assign_popen_to_job(popen, job)
        except Exception:
            log.exception("assign-to-job failed; killing subprocess")
            popen.kill()
            _close_job(job)
            raise

        assert popen.stdin is not None
        assert popen.stdout is not None
        handle = SubprocessHandle(
            pid=popen.pid,
            process=popen,
            job_handle=job,
            integrity=integrity,
            stdin=popen.stdin,
            stdout=popen.stdout,
            plugin_id=plugin_id,
            resource_limits=limits,
        )
        with self._lock:
            self._handles[handle.pid] = handle

        # Stderr pump -> logger (background thread; no join needed, the
        # thread dies when Popen closes stderr).
        if popen.stderr is not None:
            t = threading.Thread(
                target=_pump_stderr,
                args=(popen.stderr, plugin_id),
                name=f"stderr-pump-{plugin_id}",
                daemon=True,
            )
            t.start()

        log.info(
            "spawned plugin subprocess plugin_id=%s pid=%d integrity=%s",
            plugin_id,
            popen.pid,
            integrity,
        )
        return handle

    # -- spawn implementations -----------------------------------------------

    @staticmethod
    def _spawn_medium_integrity(
        cmd: list[str],
        cwd: Path,
        env: dict[str, str],
    ) -> subprocess.Popen[bytes]:
        return subprocess.Popen(  # noqa: S603 - cmd is caller-controlled
            cmd,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_CREATE_NEW_PROCESS_GROUP,
        )

    @staticmethod
    def _spawn_low_integrity(
        cmd: list[str],
        cwd: Path,
        env: dict[str, str],
        token: Any,
    ) -> subprocess.Popen[bytes]:
        """Spawn via CreateProcessAsUser then wrap the handle in a Popen.

        CPython's ``subprocess.Popen`` on Windows doesn't expose a hook for
        ``CreateProcessAsUser``. We DIY the pipes + spawn here (see
        :class:`_PopenAsUser`) and adopt the resulting handles into a
        Popen-compatible object so higher layers get the familiar API.
        Errors in this path trigger the medium-integrity fallback in
        :meth:`PluginSupervisor.spawn`.
        """
        return _PopenAsUser(cmd, cwd, env, token)

    @staticmethod
    def _assign_popen_to_job(popen: subprocess.Popen[bytes], job: Any) -> None:
        # AssignProcessToJobObject wants a PyHANDLE; we always open a fresh
        # one from the pid so this works uniformly for both standard Popen
        # (whose ._handle is an int on Windows) and _PopenAsUser.
        proc_handle = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE,
            False,  # noqa: FBT003 - Win32 API positional
            popen.pid,
        )
        try:
            _assign_process_to_job(job, proc_handle)
        finally:
            proc_handle.Close()  # type: ignore[attr-defined]

    # -- terminate ------------------------------------------------------------

    async def terminate(
        self,
        handle: SubprocessHandle,
        *,
        hard_after: float = 5.0,
        shutdown_fn: Callable[[], Awaitable[None] | None] | None = None,
    ) -> None:
        """Terminate ``handle`` gracefully then hard-close the Job Object.

        ``shutdown_fn`` is an optional callable that performs the MCP
        ``shutdown`` handshake. It is separate from the client so tests can
        supply a fake; in production SPEC-03B wires
        :meth:`MCPStdioClient.shutdown` in here. It may be sync or async — if
        it returns an awaitable we await it (this is the fix for the
        deadlock: a sync ``handle.process.wait`` would otherwise block the
        event loop before the awaitable ever ran).

        The blocking ``process.wait`` is off-loaded to the default executor so
        the event loop stays responsive; callers must be in an asyncio
        context. See :meth:`terminate_sync` for signal-handler cleanup.
        """
        if handle.closed:
            return

        # Graceful phase: give the plugin a chance to flush + exit.
        if shutdown_fn is not None:
            try:
                result = shutdown_fn()
                if inspect.isawaitable(result):
                    await result
            except Exception:
                log.warning("shutdown_fn raised for pid=%d; forcing", handle.pid, exc_info=True)

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, handle.process.wait),
                timeout=hard_after,
            )
        except TimeoutError:
            log.info("plugin pid=%d did not exit in %.1fs; killing job", handle.pid, hard_after)
        except Exception:
            log.exception("wait() failed for pid=%d", handle.pid)

        self._hard_close(handle)

    def terminate_sync(self, handle: SubprocessHandle) -> None:
        """Synchronous cleanup for signal-handler / atexit paths.

        Skips the graceful ``shutdown_fn`` handshake (which would need an
        event loop) and jumps straight to closing the Job Object. Safe to
        call from a signal handler where ``asyncio.run`` is unavailable.
        """
        if handle.closed:
            return
        self._hard_close(handle)

    def _hard_close(self, handle: SubprocessHandle) -> None:
        """Close the Job Object, drain pipes, drop from registry."""
        # Hard phase: closing the Job Object kills the whole tree.
        _close_job(handle.job_handle)

        # Belt-and-suspenders: force-kill the Popen too in case the job close
        # was rejected (e.g. the tests exercise medium-integrity + no job).
        if handle.process.poll() is None:
            try:
                handle.process.kill()
            except Exception:
                log.exception("popen.kill() failed for pid=%d", handle.pid)

        # Drain the pipes so we don't leak file descriptors.
        for stream in (handle.stdin, handle.stdout):
            with contextlib.suppress(Exception):
                stream.close()

        handle.closed = True
        with self._lock:
            self._handles.pop(handle.pid, None)
        log.info("terminated plugin pid=%d plugin_id=%s", handle.pid, handle.plugin_id)


def _pump_stderr(stream: IO[bytes], plugin_id: str) -> None:
    """Forward a subprocess' stderr lines to the logger."""
    try:
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                log.info("[%s stderr] %s", plugin_id, line)
    except Exception:  # pragma: no cover - defensive
        log.debug("stderr pump exiting for %s", plugin_id, exc_info=True)
    finally:
        with contextlib.suppress(Exception):
            stream.close()


# ---------------------------------------------------------------------------
# _PopenAsUser
# ---------------------------------------------------------------------------


class _PopenAsUser(subprocess.Popen[bytes]):
    """A ``subprocess.Popen`` that spawns via ``CreateProcessAsUser``.

    We deliberately override ``__init__`` rather than ``_execute_child`` so we
    can control pipe creation with inheritable handles. Everything after the
    spawn behaves like a normal Popen: ``wait``, ``poll``, ``kill``,
    ``stdin`` / ``stdout`` / ``stderr`` all work.
    """

    def __init__(  # noqa: PLR0915 - the Win32 spawn dance is inherently long
        self,
        cmd: list[str],
        cwd: Path,
        env: dict[str, str],
        token: Any,
    ) -> None:
        # --- create three inheritable pipes ---------------------------------
        sa_inherit = win32security.SECURITY_ATTRIBUTES()
        sa_inherit.bInheritHandle = 1

        # For each pipe we mark ONLY the end the child needs as inheritable;
        # the parent end is made non-inheritable via SetHandleInformation.
        stdin_r, stdin_w = win32pipe.CreatePipe(sa_inherit, 0)
        stdout_r, stdout_w = win32pipe.CreatePipe(sa_inherit, 0)
        stderr_r, stderr_w = win32pipe.CreatePipe(sa_inherit, 0)

        win32api.SetHandleInformation(stdin_w, win32con.HANDLE_FLAG_INHERIT, 0)
        win32api.SetHandleInformation(stdout_r, win32con.HANDLE_FLAG_INHERIT, 0)
        win32api.SetHandleInformation(stderr_r, win32con.HANDLE_FLAG_INHERIT, 0)

        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESTDHANDLES
        startup.hStdInput = stdin_r
        startup.hStdOutput = stdout_w
        startup.hStdError = stderr_w

        creation_flags = _CREATE_NEW_PROCESS_GROUP | win32con.CREATE_NO_WINDOW

        command_line = subprocess.list2cmdline(list(cmd))
        h_proc, h_thread, pid, _tid = win32process.CreateProcessAsUser(
            token,
            cmd[0],
            command_line,
            None,
            None,
            True,  # noqa: FBT003 - Win32 API positional (bInheritHandles)
            creation_flags,
            env,
            str(cwd),
            startup,
        )

        # Close the child-side handles in the parent.
        stdin_r.Close()
        stdout_w.Close()
        stderr_w.Close()

        # --- adopt handles into Popen ---------------------------------------
        # We skip Popen.__init__ entirely because it wants to CreateProcess
        # itself. We assemble the attributes it needs by hand.
        self.args = cmd

        # Snapshot the OS handle integers BEFORE detaching so we can safely
        # hand them to msvcrt / _winapi (both need plain ints, not PyHANDLE).
        stdin_w_int = int(stdin_w)
        stdout_r_int = int(stdout_r)
        stderr_r_int = int(stderr_r)
        proc_handle_int = int(h_proc)

        self.stdin = os.fdopen(msvcrt.open_osfhandle(stdin_w_int, 0), "wb", 0)
        self.stdout = os.fdopen(msvcrt.open_osfhandle(stdout_r_int, os.O_RDONLY), "rb", 0)
        self.stderr = os.fdopen(msvcrt.open_osfhandle(stderr_r_int, os.O_RDONLY), "rb", 0)

        # Detach the handles from the pywin32 wrappers now that msvcrt / this
        # class own the underlying OS handles. Detach() prevents pywin32's
        # __del__ from closing them out from under us.
        stdin_w.Detach()
        stdout_r.Detach()
        stderr_r.Detach()

        # CPython's Popen.wait / poll go through _winapi.WaitForSingleObject
        # which requires a plain int, not a PyHANDLE. Store the int form.
        self._handle = proc_handle_int  # type: ignore[assignment]
        # Keep the PyHANDLE alive on the instance so its refcount stays > 0;
        # we detach it so pywin32 doesn't double-close.
        self._pyhandle = h_proc
        h_proc.Detach()
        self.pid = pid
        self.returncode = None
        self._child_created = True
        self._closed_child_pipe_fds = False
        self._communication_started = False
        self._input = None
        self._communicate_ok = False
        self._waitpid_lock = threading.Lock()
        self._sigint_wait_secs = 0.25
        self._devnull: int | None = None
        # Close the thread handle - we don't need it.
        h_thread.Close()

        # Populate the fields Popen.__del__ expects.
        self.encoding = None
        self.errors = None
        self.text_mode = False
        self.pipesize = 0
        self.process_group = 0
        self.universal_newlines = False
        self._creationflags = creation_flags
