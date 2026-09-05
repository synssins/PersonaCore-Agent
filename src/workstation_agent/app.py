"""Application composition root — wires every subsystem together.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Threading topology (per SPEC-10 plan audit — do NOT deviate):

* **Main thread** runs :func:`webview.start` (blocking); owned by
  :class:`~workstation_agent.ui.webview.window.WebviewWindow`.
* A **dedicated background thread** runs the asyncio event loop, hosting:

  * :class:`~workstation_agent.mcp_host.host.MCPHost`
  * The audio pipeline (STT / TTS / mic / speaker / session)
  * :class:`~workstation_agent.llm.turn.LLMTurn`
  * :class:`~workstation_agent.updater_client.poller.UpdatePoller`
  * The FastAPI backend running under ``uvicorn.Server``
  * :class:`~workstation_agent.claude_code.driver.ClaudeCodeDriver`
  * The agent's own MCP server on the static named pipe
    (``run_pipe_server``)

* The systray runs on its own thread via
  :meth:`pystray.Icon.run_detached` — invoked from the asyncio thread
  during startup.
* Cross-thread communication:

  * asyncio -> main-thread pywebview via
    :class:`~workstation_agent.ui.webview.window.WebviewWindow`'s
    thread-safe queue (already provided by SPEC-07B).
  * pywebview / systray -> asyncio via
    :func:`asyncio.run_coroutine_threadsafe`.

Startup order (executed inside the asyncio thread before ``webview.start``
returns control to the main thread):

    1. Configure structured logging.
    2. Load config, audit log, session store, secret loader.
    3. Start :class:`MCPHost` (discover + spawn plugins).
    4. Start :class:`WyomingSTTClient`, :class:`WyomingTTSClient`,
       :class:`MicStream`, :class:`Speaker`, :class:`AudioSession`.
    5. Start :class:`OpenAICompatClient`, wire :class:`LLMTurn`.
    6. Wire ``AudioSession.on_transcribed -> LLMTurn.run -> TTS.speak``.
    7. Start FastAPI backend on an ephemeral port; write the ``ui-port``
       file via :func:`write_port_file`.
    8. Start :class:`ToastPresenter`, :class:`SystemTray.run_detached()`.
    9. Start :class:`UpdatePoller`, wire ``on_update_available`` to the
       toast presenter + optional voice announcement.
   10. Start :class:`ClaudeCodeDriver` and the agent's own MCP server on
       the static named pipe.
   11. Signal the main thread to open the WebviewWindow; if the
       first-run flag is missing open ``"/first-run"`` first.

Shutdown (:meth:`Application.shutdown`) reverses the above.
"""
# ruff: noqa: ANN401, BLE001, PLC0415, PLR0915, SLF001

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import uvicorn

log = logging.getLogger(__name__)

_HTTP_OK = 200


def _ensure_tests_on_path() -> None:
    """Make ``tests.fakes`` importable when running from a checkout.

    The tests directory sits at the repo root next to ``src/``; when the
    agent is launched via ``python -m workstation_agent`` from the venv,
    the CWD may not be the repo root, so ``tests.fakes`` may not be on
    ``sys.path``.  This helper locates the repo root by walking up from
    this file and prepends it if the ``tests`` package is present.
    """
    here = Path(__file__).resolve()
    for parent in (here.parent.parent.parent, here.parent.parent.parent.parent):
        if (parent / "tests" / "fakes" / "__init__.py").exists():
            parent_str = str(parent)
            if parent_str not in sys.path:
                sys.path.insert(0, parent_str)
            return

# ---------------------------------------------------------------------------
# Health record — one per subsystem
# ---------------------------------------------------------------------------


@dataclass
class Health:
    """Health snapshot for a single subsystem, produced by ``health()``."""

    ok: bool
    detail: str = ""


# ---------------------------------------------------------------------------
# Application composition root
# ---------------------------------------------------------------------------


@dataclass
class _Subsystems:
    """Handles to every started subsystem — populated by :meth:`_startup`."""

    config: Any = None
    session_store: Any = None
    mcp_host: Any = None
    stt: Any = None
    tts: Any = None
    mic: Any = None
    speaker: Any = None
    audio_session: Any = None
    llm_client: Any = None
    llm_session_id: Any = None
    toast: Any = None
    tray: Any = None
    update_poller: Any = None
    claude_code: Any = None
    mcp_server_task: asyncio.Task[None] | None = None
    audio_task: asyncio.Task[None] | None = None
    uvicorn_server: Any = None
    uvicorn_task: asyncio.Task[None] | None = None
    ui_port: int = 0
    webview_window: Any = None
    http_client: Any = None
    started: dict[str, Health] = field(default_factory=dict)


class Application:
    """Composition root — starts every subsystem and owns their lifecycle.

    Parameters
    ----------
    fake_backends:
        When ``True`` swap in-process fakes for Wyoming, OpenAI and the
        Claude Agent SDK.  Used by :mod:`scripts.boot_check` and by the
        ``--fake-backends`` / ``--diag`` CLI flags.
    headless:
        When ``True`` skip the main-thread :func:`webview.start` call —
        used by ``--diag`` and the boot check.
    autostart:
        Startup mode signal.  Currently informational only (logged +
        stored on the audit trail).
    """

    def __init__(
        self,
        *,
        fake_backends: bool = False,
        headless: bool = False,
        autostart: bool = False,
    ) -> None:
        self._fake = fake_backends
        self._headless = headless
        self._autostart = autostart

        self._subs = _Subsystems()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_ready = threading.Event()
        self._webview_ready = threading.Event()
        self._shutdown_requested = threading.Event()
        self._startup_error: BaseException | None = None
        self._startup_done = threading.Event()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def run(self) -> int:
        """Run the full application; block on the main-thread webview loop.

        Returns
        -------
        int
            0 on clean shutdown, 1 on startup failure.
        """
        self._start_loop_thread()
        self._startup_done.wait(timeout=60.0)
        if self._startup_error is not None:
            log.error("startup failed: %s", self._startup_error)
            self._stop_loop_thread()
            return 1

        if self._headless:
            log.info("headless mode: skipping webview main loop")
            self._shutdown_requested.wait()
            self._stop_loop_thread()
            return 0

        # Main thread runs pywebview — this blocks until the window closes.
        webview_window = self._subs.webview_window
        if webview_window is not None:
            try:
                webview_window.start()
            except Exception:
                log.exception("webview main loop failed")
            finally:
                self._stop_loop_thread()
        else:
            self._shutdown_requested.wait()
            self._stop_loop_thread()

        return 0

    async def diag(self) -> list[tuple[str, Health]]:
        """Run startup + collect a subsystem readiness table.

        Used by the ``--diag`` CLI flag.  Never touches the main-thread
        webview; safe to run inside an existing asyncio context.
        """
        await self._startup_async()
        rows = await self._health_snapshot()
        await self._shutdown_async()
        return rows

    async def health_all(self) -> list[tuple[str, Health]]:
        """Return a subsystem readiness table for a running instance."""
        return await self._health_snapshot()

    # ------------------------------------------------------------------
    # Loop-thread management
    # ------------------------------------------------------------------

    def _start_loop_thread(self) -> None:
        thread = threading.Thread(
            target=self._loop_thread_main,
            name="pc-agent-asyncio",
            daemon=True,
        )
        thread.start()
        self._loop_thread = thread
        self._loop_ready.wait(timeout=10.0)

    def _loop_thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._loop_ready.set()
        try:
            loop.run_until_complete(self._loop_lifecycle())
        finally:
            with contextlib.suppress(Exception):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    async def _loop_lifecycle(self) -> None:
        try:
            await self._startup_async()
        except BaseException as exc:
            self._startup_error = exc
            log.exception("_startup_async raised")
            self._startup_done.set()
            return
        self._startup_done.set()

        # Wait for shutdown request from main thread. The polling loop is
        # deliberate — `_shutdown_requested` is a threading.Event, not an
        # asyncio.Event, so we cannot await it directly.
        while not self._shutdown_requested.is_set():  # noqa: ASYNC110
            await asyncio.sleep(0.1)

        await self._shutdown_async()

    def _stop_loop_thread(self) -> None:
        self._shutdown_requested.set()
        if self._loop_thread is not None and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=15.0)

    def request_shutdown(self) -> None:
        """Ask the asyncio thread to unwind and the main thread to exit.

        Thread-safe; callable from the systray thread or from the
        webview thread.
        """
        self._shutdown_requested.set()
        webview_window = self._subs.webview_window
        if webview_window is not None:
            with contextlib.suppress(Exception):
                webview_window.stop()

    # ------------------------------------------------------------------
    # Async startup / shutdown
    # ------------------------------------------------------------------

    async def _startup_async(self) -> None:
        """Run the ordered startup sequence documented in the module docstring."""
        # Step 1 — logging.
        self._configure_logging()

        # Step 2 — config, session store, http client.
        self._subs.config = self._load_config()
        self._subs.session_store = self._start_session_store()
        self._subs.http_client = httpx.AsyncClient(timeout=30.0)

        # Step 3 — MCP host.
        self._subs.mcp_host = await self._start_mcp_host(self._subs.config)

        # Steps 4 & 5 & 6 — audio + LLM + wiring.
        await self._start_audio_pipeline(self._subs.config)

        # Step 7 — FastAPI backend.
        await self._start_fastapi_backend()

        # Step 8 — ToastPresenter + SystemTray.
        self._start_toast_and_tray()

        # Step 9 — Update poller.
        await self._start_update_poller(self._subs.config)

        # Step 10 — ClaudeCodeDriver + agent MCP server.
        self._start_claude_code_driver()
        await self._start_agent_mcp_server()

        # Step 11 — WebviewWindow (created on asyncio thread; started
        # by the main thread inside ``run()``).
        if not self._headless:
            self._create_webview_window()

        self._webview_ready.set()

    async def _shutdown_async(self) -> None:  # noqa: C901
        """Reverse-order teardown from the asyncio thread."""
        subs = self._subs

        if subs.mcp_server_task is not None:
            subs.mcp_server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await subs.mcp_server_task

        if subs.update_poller is not None:
            with contextlib.suppress(Exception):
                await subs.update_poller.stop()

        if subs.tray is not None:
            with contextlib.suppress(Exception):
                subs.tray.stop()

        if subs.uvicorn_server is not None:
            with contextlib.suppress(Exception):
                subs.uvicorn_server.should_exit = True
            if subs.uvicorn_task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await asyncio.wait_for(subs.uvicorn_task, timeout=5.0)

        if subs.audio_task is not None:
            subs.audio_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await subs.audio_task

        if subs.mic is not None:
            with contextlib.suppress(Exception):
                await subs.mic.stop()
        if subs.speaker is not None:
            with contextlib.suppress(Exception):
                await subs.speaker.stop()

        if subs.mcp_host is not None:
            with contextlib.suppress(Exception):
                await subs.mcp_host.stop()

        if subs.http_client is not None:
            with contextlib.suppress(Exception):
                await subs.http_client.aclose()

        if subs.session_store is not None:
            with contextlib.suppress(Exception):
                subs.session_store.close()

    # ------------------------------------------------------------------
    # Individual subsystem starters
    # ------------------------------------------------------------------

    def _configure_logging(self) -> None:
        from workstation_agent.config import store as _cfg_store
        from workstation_agent.observability import logging as obs_logging

        logs_dir = _cfg_store.paths()["logs_dir"]
        logs_dir.mkdir(parents=True, exist_ok=True)
        try:
            obs_logging.configure(logs_dir)
        except Exception:
            logging.basicConfig(level=logging.INFO)
        self._subs.started["logging"] = Health(ok=True, detail=str(logs_dir))

    def _load_config(self) -> Any:
        from workstation_agent.config import store as _cfg_store

        cfg = _cfg_store.load()
        self._subs.started["config"] = Health(ok=True, detail="loaded")
        return cfg

    def _start_session_store(self) -> Any:
        from workstation_agent.config import store as _cfg_store
        from workstation_agent.llm.session_store import SessionStore

        db_path = _cfg_store.paths()["conversations_db"]
        db_path.parent.mkdir(parents=True, exist_ok=True)
        store = SessionStore(db_path)
        self._subs.started["session_store"] = Health(ok=True, detail=str(db_path))
        return store

    async def _start_mcp_host(self, cfg: Any) -> Any:
        from workstation_agent.mcp_host.host import MCPHost

        host = MCPHost()
        try:
            await host.start(cfg)
        except Exception as exc:
            log.warning("MCPHost start reported error: %s", exc)
            self._subs.started["mcp_host"] = Health(ok=False, detail=repr(exc))
            return host
        self._subs.started["mcp_host"] = Health(ok=True, detail="started")
        return host

    async def _start_audio_pipeline(self, cfg: Any) -> None:
        from workstation_agent.audio.session import AudioSession, SessionMode
        from workstation_agent.audio.sink import Speaker
        from workstation_agent.audio.stt import WyomingSTTClient
        from workstation_agent.audio.tts import WyomingTTSClient
        from workstation_agent.llm.client import OpenAICompatClient

        connect_fn = None
        base_url = str(cfg.llm.base_url)
        if self._fake:
            _ensure_tests_on_path()
            from tests.fakes.fake_openai import ScenarioQueue, build_app, text_response
            from tests.fakes.fake_wyoming import FakeWyomingServer

            self._fake_wyoming = FakeWyomingServer(canned_transcript="what time is it")
            await self._fake_wyoming.__aenter__()
            connect_fn = self._fake_wyoming.connect
            self._fake_openai_queue = ScenarioQueue()
            self._fake_openai_queue.push([text_response("It is noon.")])
            self._fake_openai_app = build_app(self._fake_openai_queue)
            # In fake mode the LLM does not need a real HTTP endpoint; the
            # boot check exercises the audio+STT+TTS round trip only.
            base_url = "http://127.0.0.1:65535"

        self._subs.stt = WyomingSTTClient(
            cfg.wyoming.host, cfg.wyoming.port, connect_fn=connect_fn,
        )
        self._subs.tts = WyomingTTSClient(
            cfg.wyoming.host, cfg.wyoming.port, voice=cfg.wyoming.tts_voice,
            connect_fn=connect_fn,
        )

        # Speaker + mic — use fake backends in fake mode so we don't need
        # real audio hardware (which the boot check host lacks).
        speaker = Speaker(backend=_NullSink()) if self._fake else Speaker()
        try:
            await speaker.start()
        except Exception as exc:
            log.warning("Speaker start failed: %s (continuing)", exc)
        self._subs.speaker = speaker

        # Mic is optional; skip in fake mode entirely.
        if not self._fake:
            from workstation_agent.audio.mic import MicStream

            try:
                mic = MicStream()
                await mic.start()
                self._subs.mic = mic
            except Exception as exc:
                log.warning("MicStream start failed: %s (continuing)", exc)

        # LLM client
        self._subs.llm_client = OpenAICompatClient(
            base_url=base_url,
            model=cfg.llm.model,
            api_key="",  # loaded from DPAPI in real deployment
        )
        self._subs.llm_session_id = self._subs.session_store.start_session(
            cfg.session.mode,
        )

        # AudioSession wiring — on_transcribed dispatches into LLMTurn and
        # returns a future the session awaits.  Not started until we've
        # created a real turn callback.
        mode = SessionMode(cfg.session.mode)

        async def _on_transcribed(text: str) -> str:
            return await self._run_llm_turn(text)

        def _sync_transcribed(text: str) -> asyncio.Future[str]:
            loop = asyncio.get_running_loop()
            fut: asyncio.Future[str] = loop.create_future()

            async def _driver() -> None:
                try:
                    reply = await _on_transcribed(text)
                    fut.set_result(reply)
                except Exception as exc:
                    fut.set_exception(exc)

            asyncio.create_task(_driver())  # noqa: RUF006
            return fut

        session = AudioSession(
            stt=self._subs.stt,
            tts=self._subs.tts,
            speaker=self._subs.speaker,
            on_transcribed=_sync_transcribed,
            mode=mode,
            sticky_seconds=cfg.session.sticky_seconds,
        )
        self._subs.audio_session = session

        # We do NOT block startup on the session run() — it is a persistent
        # loop that only makes sense with a live wake source.  In fake mode
        # the boot check drives the session's on_transcribed hook directly
        # via a helper, so we skip session.run() entirely.
        self._subs.started["audio_pipeline"] = Health(ok=True, detail=f"mode={mode.value}")
        self._subs.started["llm_client"] = Health(ok=True, detail=cfg.llm.model)

    async def _run_llm_turn(self, user_text: str) -> str:
        """Drive one full LLMTurn and return the accumulated text reply."""
        # In fake mode we short-circuit to a canned string so the boot
        # check has a deterministic reply without needing the LLM stack.
        if self._fake:
            reply = "It is noon."
            try:
                task = await self._subs.tts.speak(reply)
                # Drive the TTS iterator to completion so audio is emitted.
                async for chunk in self._subs.tts.audio_chunks(task):
                    if self._subs.speaker is not None:
                        self._subs.speaker.enqueue(chunk)
            except Exception:
                log.exception("fake-mode tts flow failed")
            return reply

        from workstation_agent.llm.turn import LLMTurn

        turn = LLMTurn(
            client=self._subs.llm_client,
            host=self._subs.mcp_host,
            store=self._subs.session_store,
            session_id=self._subs.llm_session_id,
            system_prompt=self._subs.config.llm.system_prompt,
        )
        chunks: list[str] = []
        try:
            async for event in turn.run(user_text):
                if getattr(event, "kind", "") == "text_chunk":
                    chunks.append(getattr(event, "text", ""))  # noqa: PERF401
        except Exception:
            log.exception("LLMTurn raised")
        return "".join(chunks)

    async def _start_fastapi_backend(self) -> None:
        """Bind FastAPI on an ephemeral port; write ``ui-port`` for pywebview."""
        from workstation_agent.ui.backend.app import (
            BackendContext,
            create_app,
            write_port_file,
        )

        ctx = BackendContext(
            session_store=self._subs.session_store,
            mcp_host=self._subs.mcp_host,
            current_version="0.1.0",
        )
        app = create_app(ctx)

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=0,  # ephemeral — the OS picks
            log_level="warning",
            lifespan="off",
        )
        server = uvicorn.Server(config)

        # Server.serve() must run as a task on the current loop so we can
        # inspect the assigned port after `startup` completes.
        task = asyncio.create_task(server.serve(), name="uvicorn-serve")
        self._subs.uvicorn_server = server
        self._subs.uvicorn_task = task

        # Wait for the server to bind — poll ``started`` + inspect sockets.
        deadline = asyncio.get_running_loop().time() + 10.0
        while asyncio.get_running_loop().time() < deadline:
            if getattr(server, "started", False) and server.servers:
                break
            await asyncio.sleep(0.05)

        port = 0
        for s in server.servers:
            for sock in s.sockets:
                port = sock.getsockname()[1]
                break
            if port:
                break

        self._subs.ui_port = port
        if port:
            write_port_file(port)
            self._subs.started["fastapi"] = Health(ok=True, detail=f"127.0.0.1:{port}")
        else:
            self._subs.started["fastapi"] = Health(ok=False, detail="no port bound")

    def _start_toast_and_tray(self) -> None:
        from workstation_agent.ui.notifications.toast import ToastPresenter
        from workstation_agent.ui.systray.tray import SystemTray

        try:
            toast = ToastPresenter(app_id="WorkstationAgent")
            self._subs.toast = toast
            self._subs.started["toast"] = Health(ok=True, detail="ready")
        except Exception as exc:
            log.warning("ToastPresenter failed: %s", exc)
            self._subs.started["toast"] = Health(ok=False, detail=repr(exc))

        port = self._subs.ui_port

        def _url_provider() -> str:
            return f"http://127.0.0.1:{port or 8765}"

        tray = SystemTray(
            webview_window=None,  # wired after webview_window is created
            url_provider=_url_provider,
            on_exit=self.request_shutdown,
        )
        try:
            # Skip run_detached in headless mode — the tray tries to create
            # a real Win32 window which some CI environments lack.
            self._subs.tray = tray
            if not self._headless:
                tray.run_detached()
                self._subs.started["systray"] = Health(ok=True, detail="detached")
            else:
                self._subs.started["systray"] = Health(ok=True, detail="ready (headless)")
        except Exception as exc:
            log.warning("SystemTray failed: %s", exc)
            self._subs.started["systray"] = Health(ok=False, detail=repr(exc))

    async def _start_update_poller(self, cfg: Any) -> None:
        from workstation_agent.security.first_party_pubkey import FIRST_PARTY_PUBKEY
        from workstation_agent.updater_client.poller import UpdatePoller

        async def _on_update(manifest: Any, _raw: bytes, _sig: bytes) -> None:
            log.info("update-available: version=%s", manifest.version)
            toast = self._subs.toast
            if toast is not None:
                from workstation_agent.ui.notifications.toast import show_update_toast

                with contextlib.suppress(Exception):
                    show_update_toast(toast, manifest.version)

        if self._fake:
            self._subs.started["update_poller"] = Health(ok=True, detail="skipped (fake)")
            return

        poller = UpdatePoller(
            github_repo=cfg.update.github_repo,
            current_version="0.1.0",
            pubkey=FIRST_PARTY_PUBKEY,
            http=self._subs.http_client,
            on_update_available=_on_update,
            poll_interval_seconds=cfg.update.poll_interval_hours * 3600.0,
        )
        try:
            poller.start()
            self._subs.update_poller = poller
            self._subs.started["update_poller"] = Health(ok=True, detail="started")
        except Exception as exc:
            log.warning("UpdatePoller failed: %s", exc)
            self._subs.started["update_poller"] = Health(ok=False, detail=repr(exc))

    def _start_claude_code_driver(self) -> None:
        from workstation_agent.claude_code.driver import ClaudeCodeDriver

        try:
            driver = ClaudeCodeDriver(
                tts=self._subs.tts,
                audio_session=None,
            )
            self._subs.claude_code = driver
            self._subs.started["claude_code"] = Health(ok=True, detail="ready")
        except Exception as exc:
            log.warning("ClaudeCodeDriver failed: %s", exc)
            self._subs.started["claude_code"] = Health(ok=False, detail=repr(exc))

    async def _start_agent_mcp_server(self) -> None:
        """Start the agent's own MCP server on the static named pipe."""
        from workstation_agent.mcp_host import mcp_server

        if self._fake or os.environ.get("PC_AGENT_SKIP_MCP_PIPE") == "1":
            self._subs.started["mcp_server"] = Health(ok=True, detail="skipped (fake/env)")
            return

        try:
            token = mcp_server.load_token() or mcp_server.generate_and_store_token()
        except Exception as exc:
            log.warning("MCP server token setup failed: %s", exc)
            self._subs.started["mcp_server"] = Health(ok=False, detail=repr(exc))
            return

        async def _runner() -> None:
            try:
                await mcp_server.run_pipe_server(
                    token,
                    tts=self._subs.tts,
                    toast=self._subs.toast,
                    mcp_host=self._subs.mcp_host,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("agent mcp_server crashed")

        task = asyncio.create_task(_runner(), name="agent-mcp-pipe-server")
        self._subs.mcp_server_task = task
        self._subs.started["mcp_server"] = Health(ok=True, detail="listening")

    def _create_webview_window(self) -> None:
        from workstation_agent.ui.backend.app import first_run_completed
        from workstation_agent.ui.webview.window import WebviewWindow

        port = self._subs.ui_port

        def _url_provider() -> str:
            return f"http://127.0.0.1:{port or 8765}"

        window = WebviewWindow(url_provider=_url_provider)
        # Enqueue the first navigation; the queue is drained inside
        # ``start()`` on the main thread.
        if first_run_completed():
            window.open("/dashboard")
        else:
            window.open("/first-run")
        self._subs.webview_window = window
        # Wire the tray back to the webview so menu items can open pages.
        tray = self._subs.tray
        if tray is not None:
            tray._webview = window
    # ------------------------------------------------------------------
    # Health snapshot
    # ------------------------------------------------------------------

    async def _health_snapshot(self) -> list[tuple[str, Health]]:
        rows = list(self._subs.started.items())
        # If uvicorn is running, verify /dashboard responds.
        port = self._subs.ui_port
        if port:
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(f"http://127.0.0.1:{port}/dashboard")
                    ok = resp.status_code == _HTTP_OK
                    rows.append(("fastapi_dashboard", Health(
                        ok=ok, detail=f"status={resp.status_code}",
                    )))
            except Exception as exc:
                rows.append(
                    ("fastapi_dashboard", Health(ok=False, detail=repr(exc))),
                )
        return rows


# ---------------------------------------------------------------------------
# Helper — null audio sink used in --fake-backends mode
# ---------------------------------------------------------------------------


class _NullSink:
    """Discard PCM bytes; keeps :class:`Speaker` alive without hardware."""

    def write(self, data: bytes) -> None:  # noqa: ARG002
        return

    def close(self) -> None:
        return
