# SPEC-07 — UI: systray + WebView2 + FastAPI backend + toast notifications + logging

**Executor tier:** sonnet. **Branch:** `feat/spec-07-ui`. **Worktree:** `../wsa-spec-07/`.
**Depends on:** SPEC-01, SPEC-02, SPEC-03 (MCPHost Protocol), SPEC-06 (update flow surface).

## Goal

Deliver the user-facing surface: systray icon with full menu, WebView2 window pointed at a local FastAPI serving all UI pages, Windows toast notifications with action buttons, structured logging.

Visual **design** of the pages is explicitly out of scope — ship functional-unstyled HTML forms/tables that a follow-up pass with `interface-design` will restyle without changing routes/data contracts.

## Files to create / modify (only these)

- `src/workstation_agent/ui/systray/__init__.py`
- `src/workstation_agent/ui/systray/tray.py`:
  - `class SystemTray` using `pystray`. Icon PNG shipped in `ui/systray/assets/icon.png` (a plain generated 32×32 placeholder — Chris will replace).
  - Right-click menu items:
    - **Open** (double-click default) — opens WebView2 window to `/dashboard`.
    - **Mute agent** (checkbox) — toggles combined mic + speaker mute (calls into audio subsystem via injected callbacks).
    - **Session mode ›** submenu: Single-shot / Sticky / Persistent (radio) — writes to config.
    - **Reload plugins** (badge shows count of pending-reload plugins).
    - **Check for updates now** — triggers `UpdatePoller.check_now()`.
    - **Open config** — WebView2 to `/config`.
    - **Show audit log** — WebView2 to `/audit`.
    - **Show logs folder** — Explorer window at logs dir.
    - **About** — WebView2 to `/about`.
    - **Exit** — clean shutdown.
- `src/workstation_agent/ui/webview/window.py`:
  - `class WebviewWindow` — thin wrapper around `pywebview` (Edge backend on Windows). Runs its own event loop on a dedicated thread; agent stays running when window closes (`close_to_tray` config default true).
  - `open(path: str)` — navigates the window to `http://127.0.0.1:<port>{path}`; creates the window lazily on first call.
  - `close()` — hides but doesn't destroy (fast re-open).
- `src/workstation_agent/ui/backend/__init__.py`
- `src/workstation_agent/ui/backend/app.py`:
  - FastAPI app bound to `127.0.0.1:0` (OS-picked ephemeral port; port written to `%APPDATA%\WorkstationAgent\ui-port` for the WebView2 side to read).
  - Routes:
    - `GET /` → redirect to `/dashboard` (or `/first-run` if `first_run_completed` flag absent).
    - `GET /first-run` — HTML wizard per design §4.10, step navigation via `HX-Trigger` or plain form POSTs. Final POST writes config + creates flag file.
    - `GET /dashboard` — HTML: status pill, mute state, current session id, last N exchanges (calls SPEC-05 `SessionStore` — inject as dep).
    - `GET/POST /config` — form-driven grouped settings. POST validates via Pydantic schema then `config.store.save`.
    - `GET /plugins` — list installed plugins with signature status; enable/disable toggles; per-permission grant checkboxes; install-from-file (POST multipart) and install-from-registry (POST URL).
    - `GET /audit` — filtered table view backed by `mcp_host.audit.query`.
    - `GET /logs` — last N lines of today's JSONL, tail via server-sent events.
    - `GET /about` — version, update check button (POST triggers poller), rollback dropdown (POST spawns `Updater.exe --rollback <ver>`).
  - Auth: **loopback-only**; refuse any connection whose remote host isn't `127.0.0.1`. No token in v1.
  - HTML: minimal semantic markup, one shared `layout.html` + `static/skeleton.css` (dead simple, ~50 lines). NO custom design work. Include a comment banner in every template saying `<!-- SKELETON — replace with interface-design output -->`.
- `src/workstation_agent/ui/backend/templates/*.html` — Jinja2 templates for each route.
- `src/workstation_agent/ui/backend/static/skeleton.css` — placeholder.
- `src/workstation_agent/ui/notifications/__init__.py`
- `src/workstation_agent/ui/notifications/toast.py`:
  - `class ToastPresenter` using `winrt.windows.ui.notifications` — actionable toasts with buttons ("Update now", "Later", "Skip version") wired to callbacks.
  - Fallback: if `winrt` isn't available (dev on non-Windows), no-op with a WARN log.
- `src/workstation_agent/observability/__init__.py`
- `src/workstation_agent/observability/logging.py`:
  - `configure(log_dir: Path, level: str)` — `structlog` with JSON renderer, `RotatingFileHandler` daily rotation, redaction processor applying `security.dpapi.redact_key`.
  - Live level change API (`set_level(level)`) — systray menu (or `/config`) can adjust without restart.
- `src/workstation_agent/observability/tracing.py`:
  - Optional OTLP exporter using `opentelemetry-*` packages IF the deps are already present; else no-op. **Do NOT add these to `pyproject.toml`** in v1 — it's an optional plugin-installable capability. If code needs a stub, `try: import; except ImportError: pass`.
- `tests/unit/ui/test_config_routes.py` — GET/POST /config with fake config store; validation errors render inline.
- `tests/unit/ui/test_plugins_routes.py` — enable/disable toggle updates config; unsigned install requires explicit acknowledgment.
- `tests/unit/ui/test_first_run.py` — wizard flow writes correct config + flag.
- `tests/unit/ui/test_notifications.py` — toast action callback fires (via `winrt` mock).
- `tests/unit/observability/test_logging.py` — JSON output, redaction applied, log rotation triggers.

## Constraints

- Only files listed above may be created/modified.
- All templates carry the SKELETON comment banner.
- WebView2 window lifecycle must not block the main agent event loop (dedicated thread).
- FastAPI bind is loopback-only, port ephemeral, port file atomic-written.
- No secrets in URLs or query strings.

## Acceptance criteria

- `ruff check`, `pyright`, `pytest tests/unit/ui tests/unit/observability -q` green.
- Coverage on `ui/*` and `observability/*` >= 80%.
- Manual boot check (in SPEC-10) will exercise WebView2 window opening.

## Executor summary MUST report

Whether `pywebview` + WebView2 works headless in the test env (probably needs `pywebview.start(gui="edgechromium", headless=True)` or a mock — expect this to be tricky). Any UI dependencies you had to add.
