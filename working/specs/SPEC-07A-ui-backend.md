# SPEC-07A — UI backend: FastAPI routes + structured logging

**Executor tier:** sonnet. **Branch:** `feat/spec-07a-ui-backend`. **Worktree:** `../wsa-spec-07a/`.
**Depends on:** SPEC-01, SPEC-02, SPEC-03B (MCPHost), SPEC-05 (SessionStore), SPEC-06 (UpdatePoller surface).

## Goal

Everything the UI displays and edits, plus structured logging. No windowing/systray/toast code here — that's SPEC-07B.

## Files to create / modify (only these)

- `src/workstation_agent/ui/backend/__init__.py`
- `src/workstation_agent/ui/backend/app.py`:
  - FastAPI app bound to `127.0.0.1:0` (OS-picked ephemeral port); port written atomically to `%APPDATA%\WorkstationAgent\ui-port` for the WebView2 side (SPEC-07B) to read.
  - Loopback-only middleware: reject any connection whose remote host isn't `127.0.0.1`.
  - Dependency-injected surfaces via a `BackendContext` dataclass: `config_store`, `session_store`, `mcp_host`, `update_poller`, `audit_reader`. Instantiated by SPEC-10 wiring; here we just accept the dataclass.
  - Routes (each in its own `routers/*.py`):
    - `GET /` → redirect to `/dashboard` (or `/first-run` if `first_run_completed` flag absent).
    - `GET /first-run` + `POST /first-run/*` — wizard per design §4.10.
    - `GET /dashboard` — status pill, mute state, current session id, last N exchanges.
    - `GET/POST /config` — form-driven grouped settings, Pydantic validation, atomic `config.store.save`.
    - `GET /plugins`, `POST /plugins/{id}/enable`, `POST /plugins/{id}/disable`, `POST /plugins/{id}/grant/{perm}`, `POST /plugins/install-file` (multipart), `POST /plugins/install-registry`, `POST /plugins/{id}/reload`.
    - `GET /audit?filters...` — backed by `mcp_host.audit.query`.
    - `GET /logs?tail=N` + `GET /logs/stream` (SSE tail of today's JSONL).
    - `GET /about`, `POST /about/check-updates`, `POST /about/rollback` (dropdown).
  - HTML: minimal semantic markup, one shared `layout.html` + `static/skeleton.css` (~50 lines). Every template MUST start with `<!-- SKELETON — visual design lands in interface-design pass, do not polish here -->`.
- `src/workstation_agent/ui/backend/templates/*.html` — Jinja2 templates for each route.
- `src/workstation_agent/ui/backend/static/skeleton.css` — placeholder.
- `src/workstation_agent/observability/__init__.py`
- `src/workstation_agent/observability/logging.py`:
  - `configure(log_dir: Path, level: str)` — `structlog` + JSON renderer + daily rotation via `logging.handlers.TimedRotatingFileHandler`, N days retention from config.
  - Redaction processor applying `security.dpapi.redact_key`.
  - `set_level(level)` — live level change without restart.
- `src/workstation_agent/observability/tracing.py`:
  - Optional OTLP exporter guarded by `try: import opentelemetry; except ImportError: no-op`. Do NOT add OTLP deps to `pyproject.toml` (SPEC-01 doesn't list them; opt-in later).
- `tests/unit/ui/test_config_routes.py` — GET/POST /config with a fake config store; validation errors render inline.
- `tests/unit/ui/test_plugins_routes.py` — enable/disable persists to config; unsigned install requires acknowledgment param.
- `tests/unit/ui/test_first_run.py` — wizard flow writes correct config + flag.
- `tests/unit/ui/test_loopback.py` — non-127.0.0.1 request rejected.
- `tests/unit/observability/test_logging.py` — JSON output, redaction applied, rotation triggers.

## Files this SPEC may NOT touch

- Any file under `src/workstation_agent/ui/systray/`, `src/workstation_agent/ui/webview/`, `src/workstation_agent/ui/notifications/` — those are SPEC-07B.
- `pyproject.toml`, `ruff.toml`, `pytest.ini`.

## Acceptance criteria

- Green pytest.
- Coverage on `ui/backend/*` and `observability/*` >= 80%.
- Loopback-only enforcement verified.

## Executor summary MUST report

Any Jinja2 template patterns you'd like SPEC-07B to be aware of. Whether SSE for `/logs/stream` played nicely under `uvicorn`.
