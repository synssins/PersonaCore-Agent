# SPEC-01 — Project scaffolding

**Executor tier:** haiku. **Branch:** `feat/spec-01-scaffolding`. **Worktree:** `../wsa-spec-01/`.

## Goal

Land the skeleton every other subtask builds on: repo files, Python package layout, CI workflow files (skeleton only — they will grow in SPEC-10), and a `protocols` module where every subsystem's cross-cutting interfaces live.

## Files to create (only these — nothing else)

- `pyproject.toml` — Python 3.12, `hatchling` backend, deps split into `dependencies` (runtime) and `[project.optional-dependencies].dev`. Runtime deps to include: `openwakeword`, `wyoming`, `httpx`, `structlog`, `pydantic`, `pystray`, `pywebview`, `fastapi`, `uvicorn`, `jinja2`, `keyboard`, `winrt`, `pywin32`, `cryptography`, `pynacl` (Ed25519), `click`, `tomlkit`, `claude-agent-sdk`, `pyautogui`, `pywinauto`, `mss`, `pytesseract`, `playwright`, `sounddevice`, `webrtcvad-wheels`, `psutil`, `mcp`. Dev deps: `pytest`, `pytest-asyncio`, `pytest-cov`, `pytest-httpserver`, `ruff`, `pyright`, `pyinstaller`, `respx`, `dirty-equals`. (All required deps for every downstream SPEC listed here — downstream SPECs do NOT modify `pyproject.toml`.)
- `ruff.toml` — line length 100, target-version py312, all rules on by default, per-file ignores for tests.
- `pytest.ini` — `pythonpath = src`, `asyncio_mode = auto`, `--strict-markers`.
- `.gitignore` — Python, PyInstaller, venvs, `.pytest_cache`, `_incoming/`, `logs/`, `*.dpapi`, `worktree/`, `.vscode/`, `.idea/`, `dist/`, `build/`, `*.egg-info/`, `secrets.dpapi`.
- `README.md` — short "PersonaCore-Agent: Windows-first voice-controlled AI agent. See `docs/superpowers/specs/` for design."
- `LICENSE` — MIT, copyright holder "Chris (synssins)".
- `.github/workflows/ci.yml` — Windows runner, matrix (`3.12`), steps: checkout, setup-python, `pip install -e .[dev]`, `ruff check`, `pyright`, `pytest -q --cov=workstation_agent --cov-report=term-missing --cov-fail-under=80`. Trigger on push + PR to main.
- `.github/workflows/release.yml` — on tag `v*`, placeholder body: echo "release build placeholder — SPEC-10 fills this in". Trigger blocks explicit `workflow_dispatch` too.
- `src/workstation_agent/__init__.py` — `__version__ = "0.1.0.dev0"`.
- `src/workstation_agent/__main__.py` — placeholder that prints "PersonaCore-Agent framework (WIP). SPEC-10 wires the app together." and exits 0. Do NOT import subsystems here yet.
- Empty package dirs, each with an `__init__.py` containing only a one-line docstring pinning its purpose:
  - `audio/` `llm/` `mcp_host/` `claude_code/` `updater_client/` `config/` `security/` `observability/` `plugins/` `ui/` `ui/systray/` `ui/webview/` `ui/backend/` `ui/frontend/` `ui/notifications/`
- `src/workstation_agent/protocols.py` — one module with these `typing.Protocol` classes, only definitions, no implementations. Each carries a docstring naming its producer/consumer SPEC:

  ```python
  class ToolDescriptor(Protocol): ...        # SPEC-03 produces, SPEC-05 consumes
  class ToolResult(Protocol): ...
  class MCPHost(Protocol):                    # SPEC-03 produces, SPEC-05/07/08 consume
      async def tools(self) -> list[ToolDescriptor]: ...
      async def invoke(self, tool_id: str, args: dict) -> ToolResult: ...
      async def plugins(self) -> list["PluginInfo"]: ...
      async def reload(self, plugin_id: str) -> None: ...
  class PluginInfo(Protocol): ...
  class ConfirmationRequest(Protocol): ...    # SPEC-03 produces
  class ConfirmationCallback(Protocol):       # SPEC-07 implements
      async def __call__(self, req: ConfirmationRequest) -> bool: ...
  class AudioSession(Protocol): ...           # SPEC-04
  class AbortableTask(Protocol): ...
  class TTSSpeaker(Protocol): ...             # SPEC-04
      async def speak(self, text: str) -> AbortableTask: ...
  class LLMSession(Protocol): ...             # SPEC-05
  class Updater(Protocol): ...                # SPEC-06
  class ToastPresenter(Protocol): ...         # SPEC-07
  class UpdateAvailableCallback(Protocol): ...
  ```
- `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`, `tests/fakes/__init__.py`.
- `working/README.md` — one line: "planning artifacts; not published to git remote (see `.gitignore`)". **NOTE:** update `.gitignore` to include `working/` before committing anything under it, then force-add `working/README.md` — orchestrator ignores `working/*` from executor branches at merge time. Actually simpler: **leave `working/` OUT of `.gitignore`; executors must not touch `working/`**. The orchestrator alone owns `working/`.
- `CLAUDE.md` at repo root — one page: project name, "this is the framework build; see design spec and PLAN.md for scope", team roster hint, "no worker touches `working/`", "no worker touches files outside its SPEC's allowed-paths list".

## Files this SPEC may NOT touch

Everything not on the list above. In particular: `working/`, `docs/superpowers/specs/`, any Go source, any HTML/CSS/JS.

## Constraints

- No implementations, only stubs and configuration.
- `__main__.py` prints and exits — no subsystem imports.
- `pyproject.toml` MUST declare all runtime deps listed above so downstream SPECs don't fight the lockfile.
- Dependency versions: pin major only (`>=X,<X+1`) for now.

## Acceptance criteria

- `pip install -e .[dev]` succeeds on Windows.
- `ruff check .` green.
- `pyright` green (empty package = trivially typed).
- `pytest -q` runs (zero tests but exit 0).
- `python -m workstation_agent` prints the placeholder and exits 0.
- `git status` shows only files listed above (nothing else created/modified).

## Testing

Add `tests/unit/test_smoke.py` with one test: `def test_package_imports(): import workstation_agent  # noqa`.

## Executor summary MUST report

Files created (count + list). Result of each acceptance command. Any deviations from this SPEC and why.
