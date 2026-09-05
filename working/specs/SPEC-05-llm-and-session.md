# SPEC-05 — LLM client + tool bridge + session store

**Executor tier:** sonnet. **Branch:** `feat/spec-05-llm`. **Worktree:** `../wsa-spec-05/`.
**Depends on:** SPEC-01, SPEC-02. **Consumes:** SPEC-03's `MCPHost` Protocol (mocked for now).

## Goal

OpenAI-compatible chat client with streaming + tool-call loop, MCP-to-OpenAI tool schema bridge, and a SQLite-backed conversation store honoring three session modes (single_shot / sticky / persistent).

## Files to create / modify (only these)

- `src/workstation_agent/llm/__init__.py`
- `src/workstation_agent/llm/client.py`:
  - `OpenAICompatClient` — `httpx.AsyncClient`-based, streaming chat.
  - `async chat(messages, tools, *, stream=True) -> AsyncIterator[ChatDelta]`.
  - `ChatDelta` union: text chunk, tool_call start/args-delta/complete, finish reason.
  - Handles `data: [DONE]` SSE terminator and network reconnect on transient failures (bounded retries).
  - Base URL, model name, API key come from `AgentConfig` + `config.store.load_secret("llm_api_key")`.
- `src/workstation_agent/llm/tool_bridge.py`:
  - `to_openai_schema(descriptors: list[ToolDescriptor]) -> list[dict]` — maps MCP tool descriptors to OpenAI `tools=[{"type":"function","function":{...}}]` format.
  - `class ToolRouter` — receives streamed tool-call from `OpenAICompatClient`, waits for full args, dispatches to `MCPHost.invoke`, formats the result back into an OpenAI `tool` role message.
- `src/workstation_agent/llm/session_store.py`:
  - Opens `conversations.sqlite` (WAL mode).
  - Schema:
    ```sql
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY,        -- uuid
      created_at TEXT NOT NULL,
      last_activity_at TEXT NOT NULL,
      mode TEXT NOT NULL,          -- 'single_shot' | 'sticky' | 'persistent'
      title TEXT
    );
    CREATE TABLE messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL REFERENCES sessions(id),
      role TEXT NOT NULL,          -- 'system' | 'user' | 'assistant' | 'tool'
      content TEXT,                -- text or JSON tool result
      tool_calls_json TEXT,        -- nullable
      tool_call_id TEXT,           -- nullable
      ts_utc TEXT NOT NULL
    );
    ```
  - `class SessionStore`:
    - `start_session(mode: SessionMode) -> SessionId`.
    - `append(session_id, role, content=None, tool_calls=None, tool_call_id=None)`.
    - `history(session_id) -> list[OpenAIMessage]` — returns messages in OpenAI-compatible format.
    - `should_continue(session_id, now: datetime, sticky_seconds: int) -> bool` — for sticky-window logic.
- `src/workstation_agent/llm/turn.py`:
  - `class LLMTurn` — orchestrates one user turn:
    - Takes user text, gets tools from `MCPHost`, calls `OpenAICompatClient.chat`, streams deltas, dispatches tool calls through `ToolRouter`, feeds tool results back into the LLM (multi-round if the LLM makes more tool calls), yields final text chunks to the caller for TTS.
    - Emits progress events (`text_chunk`, `tool_call_started`, `tool_call_done`, `finished`) for the UI.
    - Persists every message to `SessionStore`.
- `tests/fakes/fake_openai.py`:
  - FastAPI ASGI app implementing `/v1/chat/completions` with SSE streaming. Configurable canned responses including tool-call sequences and multi-round loops.
- `tests/unit/llm/test_tool_bridge.py` — MCP descriptor → OpenAI schema conversion table.
- `tests/unit/llm/test_session_store.py` — insert, history round-trip, sticky-window boundary conditions.
- `tests/integration/llm/test_turn_loop.py`:
  - Uses `fake_openai` + a fake `MCPHost` that returns a hardcoded tool result; asserts the multi-round tool loop terminates and the final assistant text is emitted; asserts every message persisted to `SessionStore`.

## Constraints

- Do not import from `mcp_host/` — depend only on the `MCPHost` Protocol from SPEC-01.
- Streaming is required; no non-streaming code path in v1.
- API key never appears in logs or exceptions (use `security.dpapi.redact_key` in `client.py`'s log lines).
- No secrets in error messages ever.

## Acceptance criteria

- Green ruff/pyright/pytest.
- Coverage on `llm/*` >= 85%.

## Executor summary MUST report

Number of round-trips the multi-round tool loop was tested with. Any hiccups implementing SSE parsing. Whether `fake_openai` was reused (or should be reused) across other SPECs.
