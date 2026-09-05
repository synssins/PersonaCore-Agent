"""Integration tests for LLMTurn's multi-round tool loop.

Uses ``fake_openai`` (FastAPI ASGI) via ``httpx.AsyncClient(app=...)`` transport
and ``FakeMCPHost`` for tool invocation.

Tests verify:
- Single-round text-only response
- Two-round tool-call -> final text loop
- Three-round loop (tool -> tool -> text)
- Loop cap: after max_rounds the loop terminates without infinite recursion
- Every message is persisted to SessionStore
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from tests.fakes.fake_mcp_host import FakeMCPHost, FakeToolDescriptor
from tests.fakes.fake_openai import (
    ScenarioQueue,
    build_app,
    text_response,
    tool_call_response,
)
from workstation_agent.llm.client import OpenAICompatClient, _parse_sse_stream
from workstation_agent.llm.session_store import SessionStore
from workstation_agent.llm.turn import FinishedEvent, LLMTurn, TextChunkEvent, ToolCallDoneEvent

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(app: object) -> OpenAICompatClient:
    """Return an OpenAICompatClient that routes through the fake ASGI app."""
    base_url = "http://fake-openai"
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]

    class _PatchedClient(OpenAICompatClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            self._transport = transport
            self._base_url_str = base_url

        async def _stream_with_retry(  # type: ignore[override]
            self,
            payload: dict[str, object],
            headers: dict[str, str],
        ) -> object:
            async with (
                httpx.AsyncClient(
                    transport=self._transport,
                    base_url=self._base_url_str,
                    timeout=30.0,
                ) as client,
                client.stream(
                    "POST",
                    "/v1/chat/completions",
                    json=payload,
                    headers=headers,
                ) as response,
            ):
                response.raise_for_status()
                async for delta in _parse_sse_stream(response):
                    yield delta

    return _PatchedClient(
        base_url=base_url,
        model="gpt-fake",
        api_key="sk-fake-key-for-tests",
    )


async def _collect_events(turn: LLMTurn, user_text: str) -> list[object]:
    return [event async for event in turn.run(user_text)]


def _make_turn(
    client: OpenAICompatClient,
    host: FakeMCPHost,
    store: SessionStore,
    session_id: str,
    max_rounds: int = 8,
) -> LLMTurn:
    return LLMTurn(
        client=client,
        host=host,  # type: ignore[arg-type]
        store=store,
        session_id=session_id,
        max_rounds=max_rounds,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path: Path) -> Generator[SessionStore, None, None]:
    s = SessionStore(tmp_path / "turn_test.sqlite")
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_single_round_text_only(tmp_store: SessionStore) -> None:
    """No tool calls: emits text chunks and finishes in one round."""
    queue = ScenarioQueue()
    queue.push([text_response("Hello from the assistant!")])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost()
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid)

    events = await _collect_events(turn, "Hi")

    text_events = [e for e in events if isinstance(e, TextChunkEvent)]
    finished = [e for e in events if isinstance(e, FinishedEvent)]

    assert any(e.text for e in text_events)
    assert len(finished) == 1
    assert finished[0].total_rounds == 1

    history = tmp_store.history(sid)
    roles = [m["role"] for m in history]
    assert "user" in roles
    assert "assistant" in roles


@pytest.mark.asyncio
async def test_two_round_tool_loop(tmp_store: SessionStore) -> None:
    """Round 1: tool call. Round 2: final text. Tests 2-round loop."""
    queue = ScenarioQueue()
    queue.push([
        tool_call_response("call_abc", "get_weather", '{"city": "London"}'),
        text_response("It is sunny in London."),
    ])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost(
        tools=[FakeToolDescriptor("get_weather", "Get weather for a city")],
        results={"get_weather": {"temp": 22, "condition": "sunny"}},
    )
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid)

    events = await _collect_events(turn, "What's the weather in London?")

    tool_done = [e for e in events if isinstance(e, ToolCallDoneEvent)]
    finished = [e for e in events if isinstance(e, FinishedEvent)]
    text_events = [e for e in events if isinstance(e, TextChunkEvent)]

    assert len(tool_done) >= 1
    assert tool_done[0].name == "get_weather"
    assert any(e.text for e in text_events)
    assert len(finished) == 1

    assert host.calls[0] == ("get_weather", {"city": "London"})

    history = tmp_store.history(sid)
    roles = [m["role"] for m in history]
    assert "user" in roles
    assert "tool" in roles
    assert "assistant" in roles


@pytest.mark.asyncio
async def test_three_round_tool_loop(tmp_store: SessionStore) -> None:
    """Round 1: tool A. Round 2: tool B. Round 3: final text. 3-round loop."""
    queue = ScenarioQueue()
    queue.push([
        tool_call_response("call_1", "tool_a", "{}"),
        tool_call_response("call_2", "tool_b", "{}"),
        text_response("Done after two tools."),
    ])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost(
        tools=[
            FakeToolDescriptor("tool_a"),
            FakeToolDescriptor("tool_b"),
        ],
        results={"tool_a": {"a": 1}, "tool_b": {"b": 2}},
    )
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid)

    events = await _collect_events(turn, "Run both tools")

    tool_dones = [e for e in events if isinstance(e, ToolCallDoneEvent)]
    finished = [e for e in events if isinstance(e, FinishedEvent)]

    assert len(tool_dones) >= 2
    tool_names = [e.name for e in tool_dones]
    assert "tool_a" in tool_names
    assert "tool_b" in tool_names
    assert len(finished) == 1


@pytest.mark.asyncio
async def test_loop_cap_prevents_runaway(tmp_store: SessionStore) -> None:
    """With max_rounds=2, a tool-call-only server stops after 2 rounds."""
    queue = ScenarioQueue()
    queue.push([
        tool_call_response("c1", "infinite_tool", "{}"),
        tool_call_response("c2", "infinite_tool", "{}"),
        tool_call_response("c3", "infinite_tool", "{}"),
        tool_call_response("c4", "infinite_tool", "{}"),
        tool_call_response("c5", "infinite_tool", "{}"),
    ])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost(
        tools=[FakeToolDescriptor("infinite_tool")],
        results={"infinite_tool": {"looping": True}},
    )
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid, max_rounds=2)

    events = await _collect_events(turn, "Loop forever")

    finished = [e for e in events if isinstance(e, FinishedEvent)]
    assert len(finished) == 1
    assert finished[0].total_rounds <= 2


@pytest.mark.asyncio
async def test_all_messages_persisted(tmp_store: SessionStore) -> None:
    """Every message in a tool-call turn is persisted to SessionStore."""
    queue = ScenarioQueue()
    queue.push([
        tool_call_response("cid_x", "fetch_data", '{"url": "http://example.com"}'),
        text_response("Data fetched successfully."),
    ])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost(
        tools=[FakeToolDescriptor("fetch_data")],
        results={"fetch_data": {"status": 200}},
    )
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid)

    await _collect_events(turn, "Fetch the data please")

    history = tmp_store.history(sid)
    roles = [m["role"] for m in history]

    assert roles.count("user") >= 1
    assert roles.count("tool") >= 1
    assert roles.count("assistant") >= 1


@pytest.mark.asyncio
async def test_system_prompt_default_used(tmp_store: SessionStore) -> None:
    """When no system_prompt is given, the default is used."""
    from workstation_agent.llm.system_prompt import default_system_prompt

    queue = ScenarioQueue()
    queue.push([text_response("OK")])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost()
    sid = tmp_store.start_session("persistent")
    turn = LLMTurn(
        client=client,
        host=host,  # type: ignore[arg-type]
        store=tmp_store,
        session_id=sid,
        system_prompt=None,
    )

    assert turn._system_prompt == default_system_prompt()
    await _collect_events(turn, "test")


@pytest.mark.asyncio
async def test_message_ordering_assistant_before_tool_results(tmp_store: SessionStore) -> None:
    """History ordering: assistant(tool_calls) must appear BEFORE tool results.

    A 2-round loop (tool call in round 1, final text in round 2) must produce
    the sequence:
        [system, user, assistant(tool_calls=[A, B]), tool(A), tool(B), assistant(text)]

    This test uses a single-round with TWO simultaneous tool calls so that we
    can verify both tool result rows appear after the single assistant row,
    and then validates the full 2-round ordering with a subsequent text reply.
    """
    # Round 1: LLM calls two tools simultaneously.
    # Round 2: LLM gives final text answer.
    queue = ScenarioQueue()
    queue.push([
        # Round 1 — two tool calls in one stream
        tool_call_response("call_A", "tool_alpha", '{"x": 1}')
        + tool_call_response("call_B", "tool_beta", '{"y": 2}'),
        # Round 2 — final text
        text_response("All done."),
    ])

    app = build_app(queue)
    client = _make_client(app)
    host = FakeMCPHost(
        tools=[
            FakeToolDescriptor("tool_alpha", "Alpha tool"),
            FakeToolDescriptor("tool_beta", "Beta tool"),
        ],
        results={
            "tool_alpha": {"result": "alpha-ok"},
            "tool_beta": {"result": "beta-ok"},
        },
    )
    sid = tmp_store.start_session("persistent")
    turn = _make_turn(client, host, tmp_store, sid)

    await _collect_events(turn, "Run both tools please")

    # Retrieve history — excludes the system message (not stored in DB).
    history = tmp_store.history(sid)
    roles = [m["role"] for m in history]

    # Expected order: user, assistant(tool_calls), tool, tool, assistant(text)
    assert roles == ["user", "assistant", "tool", "tool", "assistant"], (
        f"Unexpected role order: {roles}"
    )

    # The first assistant message must carry the tool_calls array.
    first_assistant = history[1]
    assert "tool_calls" in first_assistant, (
        "First assistant message must contain tool_calls"
    )
    tc_ids = {tc["id"] for tc in first_assistant["tool_calls"]}
    assert "call_A" in tc_ids
    assert "call_B" in tc_ids

    # The two tool messages must reference the correct call IDs.
    tool_msgs = [m for m in history if m["role"] == "tool"]
    assert len(tool_msgs) == 2
    tool_call_ids = {m["tool_call_id"] for m in tool_msgs}
    assert tool_call_ids == {"call_A", "call_B"}

    # The final assistant message must be plain text (no tool_calls).
    last_assistant = [m for m in history if m["role"] == "assistant"][-1]
    assert "tool_calls" not in last_assistant
    assert last_assistant.get("content") == "All done."
