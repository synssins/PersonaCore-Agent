"""Unit tests for ClaudeCodeDriver — voice-mediated tool approval."""
# ruff: noqa: ANN401, ARG001, S108, PERF401

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests.fakes.fake_claude_sdk import (
    FakeTransport,
    canned_events,
    make_result_message,
    make_text_message,
    make_tool_use_message,
)
from workstation_agent.claude_code.driver import CCEvent, ClaudeCodeDriver

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeTTS:
    """Minimal TTSSpeaker stub."""

    def __init__(self) -> None:
        self.spoken: list[str] = []

    async def speak(self, text: str) -> None:
        self.spoken.append(text)


async def _collect(
    driver: ClaudeCodeDriver,
    prompt: str,
    on_tool_use: Any | None = None,
) -> list[CCEvent]:
    """Drive the run() generator to completion and return collected events."""
    events: list[CCEvent] = []
    kwargs: dict[str, Any] = {}
    if on_tool_use is not None:
        kwargs["on_tool_use"] = on_tool_use
    async for ev in driver.run(prompt, **kwargs):
        events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Tests: plain text response (no tool use)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_plain_text_response() -> None:
    """Driver yields assistant + result events for a plain text reply."""
    transport = FakeTransport(
        canned_events(
            make_text_message("The answer is 42."),
            make_result_message(),
        ),
    )
    driver = ClaudeCodeDriver(transport=transport)
    events = await _collect(driver, "What is the answer?")

    kinds = [e.kind for e in events]
    assert "assistant" in kinds
    assert "result" in kinds


@pytest.mark.asyncio
async def test_driver_result_event_is_last() -> None:
    transport = FakeTransport(
        canned_events(
            make_text_message("hi"),
            make_result_message(),
        ),
    )
    driver = ClaudeCodeDriver(transport=transport)
    events = await _collect(driver, "hi")
    assert events[-1].kind == "result"


# ---------------------------------------------------------------------------
# Tests: voice-mediated tool approval — approved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_tool_use_approved_by_voice() -> None:
    """tool_use event emitted when user says 'yes' via fake audio_session."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Bash", {"cmd": "ls"}),
            make_result_message(),
        ),
    )
    tts = _FakeTTS()
    # audio_session returns "yes"
    audio_session = AsyncMock(return_value="yes")

    driver = ClaudeCodeDriver(
        tts=tts,
        audio_session=audio_session,
        transport=transport,
    )
    events = await _collect(driver, "list files")

    # Challenge was spoken
    assert any("Bash" in s for s in tts.spoken)
    audio_session.assert_awaited_once()

    tool_events = [e for e in events if e.kind == "tool_use"]
    assert len(tool_events) == 1
    assert tool_events[0].tool_name == "Bash"
    assert tool_events[0].approved is True

    denied_events = [e for e in events if e.kind == "denied"]
    assert len(denied_events) == 0


# ---------------------------------------------------------------------------
# Tests: voice-mediated tool approval — denied
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_tool_use_denied_by_voice() -> None:
    """denied event emitted when user says 'no' via fake audio_session."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Write", {"path": "/etc/passwd", "content": "x"}),
            make_result_message(),
        ),
    )
    tts = _FakeTTS()
    audio_session = AsyncMock(return_value="no thank you")

    driver = ClaudeCodeDriver(
        tts=tts,
        audio_session=audio_session,
        transport=transport,
    )
    events = await _collect(driver, "overwrite system file")

    denied_events = [e for e in events if e.kind == "denied"]
    assert len(denied_events) == 1
    assert denied_events[0].approved is False

    tool_events = [e for e in events if e.kind == "tool_use"]
    assert len(tool_events) == 0


# ---------------------------------------------------------------------------
# Tests: voice-mediated tool approval — timeout → deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_tool_use_timeout_denied() -> None:
    """If audio_session times out, tool is denied."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Bash", {"cmd": "rm -rf /"}),
            make_result_message(),
        ),
    )

    async def _slow_audio() -> str | None:
        await asyncio.sleep(10)  # longer than timeout
        return "yes"

    driver = ClaudeCodeDriver(
        audio_session=_slow_audio,
        approval_timeout_s=0.05,  # very short timeout
        transport=transport,
    )
    events = await _collect(driver, "dangerous command")

    denied_events = [e for e in events if e.kind == "denied"]
    assert len(denied_events) == 1
    assert denied_events[0].approved is False


# ---------------------------------------------------------------------------
# Tests: no audio_session → deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_no_audio_session_denies_all() -> None:
    """Without audio_session, all tool_use calls are denied."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Read", {"path": "/secret"}),
            make_result_message(),
        ),
    )
    driver = ClaudeCodeDriver(transport=transport)  # no audio_session
    events = await _collect(driver, "read secret file")

    denied_events = [e for e in events if e.kind == "denied"]
    assert len(denied_events) == 1


# ---------------------------------------------------------------------------
# Tests: custom on_tool_use hook overrides voice hook
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_custom_hook_overrides_voice() -> None:
    """on_tool_use kwarg bypasses the default voice approval loop."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Glob", {"pattern": "**/*.py"}),
            make_result_message(),
        ),
    )
    hook_calls: list[str] = []

    async def my_hook(tool_name: str, tool_input: dict[str, Any]) -> bool:
        hook_calls.append(tool_name)
        return True  # always approve

    driver = ClaudeCodeDriver(transport=transport)
    events = await _collect(driver, "list python files", on_tool_use=my_hook)

    assert "Glob" in hook_calls
    tool_events = [e for e in events if e.kind == "tool_use"]
    assert len(tool_events) == 1
    assert tool_events[0].approved is True


# ---------------------------------------------------------------------------
# Tests: audio_session returns None → deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_driver_audio_none_denies() -> None:
    """audio_session returning None is treated as deny."""
    transport = FakeTransport(
        canned_events(
            make_tool_use_message("Edit", {"path": "/tmp/x", "content": "y"}),
            make_result_message(),
        ),
    )
    audio_session = AsyncMock(return_value=None)

    driver = ClaudeCodeDriver(audio_session=audio_session, transport=transport)
    events = await _collect(driver, "edit file")

    denied = [e for e in events if e.kind == "denied"]
    assert len(denied) == 1


# ---------------------------------------------------------------------------
# Tests: CCEvent dataclass defaults
# ---------------------------------------------------------------------------


def test_cc_event_defaults() -> None:
    ev = CCEvent(kind="assistant")
    assert ev.tool_name is None
    assert ev.tool_input == {}
    assert ev.approved is True
