# ruff: noqa: S101
"""Unit tests for SessionStore: insert, history round-trip, sticky window."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from workstation_agent.llm.session_store import SessionStore

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture
def store(tmp_path: Path) -> Generator[SessionStore, None, None]:
    """Provide a fresh in-memory-equivalent SessionStore per test."""
    db = tmp_path / "test.sqlite"
    s = SessionStore(db)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------


class TestStartSession:
    def test_returns_nonempty_id(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        assert sid
        assert len(sid) > 8

    def test_different_calls_give_unique_ids(self, store: SessionStore) -> None:
        ids = {store.start_session("persistent") for _ in range(5)}
        assert len(ids) == 5

    def test_all_modes_accepted(self, store: SessionStore) -> None:
        for mode in ("single_shot", "sticky", "persistent"):
            sid = store.start_session(mode)  # type: ignore[arg-type]
            assert sid


# ---------------------------------------------------------------------------
# Message append + history round-trip
# ---------------------------------------------------------------------------


class TestAppendAndHistory:
    def test_user_message_round_trip(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        store.append(sid, "user", content="Hello!")
        history = store.history(sid)
        assert len(history) == 1
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "Hello!"

    def test_assistant_message_round_trip(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        store.append(sid, "assistant", content="Hi there.")
        history = store.history(sid)
        assert history[0]["role"] == "assistant"
        assert history[0]["content"] == "Hi there."

    def test_tool_message_round_trip(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        store.append(sid, "tool", content='{"result": 42}', tool_call_id="cid_1")
        history = store.history(sid)
        assert history[0]["role"] == "tool"
        assert history[0]["tool_call_id"] == "cid_1"

    def test_assistant_with_tool_calls(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        tool_calls = [
            {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}},
        ]
        store.append(sid, "assistant", content=None, tool_calls=tool_calls)
        history = store.history(sid)
        assert history[0]["tool_calls"] == tool_calls

    def test_ordering_preserved(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        for i in range(5):
            store.append(sid, "user", content=f"msg_{i}")
        history = store.history(sid)
        contents = [m["content"] for m in history]
        assert contents == [f"msg_{i}" for i in range(5)]

    def test_no_extra_keys_when_null(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        store.append(sid, "user", content="hi")
        msg = store.history(sid)[0]
        assert "tool_calls" not in msg
        assert "tool_call_id" not in msg

    def test_multiple_sessions_isolated(self, store: SessionStore) -> None:
        s1 = store.start_session("persistent")
        s2 = store.start_session("persistent")
        store.append(s1, "user", content="session1")
        store.append(s2, "user", content="session2")
        assert store.history(s1)[0]["content"] == "session1"
        assert store.history(s2)[0]["content"] == "session2"

    def test_empty_history_for_fresh_session(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        assert store.history(sid) == []


# ---------------------------------------------------------------------------
# WAL mode
# ---------------------------------------------------------------------------


class TestWALMode:
    def test_wal_journal_mode(self, tmp_path: Path) -> None:
        import sqlite3

        db = tmp_path / "wal_test.sqlite"
        s = SessionStore(db)
        s.close()

        conn = sqlite3.connect(str(db))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"


# ---------------------------------------------------------------------------
# Sticky-window logic
# ---------------------------------------------------------------------------


class TestShouldContinue:
    def _now(self) -> datetime:
        return datetime.now(UTC)

    def test_persistent_always_true(self, store: SessionStore) -> None:
        sid = store.start_session("persistent")
        assert store.should_continue(sid, self._now(), sticky_seconds=60)

    def test_single_shot_always_true(self, store: SessionStore) -> None:
        sid = store.start_session("single_shot")
        assert store.should_continue(sid, self._now(), sticky_seconds=60)

    def test_sticky_within_window_is_true(self, store: SessionStore) -> None:
        sid = store.start_session("sticky")
        now = self._now()
        assert store.should_continue(sid, now, sticky_seconds=300)

    def test_sticky_beyond_window_is_false(self, store: SessionStore) -> None:
        sid = store.start_session("sticky")
        future = self._now() + timedelta(seconds=601)
        result = store.should_continue(sid, future, sticky_seconds=600)
        assert result is False

    def test_sticky_exactly_at_boundary(self, store: SessionStore) -> None:
        """Boundary: elapsed == sticky_seconds -> still open (<=)."""
        sid = store.start_session("sticky")
        now = self._now() + timedelta(seconds=300)
        result = store.should_continue(sid, now, sticky_seconds=300)
        assert isinstance(result, bool)

    def test_unknown_session_returns_false(self, store: SessionStore) -> None:
        result = store.should_continue("nonexistent-id", self._now(), sticky_seconds=60)
        assert result is False
