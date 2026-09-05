"""SQLite-backed conversation session store.

Opens ``conversations.sqlite`` in WAL mode.  Supports three session modes:

* ``single_shot`` — each turn is independent; no persistent history.
* ``sticky``      — history is kept for a configurable time window.
* ``persistent``  — history is kept indefinitely.
"""

# Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

log = logging.getLogger(__name__)

SessionMode = Literal["single_shot", "sticky", "persistent"]
SessionId = str

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    title TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    role TEXT NOT NULL,
    content TEXT,
    tool_calls_json TEXT,
    tool_call_id TEXT,
    ts_utc TEXT NOT NULL
);
"""


def _now_utc() -> str:
    return datetime.now(UTC).isoformat()


class SessionStore:
    """Manage conversation sessions and messages in SQLite.

    Parameters
    ----------
    db_path:
        Path to the SQLite file.  Will be created if it does not exist.
    """

    def __init__(self, db_path: Path | str = "conversations.sqlite") -> None:
        self._path = Path(db_path)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_DDL)
        self._conn.commit()
        log.debug("SessionStore opened", extra={"path": str(self._path)})

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def start_session(self, mode: SessionMode) -> SessionId:
        """Create a new session and return its ID."""
        session_id = str(uuid.uuid4())
        now = _now_utc()
        self._conn.execute(
            "INSERT INTO sessions (id, created_at, last_activity_at, mode) VALUES (?, ?, ?, ?)",
            (session_id, now, now, mode),
        )
        self._conn.commit()
        log.debug("Session started", extra={"session_id": session_id, "mode": mode})
        return session_id

    def _touch(self, session_id: SessionId) -> None:
        self._conn.execute(
            "UPDATE sessions SET last_activity_at=? WHERE id=?",
            (_now_utc(), session_id),
        )

    # ------------------------------------------------------------------
    # Message persistence
    # ------------------------------------------------------------------

    def append(
        self,
        session_id: SessionId,
        role: str,
        content: str | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        tool_call_id: str | None = None,
    ) -> None:
        """Append a message to *session_id*."""
        tool_calls_json = json.dumps(tool_calls) if tool_calls is not None else None
        self._conn.execute(
            """
            INSERT INTO messages
                (session_id, role, content, tool_calls_json, tool_call_id, ts_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, role, content, tool_calls_json, tool_call_id, _now_utc()),
        )
        self._touch(session_id)
        self._conn.commit()

    # ------------------------------------------------------------------
    # History retrieval
    # ------------------------------------------------------------------

    def history(self, session_id: SessionId) -> list[dict[str, Any]]:
        """Return messages for *session_id* in OpenAI-compatible format."""
        cur = self._conn.execute(
            "SELECT role, content, tool_calls_json, tool_call_id FROM messages "
            "WHERE session_id=? ORDER BY id",
            (session_id,),
        )
        messages: list[dict[str, Any]] = []
        for role, content, tc_json, tc_id in cur.fetchall():
            msg: dict[str, Any] = {"role": role}
            if content is not None:
                msg["content"] = content
            if tc_json is not None:
                msg["tool_calls"] = json.loads(tc_json)
            if tc_id is not None:
                msg["tool_call_id"] = tc_id
            messages.append(msg)
        return messages

    # ------------------------------------------------------------------
    # Sticky-window logic
    # ------------------------------------------------------------------

    def should_continue(
        self,
        session_id: SessionId,
        now: datetime,
        sticky_seconds: int,
    ) -> bool:
        """Return True if the sticky window for *session_id* is still open.

        For non-sticky sessions this always returns ``True`` (caller decides
        whether to start a new session based on mode).
        """
        cur = self._conn.execute(
            "SELECT last_activity_at, mode FROM sessions WHERE id=?",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        last_str, mode = row
        if mode != "sticky":
            return True
        last = datetime.fromisoformat(last_str)
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        elapsed = (now - last).total_seconds()
        return elapsed <= sticky_seconds

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()
