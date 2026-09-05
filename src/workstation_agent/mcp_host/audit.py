"""Append-only audit log backed by SQLite (WAL mode).

Schema (design §4.6):

    CREATE TABLE audit_log (
        rowid     INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        TEXT    NOT NULL,   -- ISO-8601 UTC timestamp
        event     TEXT    NOT NULL,   -- event type string
        plugin_id TEXT,
        tool_id   TEXT,
        args_json TEXT,
        result    TEXT,
        decision  TEXT,
        detail    TEXT
    );

UPDATE and DELETE are blocked by triggers that raise an abort error.
The database is opened in WAL mode for concurrent reads.

Usage::

    from workstation_agent.mcp_host.audit import AuditEvent, AuditQuery, log, query

    await asyncio.to_thread(log, AuditEvent(event="tool_invoke", plugin_id="hello_world"))
    rows = query(AuditQuery(plugin_id="hello_world"))
"""
# ruff: noqa: S608

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any

import workstation_agent.config.store as _store

_log = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    rowid     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,
    event     TEXT    NOT NULL,
    plugin_id TEXT,
    tool_id   TEXT,
    args_json TEXT,
    result    TEXT,
    decision  TEXT,
    detail    TEXT
);
"""

_CREATE_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE not allowed');
END;
"""

_WAL_PRAGMA = "PRAGMA journal_mode=WAL;"


@dataclass
class AuditEvent:
    """One row in the audit log."""

    event: str
    plugin_id: str | None = None
    tool_id: str | None = None
    args: dict[str, Any] | None = None
    result: str | None = None
    decision: str | None = None
    detail: str | None = None
    ts: str = field(default="")

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = datetime.now(tz=UTC).isoformat()


@dataclass
class AuditQuery:
    """Filters for :func:`query`."""

    plugin_id: str | None = None
    tool_id: str | None = None
    event: str | None = None
    since: str | None = None
    until: str | None = None
    limit: int = 500


_local = threading.local()
_db_path: Path | None = None
_path_lock = threading.Lock()


def _get_db_path() -> Path:
    global _db_path  # noqa: PLW0603
    with _path_lock:
        if _db_path is None:
            _db_path = _store.paths()["audit_db"]
        return _db_path


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    """Return a thread-local WAL-mode connection, creating schema on first use."""
    path = db_path or _get_db_path()
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    conn_path: str | None = getattr(_local, "conn_path", None)

    if conn is None or conn_path != str(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        new_conn = sqlite3.connect(str(path), check_same_thread=False)
        new_conn.row_factory = sqlite3.Row
        new_conn.execute(_WAL_PRAGMA)
        new_conn.executescript(_CREATE_TABLE + _CREATE_TRIGGERS)
        new_conn.commit()
        _local.conn = new_conn
        _local.conn_path = str(path)
        conn = new_conn
    return conn


def set_db_path(path: Path) -> None:
    """Override the database path (test isolation)."""
    global _db_path  # noqa: PLW0603
    with _path_lock:
        _db_path = path
    _local.conn = None
    _local.conn_path = None


def reset_connection() -> None:
    """Close and discard the thread-local connection (tests / teardown)."""
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    if conn is not None:
        with contextlib.suppress(Exception):
            conn.close()
    _local.conn = None
    _local.conn_path = None


def log(event: AuditEvent, *, db_path: Path | None = None) -> None:
    """Append *event* to the audit log.

    Thread-safe; safe to call from asyncio via ``asyncio.to_thread``.
    """
    args_json: str | None = None
    if event.args is not None:
        try:
            args_json = json.dumps(event.args, separators=(",", ":"))
        except (TypeError, ValueError):
            args_json = str(event.args)

    conn = _connect(db_path)
    conn.execute(
        """
        INSERT INTO audit_log (ts, event, plugin_id, tool_id, args_json, result, decision, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.ts,
            event.event,
            event.plugin_id,
            event.tool_id,
            args_json,
            event.result,
            event.decision,
            event.detail,
        ),
    )
    conn.commit()
    _log.debug(
        "audit: event=%s plugin=%s tool=%s decision=%s",
        event.event,
        event.plugin_id,
        event.tool_id,
        event.decision,
    )


def query(filters: AuditQuery, *, db_path: Path | None = None) -> list[AuditEvent]:
    """Return audit rows matching *filters*, newest-first."""
    clauses: list[str] = []
    params: list[Any] = []

    if filters.plugin_id is not None:
        clauses.append("plugin_id = ?")
        params.append(filters.plugin_id)
    if filters.tool_id is not None:
        clauses.append("tool_id = ?")
        params.append(filters.tool_id)
    if filters.event is not None:
        clauses.append("event = ?")
        params.append(filters.event)
    if filters.since is not None:
        clauses.append("ts >= ?")
        params.append(filters.since)
    if filters.until is not None:
        clauses.append("ts <= ?")
        params.append(filters.until)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT ts, event, plugin_id, tool_id, args_json, result, decision, detail "
        f"FROM audit_log {where} ORDER BY rowid DESC LIMIT ?"
    )
    params.append(filters.limit)

    conn = _connect(db_path)
    rows = conn.execute(sql, params).fetchall()
    result: list[AuditEvent] = []
    for row in rows:
        args_dict: dict[str, Any] | None = None
        if row["args_json"] is not None:
            with contextlib.suppress(json.JSONDecodeError):
                args_dict = json.loads(row["args_json"])
        result.append(
            AuditEvent(
                ts=row["ts"],
                event=row["event"],
                plugin_id=row["plugin_id"],
                tool_id=row["tool_id"],
                args=args_dict,
                result=row["result"],
                decision=row["decision"],
                detail=row["detail"],
            ),
        )
    return result
