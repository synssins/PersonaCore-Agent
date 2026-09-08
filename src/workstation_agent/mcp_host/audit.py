"""Append-only audit log backed by SQLite (WAL mode).

Schema (design §4.6, extended for contract §5.7)::

    CREATE TABLE audit_log (
        rowid          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts             TEXT    NOT NULL,   -- ISO-8601 UTC timestamp
        event          TEXT    NOT NULL,   -- event type string
        plugin_id      TEXT,
        tool_id        TEXT,
        args_json      TEXT,               -- string values truncated, §5.7
        result         TEXT,
        decision       TEXT,
        detail         TEXT,
        code           TEXT,               -- §5.2 outcome code
        duration_ms    REAL,               -- §5.7 duration
        request_id     TEXT,               -- §5.7 MCP request id
        correlation_id TEXT,               -- confirm prompt ↔ outcome
        session_id     TEXT                -- transport connection
    );

UPDATE and DELETE are blocked by triggers that raise an abort error.
The database is opened in WAL mode for concurrent reads.

Migration
---------
The five columns after ``detail`` were added after rows already existed in
the field.  The migration is **purely additive**: ``ALTER TABLE ... ADD
COLUMN`` for whatever ``PRAGMA table_info`` says is missing.  Nothing is
copied, rewritten or dropped, so no row is ever UPDATEd or DELETEd and the
append-only triggers stay in force throughout — ``ALTER TABLE`` is DDL and
does not fire row triggers, so the guarantee did not have to be relaxed to
make the migration possible.  Pre-migration rows keep their original values
and read back with ``NULL`` in the new columns.

Historic rows carry the confirm correlation id inside the free-text
``detail`` column (``correlation_id=<hex>``).  Those rows cannot be
rewritten — that is the point of an append-only log — so :func:`query`
recovers the id on the *read* side when the column is NULL.  New rows write
the column and leave it out of ``detail``.

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
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any

import workstation_agent.config.store as _store

_log = logging.getLogger(__name__)

#: §5.7 — "the arguments (with ``data`` fields of serial and file writes
#: truncated to 200 characters)".  Applied to *every* string value rather
#: than only the ones named ``data``: the rule exists so a megabyte of
#: serial traffic or file content cannot be copied wholesale into the audit
#: database, and a family that names its payload ``content``, ``text`` or
#: ``hex`` (§6.1 names all three) would otherwise slip straight past a
#: key-name check.
MAX_ARG_VALUE_CHARS = 200

#: Belt-and-braces bound on the whole serialised blob, for args with many
#: keys.  Per-value truncation caps each value but not their number.
MAX_ARGS_JSON_CHARS = 8000

_MAX_ARG_DEPTH = 6
_MAX_ARG_ITEMS = 100

_CORRELATION_IN_DETAIL = re.compile(r"correlation_id=([A-Za-z0-9_-]+)")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    rowid          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT    NOT NULL,
    event          TEXT    NOT NULL,
    plugin_id      TEXT,
    tool_id        TEXT,
    args_json      TEXT,
    result         TEXT,
    decision       TEXT,
    detail         TEXT,
    code           TEXT,
    duration_ms    REAL,
    request_id     TEXT,
    correlation_id TEXT,
    session_id     TEXT
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

#: Columns added after the original schema shipped, in order.
_MIGRATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("code", "TEXT"),
    ("duration_ms", "REAL"),
    ("request_id", "TEXT"),
    ("correlation_id", "TEXT"),
    ("session_id", "TEXT"),
)

_ALL_COLUMNS = (
    "ts",
    "event",
    "plugin_id",
    "tool_id",
    "args_json",
    "result",
    "decision",
    "detail",
    "code",
    "duration_ms",
    "request_id",
    "correlation_id",
    "session_id",
)

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
    # --- §5.7 additions ---------------------------------------------------
    code: str | None = None
    duration_ms: float | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    session_id: str | None = None

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
    code: str | None = None
    correlation_id: str | None = None
    session_id: str | None = None


_local = threading.local()
_db_path: Path | None = None
_path_lock = threading.Lock()


def _get_db_path() -> Path:
    global _db_path  # noqa: PLW0603
    with _path_lock:
        if _db_path is None:
            _db_path = _store.paths()["audit_db"]
        return _db_path


def _migrate(conn: sqlite3.Connection) -> None:
    """Add any §5.7 columns the existing table is missing.

    Additive only.  No row is read, rewritten or removed, so the append-only
    triggers are neither dropped nor bypassed: ``ALTER TABLE ... ADD COLUMN``
    is DDL and does not fire ``BEFORE UPDATE``/``BEFORE DELETE`` row
    triggers.  Existing rows keep every value they had; the new columns read
    back as NULL for them.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if not existing:  # pragma: no cover — table always exists by this point
        return
    for name, sql_type in _MIGRATION_COLUMNS:
        if name in existing:
            continue
        _log.info("audit: migrating audit_log — adding column %s", name)
        conn.execute(f"ALTER TABLE audit_log ADD COLUMN {name} {sql_type}")


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
        _migrate(new_conn)
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


def truncate_args(value: Any, *, depth: int = 0) -> Any:  # noqa: ANN401
    """Return *value* with every string truncated to :data:`MAX_ARG_VALUE_CHARS`.

    Recurses into dicts and lists so a payload nested one level down (§6.1's
    ``{"args": {"data": ...}}`` shapes) is truncated too, with a depth and
    item bound so a hostile or merely enormous argument object cannot turn
    audit logging into the expensive part of a tool call.
    """
    if isinstance(value, str):
        return value[:MAX_ARG_VALUE_CHARS]
    if depth >= _MAX_ARG_DEPTH:
        # Below the bound, keep scalars and drop structure rather than
        # recursing forever on a self-referential object.
        return None if isinstance(value, (dict, list, tuple)) else value
    if isinstance(value, dict):
        return {
            str(k)[:MAX_ARG_VALUE_CHARS]: truncate_args(v, depth=depth + 1)
            for k, v in list(value.items())[:_MAX_ARG_ITEMS]
        }
    if isinstance(value, (list, tuple)):
        return [truncate_args(v, depth=depth + 1) for v in list(value)[:_MAX_ARG_ITEMS]]
    return value


def _encode_args(args: dict[str, Any] | None) -> str | None:
    """Serialise *args* for storage, truncated per §5.7."""
    if args is None:
        return None
    try:
        payload = json.dumps(truncate_args(args), separators=(",", ":"), default=str)
    except (TypeError, ValueError, RecursionError):
        payload = str(args)[:MAX_ARGS_JSON_CHARS]
    if len(payload) > MAX_ARGS_JSON_CHARS:
        # Stay valid JSON rather than slicing a document in half.
        keys = [str(k)[:MAX_ARG_VALUE_CHARS] for k in list(args)[:_MAX_ARG_ITEMS]]
        payload = json.dumps(
            {"_truncated": True, "_keys": keys},
            separators=(",", ":"),
        )
    return payload


def log(event: AuditEvent, *, db_path: Path | None = None) -> None:
    """Append *event* to the audit log.

    Thread-safe; safe to call from asyncio via ``asyncio.to_thread``.
    """
    args_json = _encode_args(event.args)

    conn = _connect(db_path)
    conn.execute(
        """
        INSERT INTO audit_log (
            ts, event, plugin_id, tool_id, args_json, result, decision, detail,
            code, duration_ms, request_id, correlation_id, session_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            event.code,
            event.duration_ms,
            event.request_id,
            event.correlation_id,
            event.session_id,
        ),
    )
    conn.commit()
    _log.debug(
        "audit: event=%s plugin=%s tool=%s decision=%s code=%s duration_ms=%s",
        event.event,
        event.plugin_id,
        event.tool_id,
        event.decision,
        event.code,
        event.duration_ms,
    )


def _row_correlation_id(row: sqlite3.Row) -> str | None:
    """Read the correlation id, recovering it from legacy ``detail`` text.

    Rows written before the column existed embedded ``correlation_id=<hex>``
    in ``detail``.  They cannot be rewritten (append-only), so the recovery
    happens here on read.
    """
    stored = row["correlation_id"]
    if stored:
        return str(stored)
    detail = row["detail"]
    if not detail:
        return None
    match = _CORRELATION_IN_DETAIL.search(str(detail))
    return match.group(1) if match else None


#: ``AuditQuery`` field → SQL comparison.  Table-driven so adding a filter is
#: a one-line change and cannot drift from the column list.
_FILTER_SQL: tuple[tuple[str, str], ...] = (
    ("plugin_id", "plugin_id = ?"),
    ("tool_id", "tool_id = ?"),
    ("event", "event = ?"),
    ("since", "ts >= ?"),
    ("until", "ts <= ?"),
    ("code", "code = ?"),
    ("correlation_id", "correlation_id = ?"),
    ("session_id", "session_id = ?"),
)


def _build_where(filters: AuditQuery) -> tuple[str, list[Any]]:
    """Turn *filters* into a parameterised WHERE clause."""
    clauses: list[str] = []
    params: list[Any] = []
    for attr, sql in _FILTER_SQL:
        value = getattr(filters, attr)
        if value is not None:
            clauses.append(sql)
            params.append(value)
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", params


def query(filters: AuditQuery, *, db_path: Path | None = None) -> list[AuditEvent]:
    """Return audit rows matching *filters*, newest-first."""
    where, params = _build_where(filters)
    sql = (
        f"SELECT {', '.join(_ALL_COLUMNS)} "
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
                parsed = json.loads(row["args_json"])
                if isinstance(parsed, dict):
                    args_dict = parsed
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
                code=row["code"],
                duration_ms=row["duration_ms"],
                request_id=row["request_id"],
                correlation_id=_row_correlation_id(row),
                session_id=row["session_id"],
            ),
        )
    return result
