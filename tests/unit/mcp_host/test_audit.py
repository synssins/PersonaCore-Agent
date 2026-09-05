"""Unit tests for workstation_agent.mcp_host.audit."""
# ruff: noqa: PT012

from __future__ import annotations

import sqlite3

import pytest

import workstation_agent.mcp_host.audit as audit_mod
from workstation_agent.mcp_host.audit import AuditEvent, AuditQuery, log, query


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Each test gets its own audit.db, thread-local connection is reset after."""
    db_path = tmp_path / "test_audit.db"
    audit_mod.set_db_path(db_path)
    yield db_path
    audit_mod.reset_connection()


def test_schema_created(isolated_db):
    """Calling log() once creates the audit_log table with WAL mode."""
    event = AuditEvent(event="test_schema")
    log(event, db_path=isolated_db)

    conn = sqlite3.connect(str(isolated_db))
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    assert cursor.fetchone() is not None

    wal = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert wal == "wal"
    conn.close()


def test_trigger_created(isolated_db):
    """UPDATE and DELETE triggers are present after schema creation."""
    log(AuditEvent(event="init"), db_path=isolated_db)

    conn = sqlite3.connect(str(isolated_db))
    triggers = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'",
        ).fetchall()
    }
    conn.close()
    assert "audit_log_no_update" in triggers
    assert "audit_log_no_delete" in triggers


def test_log_inserts_row(isolated_db):
    """log() inserts a row readable by query()."""
    event = AuditEvent(
        event="tool_invoke",
        plugin_id="hello_world",
        tool_id="hello_world.echo",
        args={"text": "hi"},
        result="ok",
        decision="allow",
    )
    log(event, db_path=isolated_db)

    rows = query(AuditQuery(), db_path=isolated_db)
    assert len(rows) == 1
    assert rows[0].event == "tool_invoke"
    assert rows[0].plugin_id == "hello_world"
    assert rows[0].tool_id == "hello_world.echo"
    assert rows[0].args == {"text": "hi"}
    assert rows[0].result == "ok"
    assert rows[0].decision == "allow"


def test_log_multiple_rows(isolated_db):
    """Multiple log() calls produce multiple rows."""
    for i in range(5):
        log(AuditEvent(event="tick", detail=str(i)), db_path=isolated_db)

    rows = query(AuditQuery(limit=10), db_path=isolated_db)
    assert len(rows) == 5


def test_update_raises(isolated_db):
    """UPDATE on audit_log raises due to trigger."""
    log(AuditEvent(event="immutable"), db_path=isolated_db)
    conn = sqlite3.connect(str(isolated_db))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_log SET event='hacked' WHERE 1=1")
        conn.commit()
    conn.close()


def test_delete_raises(isolated_db):
    """DELETE on audit_log raises due to trigger."""
    log(AuditEvent(event="immutable"), db_path=isolated_db)
    conn = sqlite3.connect(str(isolated_db))
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE 1=1")
        conn.commit()
    conn.close()


def test_query_filter_plugin_id(isolated_db):
    """query(plugin_id=...) returns only rows for that plugin."""
    log(AuditEvent(event="e", plugin_id="plugin_a"), db_path=isolated_db)
    log(AuditEvent(event="e", plugin_id="plugin_b"), db_path=isolated_db)
    log(AuditEvent(event="e", plugin_id="plugin_a"), db_path=isolated_db)

    rows = query(AuditQuery(plugin_id="plugin_a"), db_path=isolated_db)
    assert len(rows) == 2
    assert all(r.plugin_id == "plugin_a" for r in rows)


def test_query_filter_event(isolated_db):
    """query(event=...) returns only rows with that event type."""
    log(AuditEvent(event="alpha"), db_path=isolated_db)
    log(AuditEvent(event="beta"), db_path=isolated_db)
    log(AuditEvent(event="alpha"), db_path=isolated_db)

    rows = query(AuditQuery(event="alpha"), db_path=isolated_db)
    assert len(rows) == 2
    assert all(r.event == "alpha" for r in rows)


def test_query_filter_tool_id(isolated_db):
    """query(tool_id=...) filters by tool."""
    log(AuditEvent(event="e", tool_id="foo.bar"), db_path=isolated_db)
    log(AuditEvent(event="e", tool_id="baz.qux"), db_path=isolated_db)

    rows = query(AuditQuery(tool_id="foo.bar"), db_path=isolated_db)
    assert len(rows) == 1
    assert rows[0].tool_id == "foo.bar"


def test_query_limit(isolated_db):
    """query(limit=N) returns at most N rows."""
    for _i in range(10):
        log(AuditEvent(event="bulk"), db_path=isolated_db)

    rows = query(AuditQuery(limit=3), db_path=isolated_db)
    assert len(rows) == 3


def test_query_since_until(isolated_db):
    """query(since=..., until=...) filters by timestamp."""
    log(AuditEvent(event="e", ts="2026-01-01T00:00:00+00:00"), db_path=isolated_db)
    log(AuditEvent(event="e", ts="2026-06-01T00:00:00+00:00"), db_path=isolated_db)
    log(AuditEvent(event="e", ts="2026-12-01T00:00:00+00:00"), db_path=isolated_db)

    rows = query(
        AuditQuery(since="2026-03-01T00:00:00+00:00", until="2026-09-01T00:00:00+00:00"),
        db_path=isolated_db,
    )
    assert len(rows) == 1
    assert "2026-06" in rows[0].ts


def test_query_empty(isolated_db):
    """query() returns empty list when the table is empty."""
    rows = query(AuditQuery(), db_path=isolated_db)
    assert rows == []


def test_audit_event_auto_ts():
    """AuditEvent without explicit ts fills in a UTC ISO-8601 timestamp."""
    e = AuditEvent(event="x")
    assert e.ts
    assert "T" in e.ts


def test_audit_event_explicit_ts():
    """AuditEvent with explicit ts preserves it."""
    e = AuditEvent(event="x", ts="2026-01-01T12:00:00+00:00")
    assert e.ts == "2026-01-01T12:00:00+00:00"
