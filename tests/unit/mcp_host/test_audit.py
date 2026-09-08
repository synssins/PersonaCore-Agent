"""Unit tests for workstation_agent.mcp_host.audit."""
# ruff: noqa: PT012

from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# §5.7: duration, MCP request id, and 200-character argument truncation
# ---------------------------------------------------------------------------

_LEGACY_SCHEMA = """
CREATE TABLE audit_log (
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
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE not allowed');
END;
CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE not allowed');
END;
"""


def _make_legacy_db(path):
    """Build a pre-migration audit.db that already has rows in it."""
    conn = sqlite3.connect(str(path))
    conn.executescript(_LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO audit_log (ts, event, plugin_id, tool_id, args_json, result, "
        "decision, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "2026-01-01T00:00:00+00:00",
            "tool_confirmed",
            "legacy_plugin",
            "legacy.write",
            '{"path":"/x"}',
            "ok",
            "confirm_allowed",
            "correlation_id=deadbeef",
        ),
    )
    conn.commit()
    conn.close()


def test_new_schema_has_the_contract_columns(isolated_db):
    """§5.7 needs a duration column and an MCP-request-id column."""
    log(AuditEvent(event="init"), db_path=isolated_db)
    conn = sqlite3.connect(str(isolated_db))
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    conn.close()
    assert {"duration_ms", "request_id", "code", "correlation_id", "session_id"} <= cols


def test_migration_adds_columns_to_a_populated_legacy_db(tmp_path):
    """An existing audit.db with rows in it migrates additively.

    No row is copied, rewritten or dropped: the historic row keeps every
    value it had and simply reads back with NULL in the new columns.
    """
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    audit_mod.set_db_path(db)
    try:
        log(AuditEvent(event="post_migration", code="denied", duration_ms=12.5,
                       request_id="99", session_id="s1"), db_path=db)

        conn = sqlite3.connect(str(db))
        cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        conn.close()
        assert {"code", "duration_ms", "request_id", "correlation_id", "session_id"} <= cols

        rows = query(AuditQuery(plugin_id="legacy_plugin"), db_path=db)
        assert len(rows) == 1, "the pre-existing row must survive the migration"
        assert rows[0].tool_id == "legacy.write"
        assert rows[0].result == "ok"
        assert rows[0].duration_ms is None

        fresh = query(AuditQuery(event="post_migration"), db_path=db)
        assert fresh[0].code == "denied"
        assert fresh[0].duration_ms == 12.5
        assert fresh[0].request_id == "99"
    finally:
        audit_mod.reset_connection()


def test_migrated_db_still_refuses_update_and_delete(tmp_path):
    """The append-only triggers are NOT relaxed to make the migration possible.

    ``ALTER TABLE ... ADD COLUMN`` is DDL and does not fire row triggers, so
    the migration never needed to drop them — and this asserts it did not.
    """
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    audit_mod.set_db_path(db)
    try:
        log(AuditEvent(event="after"), db_path=db)  # triggers the migration

        conn = sqlite3.connect(str(db))
        triggers = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'",
            ).fetchall()
        }
        assert triggers == {"audit_log_no_update", "audit_log_no_delete"}

        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_log SET event='hacked'")
            conn.commit()
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM audit_log")
            conn.commit()

        # Including on the new columns specifically.
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE audit_log SET duration_ms=0")
            conn.commit()
        conn.close()
    finally:
        audit_mod.reset_connection()


def test_migration_is_idempotent(tmp_path):
    """Re-opening an already-migrated database does not fail or duplicate."""
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    audit_mod.set_db_path(db)
    try:
        log(AuditEvent(event="one"), db_path=db)
        audit_mod.reset_connection()
        log(AuditEvent(event="two"), db_path=db)
        assert len(query(AuditQuery(limit=50), db_path=db)) == 3
    finally:
        audit_mod.reset_connection()


def test_legacy_correlation_id_recovered_from_detail(tmp_path):
    """A pre-migration row's correlation id is recovered on read.

    It cannot be moved into the column: the row cannot be UPDATEd.
    """
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    audit_mod.set_db_path(db)
    try:
        rows = query(AuditQuery(plugin_id="legacy_plugin"), db_path=db)
        assert rows[0].correlation_id == "deadbeef"
    finally:
        audit_mod.reset_connection()


def test_args_string_values_truncated_at_200_chars(isolated_db):
    """§5.7: argument payloads are truncated to 200 characters."""
    payload = "A" * 5000
    log(
        AuditEvent(event="tool_invoke", tool_id="serial_write", args={"data": payload}),
        db_path=isolated_db,
    )

    conn = sqlite3.connect(str(isolated_db))
    stored = conn.execute("SELECT args_json FROM audit_log").fetchone()[0]
    conn.close()

    assert len(stored) < 300, "the whole 5,000-character payload was written to the log"

    rows = query(AuditQuery(), db_path=isolated_db)
    assert rows[0].args is not None
    assert len(rows[0].args["data"]) == 200
    assert rows[0].args["data"] == payload[:200]


def test_args_truncation_reaches_nested_values(isolated_db):
    """A payload one level down is truncated too."""
    log(
        AuditEvent(event="e", args={"body": {"content": "B" * 4000}}),
        db_path=isolated_db,
    )
    rows = query(AuditQuery(), db_path=isolated_db)
    assert rows[0].args is not None
    assert len(rows[0].args["body"]["content"]) == 200


def test_short_args_are_untouched(isolated_db):
    """Truncation must not disturb ordinary arguments."""
    log(AuditEvent(event="e", args={"text": "hi", "n": 3}), db_path=isolated_db)
    rows = query(AuditQuery(), db_path=isolated_db)
    assert rows[0].args == {"text": "hi", "n": 3}


def test_args_with_very_many_keys_stay_bounded_and_valid_json(isolated_db):
    """Per-value truncation caps each value but not their number."""
    args = {f"k{i}": "C" * 200 for i in range(500)}
    log(AuditEvent(event="e", args=args), db_path=isolated_db)

    conn = sqlite3.connect(str(isolated_db))
    stored = conn.execute("SELECT args_json FROM audit_log").fetchone()[0]
    conn.close()

    assert len(stored) <= audit_mod.MAX_ARGS_JSON_CHARS
    assert json.loads(stored)["_truncated"] is True


def test_unserialisable_args_do_not_break_logging(isolated_db):
    """An argument object the JSON encoder cannot handle must not lose the row."""
    log(AuditEvent(event="e", args={"blob": {1, 2, 3}}), db_path=isolated_db)
    rows = query(AuditQuery(), db_path=isolated_db)
    assert len(rows) == 1


def test_self_referential_args_do_not_recurse_forever(isolated_db):
    """A cyclic argument object is bounded, not a hang."""
    args: dict = {"name": "loop"}
    args["self"] = args
    log(AuditEvent(event="e", args=args), db_path=isolated_db)
    rows = query(AuditQuery(), db_path=isolated_db)
    assert len(rows) == 1


def test_query_filters_on_the_new_columns(isolated_db):
    """The new columns are queryable, not merely stored."""
    log(AuditEvent(event="a", code="denied", session_id="s1",
                   correlation_id="c1"), db_path=isolated_db)
    log(AuditEvent(event="b", code="error", session_id="s2"), db_path=isolated_db)

    assert len(query(AuditQuery(code="denied"), db_path=isolated_db)) == 1
    assert len(query(AuditQuery(session_id="s2"), db_path=isolated_db)) == 1
    assert len(query(AuditQuery(correlation_id="c1"), db_path=isolated_db)) == 1
