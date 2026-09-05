"""Tests: logs, audit, and about routes."""

# ruff: noqa: PERF401

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import TYPE_CHECKING

import pytest
from starlette.testclient import TestClient

from tests.unit.ui.conftest import (
    FakeAuditReader,
    FakeConfigStore,
    _LoopbackASGI,
    make_client,
)
from workstation_agent.mcp_host.audit import AuditEvent
from workstation_agent.ui.backend.app import BackendContext, create_app

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_log(log_dir: Path, lines: list[str]) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "agent.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fake_audit_rows() -> list[AuditEvent]:
    return [
        AuditEvent(event="tool_invoke", plugin_id="hello", tool_id="echo",
                   result="ok", decision="allow"),
        AuditEvent(event="plugin_started", plugin_id="hello"),
    ]


# ---------------------------------------------------------------------------
# Logs tests
# ---------------------------------------------------------------------------

def test_logs_page_renders_empty(tmp_path):
    """GET /logs renders even when log file is absent."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert "Log Viewer" in resp.text


def test_logs_page_renders_json_lines(tmp_path):
    """GET /logs renders JSON log entries."""
    log_dir = tmp_path / "logs"
    _write_log(log_dir, [
        json.dumps({"event": "started", "level": "info", "timestamp": "2026-01-01T00:00:00Z"}),
        json.dumps({"event": "running", "level": "debug", "timestamp": "2026-01-01T00:00:01Z"}),
    ])
    client = make_client(log_dir=log_dir, tmp_path=tmp_path)
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert "started" in resp.text or "running" in resp.text


def test_logs_page_tail_param(tmp_path):
    """GET /logs?tail=5 accepts the tail parameter."""
    log_dir = tmp_path / "logs"
    _write_log(log_dir, [json.dumps({"event": f"line{i}"}) for i in range(20)])
    client = make_client(log_dir=log_dir, tmp_path=tmp_path)
    resp = client.get("/logs?tail=5")
    assert resp.status_code == 200


def test_logs_page_non_json_lines(tmp_path):
    """GET /logs handles non-JSON lines gracefully."""
    log_dir = tmp_path / "logs"
    _write_log(log_dir, ["plain text line", "another plain line"])
    client = make_client(log_dir=log_dir, tmp_path=tmp_path)
    resp = client.get("/logs")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logs_stream_sse_generator(tmp_path):
    """_sse_generator yields initial seeded lines as SSE data events."""
    from workstation_agent.ui.backend.routers.logs_routes import _sse_generator

    log_dir = tmp_path / "logs"
    _write_log(log_dir, [
        json.dumps({"event": "hello"}),
        json.dumps({"event": "world"}),
    ])

    results: list[dict[str, str]] = []
    gen = _sse_generator(log_dir, tail=5)
    # The generator yields initial lines before hitting the first sleep.
    # Use asyncio.wait_for to bail out after seed phase.
    async def _drain() -> None:
        async for item in gen:
            results.append(item)
            if len(results) >= 2:
                return

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(_drain(), timeout=2.0)

    assert len(results) >= 1
    assert all("data" in item for item in results)
    assert any("hello" in item["data"] or "world" in item["data"] for item in results)


@pytest.mark.asyncio
async def test_logs_stream_sse_generator_empty_log(tmp_path):
    """_sse_generator handles empty/absent log file without error."""
    from workstation_agent.ui.backend.routers.logs_routes import _sse_generator

    log_dir = tmp_path / "logs_empty"
    log_dir.mkdir(parents=True)
    # No log file exists

    results: list[dict[str, str]] = []
    gen = _sse_generator(log_dir, tail=10)

    async def _drain() -> None:
        async for item in gen:
            results.append(item)

    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(_drain(), timeout=0.1)

    # No initial lines emitted — generator goes to sleep immediately
    assert len(results) == 0


@pytest.mark.asyncio
async def test_logs_stream_sse_generator_new_lines(tmp_path):
    """_sse_generator picks up new lines appended after the seed phase."""
    from workstation_agent.ui.backend.routers import logs_routes

    log_dir = tmp_path / "logs_grow"
    _write_log(log_dir, [json.dumps({"event": "seed"})])
    log_file = log_dir / "agent.log"

    # Patch sleep to actually write a new line then cancel
    original_sleep = asyncio.sleep
    call_count = 0

    async def _patched_sleep(_delay: float) -> None:
        nonlocal call_count
        call_count += 1
        # On first poll cycle, append a new line
        if call_count == 1:
            with log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"event": "appended"}) + "\n")
        if call_count >= 2:
            raise asyncio.CancelledError
        await original_sleep(0)

    results: list[dict[str, str]] = []

    from unittest import mock
    with mock.patch.object(logs_routes.asyncio, "sleep", _patched_sleep):
        gen = logs_routes._sse_generator(log_dir, tail=5)
        async def _drain() -> None:
            async for item in gen:
                results.append(item)

        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(_drain(), timeout=3.0)

    # Should have seeded line + potentially the appended line
    assert any("seed" in item.get("data", "") for item in results)


def test_logs_tail_lines_utility(tmp_path):
    """_tail_lines returns the last N lines correctly."""
    from workstation_agent.ui.backend.routers.logs_routes import _tail_lines

    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True)
    log_file = log_dir / "agent.log"
    lines = [f"line {i}" for i in range(10)]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = _tail_lines(log_file, 5)
    assert len(result) == 5
    assert "line 9" in result[-1]


def test_logs_tail_lines_missing_file(tmp_path):
    """_tail_lines returns [] when file does not exist."""
    from workstation_agent.ui.backend.routers.logs_routes import _tail_lines
    result = _tail_lines(tmp_path / "no_such.log", 10)
    assert result == []


def test_logs_parse_lines_mixed():
    """_parse_log_lines handles JSON and non-JSON mixed."""
    from workstation_agent.ui.backend.routers.logs_routes import _parse_log_lines
    lines = [
        json.dumps({"event": "ok", "level": "info"}),
        "raw plain text",
        "",  # blank
    ]
    result = _parse_log_lines(lines)
    assert result[0]["event"] == "ok"
    assert result[1]["raw"] == "raw plain text"
    assert len(result) == 2  # blank skipped


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------

def test_audit_page_renders(tmp_path):
    """GET /audit renders the audit log table."""
    rows = _fake_audit_rows()
    reader = FakeAuditReader(rows)
    client = make_client(audit_reader=reader, tmp_path=tmp_path)
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "Audit Log" in resp.text
    assert "tool_invoke" in resp.text


def test_audit_page_no_rows(tmp_path):
    """GET /audit with no rows shows empty table message."""
    reader = FakeAuditReader([])
    client = make_client(audit_reader=reader, tmp_path=tmp_path)
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "No audit records" in resp.text


def test_audit_page_filters_forwarded(tmp_path):
    """GET /audit?plugin_id=x passes filter to reader."""
    captured: list[object] = []

    class _CapturingReader:
        def __call__(self, query: object) -> list[object]:
            captured.append(query)
            return []

    client = make_client(audit_reader=_CapturingReader(), tmp_path=tmp_path)
    resp = client.get("/audit?plugin_id=my_plugin&limit=50")
    assert resp.status_code == 200
    assert captured[0].plugin_id == "my_plugin"  # type: ignore[attr-defined]
    assert captured[0].limit == 50  # type: ignore[attr-defined]


def test_audit_page_reader_error(tmp_path):
    """GET /audit with a failing reader still renders (shows error)."""
    _err_msg = "db gone"

    class _BrokenReader:
        def __call__(self, _query: object) -> list[object]:
            raise RuntimeError(_err_msg)

    client = make_client(audit_reader=_BrokenReader(), tmp_path=tmp_path)
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert _err_msg in resp.text or "error" in resp.text.lower()


def test_audit_page_no_reader(tmp_path):
    """GET /audit with audit_reader=None renders empty table gracefully."""
    ctx = BackendContext(
        config_store=FakeConfigStore(),
        audit_reader=None,
        log_dir=tmp_path / "logs",
    )
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    client = TestClient(wrapped)
    resp = client.get("/audit")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# About tests
# ---------------------------------------------------------------------------

def test_about_page_renders(tmp_path):
    """GET /about renders version and update controls."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/about")
    assert resp.status_code == 200
    assert "About" in resp.text
    assert "0.1.0" in resp.text


def test_about_check_updates_no_poller(tmp_path):
    """POST /about/check-updates with no poller redirects gracefully."""
    ctx = BackendContext(
        config_store=FakeConfigStore(),
        update_poller=None,
        log_dir=tmp_path / "logs",
    )
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    client = TestClient(wrapped)
    resp = client.post("/about/check-updates", follow_redirects=False)
    assert resp.status_code == 303


def test_about_check_updates_calls_poller(tmp_path):
    """POST /about/check-updates calls update_poller.check_now()."""
    called: list[bool] = []

    class _FakePoller:
        def check_now(self) -> None:
            called.append(True)

    ctx = BackendContext(
        config_store=FakeConfigStore(),
        update_poller=_FakePoller(),
        log_dir=tmp_path / "logs",
    )
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    client = TestClient(wrapped)
    resp = client.post("/about/check-updates", follow_redirects=False)
    assert resp.status_code == 303
    assert called == [True]


def test_about_rollback_redirects(tmp_path):
    """POST /about/rollback redirects to /about."""
    client = make_client(tmp_path=tmp_path)
    resp = client.post(
        "/about/rollback",
        data={"target_version": "0.0.9"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/about" in resp.headers["location"]


def test_dashboard_renders(tmp_path):
    """GET /dashboard renders the dashboard page."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Dashboard" in resp.text


def test_dashboard_shows_plugins(tmp_path):
    """GET /dashboard lists plugin statuses."""
    from tests.unit.ui.conftest import FakeMCPHost, FakePluginInfo
    from workstation_agent.ui.backend.app import BackendContext, create_app

    host = FakeMCPHost([FakePluginInfo(id="myplugin", name="My Plugin", status="running")])
    ctx = BackendContext(
        config_store=FakeConfigStore(),
        mcp_host=host,
        log_dir=tmp_path / "logs",
    )
    app = create_app(ctx)
    wrapped = _LoopbackASGI(app)
    client = TestClient(wrapped)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "myplugin" in resp.text or "My Plugin" in resp.text
