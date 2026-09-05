"""Tests: structured logging — JSON output, redaction, rotation."""

# ruff: noqa: S106

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from pathlib import Path


def _read_json_lines(path: Path) -> list[dict]:
    """Parse JSONL file and return list of dicts."""
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped:
            with contextlib.suppress(json.JSONDecodeError):
                result.append(json.loads(stripped))
    return result


def test_configure_creates_log_file(tmp_path):
    """configure() creates the log file in the specified directory."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs"
    configure(log_dir, level="DEBUG")
    assert (log_dir / "agent.log").exists()


def test_json_output(tmp_path):
    """Log messages are written as valid JSON lines."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs2"
    configure(log_dir, level="DEBUG")

    logger = logging.getLogger("test_json_output")
    logger.info("hello from test")

    records = _read_json_lines(log_dir / "agent.log")
    assert len(records) >= 1
    last = records[-1]
    assert "event" in last or "message" in last


def test_redaction_api_key(tmp_path):
    """Structured events with 'api_key' field are redacted."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs_redact"
    configure(log_dir, level="DEBUG")

    log = structlog.get_logger("test_redact")
    log.info("test event", api_key="super_secret_value_12345")

    records = _read_json_lines(log_dir / "agent.log")
    assert len(records) >= 1
    last = records[-1]
    # api_key value should be redacted
    assert last.get("api_key") != "super_secret_value_12345"
    assert "REDACT" in str(last.get("api_key", ""))


def test_redaction_password(tmp_path):
    """Events with 'password' field are redacted."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs_pass"
    configure(log_dir, level="DEBUG")

    log = structlog.get_logger("test_redact_password")
    log.warning("auth attempt", password="hunter2")

    records = _read_json_lines(log_dir / "agent.log")
    assert len(records) >= 1
    last = records[-1]
    assert last.get("password") != "hunter2"
    assert "REDACT" in str(last.get("password", ""))


def test_set_level_changes_level(tmp_path):
    """set_level() changes the active log level without restart."""
    from workstation_agent.observability.logging import configure, set_level

    log_dir = tmp_path / "logs_level"
    configure(log_dir, level="WARNING")

    logger = logging.getLogger("test_level")
    # INFO should be suppressed at WARNING level
    assert logger.getEffectiveLevel() >= logging.WARNING

    set_level("DEBUG")
    assert logging.getLogger().level == logging.DEBUG


def test_set_level_invalid_is_noop(tmp_path):
    """set_level() with an unrecognised level string does nothing."""
    from workstation_agent.observability.logging import configure, set_level

    log_dir = tmp_path / "logs_noop"
    configure(log_dir, level="INFO")
    before = logging.getLogger().level
    set_level("NOT_A_LEVEL")
    assert logging.getLogger().level == before


def test_log_dir_created_if_missing(tmp_path):
    """configure() creates nested log directory if it does not exist."""
    from workstation_agent.observability.logging import configure

    deep_dir = tmp_path / "a" / "b" / "c"
    assert not deep_dir.exists()
    configure(deep_dir, level="INFO")
    assert deep_dir.exists()
    assert (deep_dir / "agent.log").exists()


def test_rotation_handler_configured(tmp_path):
    """configure() installs a TimedRotatingFileHandler."""
    import logging.handlers

    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs_rot"
    configure(log_dir, level="INFO")

    root = logging.getLogger()
    handler_types = [type(h) for h in root.handlers]
    assert logging.handlers.TimedRotatingFileHandler in handler_types


def test_structlog_get_logger(tmp_path):
    """structlog.get_logger() returns a usable bound logger after configure()."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs_struct"
    configure(log_dir, level="DEBUG")

    log = structlog.get_logger("smoke")
    # Should not raise
    log.info("structlog smoke test", key="value")


def test_redaction_token_in_value(tmp_path):
    """String values containing 'token' in the key name are redacted."""
    from workstation_agent.observability.logging import configure

    log_dir = tmp_path / "logs_token"
    configure(log_dir, level="DEBUG")

    log = structlog.get_logger("test_token")
    log.info("bearer check", token="bearer_abc123")

    records = _read_json_lines(log_dir / "agent.log")
    last = records[-1]
    assert last.get("token") != "bearer_abc123"


def test_tracing_noop_without_otel():
    """tracing.configure() and get_tracer() are safe no-ops without opentelemetry."""
    from workstation_agent.observability import tracing

    # Should not raise even if opentelemetry is absent
    tracing.configure(service_name="test-svc", otlp_endpoint="http://localhost:4317")
    tracer = tracing.get_tracer("test")
    with tracer.start_as_current_span("test-span"):
        pass  # no-op or real span — either is fine
