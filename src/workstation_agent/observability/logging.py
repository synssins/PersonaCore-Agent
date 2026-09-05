"""Structured logging: structlog + JSON renderer + daily rotation + redaction.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
from typing import TYPE_CHECKING, Any

import structlog

from workstation_agent.security.dpapi import redact_key

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Patterns whose values should be scrubbed from log output.
_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "api_key_ref",
        "password",
        "secret",
        "token",
        "authorization",
        "dpapi",
        "credential",
    },
)
_REDACT_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in _REDACT_KEYS) + r")\b",
)
_PLACEHOLDER = "***REDACTED***"


def _redact_value(value: object) -> object:
    """Recursively redact sensitive string values."""
    if isinstance(value, dict):
        return {
            k: (_PLACEHOLDER if _REDACT_PATTERN.search(str(k)) else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return type(value)(_redact_value(v) for v in value)
    if isinstance(value, str):
        return redact_key(value)  # strip sk-... patterns, otherwise return unchanged
    return value


def _redaction_processor(
    _logger: structlog.types.WrappedLogger,
    _method: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """structlog processor that scrubs sensitive fields from the event dict."""
    scrubbed: structlog.types.EventDict = {
        k: (_PLACEHOLDER if _REDACT_PATTERN.search(str(k)) else _redact_value(v))
        for k, v in event_dict.items()
    }
    return scrubbed


# ---------------------------------------------------------------------------
# Root handler references (so set_level can update them)
# ---------------------------------------------------------------------------

_file_handler: logging.handlers.TimedRotatingFileHandler | None = None
_console_handler: logging.StreamHandler[Any] | None = None


def configure(log_dir: Path, level: str = "INFO", retention_days: int = 7) -> None:
    """Configure structlog + stdlib logging with JSON output and daily rotation.

    Args:
        log_dir: Directory for JSONL log files.
        level: Initial log level string (e.g. ``"INFO"``).
        retention_days: How many daily rotated files to keep.
    """
    global _file_handler, _console_handler  # noqa: PLW0603
    from pathlib import Path as _Path  # noqa: PLC0415

    _Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = _Path(log_dir) / "agent.log"

    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # -------------------------------------------------------------------
    # stdlib handlers
    # -------------------------------------------------------------------
    _file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",
        interval=1,
        backupCount=retention_days,
        encoding="utf-8",
        utc=True,
    )
    _file_handler.setLevel(numeric_level)

    _console_handler = logging.StreamHandler()
    _console_handler.setLevel(numeric_level)

    root = logging.getLogger()
    root.setLevel(numeric_level)
    # Remove any pre-existing handlers to avoid duplicate output
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(_file_handler)
    root.addHandler(_console_handler)

    # -------------------------------------------------------------------
    # structlog processors
    # -------------------------------------------------------------------
    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redaction_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )

    _file_handler.setFormatter(formatter)
    _console_handler.setFormatter(formatter)


def set_level(level: str) -> None:
    """Change the active log level without restarting.

    Args:
        level: Level name string, e.g. ``"DEBUG"`` or ``"WARNING"``.
    """
    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        return

    logging.getLogger().setLevel(numeric_level)
    if _file_handler is not None:
        _file_handler.setLevel(numeric_level)
    if _console_handler is not None:
        _console_handler.setLevel(numeric_level)

    # Re-configure structlog wrapper with new level
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
    )
