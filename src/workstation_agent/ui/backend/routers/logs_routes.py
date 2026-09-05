"""Log viewer routes: GET /logs, GET /logs/stream (SSE).

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
from typing import TYPE_CHECKING, Annotated

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates

log = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])

_DEFAULT_TAIL = 100
_SSE_POLL_INTERVAL = 1.0  # seconds between tail checks


def _today_log_file(log_dir: Path) -> Path:
    """Return the expected log file path for today."""
    return log_dir / "agent.log"


def _tail_lines(path: Path, n: int) -> list[str]:
    """Return the last *n* lines from *path* without loading the whole file."""
    if not path.exists():
        return []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return list(collections.deque(fh, maxlen=n))
    except OSError:
        log.exception("tail_lines: failed to read %s", path)
        return []


def _parse_log_lines(lines: list[str]) -> list[dict[str, object]]:
    """Parse JSONL lines; return raw string for non-JSON lines."""
    result: list[dict[str, object]] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line:
            continue
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            result.append({"raw": line})
    return result


@router.get("", response_class=HTMLResponse)
async def logs_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    tail: Annotated[int, Query(ge=1, le=10000)] = _DEFAULT_TAIL,
) -> HTMLResponse:
    """Render the log viewer page."""
    log_file = _today_log_file(ctx.log_dir)
    raw_lines = _tail_lines(log_file, tail)
    entries = _parse_log_lines(raw_lines)
    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "entries": entries,
            "tail": tail,
            "log_file": str(log_file),
        },
    )


async def _sse_generator(  # noqa: C901
    log_dir: Path,
    tail: int,
) -> AsyncIterator[dict[str, str]]:
    """Async generator yielding new log lines as SSE data events."""
    log_file = _today_log_file(log_dir)
    # Seed: send the last `tail` lines immediately
    initial = _tail_lines(log_file, tail)
    for line in initial:
        stripped = line.rstrip("\n")
        if stripped:
            yield {"data": stripped}

    # Track file offset for new lines
    offset = log_file.stat().st_size if log_file.exists() else 0

    while True:
        await asyncio.sleep(_SSE_POLL_INTERVAL)
        if not log_file.exists():
            continue
        try:
            current_size = log_file.stat().st_size
        except OSError:
            continue
        if current_size <= offset:
            # File rotated or unchanged
            if current_size < offset:
                offset = 0
            continue
        try:
            with log_file.open(encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                new_data = fh.read()
                offset = fh.tell()
        except OSError:
            continue
        for line in new_data.splitlines():
            stripped = line.strip()
            if stripped:
                yield {"data": stripped}


@router.get("/stream")
async def logs_stream(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
    tail: Annotated[int, Query(ge=1, le=1000)] = 50,
) -> EventSourceResponse:
    """Server-Sent Events stream of log tail.

    Clients connect once; new lines are pushed as SSE ``data`` events.
    """
    async def _guarded() -> AsyncIterator[dict[str, str]]:
        async for item in _sse_generator(ctx.log_dir, tail):
            if await request.is_disconnected():
                break
            yield item

    return EventSourceResponse(_guarded())
