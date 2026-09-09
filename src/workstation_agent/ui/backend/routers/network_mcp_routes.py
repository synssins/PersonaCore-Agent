"""Network MCP credential surface: GET /network-mcp, rotate-token, regenerate-certificate.

Contract §3: the URL, the certificate fingerprint and the bearer token are
shown **once**, each with a copy button, so the operator can paste them into
PersonaCore's Plugins page and secret store. :func:`NetworkMCPServer.info`
(``network_mcp/server.py``) is the read-only source for all of it; this
router never mutates anything under ``network_mcp/``.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from workstation_agent.ui.backend.app import BackendContext, get_context, templates
from workstation_agent.ui.backend.credential_reveal import (
    RevealPersistenceError,
    consume_reveal,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/network-mcp", tags=["network-mcp"])


def _token_identity(token: str) -> str:
    """A stand-in for the token that is safe to keep in the reveal-state file.

    Never the token itself: :func:`consume_reveal` persists whatever it is
    given to disk, and the whole point of this surface is that the token
    only ever lives in memory and in what the operator pasted elsewhere.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.get("", response_class=HTMLResponse)
async def network_mcp_page(
    request: Request,
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> HTMLResponse:
    """Render the endpoint's identity, and the token/fingerprint if unseen."""
    server: Any = ctx.network_mcp

    info = None
    error: str | None = None
    if server is not None:
        try:
            info = server.info()
        except Exception as exc:  # noqa: BLE001 — surfaced to the page, not raised
            log.warning("network-mcp: info() failed: %s", exc)
            error = "Could not read the network MCP endpoint's current state."

    reveal_token = False
    reveal_fingerprint = False
    reveal_error: str | None = None
    if info is not None:
        try:
            reveal_token = consume_reveal("token", _token_identity(info.token))
            reveal_fingerprint = consume_reveal("fingerprint", info.fingerprint)
        except RevealPersistenceError:
            # Fail closed: neither value is shown when we cannot durably
            # record that it was shown. Told to the operator explicitly --
            # the alternative (reveal anyway) would turn a write failure
            # into a silent, standing leak of the token.
            log.exception("network-mcp: reveal state persistence failed")
            reveal_token = reveal_fingerprint = False
            reveal_error = (
                "Could not record that the token/fingerprint were shown, so they "
                "are being kept hidden for safety. Check that this workstation's "
                "%APPDATA%\\WorkstationAgent directory is writable, then reload "
                "this page."
            )

    return templates.TemplateResponse(
        request,
        "network_mcp.html",
        {
            "enabled": server is not None,
            "info": info,
            "error": error,
            "reveal_error": reveal_error,
            "reveal_token": reveal_token,
            "reveal_fingerprint": reveal_fingerprint,
        },
    )


@router.post("/rotate-token")
async def rotate_token(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Generate a fresh bearer token; it is shown once on the next page load."""
    if ctx.network_mcp is not None:
        with contextlib.suppress(Exception):
            ctx.network_mcp.rotate_token()
        log.info("network-mcp: token rotated")
    return RedirectResponse(url="/network-mcp", status_code=303)


@router.post("/regenerate-certificate")
async def regenerate_certificate(
    ctx: Annotated[BackendContext, Depends(get_context)],
) -> RedirectResponse:
    """Generate a fresh certificate; changes the pinned fingerprint.

    The exported registration must be regenerated and reinstalled on
    PersonaCore's Plugins page afterwards, or the core's pin fails.
    """
    if ctx.network_mcp is not None:
        with contextlib.suppress(Exception):
            ctx.network_mcp.regenerate_certificate()
        log.info("network-mcp: certificate regenerated")
    return RedirectResponse(url="/network-mcp", status_code=303)
