"""Refusing request bodies a form handler cannot actually read (P23).

Starlette parses a non-form body -- a JSON body, say -- as an *empty*
``FormData`` rather than raising. Every handler in this backend that reads its
fields as ``Form(...)`` parameters with defaults therefore has the same latent
hole: a caller that posts the wrong encoding gets every default written over
whatever the operator had, with a 200 and no error.

That is not hypothetical. The system tray posted JSON at ``POST /config`` --
a route whose contract is "replace the entire configuration with this form" --
and reset the owner's LLM base URL, model, Wyoming host, wake settings and
update channel on every mute click and every session-mode click, in shipped
alpha.12 and alpha.13.

The instance was in the tray. The *class* is here: a body that did not parse as
the form the handler expected must be refused, not treated as an empty one. One
helper, so a handler added next month gets the same answer for free.

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import Request

#: The two encodings an HTML ``<form method="post">`` can arrive as.
FORM_MEDIA_TYPES = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
})


def request_media_type(request: Request) -> str:
    """*request*'s content type with any parameters (``; boundary=...``) removed."""
    return request.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def not_a_form_body(request: Request, *, saves: str, instead: str = "") -> str | None:
    """Why *request*'s body must not be read as a form, or ``None`` if it may be.

    *saves* names what this route would have overwritten, so the message tells
    the caller what did **not** happen rather than just naming a status code.
    *instead* optionally points at the route that does what the caller probably
    meant.
    """
    media_type = request_media_type(request)
    if media_type in FORM_MEDIA_TYPES:
        return None
    arrived = media_type or "a body with no content type"
    message = (
        f"This route {saves} from an HTML form body "
        f"({' or '.join(sorted(FORM_MEDIA_TYPES))}), and the request arrived as "
        f"{arrived}. Nothing was saved."
    )
    if instead:
        message = f"{message} {instead}"
    return message
