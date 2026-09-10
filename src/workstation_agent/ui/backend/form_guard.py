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
    from starlette.datastructures import FormData

#: The two encodings an HTML ``<form method="post">`` can arrive as.
FORM_MEDIA_TYPES = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
})

#: Hidden field every form in this backend submits, naming what that submission
#: speaks for. See :func:`speaks_for`.
SPEAKS_FOR_FIELD = "speaks_for"


def speaks_for(form: FormData) -> frozenset[str]:
    """The tokens *form* declared it speaks for; empty when it declared nothing.

    The encoding check above catches a body that is not a form. It cannot catch
    a body that *is* form-encoded but carries nothing meaningful -- and for some
    fields, carrying nothing is a legitimate answer. An unticked HTML checkbox
    is omitted from the submission entirely, and "no tool is set to always
    prompt" is likewise submitted as no fields at all. So "the operator chose
    the empty answer" and "this body did not come from that form" arrive
    identically, which is the exact indistinguishability that erased the
    configuration in the first place.

    A form therefore declares its own scope in a hidden field, and the handler
    reads it back here: a token present means the submission speaks for that
    thing and its silence is an answer; a token absent means this caller never
    had an opinion, and whatever is stored stands.

    Tokens are whatever the reading handler finds useful -- ``config.html``'s
    settings form names the checkboxes it renders, its confirmation form names
    the one policy it owns.
    """
    return frozenset(str(form.get(SPEAKS_FOR_FIELD) or "").split())


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
