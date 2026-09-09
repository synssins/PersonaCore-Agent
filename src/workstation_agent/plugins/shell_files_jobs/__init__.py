"""The ``shell``, ``files`` and ``jobs`` families (contract §5.2-§5.4, §6, §6.1).

Why one plugin for three families
---------------------------------
Contract §5.8 says "a family is an Agent plugin", and two of these three cannot
be separate processes.  §5.4's jobs are **in memory and die with the Agent**:
``shell_run`` creates the job and ``jobs_wait`` / ``jobs_output`` / ``jobs_list``
/ ``jobs_kill`` read and kill it, so ``shell`` and ``jobs`` must share one
address space.  Plugins here are separate OS processes talking JSON-RPC over
their own stdio pipes; there is no channel between two of them.

``files`` could have been its own plugin, and was, until the signature settled
it.  A helper module shared between two plugin *packages* is covered by neither
signature, and the sanitisation in this file is a security control — it would
have been tamperable without invalidating anything.  Duplicating it into two
packages instead would mean two copies of the one boundary that must never
disagree.  One signed package, three families, is the version where every line
of this file is covered by the signature that quarantines the plugin if it
changes.

The plugin id is therefore not a family name.  That is already the shipped
convention: ``screen_vision`` hosts ``screen.*`` and ``desktop_control`` hosts
``desktop.*``.  Tool resolution is by tool name (``host._resolve_tool``), never
by splitting the id, so nothing downstream cares.

The original reason for a *single module* is gone and the shape is kept anyway.
``loader._covered_files`` once hashed only ``__init__.py`` and ``__main__.py``,
so a third module here would have run unsigned while ``verify`` still said
``valid``; the covered set is now every importable file in the package tree,
recursively, and a submodule would be signed like anything else.  This file
stays one module because the boundary it enforces reads better in one place,
not because it has to.  ``test_the_signature_covers_every_module_in_the_package``
asserts the covered set against what is actually on disk, so it keeps holding
whichever way that goes — and it also pins that nothing non-Python has appeared
here, since ``.pyd``/``.so``/sourceless ``.pyc`` are now hashed byte-for-byte
and would need a ``.gitattributes`` entry to be stable across checkouts.

``jobs_*`` reaches this plugin's jobs, and says so
---------------------------------------------------
``adb_shell`` (B7) is also job-capable and its jobs live in the **adb plugin's**
process.  Nothing lets one plugin subprocess see another's, and
``host._resolve_tool`` matches a tool name to exactly one plugin, so
``jobs.wait`` always arrives here.  Three answers were possible; the one that
can be built without a host change is the one shipped, and its boundary is made
visible rather than left to be discovered:

* **Shipped (v1).**  ``jobs_*`` serves this plugin's jobs.  ``jobs_list``
  carries an explicit ``scope`` so it never implies it listed everything, and a
  well-formed id belonging to another family is answered ``code: "error"``
  naming the owner — **never** ``unknown_job``, which §5.2 defines as "an id
  from before the Agent last restarted".  Saying "it died" about a job that is
  running in the next process is a lie an operator cannot debug.
  Consequence, stated plainly: contract §11 item 4 ("a 40-second command
  returns a job id; 'wait for it' returns the output") holds for ``shell_run``
  and **not** for ``adb_shell`` until the change below lands.
* **Target: route by id prefix in the host.**  Job ids here are
  ``j-shell-<hex>``, matching B7's ``j-adb-<hex>``, and the owning family is
  declared as ``jobs:shell`` in the signed manifest.  ``MCPHost.invoke`` can
  then send a ``jobs.*`` call to the plugin whose ``jobs:`` declaration matches
  the id's prefix, and fan ``jobs.list`` out across all of them.  That is a
  host change and the host is not this subtask's to edit; the id format and
  the declaration are here so it is pure routing when someone makes it.
* **Rejected: the host adopts every registry.**  Killing a process tree has to
  happen in the process that owns it, so an adopted registry still calls back
  into the owning plugin — the same routing, plus a cache that can go stale.

Jobs are per-plugin, not per-caller
-----------------------------------
There is one of this process for the whole Agent, and ``host.invoke`` does not
pass the transport's session identity into a tool's arguments — B2 plumbed it
as far as the permissions evaluator and no further.  So a job created by one
caller can be waited on, paged and killed by any other caller that reaches this
plugin.  That is stated rather than papered over: nothing on this side can
distinguish two callers.  Job ids are 64 bits of ``uuid4`` so they are not
guessable, which bounds the exposure to whoever was actually told an id, but it
is not isolation and should not be described as any.  Real per-caller job
ownership needs the session id to reach the plugin, which is a host change.

The three things that are easy to get wrong here
------------------------------------------------
1. **Sanitisation is this module's job, at this module's boundary.**  §5.3 says
   binary never travels in v1.  ``shell.run`` and ``jobs.output`` hand back
   whatever a process wrote to a pipe — ``type image.png`` writes bytes that are
   not text, and a crashing command writes a stack trace.  The host's
   ``conform_result`` would *truncate* an over-cap result and pass a lone
   surrogate straight through, so relying on it is how binary reaches the model.
   Every result leaves through :func:`finalise`, which refuses rather than
   mangles.

2. **This runs at low integrity.**  ``mcp_host/supervisor.py`` spawns plugins
   with a low-integrity primary token inside a Job Object with a 16-variable
   environment allow-list.  A low-integrity process may read almost anywhere
   (the default mandatory policy is no-write-up, not no-read-up) but may write
   almost nowhere: ``%USERPROFILE%\\Documents`` is readable and **not
   writable**.  That is why the manifest declares a third root under
   ``AppData\\LocalLow``, which carries a Low mandatory label and therefore is
   writable, and why :func:`files_write` translates the resulting
   ``PermissionError`` into a sentence that says so instead of an errno.

3. **The 25 s boundary is shared with a confirmation prompt this process cannot
   see.**  See :func:`clamp_wait`.

What §5.2's forbidden list does and does not cover
--------------------------------------------------
§5.2: "The Agent never returns a stack trace, an absolute path outside a
declared root, or the token."  That is a rule about the **Agent's own prose** —
the ``reason`` field — and :func:`sanitise_reason` enforces it on every one:
first line only, anything credential-shaped replaced, anything path-shaped
replaced, bounded.  No exception message is ever interpolated into a
``reason``, because an ``OSError``'s message carries a filename.

It is not, and cannot be, a rule about the verbatim output of a program the
owner confirmed at a §7 prompt.  ``shell_run``'s whole contract (§6.1) is to
return ``stdout`` and ``stderr``; a failing command's error text *is* the
answer, and ``Get-ChildItem C:\\Windows`` prints paths outside every root by
construction.  Redacting those would leave a tool that cannot report what it
did.  The confinement that applies to ``shell.run`` is on its ``cwd``, and the
control on its power is §7's always-prompt.  What this module guarantees about
that output is the part §5.3 does make absolute: it is valid UTF-8 or it does
not travel at all.

Symlinks, and the one check only this layer can do
--------------------------------------------------
The gate's root confinement is deliberately **lexical**: ``normalise_path``
resolves ``..`` as string work and never calls ``Path.resolve()``, because
consulting the filesystem would make the answer depend on where the Agent was
launched.  That is right for the gate and it means a junction or symlink inside
a declared root pointing at ``C:/Windows/System32`` passes it.  This module is
the layer that actually opens the file, so it is the only one that can resolve
the link and confine the **real** path.  :func:`resolve_in_roots` does that, and
it is not defence in depth for its own sake — it closes an escape the gate
cannot close.
"""
# ruff: noqa: PTH100, PTH103, PTH107, PTH110, PTH111, PTH112, PTH118, PTH120,
# ruff: noqa: PTH123, PTH202, S603
# PTH*:  this module does deliberate os.path string work so the roots it
#        compares are byte-for-byte the strings permissions.normalise_path
#        produces.  Routing through pathlib would re-normalise per platform
#        and invite a .resolve() in the wrong place.  os.path.realpath is
#        used on purpose and is the one filesystem-consulting call here.
# S603:  every subprocess call in this module is shell=False with an argv
#        list.  The command text is the *argument* of a §7 always-prompt
#        tool, which is the design, not an injection.

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

# The comparison layer is imported, never re-derived.  Commit 4f28d81 is
# explicit that normalise_path / is_absolute_path / _is_within are closed
# findings with mutation-proven tests and that "re-deriving them would have
# reopened bugs that took six rounds to close".  _is_within is private to
# permissions.py; importing it is the lesser evil against writing a second
# UNC-aware prefix test that can disagree with the gate's.
from workstation_agent.mcp_host.permissions import (
    UNINSPECTABLE,
    _is_within,
    is_absolute_path,
    normalise_path,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterator

log = logging.getLogger(__name__)

__all__ = [
    "CALL_BUDGET_S",
    "ENV_WHITELIST",
    "MAX_JOBS",
    "MAX_RESULT_CHARS",
    "JobRegistry",
    "clamp_wait",
    "declared_roots",
    "decode_stream",
    "dispatch",
    "error",
    "files_list",
    "files_read",
    "files_write",
    "finalise",
    "jobs_kill",
    "jobs_list",
    "jobs_output",
    "jobs_wait",
    "render",
    "resolve_in_roots",
    "shell_run",
]

# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------

#: §5.3 — a tool call must answer within 25 s of wall clock.
CALL_BUDGET_S: Final = 25.0

#: §7 — the confirmation prompt's window.  See :func:`clamp_wait`.
PROMPT_WINDOW_S: Final = 20.0

#: Room for JSON-RPC serialisation, the pipe, and the host's own bookkeeping
#: between this process returning and the core's clock stopping.
TRANSIT_RESERVE_S: Final = 1.5

#: §5.3 — text results are capped at 60,000 characters.
MAX_RESULT_CHARS: Final = 60_000

#: §5.4 — at most 8 concurrent jobs; a ninth is refused.
MAX_JOBS: Final = 8

#: §5.4 — finished jobs are kept 30 minutes.
JOB_RETENTION_S: Final = 30 * 60.0

#: §5.4 — ``wait_s`` defaults to 20 and maxes at 25.
DEFAULT_WAIT_S: Final = 20
MAX_WAIT_S: Final = 25

#: How much of one job's output is held in memory.  A job is not obliged to be
#: polite: ``dir /s C:\`` writes hundreds of megabytes, and an unbounded
#: bytearray in a process with a Job Object memory limit is a crash, not a
#: capture.  Past this the tail is dropped and ``dropped_bytes`` says so.
MAX_CAPTURE_BYTES: Final = 8 * 1024 * 1024

#: §7's always-prompt list, restricted to the tools this plugin owns.  Used
#: only by :func:`clamp_wait` to budget for a prompt this process cannot see;
#: it is **not** a permission decision, which belongs to the gate.
ALWAYS_PROMPT_TOOLS: Final = frozenset({"shell.run", "files.write"})

#: §5.2 codes.
CODE_DENIED: Final = "denied"
CODE_UNKNOWN_JOB: Final = "unknown_job"
CODE_NOT_FOUND: Final = "not_found"
CODE_TIMEOUT: Final = "timeout"
CODE_ERROR: Final = "error"

#: The sentence §5.3 requires on every refusal of untransportable content.
_BINARY_SENTENCE: Final = "binary transfer is not available yet"

#: Mirror of ``mcp_host.supervisor.ENV_WHITELIST``.  Copied rather than
#: imported because importing the supervisor drags pywin32 into every plugin
#: subprocess for one tuple of strings.  ``test_env_whitelist_matches_the_
#: supervisor`` asserts the two are identical, so drift is loud rather than
#: silent.  Children of this plugin get the same 16 variables the plugin got,
#: which is what keeps the network endpoint's bearer token out of reach of
#: anything ``shell.run`` starts: it is not in this process's environment, so
#: it cannot be in a child's.
ENV_WHITELIST: Final[tuple[str, ...]] = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PATHEXT",
    "PATH",
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)

_CREATE_NO_WINDOW: Final = 0x08000000

#: When this process started.  §5.2 wants ``unknown_job`` to name the restart.
STARTED_AT: Final = time.time()


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def iso(epoch: float) -> str:
    """Format *epoch* as ISO-8601 with an offset (§6.1)."""
    return datetime.fromtimestamp(epoch, tz=UTC).astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# §5.2 envelopes, and the one boundary every result leaves through
# ---------------------------------------------------------------------------

# Every constant and function in this block is a copy of the one in
# ``mcp_host/host.py``, kept in step by the parity tests rather than by
# discipline.  Copied and not imported because importing the host drags the
# audit database, the permission gate and pywin32's job-object layer into a
# low-integrity sandbox for a handful of regexes.
#
# The first version of this file transcribed the host's *unfixed* primitives
# and inherited three of the four defects P3 later closed there: the cap
# overshot 60,000 by the length of its own marker, the reason bound landed on
# 301 because the ellipsis was not counted, and credentials were not scrubbed
# at all.  They are fixed here in the same way and the parity tests assert
# agreement, so the next fix to either side cannot land on only one.

#: §5.6's angle-pipe token shape, matched rather than enumerated.
_ANGLE_PIPE_TOKEN: Final = re.compile(r"<\|[^<>|]{0,64}\|>")

#: The bracket-and-tag forms: Llama-2 / Mistral markers and the SentencePiece
#: sentence delimiters.
_BRACKET_TOKEN: Final = re.compile(
    r"\[/?INST\]|\[/?SYS\]|<</?SYS>>|</?s>|<\|?/?im_(?:start|end)\|?>",
    re.IGNORECASE,
)

_STRIP_PASSES: Final = 8

#: What replaces content the stripper could not finish cleaning.
_UNSTRIPPABLE: Final = (
    "[withheld: this output nests chat-template special tokens more deeply than "
    "the Agent unwinds, so it could not be made safe to display]"
)


def strip_special_tokens(text: str) -> str:
    """Remove chat-template special tokens from untrusted content (§5.6).

    Applied to a fixed point, because a single pass is defeated by nesting:
    ``<|im_<|im_start|>start|>`` contains ``<|im_start|>``, and removing the
    inner one leaves a freshly-assembled one behind.

    **Exhausting the pass budget is a refusal, not a partial result.**  The
    budget stops an adversarial input from spinning here; returning the
    half-stripped text on exhaustion would make "I could not finish"
    indistinguishable from "there was nothing to strip".  Text that reached a
    fixed point on the last allowed pass is clean and comes back normally —
    exhaustion alone is not the failure, surviving tokens are.
    """
    if not text:
        return text
    current = text
    for _ in range(_STRIP_PASSES):
        stripped = _BRACKET_TOKEN.sub("", _ANGLE_PIPE_TOKEN.sub("", current))
        if stripped == current:
            return current
        current = stripped
    if _ANGLE_PIPE_TOKEN.search(current) or _BRACKET_TOKEN.search(current):
        log.warning(
            "special-token stripping did not converge in %d passes; withholding content",
            _STRIP_PASSES,
        )
        return _UNSTRIPPABLE
    return current


#: Anything path-shaped.  The drive-letter alternative deliberately does not
#: require a following separator — ``C:secret.txt`` is the drive-relative form
#: and leaks just as much as ``C:\\secret.txt`` — but it does require at least
#: one following non-space character, or it would also eat the bare ``adb:``
#: or ``Authorization:`` that begins many messages, destroying the credential
#: keyword before :data:`_CREDENTIAL_KV` can key on it.
#:
#: An earlier version of this scrubber replaced any *word* containing ``:`` or
#: a separator.  That ate the ISO-8601 timestamp §5.2 requires in an
#: ``unknown_job`` reason, turning the one piece of information the sentence
#: exists to carry into ``<path>``.
_ABS_PATH: Final = re.compile(r"(?:[A-Za-z]:[^\s'\"]+|\\\\[^\s'\"]*|(?<![\w.])/[^\s'\"]*)")

_REASON_LIMIT: Final = 300
_REDACTED: Final = "[redacted]"

#: ``key: value`` / ``key=value`` where the key names a credential.  The value
#: pattern is the rest of the line, not ``\\S+``: a credential key means
#: everything after it on that line is the credential.
_CREDENTIAL_KV: Final = re.compile(
    r"(?i)\b(authorization|auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|bearer|api[-_]?key|apikey|secret|password|passwd|pwd|"
    r"session[-_]?id|cookie|set-cookie|x-api-key)\b\s*[:=]\s*.+",
)

#: A bare ``Bearer <token>`` anywhere in the line.
_BEARER: Final = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")

#: A long run of credential-shaped characters.  Deliberately long (40) so
#: ordinary text survives while a 32-byte token in hex or base64 does not.
_LONG_OPAQUE: Final = re.compile(r"(?<![\w./-])[A-Za-z0-9._~+/=-]{40,}(?![\w./-])")


def sanitise_reason(text: str) -> str:
    """Reduce *text* to one bounded, credential-free, path-free sentence.

    §5.2: "The Agent never returns a stack trace, an absolute path outside a
    declared root, **or the token**."  All three are removed rather than hoped
    for: only the first line survives (a traceback is multi-line), anything
    credential-shaped is replaced, anything path-shaped is replaced, and the
    result is bounded — with the ellipsis counted, so 300 means 300.

    Credentials are scrubbed **before** paths.  Otherwise the path pattern
    consumes the ``Authorization:`` keyword and leaves the credential pattern
    nothing to key on.
    """
    first = str(text).splitlines()[0] if text else ""
    out = _CREDENTIAL_KV.sub(lambda m: f"{m.group(1)}={_REDACTED}", first)
    out = _BEARER.sub(f"Bearer {_REDACTED}", out)
    out = _LONG_OPAQUE.sub(_REDACTED, out)
    out = _ABS_PATH.sub("<path>", out)
    out = strip_special_tokens(out).strip()
    if len(out) > _REASON_LIMIT:
        out = out[: _REASON_LIMIT - 1] + "…"
    return out or "the tool failed without a message"


def error(code: str, reason: str) -> dict[str, Any]:
    """Build a §5.2 failure envelope."""
    return {"ok": False, "code": code, "reason": sanitise_reason(reason)}


def _too_big(size: int, unit: str) -> dict[str, Any]:
    return error(
        CODE_ERROR,
        f"the result is {size} {unit}, over the {MAX_RESULT_CHARS}-character cap, "
        f"so it was not returned; {_BINARY_SENTENCE}",
    )


def render(payload: dict[str, Any]) -> str:
    """Serialise *payload* exactly as it will appear in the result's text block.

    There must be exactly one of these.  An earlier version measured the cap
    against ``separators=(",", ":")`` while ``__main__`` put
    ``separators=(",", ": ")`` on the wire — 5 % longer — so ``finalise``
    approved payloads that ``host._cap_text`` then truncated.  A boundary that
    measures something other than what leaves is not a boundary, so the
    measuring and the emitting are now the same call.

    ``ensure_ascii=False`` keeps a non-ASCII character one character, which is
    what ``host._cap_text`` will count after ``json.loads``; the transport
    escapes it again on the pipe, and that is the transport's business.
    """
    return json.dumps(payload, separators=(",", ": "), ensure_ascii=False)


#: The two halves of an angle-pipe token.  A string carrying one of these but
#: no complete token survives :func:`strip_special_tokens` and can still form a
#: token against its neighbour once the envelope is rendered.
_PARTIAL_MARKER: Final = ("<|", "|>")


def _strip_strings(value: Any) -> Any:  # noqa: ANN401 - any JSON value
    """Apply §5.6 stripping to every string in a JSON-shaped structure."""
    if isinstance(value, str):
        return strip_special_tokens(value)
    if isinstance(value, dict):
        return {k: _strip_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_strings(v) for v in value]
    return value


def _withhold_partial_markers(value: Any) -> Any:  # noqa: ANN401 - any JSON value
    """Replace strings holding half a token, so none can form across fields.

    Only :data:`_ANGLE_PIPE_TOKEN` can splice: it is the one pattern with a
    wildcard body.  Every other form is a literal that JSON's own separators
    keep apart.  So removing the strings that carry ``<|`` or ``|>`` is
    sufficient, and :data:`_UNSTRIPPABLE` contains neither, which makes the
    result a fixed point in one pass rather than a loop that might not settle.
    """
    if isinstance(value, str):
        return _UNSTRIPPABLE if any(m in value for m in _PARTIAL_MARKER) else value
    if isinstance(value, dict):
        return {k: _withhold_partial_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_withhold_partial_markers(v) for v in value]
    return value


def finalise(payload: dict[str, Any]) -> dict[str, Any]:
    """The **only** exit from this plugin.  Refuse what §5.3 says cannot travel.

    Two rules, both of which the host would silently paper over if this
    function did not run first:

    * **Not valid UTF-8.**  A Python ``str`` can hold a lone surrogate — from a
      Windows filename, or from any decoder run with ``surrogateescape`` — and
      ``json.dumps`` will happily emit it as a ``\\udcXX`` escape.  It is not
      encodable as UTF-8, so it is not text, so §5.3 says it does not travel.
      Encoding here is the check; the encoded bytes are then thrown away and
      the transport encodes again.
    * **Over the cap.**  ``host._cap_text`` truncates and appends a marker,
      which is right for a *stream* the caller can page.  §5.3's other
      sentence — a result over the cap is ``ok: false``, ``code: "error"`` —
      is the backstop for a result that is not pageable, and it has to fire
      here because by the time the host sees it, silent truncation is the
      only thing left.

    Note the order: the encode check runs first, so a payload that is both
    binary and enormous is refused as binary, which is the more specific and
    more useful answer.

    §5.6 stripping happens here too, **per field, before rendering**, and that
    is not belt-and-braces.  ``host._conform_text_block`` strips the whole
    serialised envelope, and since P3 its stripper answers "I could not
    converge" by returning :data:`_UNSTRIPPABLE` — a sentence — in place of
    whatever it was given.  For this family that would replace an entire valid
    JSON result with prose, because ``shell.run`` is the tool that hands back
    arbitrary process output.  Stripping each string first means the host's
    pass finds nothing and is a no-op, and a command that prints deeply nested
    markers loses only the field it printed them into.
    """
    payload = _strip_strings(payload)
    text = render(payload)
    if strip_special_tokens(text) != text:
        # A token that exists in neither field but appears once they are
        # rendered next to each other: ``{"stdout": "<|im_", "stderr":
        # "x|>"}`` serialises to a string in which ``_ANGLE_PIPE_TOKEN``
        # matches ACROSS the field boundary, and the host's pass would then
        # delete the JSON structure between them.  A command controls both
        # streams, so this is reachable on purpose, not just by accident.
        payload = _withhold_partial_markers(payload)
        text = render(payload)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return error(
            CODE_ERROR,
            f"the result is {len(text)} characters and is not valid UTF-8, "
            f"so it was not returned; {_BINARY_SENTENCE}",
        )
    if len(text) > MAX_RESULT_CHARS:
        return _too_big(len(text), "characters")
    return payload


# ---------------------------------------------------------------------------
# Decoding what a process or a file produced
# ---------------------------------------------------------------------------

_MAX_UTF8_SEQUENCE: Final = 4


def _is_truncated_utf8(tail: bytes) -> bool:
    """Return True if *tail* is the beginning of a valid UTF-8 sequence.

    The discrimination this whole module turns on: a partial read that stops
    in the middle of a character is **text that we have not finished reading**,
    while a byte that no continuation could complete is **not text**.  Tested
    by padding with continuation bytes: if any padding makes it decode, the
    sequence was merely unfinished.
    """
    if not tail or len(tail) >= _MAX_UTF8_SEQUENCE:
        return False
    for pad in range(1, _MAX_UTF8_SEQUENCE):
        try:
            (tail + b"\x80" * pad).decode("utf-8")
        except UnicodeDecodeError:
            continue
        return True
    return False


def decode_stream(
    raw: bytes,
    *,
    what: str,
    more_follows: bool,
) -> tuple[str, int] | dict[str, Any]:
    """Decode *raw* as UTF-8, or return a §5.3 refusal envelope.

    Returns ``(text, bytes_consumed)`` on success.  ``bytes_consumed`` is what
    the caller must add to ``from_byte`` to resume, and it is **less than**
    ``len(raw)`` only when the read stopped inside a character and more bytes
    follow — the one case where a short decode is honest rather than lossy.

    Args:
        raw: The bytes read from a pipe or a file.
        what: What this is, for the refusal sentence ("the command's stdout").
        more_follows: True when the underlying source has more bytes after
            *raw*.  A truncated trailing sequence is tolerated only then; at
            the end of a file or a finished process there is nothing left to
            complete it with, so an incomplete sequence is corruption.
    """
    try:
        return raw.decode("utf-8"), len(raw)
    except UnicodeDecodeError as exc:
        pass_start = exc.start

    tail = raw[pass_start:]
    if more_follows and _is_truncated_utf8(tail):
        return raw[:pass_start].decode("utf-8"), pass_start

    if pass_start == 0 and raw and 0x80 <= raw[0] <= 0xBF:  # noqa: PLR2004
        # A continuation byte at offset 0 means the caller's from_byte landed
        # inside a character.  Saying "this file is binary" would be a lie
        # about a perfectly good text file, and the caller cannot act on it.
        return error(
            CODE_ERROR,
            f"the requested byte offset is in the middle of a character in {what}; "
            f"resume from the byte offset the previous call reported",
        )
    return error(
        CODE_ERROR,
        f"{what} is {len(raw)} bytes and is not valid UTF-8 at byte {pass_start}, "
        f"so it was not returned; {_BINARY_SENTENCE}",
    )


#: §5.3's trailing marker, as a template.  The rendered marker counts toward
#: the cap it announces — see :func:`_truncate_to`.
_CAP_MARKER: Final = "[... {n} more characters; use jobs_output to page ...]"


def _truncate_to(text: str, limit: int) -> str:
    """Truncate *text* so the result — marker included — is at most *limit*.

    The marker's length depends on the number it reports, which depends on
    where the cut lands, which depends on the marker's length.  Sizing the
    marker for the worst case (``n`` = the whole length) breaks that circle in
    one pass and makes ``len(result) <= limit`` provable: the real ``n`` is
    never larger than the worst case, so the real marker is never longer than
    the one budgeted for.
    """
    if len(text) <= limit:
        return text
    worst = _CAP_MARKER.format(n=len(text))
    if limit <= len(worst):
        return worst[:limit]
    keep = limit - len(worst)
    return text[:keep] + _CAP_MARKER.format(n=len(text) - keep)


def cap_text(text: str) -> str:
    """Apply §5.3's cap to a pageable stream, **marker included**.

    Slicing to 60,000 and *then* appending a ~70-character marker — which is
    what this function did when it was transcribed from the host's unfixed
    copy — yields a 60,070-character result: over the cap it claims to
    enforce, and over the cap ``host.conform_result`` re-applies, which cut
    the marker in half and appended a second one reporting a nonsense
    remainder.  Landing at or under 60,000 makes the host's cap a no-op here.
    """
    return _truncate_to(text, MAX_RESULT_CHARS)


# ---------------------------------------------------------------------------
# Roots
# ---------------------------------------------------------------------------


def _manifest_permissions() -> list[str]:
    toml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin.toml")
    try:
        with open(toml_path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        log.exception("could not read the plugin manifest; no roots are available")
        return []
    perms = data.get("declared_permissions", [])
    return [str(p) for p in perms] if isinstance(perms, list) else []


def declared_roots() -> tuple[tuple[str, str], ...]:
    """The ``path:`` roots from this plugin's own signed manifest.

    Read from the same field the gate reads, so the plugin cannot be confined
    to something different from what was signed.  Absence of any ``path:``
    entry means no path access at all — the same inversion
    ``permissions._outside_declared_paths`` makes, for the same reason.

    Each root is returned twice: the ``normalise_path`` form, which is
    lower-cased and slash-unified and is the **only** form ever compared, and
    the expanded form with its original case, which is what a result shows a
    person.  Comparing case-insensitively is right on Windows; handing back a
    lower-cased path is not, because it stops looking like the folder the
    person sees in Explorer.
    """
    out: list[tuple[str, str]] = []
    for perm in _manifest_permissions():
        if not perm.startswith("path:"):
            continue
        raw = perm[len("path:") :].strip()
        if raw in ("*", "/", "\\"):
            out.append(("/", os.sep))
            continue
        norm = normalise_path(raw)
        if norm and norm != UNINSPECTABLE and is_absolute_path(norm):
            out.append((norm, os.path.normpath(os.path.expanduser(os.path.expandvars(raw)))))
    return tuple(out)


_ROOTS: tuple[tuple[str, str], ...] = ()
_ROOTS_LOCK = threading.Lock()


def roots() -> tuple[str, ...]:
    """The comparison form of every declared root."""
    return tuple(norm for norm, _ in _root_pairs())


def _root_pairs() -> tuple[tuple[str, str], ...]:
    global _ROOTS  # noqa: PLW0603 - one process-lifetime cache, guarded
    with _ROOTS_LOCK:
        if not _ROOTS:
            _ROOTS = declared_roots()
        return _ROOTS


_WRITABLE: list[str | None] = []


def writable_root() -> str | None:
    """The root a low-integrity process can actually write to, if declared.

    Identified by trying, not by pattern-matching the name: whether a folder
    admits a low-integrity write is a property of its mandatory label, and the
    only reliable way to know is to create something there.  Memoised, because
    otherwise every ``shell.run`` without a ``cwd`` would leave a probe file's
    worth of churn in the user's folders.
    """
    with _ROOTS_LOCK:
        if _WRITABLE:
            return _WRITABLE[0]
    found = _probe_writable_root()
    with _ROOTS_LOCK:
        if not _WRITABLE:
            _WRITABLE.append(found)
        return _WRITABLE[0]


def _probe_writable_root() -> str | None:
    for _norm, candidate in _root_pairs():
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, f".wsa-probe-{os.getpid()}")
            with open(probe, "wb"):
                pass
            os.remove(probe)
        except OSError:
            continue
        return candidate
    return None


def resolve_in_roots(raw: object, *, must_exist: bool = False) -> tuple[str, str] | dict[str, Any]:  # noqa: PLR0911 - each return is a distinct refusal with its own sentence
    """Resolve *raw* to ``(real_path, display_path)`` inside a declared root.

    Returns a §5.2 refusal envelope instead if it is outside.  Contract §6 is
    explicit that this is a *denial*, not something a prompt can approve: "all
    of them are confined to the declared roots: a path outside is `denied`".

    Both the lexical form and the ``realpath`` form must be inside a root.
    Requiring the lexical form keeps this in step with the gate; requiring the
    real form is the part the gate cannot do, and is what stops a junction
    inside a root from reaching outside it.
    """
    if not isinstance(raw, str) or not raw.strip():
        return error(CODE_ERROR, "path must be a non-empty string")

    declared = roots()
    if not declared:
        return error(CODE_DENIED, "this plugin declares no folders, so it has no file access")

    lexical = normalise_path(raw)
    if not lexical or lexical == UNINSPECTABLE or not is_absolute_path(lexical):
        return error(
            CODE_DENIED,
            "the path was refused: it must be an absolute path inside the folders "
            "this workstation makes available",
        )
    if not any(_is_within(lexical, root) for root in declared):
        return error(
            CODE_DENIED,
            "the path is outside the folders this workstation makes available, "
            "so it was refused",
        )

    expanded = os.path.expanduser(os.path.expandvars(raw))
    try:
        real = os.path.realpath(expanded)
    except OSError:
        return error(CODE_DENIED, "the path could not be resolved, so it was refused")

    real_norm = normalise_path(real)
    if (
        not real_norm
        or real_norm == UNINSPECTABLE
        or not any(_is_within(real_norm, root) for root in declared)
    ):
        # A link inside a root that points outside it.  The gate's lexical
        # comparison cannot see this; this layer is the only one that can.
        log.warning("refusing a link that resolves outside every declared root")
        return error(
            CODE_DENIED,
            "the path resolves to a location outside the folders this workstation "
            "makes available, so it was refused",
        )

    if must_exist and not os.path.exists(real):
        return error(CODE_NOT_FOUND, "there is no file or folder at that path")
    # The display form is the caller's own path with separators tidied, not
    # `real`: `realpath` would silently substitute a link's target, and a
    # result that names a different file from the one that was asked for is
    # confusing at best.  Both are confined; only one is recognisable.
    return real, os.path.normpath(expanded)


# ---------------------------------------------------------------------------
# The 25 s boundary
# ---------------------------------------------------------------------------


def clamp_wait(
    requested: object,
    tool: str,
    *,
    prompt_s: float | None = None,
) -> float:
    """Return how long this call may actually block (§5.3, §5.4, §7).

    §5.3 gives the whole call 25 s against the core's 30 s read timeout.  For
    ``shell.run`` that 25 s is shared with a §7 confirmation prompt whose
    window is 20 s — and the prompt happens in the **host**, in
    ``host._do_confirm``, before this process is called at all.  The documented
    rule is ``min(wait_s, 25 - prompt_duration)``, and the honest problem is
    that this process cannot observe ``prompt_duration``: the host passes the
    tool's arguments through unchanged and nothing carries the elapsed time.

    So *prompt_s* is an input.  When the host supplies it (as
    ``params._meta.prompt_ms``; see the subtask summary, which asks for that
    host change) it is used exactly.  When it does not, the fallback is the
    only safe one: a tool on §7's always-prompt list is assumed to have spent
    the whole 20 s window, and a tool §7 pre-approves is assumed to have spent
    none.  Guessing low is the failure that matters — a 20 s prompt followed by
    a 20 s wait is 40 s, past the core's 30 s read timeout, and the core sees a
    dead connection instead of the job envelope §5.4 promises.  Guessing high
    costs nothing but an early job handle, which is precisely the shape §5.4
    already defines for work that outlives its wait.

    In practice: ``shell.run`` blocks ~3.5 s then hands back a job, and
    ``jobs.wait`` — pre-approved, never prompted — gets the full ~23.5 s.  That
    is §5.4's intended flow, not a degradation of it.
    """
    # `requested` is whatever arrived over JSON-RPC, including a dict or a
    # list.  `int()` on those raises TypeError; `int("twenty")` raises
    # ValueError; both mean "no usable number", which is what the default is
    # for.  Booleans are ints in Python and `wait_s: true` is meaningless, so
    # they take the default too.
    wanted = DEFAULT_WAIT_S
    if isinstance(requested, (int, float, str)) and not isinstance(requested, bool):
        try:
            wanted = int(requested)
        except (TypeError, ValueError):
            wanted = DEFAULT_WAIT_S
    wanted = max(0, min(wanted, MAX_WAIT_S))

    if prompt_s is None:
        prompt_s = PROMPT_WINDOW_S if tool in ALWAYS_PROMPT_TOOLS else 0.0
    prompt_s = max(0.0, min(float(prompt_s), CALL_BUDGET_S))

    budget = CALL_BUDGET_S - prompt_s - TRANSIT_RESERVE_S
    return max(0.0, min(float(wanted), budget))


# ---------------------------------------------------------------------------
# Jobs (§5.4)
# ---------------------------------------------------------------------------


@dataclass
class Job:
    """One §5.4 job.  In memory; dies with this process, as §5.4 requires."""

    job_id: str
    tool: str
    started: float
    proc: subprocess.Popen[bytes] | None = None
    state: str = "running"
    exit_code: int | None = None
    finished: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    done: threading.Event = field(default_factory=threading.Event)
    combined: bytearray = field(default_factory=bytearray)
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    dropped_bytes: int = 0

    def append(self, which: str, chunk: bytes) -> None:
        """Append *chunk*, dropping the tail past :data:`MAX_CAPTURE_BYTES`."""
        with self.lock:
            room = MAX_CAPTURE_BYTES - len(self.combined)
            if room <= 0:
                self.dropped_bytes += len(chunk)
                return
            keep = chunk[:room]
            self.dropped_bytes += len(chunk) - len(keep)
            self.combined.extend(keep)
            (self.stdout if which == "stdout" else self.stderr).extend(keep)

    def snapshot(self, which: str = "combined") -> bytes:
        with self.lock:
            return bytes(getattr(self, which))

    def descriptor(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "tool": self.tool,
            "state": self.state,
            "started": iso(self.started),
            "finished": None if self.finished is None else iso(self.finished),
        }


class JobRegistry:
    """The in-memory job table.  §5.4: at most 8 running, kept 30 minutes."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def reap(self, *, now: float | None = None) -> None:
        """Drop jobs that finished more than :data:`JOB_RETENTION_S` ago."""
        cutoff = (time.time() if now is None else now) - JOB_RETENTION_S
        with self._lock:
            stale = [
                jid
                for jid, job in self._jobs.items()
                if job.finished is not None and job.finished < cutoff
            ]
            for jid in stale:
                del self._jobs[jid]

    def running(self) -> int:
        with self._lock:
            return sum(1 for job in self._jobs.values() if job.state == "running")

    def add(self, job: Job) -> bool:
        """Register *job* unless 8 are already running (§5.4)."""
        with self._lock:
            if sum(1 for j in self._jobs.values() if j.state == "running") >= MAX_JOBS:
                return False
            self._jobs[job.job_id] = job
            return True

    def get(self, job_id: object) -> Job | None:
        if not isinstance(job_id, str):
            return None
        with self._lock:
            return self._jobs.get(job_id)

    def retire(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)

    def all(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.started)

    def kill_all(self) -> None:
        for job in self.all():
            with contextlib.suppress(Exception):
                _terminate_tree(job)


REGISTRY = JobRegistry()


#: The family that owns a job id.  ``j-shell-<hex>`` here, ``j-adb-<hex>`` in
#: the adb plugin.  Kept in step with the manifest's ``jobs:`` declaration by
#: ``test_the_job_id_prefix_matches_the_manifest``.
JOB_FAMILY: Final = "shell"

#: ``j-<family>-<hex>``.  Recognising the shape is what lets this plugin tell
#: "an id from a family that lives somewhere else" apart from "an id that no
#: longer exists", which §5.2 gives two different codes for.
_JOB_ID_RE: Final = re.compile(r"j-(?P<family>[a-z][a-z0-9_]*)-[0-9a-f]{4,}\Z")


def _unknown_job(job_id: object) -> dict[str, Any]:
    """§5.2's ``unknown_job``, or an honest refusal for someone else's job.

    ``unknown_job`` means "an id from before the Agent last restarted".  Using
    it for an id that belongs to another plugin would tell an operator their
    running job had died, which is both false and undebuggable — the job is
    right there in the next process, doing what they asked.
    """
    if isinstance(job_id, str):
        match = _JOB_ID_RE.match(job_id.strip())
        if match is not None and match.group("family") != JOB_FAMILY:
            other = match.group("family")
            return error(
                CODE_ERROR,
                f"that job belongs to the {other} family, which keeps its own jobs, and "
                f"jobs_wait, jobs_output, jobs_list and jobs_kill only reach {JOB_FAMILY} "
                f"jobs on this workstation; use the {other} family's own tools for it",
            )
    return error(
        CODE_UNKNOWN_JOB,
        f"there is no job {job_id!r}; it may be an id from before the Agent last "
        f"restarted at {iso(STARTED_AT)}",
    )


def _pump(job: Job, which: str, stream: Any) -> None:  # noqa: ANN401 - IO[bytes]
    # `read1`, not `read`.  `BufferedReader.read(n)` blocks until it has all n
    # bytes or the pipe closes, so a job that prints a line and then runs for a
    # minute produces NOTHING for jobs_output until it exits — which defeats
    # the whole point of §5.4's "output: what has been produced so far".
    # `read1` does one underlying read and returns what is there.  The
    # supervisor's low-integrity path hands back an unbuffered raw stream,
    # which has no `read1` and whose `read` is already a single syscall, hence
    # the fallback.
    read = getattr(stream, "read1", None) or stream.read
    try:
        while True:
            chunk = read(65536)
            if not chunk:
                return
            job.append(which, chunk)
    except (OSError, ValueError):  # pragma: no cover - pipe torn down
        return
    finally:
        with contextlib.suppress(Exception):
            stream.close()


def _reap_process(job: Job) -> None:
    proc = job.proc
    if proc is None:  # pragma: no cover - only set for real jobs
        return
    try:
        code = proc.wait()
    except Exception:  # noqa: BLE001 - the job must always reach a final state
        code = None
    with job.lock:
        job.exit_code = code
        job.finished = time.time()
        if job.state != "killed":
            job.state = "done" if code == 0 else "failed"
    job.done.set()


def _terminate_tree(job: Job) -> None:
    """Kill the job's whole process tree (§5.4 ``jobs_kill``).

    ``Popen.kill`` kills the shell and leaves whatever it started behind.  The
    Job Object would collect them when the Agent exits, which is far too late
    for a tool whose contract is "terminates the process tree", so ``taskkill
    /T`` is used first and ``Popen.kill`` is the fallback when it is missing or
    refuses.
    """
    proc = job.proc
    if proc is None or proc.poll() is not None:
        return
    with job.lock:
        job.state = "killed"
    try:
        subprocess.run(
            # taskkill is resolved through the sandbox's own PATH, which is the
            # 16-variable allow-list's copy of the parent's.
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=_CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        log.warning("taskkill unavailable; falling back to a direct kill")
    if proc.poll() is None:
        with contextlib.suppress(Exception):
            proc.kill()


# ---------------------------------------------------------------------------
# shell (§6, §6.1)
# ---------------------------------------------------------------------------


def child_env() -> dict[str, str]:
    """The environment a spawned command gets.

    Rebuilt from :data:`ENV_WHITELIST` rather than inherited wholesale so the
    guarantee holds even when this module is exercised outside the supervisor
    (tests, a developer running the plugin by hand): a child never sees more
    than the sixteen variables the sandbox allows, and the network endpoint's
    bearer token is in none of them.
    """
    return {name: os.environ[name] for name in ENV_WHITELIST if name in os.environ}


def _build_argv(command: str, shell: str) -> list[str] | dict[str, Any]:
    if shell == "cmd":
        comspec = os.environ.get("COMSPEC") or "cmd.exe"
        return [comspec, "/d", "/c", command]
    if shell == "powershell":
        return [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]
    return error(CODE_ERROR, "shell must be 'powershell' or 'cmd'")


def _finished_shell_result(job: Job, started: float) -> dict[str, Any]:
    """The §6.1 ``shell_run`` shape for a command that finished in time."""
    out: dict[str, str] = {}
    for which, label in (("stdout", "the command's stdout"), ("stderr", "the command's stderr")):
        decoded = decode_stream(job.snapshot(which), what=label, more_follows=False)
        if isinstance(decoded, dict):
            return decoded
        text, _ = decoded
        out[which] = cap_text(text)
    return {
        "ok": True,
        "job_id": None,
        "exit_code": job.exit_code,
        "stdout": out["stdout"],
        "stderr": out["stderr"],
        "duration_s": round(time.time() - started, 3),
    }


def _running_shell_result(job: Job) -> dict[str, Any]:
    """The §5.4 shape for a command that outlived its wait."""
    raw = job.snapshot()
    decoded = decode_stream(raw, what="the command's output", more_follows=True)
    if isinstance(decoded, dict):
        # The output so far is not text.  The job keeps running and keeps
        # being killable, but nothing from it travels: §5.3 has no "partly
        # binary" state.  jobs_kill still works, which is the important part.
        decoded["job_id"] = job.job_id
        return decoded
    text, consumed = decoded
    capped = cap_text(text)
    return {
        "ok": True,
        "job_id": job.job_id,
        "state": job.state,
        "output": capped,
        "output_bytes": consumed,
    }


def _shell_plan(args: dict[str, Any]) -> tuple[list[str], str, str] | dict[str, Any]:  # noqa: PLR0911 - each return is a distinct refusal with its own sentence
    """Validate ``shell_run``'s arguments into ``(argv, cwd, shell)``."""
    command = args.get("command")
    if not isinstance(command, str) or not command.strip():
        return error(CODE_ERROR, "command must be a non-empty string")

    shell = args.get("shell") or "powershell"
    if not isinstance(shell, str):
        return error(CODE_ERROR, "shell must be 'powershell' or 'cmd'")
    argv = _build_argv(command, shell.lower())
    if isinstance(argv, dict):
        return argv

    raw_cwd = args.get("cwd")
    if raw_cwd is None:
        default = writable_root()
        if default is None:
            return error(CODE_ERROR, "this plugin has no folder it can run a command in")
        return argv, default, shell

    resolved = resolve_in_roots(raw_cwd, must_exist=True)
    if isinstance(resolved, dict):
        return resolved
    if not os.path.isdir(resolved[0]):
        return error(CODE_NOT_FOUND, "the working directory does not exist")
    return argv, resolved[0], shell


def shell_run(args: dict[str, Any], *, prompt_s: float | None = None) -> dict[str, Any]:
    """``shell_run(command, cwd?, shell="powershell"|"cmd", wait_s?)`` — §6, §6.1."""
    plan = _shell_plan(args)
    if isinstance(plan, dict):
        return plan
    argv, cwd, shell = plan

    wait_s = clamp_wait(args.get("wait_s"), "shell.run", prompt_s=prompt_s)

    REGISTRY.reap()
    # 64 bits, not the contract example's four hex digits.  A job id is the
    # only thing separating one caller's job from another's — see "Jobs are
    # per-plugin, not per-caller" above — so it must not be guessable.  It is a
    # mitigation, not isolation.
    job = Job(
        job_id=f"j-{JOB_FAMILY}-{uuid.uuid4().hex[:16]}",
        tool="shell.run",
        started=time.time(),
    )
    if not REGISTRY.add(job):
        return error(
            CODE_ERROR,
            f"{MAX_JOBS} jobs are already running on this workstation, which is the "
            f"limit; wait for one to finish or stop one with jobs_kill",
        )

    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=child_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        REGISTRY.retire(job.job_id)
        return error(CODE_NOT_FOUND, f"the {shell} interpreter was not found on this workstation")
    except OSError:
        REGISTRY.retire(job.job_id)
        log.exception("failed to start a command")
        return error(CODE_ERROR, "the command could not be started on this workstation")

    job.proc = proc
    for which, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
        threading.Thread(
            target=_pump, args=(job, which, stream), name=f"{job.job_id}-{which}", daemon=True,
        ).start()
    threading.Thread(
        target=_reap_process, args=(job,), name=f"{job.job_id}-wait", daemon=True,
    ).start()

    if job.done.wait(timeout=wait_s):
        result = _finished_shell_result(job, job.started)
        # The caller never learned this id, so leaving it in the table would
        # only put an unreachable row in jobs_list.  §5.4's thirty-minute
        # retention is for jobs a caller was handed.
        REGISTRY.retire(job.job_id)
        return result
    return _running_shell_result(job)


# ---------------------------------------------------------------------------
# files (§6, §6.1)
# ---------------------------------------------------------------------------


def _coerce_offset(value: object, default: int) -> int | dict[str, Any]:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        return error(CODE_ERROR, "byte offsets must be whole numbers")
    if value < 0:
        return error(CODE_ERROR, "byte offsets cannot be negative")
    return value


def _coerce_max_bytes(value: object) -> int | dict[str, Any]:
    if value is None:
        return MAX_RESULT_CHARS
    if isinstance(value, bool) or not isinstance(value, int):
        return error(CODE_ERROR, "max_bytes must be a whole number")
    if value < 1:
        return error(CODE_ERROR, "max_bytes must be at least 1")
    # Clamped rather than refused: `truncated` and `total_bytes` in the result
    # tell the caller exactly what it got, so nothing is hidden by clamping,
    # and a caller that asked for too much gets data instead of an error.
    return min(value, MAX_RESULT_CHARS)


def _scan(real: str) -> Iterator[os.DirEntry[str]]:
    with os.scandir(real) as it:
        yield from sorted(it, key=lambda e: e.name)


def _list_entries(real: str) -> tuple[list[dict[str, Any]], int]:
    """Return ``(entries, skipped)`` for one directory."""
    entries: list[dict[str, Any]] = []
    skipped = 0
    for entry in _scan(real):
        try:
            entry.name.encode("utf-8")
        except UnicodeEncodeError:
            # A Windows filename may contain an unpaired surrogate, which is
            # not UTF-8 and so cannot travel (§5.3).  Dropping the one entry
            # and saying so beats refusing the whole listing, and beats
            # mangling a name that would then not be a valid path.
            skipped += 1
            continue
        try:
            stat = entry.stat()
            is_dir = entry.is_dir()
        except OSError:
            skipped += 1
            continue
        entries.append({
            "name": entry.name,
            "kind": "dir" if is_dir else "file",
            "size": 0 if is_dir else stat.st_size,
            "modified": iso(stat.st_mtime),
        })
    return entries, skipped


def files_list(args: dict[str, Any]) -> dict[str, Any]:
    """``files_list(path)`` — §6.1's ``{"ok", "path", "entries"}``."""
    resolved = resolve_in_roots(args.get("path"), must_exist=True)
    if isinstance(resolved, dict):
        return resolved
    real, display = resolved
    if not os.path.isdir(real):
        return error(CODE_ERROR, "that path is a file, not a folder")

    try:
        entries, skipped = _list_entries(real)
    except PermissionError:
        return error(CODE_DENIED, "this workstation would not let the Agent read that folder")
    except OSError:
        log.exception("files_list failed")
        return error(CODE_ERROR, "that folder could not be listed on this workstation")

    payload: dict[str, Any] = {"ok": True, "path": display, "entries": entries}
    if skipped:
        payload["skipped_entries"] = skipped
    # A directory listing has no from_byte to page with, so it is bounded here
    # rather than refused wholesale by finalise().
    truncated = False
    while len(render(payload)) > MAX_RESULT_CHARS:
        if not entries:  # pragma: no cover - a single entry cannot reach the cap
            return _too_big(MAX_RESULT_CHARS, "characters")
        entries.pop()
        truncated = True
    if truncated:
        payload["truncated"] = True
    return payload


def files_read(args: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 - each return is a distinct refusal with its own sentence
    """``files_read(path, from_byte?, max_bytes?)`` — §6.1, including its bounds."""
    resolved = resolve_in_roots(args.get("path"), must_exist=True)
    if isinstance(resolved, dict):
        return resolved
    real, display = resolved
    if os.path.isdir(real):
        return error(CODE_ERROR, "that path is a folder, not a file")

    from_byte = _coerce_offset(args.get("from_byte"), 0)
    if isinstance(from_byte, dict):
        return from_byte
    max_bytes = _coerce_max_bytes(args.get("max_bytes"))
    if isinstance(max_bytes, dict):
        return max_bytes

    try:
        total = os.path.getsize(real)
        if from_byte >= total:
            # §6.1's bounds rule: past the end is ok:true with nothing in it
            # and the real total, never an error.
            return {
                "ok": True,
                "path": display,
                "from_byte": from_byte,
                "bytes": 0,
                "total_bytes": total,
                "content": "",
                "truncated": False,
            }
        with open(real, "rb") as fh:
            fh.seek(from_byte)
            raw = fh.read(max_bytes)
    except FileNotFoundError:
        return error(CODE_NOT_FOUND, "there is no file at that path")
    except PermissionError:
        return error(CODE_DENIED, "this workstation would not let the Agent read that file")
    except OSError:
        log.exception("files_read failed")
        return error(CODE_ERROR, "that file could not be read on this workstation")

    more = from_byte + len(raw) < total
    decoded = decode_stream(raw, what="that file", more_follows=more)
    if isinstance(decoded, dict):
        return decoded
    content, consumed = decoded
    return {
        "ok": True,
        "path": display,
        "from_byte": from_byte,
        "bytes": consumed,
        "total_bytes": total,
        "content": content,
        "truncated": from_byte + consumed < total,
    }


def files_write(args: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 - each return is a distinct refusal with its own sentence
    """``files_write(path, content, append?)`` — §6.

    §6.1 pins no shape for this one, so the keys mirror ``files_read``'s.
    """
    content = args.get("content")
    if not isinstance(content, str):
        return error(CODE_ERROR, "content must be text")
    try:
        payload = content.encode("utf-8")
    except UnicodeEncodeError:
        return error(
            CODE_ERROR,
            f"the content is not valid UTF-8, so it was not written; {_BINARY_SENTENCE}",
        )

    append = args.get("append")
    if append is None:
        append = False
    if not isinstance(append, bool):
        return error(CODE_ERROR, "append must be true or false")

    resolved = resolve_in_roots(args.get("path"))
    if isinstance(resolved, dict):
        return resolved
    real, display = resolved
    if os.path.isdir(real):
        return error(CODE_ERROR, "that path is a folder, not a file")

    try:
        parent = os.path.dirname(real)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(real, "ab" if append else "wb") as fh:
            fh.write(payload)
        total = os.path.getsize(real)
    except PermissionError:
        # The single most likely real-hardware failure here, and an errno tells
        # nobody anything.  Plugins run with a low-integrity token, which may
        # read almost anywhere and write almost nowhere.
        return error(
            CODE_DENIED,
            "the file could not be written: the Agent's plugins run at low integrity "
            "and that folder does not allow it. Write to the Agent's own folder "
            "instead, which does",
        )
    except OSError:
        log.exception("files_write failed")
        return error(CODE_ERROR, "that file could not be written on this workstation")

    return {
        "ok": True,
        "path": display,
        "bytes": len(payload),
        "total_bytes": total,
        "append": append,
    }


# ---------------------------------------------------------------------------
# jobs (§5.4, §6.1)
# ---------------------------------------------------------------------------


def _job_output_payload(
    job: Job,
    from_byte: int,
    max_bytes: int,
) -> dict[str, Any]:
    raw = job.snapshot()
    total = len(raw)
    if from_byte >= total:
        # §6.1's bounds rule, the same as files_read's.
        return {
            "ok": True,
            "job_id": job.job_id,
            "state": job.state,
            "exit_code": job.exit_code,
            "output": "",
            "from_byte": from_byte,
            "bytes": 0,
            "total_bytes": total,
            "truncated": False,
        }
    window = raw[from_byte : from_byte + max_bytes]
    more = from_byte + len(window) < total or job.state == "running"
    decoded = decode_stream(window, what="the job's output", more_follows=more)
    if isinstance(decoded, dict):
        decoded["job_id"] = job.job_id
        return decoded
    text, consumed = decoded
    payload: dict[str, Any] = {
        "ok": True,
        "job_id": job.job_id,
        "state": job.state,
        "exit_code": job.exit_code,
        "output": text,
        "from_byte": from_byte,
        "bytes": consumed,
        "total_bytes": total,
        "truncated": from_byte + consumed < total,
    }
    if job.dropped_bytes:
        payload["dropped_bytes"] = job.dropped_bytes
    return payload


def jobs_wait(args: dict[str, Any], *, prompt_s: float | None = None) -> dict[str, Any]:
    """``jobs_wait(job_id, wait_s ≤ 25)`` — §5.4."""
    REGISTRY.reap()
    job = REGISTRY.get(args.get("job_id"))
    if job is None:
        return _unknown_job(args.get("job_id"))
    job.done.wait(timeout=clamp_wait(args.get("wait_s"), "jobs.wait", prompt_s=prompt_s))
    return _job_output_payload(job, 0, MAX_RESULT_CHARS)


def jobs_output(args: dict[str, Any]) -> dict[str, Any]:
    """``jobs_output(job_id, from_byte, max_bytes ≤ 60000)`` — §5.4."""
    REGISTRY.reap()
    job = REGISTRY.get(args.get("job_id"))
    if job is None:
        return _unknown_job(args.get("job_id"))
    from_byte = _coerce_offset(args.get("from_byte"), 0)
    if isinstance(from_byte, dict):
        return from_byte
    max_bytes = _coerce_max_bytes(args.get("max_bytes"))
    if isinstance(max_bytes, dict):
        return max_bytes
    return _job_output_payload(job, from_byte, max_bytes)


def jobs_list(_args: dict[str, Any]) -> dict[str, Any]:
    """``jobs_list()`` — running jobs and those that finished in the last 30 min.

    ``scope`` is an extra key (§6.1 allows them) and it is not decoration: this
    plugin can only see its own jobs, and a bare list would read as "these are
    all the jobs on this workstation".  Naming what was searched is the
    difference between a partial answer and a wrong one.
    """
    REGISTRY.reap()
    return {
        "ok": True,
        "jobs": [job.descriptor() for job in REGISTRY.all()],
        "scope": [JOB_FAMILY],
    }


def jobs_kill(args: dict[str, Any]) -> dict[str, Any]:
    """``jobs_kill(job_id)`` — terminates the process tree (§5.4)."""
    REGISTRY.reap()
    job = REGISTRY.get(args.get("job_id"))
    if job is None:
        return _unknown_job(args.get("job_id"))
    if job.state != "running":
        return {"ok": True, "job_id": job.job_id, "state": job.state, "exit_code": job.exit_code}
    _terminate_tree(job)
    job.done.wait(timeout=5.0)
    with job.lock:
        job.state = "killed"
        if job.finished is None:
            job.finished = time.time()
    return {"ok": True, "job_id": job.job_id, "state": "killed", "exit_code": job.exit_code}


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

#: The contract's internal ``family.verb`` names (``network_mcp/tools.py``'s
#: ``internal_name``).  These, not the ``family_verb`` wire spellings, are what
#: ``host.invoke`` resolves and what the manifest's ``args:`` entries name.
_HANDLERS: Final[dict[str, Any]] = {
    "shell.run": shell_run,
    "files.list": files_list,
    "files.read": files_read,
    "files.write": files_write,
    "jobs.wait": jobs_wait,
    "jobs.output": jobs_output,
    "jobs.list": jobs_list,
    "jobs.kill": jobs_kill,
}

#: The two verbs that block, and so are the two that take the prompt duration
#: :func:`clamp_wait` budgets against.
_BLOCKING_TOOLS: Final = frozenset({"shell.run", "jobs.wait"})

TOOL_NAMES: Final[tuple[str, ...]] = tuple(_HANDLERS)


def dispatch(tool: str, args: dict[str, Any], *, prompt_s: float | None = None) -> dict[str, Any]:
    """Run *tool* and return a §5.2 envelope that has passed :func:`finalise`.

    Every exception becomes an envelope here.  §5.2 forbids returning a stack
    trace, so the traceback goes to this process's stderr — which the
    supervisor pumps into the Agent's log, where an operator can read it — and
    the model gets a sentence.  The exception's *message* is deliberately not
    interpolated: an OSError's message carries a filename, and a filename in a
    ``reason`` is the leak §5.2 names.
    """
    if not isinstance(args, dict):
        return finalise(error(CODE_ERROR, "arguments must be an object"))
    handler = _HANDLERS.get(tool)
    if handler is None:
        return finalise(error(CODE_NOT_FOUND, f"there is no tool called {tool!r} in this plugin"))
    try:
        if tool in _BLOCKING_TOOLS:
            return finalise(handler(args, prompt_s=prompt_s))
        return finalise(handler(args))
    except Exception:
        log.exception("tool=%s raised", tool)
        print(f"[{tool}] raised; see the Agent log", file=sys.stderr)  # noqa: T201
        return finalise(error(CODE_ERROR, "the tool failed on this workstation"))
