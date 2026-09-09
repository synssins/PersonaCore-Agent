"""The ``adb`` family — Android Debug Bridge over a subprocess (contract §6).

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

Six tools, all of them ``adb.exe`` invocations: :func:`adb_devices`,
:func:`adb_shell` (job-capable, §5.4), :func:`adb_push`, :func:`adb_pull`
(text-only in v1, §10), :func:`adb_install` and :func:`adb_logcat`.

Three things about this family are not obvious and are the reason most of the
code below exists.

**The gate's argument classes split down the middle of this family.**  A phone
path and a phone command are ``foreign``: comparing ``/sdcard/DCIM/x.jpg``
against a Windows root never matches, so declaring it ``ws_path`` denies every
legitimate call.  But ``adb_push`` and ``adb_install`` read a file *from this
workstation*, and §6 says their local path is confined to the declared roots
exactly as ``files_read`` is — so ``workstation_path`` is ``ws_path`` and the
manifest deliberately lists **no** ``confirmable_conditions``, which leaves
``outside_declared_paths`` as a hard guard and makes an out-of-roots push a
``denied``, not a prompt.  See ``plugin.toml``.

**The sandbox fights ADB.**  The plugin runs at low integrity, inside a Job
Object with an active-process limit, with a 16-variable environment whitelist
that does not include anything ADB-specific.  ``adb`` forks a persistent server
process, so one tool call can cost two process slots; ADB also wants to write an
RSA key under ``%USERPROFILE%\\.android``, which a low-integrity process cannot
do.  :data:`_MAX_CONCURRENT_ADB` bounds the first and :func:`resolve_adb_home`
fixes the second by pointing ADB at a directory we can prove is writable.

**Result sanitisation is this family's own job.**  ``adb_logcat`` streams
Android system logs, which carry crash stack traces and authorisation tokens
from logged requests by design.  Those are on the contract's forbidden list, so
they are removed here (:func:`redact_log_text`) rather than relayed.  Every
result also goes through the §5.3 UTF-8 and 60,000-character rules and §5.6
special-token stripping.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

__all__ = [
    "MAX_RESULT_CHARS",
    "AdbNotFoundError",
    "AdbRun",
    "adb_device_rows",
    "adb_devices",
    "adb_install",
    "adb_logcat",
    "adb_pull",
    "adb_push",
    "adb_shell",
    "decode_output",
    "fit_envelope",
    "redact_log_text",
    "resolve_adb_home",
    "resolve_adb_path",
    "sanitise_reason",
    "sanitise_text",
    "strip_special_tokens",
]


# ---------------------------------------------------------------------------
# §5.2 codes
# ---------------------------------------------------------------------------

CODE_NOT_FOUND = "not_found"
CODE_TIMEOUT = "timeout"
CODE_ERROR = "error"


def failure(code: str, reason: str) -> dict[str, Any]:
    """Build a §5.2 failure envelope with the reason already sanitised."""
    return {"ok": False, "code": code, "reason": sanitise_reason(reason)}


# ---------------------------------------------------------------------------
# §5.3 / §5.6 — result sanitisation, owned by this family
# ---------------------------------------------------------------------------
#
# Deliberately a local copy rather than an import of ``mcp_host.host``: this
# runs in a separate low-integrity process, importing the host would drag the
# audit database, the permission gate and pywin32's job-object layer into the
# sandbox, and only ``__init__.py`` and ``__main__.py`` are covered by the
# plugin signature (``loader._resolve_module_paths``), so a sibling module
# would be unsigned code enforcing a security control.  The plan is explicit
# that "each family owns the check for its own tools".  A parity test drives
# this copy, the ``devices`` copy and the host's through one corpus.

#: §5.3 — text results are capped by the Agent at 60,000 characters.
MAX_RESULT_CHARS = 60_000

_ANGLE_PIPE_TOKEN = re.compile(r"<\|[^<>|]{0,64}\|>")
_BRACKET_TOKEN = re.compile(
    r"\[/?INST\]|\[/?SYS\]|<</?SYS>>|</?s>|<\|?/?im_(?:start|end)\|?>",
    re.IGNORECASE,
)
_STRIP_PASSES = 8

#: Anything path-shaped.  The drive-letter alternative deliberately does not
#: require a following *separator* — ``C:secret.txt`` is the drive-relative
#: form and leaks just as much as ``C:\secret.txt`` — but it does require at
#: least one following non-space character.  Without that it also matched the
#: bare ``adb:`` and ``Authorization:`` that begin most of this family's
#: messages, turning "adb: failed to install" into "ad<path> failed to
#: install" and, worse, destroying the credential keyword before
#: :data:`_CREDENTIAL_KV` could key on it.  A drive-relative path never has a
#: space after the colon; a prose label always does.
_ABS_PATH = re.compile(r"(?:[A-Za-z]:[^\s'\"]+|\\\\[^\s'\"]*|(?<![\w.])/[^\s'\"]*)")

_REASON_LIMIT = 300


#: What replaces content the stripper could not finish cleaning.  A refusal,
#: not a best effort: see :func:`strip_special_tokens`.
_UNSTRIPPABLE = (
    "[withheld: this output nests chat-template special tokens more deeply than "
    "the Agent unwinds, so it could not be made safe to display]"
)

#: §5.3's trailing marker, as a template.  The rendered marker counts toward
#: the cap it announces — see :func:`_truncate_to`.
_CAP_MARKER = "[... {n} more characters; use jobs_output to page ...]"


def strip_special_tokens(text: str) -> str:
    """Remove chat-template special tokens from untrusted content (§5.6).

    Applied to a fixed point rather than in one pass: ``<|im_<|im_start|>start|>``
    reassembles into a fresh ``<|im_start|>`` when the inner token is removed.

    **Exhausting the pass budget is a refusal, not a partial result.**  The
    loop is bounded because each pass only deletes, so an unbounded version
    terminates but takes O(n) passes over an O(n) string — a 60,000-character
    adversarial input would spin here, which is a denial of service traded for
    a completeness nobody needs (no legitimate device output nests these eight
    deep).  Returning the partially-stripped text on exhaustion, though, makes
    "I could not finish" indistinguishable from "there was nothing to strip",
    and the caller cannot tell the difference.  So the budget is kept and the
    result is *checked*: if tokens genuinely survive, the content is withheld
    and the reason says so.  Text that reached a fixed point on the last
    allowed pass is clean and is returned normally — exhaustion alone is not
    the failure, surviving tokens are.
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


def _truncate_to(text: str, limit: int) -> str:
    """Truncate *text* so the result — marker included — is at most *limit*.

    The marker's length depends on the number it reports, which depends on
    where the cut lands, which depends on the marker's length.  Sizing the
    marker for the worst case (``n`` = the whole length) breaks that circle in
    a single pass and makes ``len(result) <= limit`` provable rather than
    approximate: the real ``n`` is never larger than the worst case, so the
    real marker is never longer than the one budgeted for.
    """
    if len(text) <= limit:
        return text
    worst = _CAP_MARKER.format(n=len(text))
    if limit <= len(worst):
        # No room for text and marker both.  The marker is the more useful of
        # the two — it says the content was cut — but it must still fit.
        return worst[:limit]
    keep = limit - len(worst)
    return text[:keep] + _CAP_MARKER.format(n=len(text) - keep)


def cap_text(text: str) -> str:
    """Apply §5.3's 60,000-character cap, **marker included**.

    The marker counts toward the cap.  Slicing to 60,000 and *then* appending
    a ~70-character marker yields a 60,070-character result — over the cap it
    claims to enforce, and over the host's cap too, so ``conform_result``
    re-caps the string, cuts this marker in half and appends a second one
    reporting a nonsense remainder.  Landing at or under 60,000 means the
    transport's cap never fires on this family's output at all.
    """
    return _truncate_to(text, MAX_RESULT_CHARS)


def sanitise_text(text: str) -> str:
    """Strip §5.6 tokens then apply the §5.3 cap, in that order.

    Order matters: capping first could cut a special token in half and leave a
    fragment the stripper no longer recognises.
    """
    return cap_text(strip_special_tokens(text))


#: Room fit_envelope keeps free for the note it adds after dropping rows, so
#: adding that note cannot itself push the envelope back over the cap.
_NOTE_RESERVE = 240


def fit_envelope(result: dict[str, Any]) -> dict[str, Any]:
    """Make the *rendered* result fit §5.3's cap, or refuse.

    §5.2 renders a result as "a JSON object rendered as text" and §5.3 caps
    that text.  Capping a field is therefore not enough: the JSON wrapper
    pushes the rendered object past the cap, the host's cap fires on the
    serialised string, and the model receives truncated — that is,
    syntactically invalid — JSON.

    Two payload shapes have to be handled, because these families produce
    both.  A long **string** (shell stdout, a captured log) is truncated with
    §5.3's marker.  A long **list** (``devices_list``'s ``usb``/``adb``/``com``
    rows) contains no string to truncate at all, so rows are dropped from the
    end and a note says how many — an earlier version collected only top-level
    strings and silently returned an oversized envelope for exactly that
    shape.  An envelope still too large after both, with nothing left to
    shrink, is **refused**: returning something already measured as too large
    is the one outcome with no honest reading downstream.
    """
    serialised = json.dumps(result, separators=(",", ":"))
    if len(serialised) <= MAX_RESULT_CHARS:
        return result

    trimmed = dict(result)

    # 1. The longest top-level string, sized against the rest of the envelope.
    text_keys = [k for k, v in trimmed.items() if isinstance(v, str)]
    if text_keys:
        longest = max(text_keys, key=lambda k: len(trimmed[k]))
        # Set the flag BEFORE measuring.  It is part of the envelope the text
        # has to fit inside, and measuring without it left the result 17
        # characters over -- whereupon there was no list to shrink either and
        # a payload that had just been truncated successfully was refused.
        # Measured with the same json.dumps flags __main__ serialises with, so
        # this counts the characters that actually go on the wire.
        trimmed["truncated"] = True
        overhead = (
            len(json.dumps(trimmed, separators=(",", ":"))) - len(trimmed[longest])
        )
        trimmed[longest] = _truncate_to(
            trimmed[longest], max(0, MAX_RESULT_CHARS - overhead),
        )
        serialised = json.dumps(trimmed, separators=(",", ":"))
        if len(serialised) <= MAX_RESULT_CHARS:
            return trimmed

    # 2. Rows, dropped from the end of whichever list is longest.  A tenth at
    #    a time: one row per pass would take thousands of re-serialisations on
    #    the list sizes that reach this branch at all.  ``notes`` is excluded —
    #    it is the key that explains the trimming, so trimming it away first
    #    would delete the explanation and keep the data.
    dropped = 0
    target = MAX_RESULT_CHARS - _NOTE_RESERVE
    while len(serialised) > target:
        list_keys = [
            k for k, v in trimmed.items() if isinstance(v, list) and v and k != "notes"
        ]
        if not list_keys:
            break
        longest = max(list_keys, key=lambda k: len(trimmed[k]))
        rows = trimmed[longest]
        keep = max(0, len(rows) - max(1, len(rows) // 10))
        trimmed[longest] = rows[:keep]
        dropped += len(rows) - keep
        trimmed["truncated"] = True
        serialised = json.dumps(trimmed, separators=(",", ":"))

    if dropped:
        note = (
            f"{dropped} entries were left out: the full list is over the "
            f"60,000-character limit."
        )
        trimmed["notes"] = [*(trimmed.get("notes") or []), note]
        serialised = json.dumps(trimmed, separators=(",", ":"))

    if len(serialised) > MAX_RESULT_CHARS:
        return {
            "ok": False,
            "code": "error",
            "reason": (
                f"This result is {len(serialised)} characters, over the "
                f"60,000-character limit, and could not be shortened; "
                f"binary transfer is not available yet."
            ),
        }
    return trimmed


def sanitise_reason(text: str) -> str:
    """Make an arbitrary message safe to use as a §5.2 ``reason``.

    §5.2: the Agent never returns a stack trace, an absolute path outside a
    declared root, **or the token**.  A traceback is multi-line, so only the
    first line survives; anything path-shaped is replaced; anything
    credential-shaped is replaced with the same patterns ``adb_logcat`` uses;
    the result is bounded.
    """
    first_line = str(text).splitlines()[0] if text else ""
    # Credentials BEFORE paths.  The forbidden list's third item is "or the
    # token", and an exception message is untrusted content like any other:
    # `adb` echoes the command it was running, and a command can carry a
    # credential.  Same patterns the logcat redactor uses, so there is one
    # place to keep them correct.  Order matters: the path pattern would
    # otherwise consume the "Authorization:" keyword and leave the credential
    # regex nothing to key on.  Nothing leaks by going in this order — a
    # credential value containing a path is replaced wholesale.
    redacted = _CREDENTIAL_KV.sub(lambda m: f"{m.group(1)}={_REDACTED}", first_line)
    redacted = _BEARER.sub(f"Bearer {_REDACTED}", redacted)
    redacted = _LONG_OPAQUE.sub(_REDACTED, redacted)
    redacted = _ABS_PATH.sub("<path>", redacted)
    redacted = strip_special_tokens(redacted)
    if len(redacted) > _REASON_LIMIT:
        # The ellipsis counts, exactly as the cap marker does in _truncate_to.
        redacted = redacted[: _REASON_LIMIT - 1] + "…"
    return redacted or "the tool failed without a message"


def decode_output(raw: bytes, *, what: str) -> tuple[str | None, dict[str, Any] | None]:
    """Decode subprocess output as strict UTF-8, or return a §5.3 refusal.

    Returns ``(text, None)`` on success and ``(None, failure_envelope)`` when
    the bytes are not valid UTF-8.  §5.3: "Binary never travels in v1. A file
    result over the cap or not valid UTF-8 is ``ok: false``, ``code: "error"``,
    ``reason`` giving the size and 'binary transfer is not available yet'."

    ``errors="replace"`` is specifically *not* used.  Mangling binary into
    U+FFFD would hand the model something that looks like text, reads like
    nonsense and cannot be told apart from a device that really printed
    replacement characters — which is how "binary never travels" quietly stops
    being true.
    """
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, failure(
            CODE_ERROR,
            f"{what} produced {len(raw)} bytes that are not valid UTF-8; "
            f"binary transfer is not available yet.",
        )


# ---------------------------------------------------------------------------
# Logcat redaction — stack traces and credentials never leave the workstation
# ---------------------------------------------------------------------------

_REDACTED = "[redacted]"

#: Lines that are part of a Java/Kotlin/ART stack trace.  Android crash dumps
#: are exactly what the contract's forbidden list names, and logcat carries
#: them by design, so the frames go and a marker stays: the operator can still
#: see *that* something crashed and which exception it was is deliberately kept
#: only as far as the type name, which is diagnosis without the trace.
_STACK_LINE = re.compile(
    r"""^\s*(?:
          at\s+[\w$.<>\[\]]+\(.*\)          # at com.foo.Bar.baz(Bar.java:12)
        | Caused\s+by:\s.*                   # Caused by: java.lang.Foo: ...
        | \.{3}\s+\d+\s+more\s*$             # ... 7 more
        | \#\d{2}\s+pc\s+.*                  # native backtrace frame
        | backtrace:\s*$
        | \s*native:\s+\#\d+.*
    )\s*$""",
    re.VERBOSE,
)

#: ``key: value`` / ``key=value`` where the key names a credential.
#:
#: The value pattern is "the rest of the line", not ``\S+``.  With ``\S+`` the
#: line ``Authorization: Bearer eyJhbGci….verysecret`` matched only the word
#: ``Bearer`` — the key's "value" — and left the token itself sitting in the
#: output, where no later pattern looked at it again (it is under the 40-char
#: floor :data:`_LONG_OPAQUE` needs, and the ``bearer`` keyword had already
#: been consumed).  A credential key means everything after it on that line is
#: the credential.
_CREDENTIAL_KV = re.compile(
    r"(?i)\b(authorization|auth[-_]?token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|bearer|api[-_]?key|apikey|secret|password|passwd|pwd|"
    r"session[-_]?id|cookie|set-cookie|x-api-key)\b\s*[:=]\s*.+",
)

#: A bare ``Bearer <token>`` anywhere in the line.
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")

#: A long run of credential-shaped characters with no spaces.  Deliberately
#: long (40) so ordinary logcat — package names, class names, hashes of a
#: dozen characters — survives, while a 32-byte token rendered as hex (64
#: chars) or base64 (43 chars) does not.
_LONG_OPAQUE = re.compile(r"(?<![\w./-])[A-Za-z0-9._~+/=-]{40,}(?![\w./-])")


def redact_log_text(text: str) -> tuple[str, int]:
    """Remove stack traces and credential-shaped strings from log output.

    Returns the redacted text and how many redactions were made, so the caller
    can put the count in the result: an operator who sees ``"redacted": 0``
    knows nothing was removed, and one who sees ``"redacted": 41`` knows to go
    and look at the device directly.  Silent redaction would be worse than none
    — it would make a truncated log look complete.

    **This is best-effort, not a control, and nothing downstream may treat a
    redacted log as sanitised-by-guarantee.**  Matching is line-by-line and
    pattern-based, so three things get through by construction: a credential
    wrapped across two lines, a short token (under the 40-character floor
    :data:`_LONG_OPAQUE` needs, with no keyword next to it), and a credential
    under a key nobody thought to list.  Pattern redaction cannot be made
    complete — a log line is arbitrary text chosen by whatever app wrote it —
    so the honest posture is a stated best effort plus the ``redacted`` count,
    rather than a claim of safety the mechanism cannot support.  Logcat output
    stays untrusted content: the core fences it (§5.6, ``agent/untrusted.py``)
    exactly as it fences everything else a device printed, and that fence, not
    this function, is what makes it safe to *show*.  What this function is for
    is the narrower contract promise — that the Agent does not itself hand
    back a stack trace or a token it could recognise.
    """
    redactions = 0
    out: list[str] = []
    for line in text.splitlines():
        if _STACK_LINE.match(line):
            redactions += 1
            if out and out[-1] == _REDACTED + " stack frame":
                continue
            out.append(_REDACTED + " stack frame")
            continue
        scrubbed, n = _CREDENTIAL_KV.subn(
            lambda m: f"{m.group(1)}={_REDACTED}", line,
        )
        scrubbed, n2 = _BEARER.subn(f"Bearer {_REDACTED}", scrubbed)
        scrubbed, n3 = _LONG_OPAQUE.subn(_REDACTED, scrubbed)
        redactions += n + n2 + n3
        out.append(scrubbed)
    return "\n".join(out), redactions


# ---------------------------------------------------------------------------
# Where adb.exe is, and where it may keep its key
# ---------------------------------------------------------------------------


class AdbNotFoundError(RuntimeError):
    """No usable ``adb`` binary was found."""


#: Config key: ``[adb] binary_path`` in ``%APPDATA%\\WorkstationAgent\\config.toml``.
#:
#: Read straight off disk with ``tomllib`` rather than through
#: ``workstation_agent.config``, for two reasons.  The plugin is a separate
#: low-integrity process and importing the config package pulls pydantic and
#: tomlkit into the sandbox for one string.  And the setting cannot arrive by
#: environment variable at all: ``supervisor.ENV_WHITELIST`` is an exact
#: 16-name list and nothing may be added to it from here (B6 owns that file),
#: so a ``PC_AGENT_ADB_PATH`` variable would simply never reach the child.
#: ``APPDATA`` *is* on the whitelist, so the file is reachable.
_CONFIG_SECTION = "adb"
_CONFIG_KEY = "binary_path"
_APPDATA_DIR_NAME = "WorkstationAgent"

#: Places ``adb`` is normally installed, tried after ``PATH``.
_WELL_KNOWN_ADB_DIRS = (
    r"%LOCALAPPDATA%\Android\Sdk\platform-tools",
    r"%PROGRAMFILES%\Android\platform-tools",
    r"%PROGRAMFILES(X86)%\Android\android-sdk\platform-tools",
    r"%SYSTEMDRIVE%\platform-tools",
)


def _config_file() -> Path:
    """Return the on-disk config path, honouring the test override."""
    override = os.environ.get("PC_AGENT_APPDATA")
    base = Path(override) if override else Path(os.environ.get("APPDATA") or Path.home())
    if not override:
        base = base / _APPDATA_DIR_NAME
    return base / "config.toml"


def _configured_adb_path() -> str | None:
    """Read ``[adb] binary_path`` from the config file, if it is set."""
    path = _config_file()
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        log.warning("config.toml could not be parsed; falling back to PATH for adb")
        return None
    section = doc.get(_CONFIG_SECTION)
    if not isinstance(section, dict):
        return None
    value = section.get(_CONFIG_KEY)
    return value.strip() if isinstance(value, str) and value.strip() else None


def resolve_adb_path() -> str:
    """Return the path to ``adb``, or raise :class:`AdbNotFoundError`.

    Order: the operator's configured path, then ``PATH``, then the usual SDK
    install locations.  The configured path wins outright and is *not* silently
    replaced by a ``PATH`` hit when it does not exist — an operator who pointed
    the Agent at a specific ADB and got a different one would have no way to
    tell, and "the binary you configured is not there" is the more useful
    sentence.
    """
    configured = _configured_adb_path()
    if configured:
        if Path(configured).is_file():
            return configured
        msg = (
            "The adb binary configured for this workstation does not exist. "
            "Check the ADB path in the Agent's settings."
        )
        raise AdbNotFoundError(msg)

    found = shutil.which("adb")
    if found:
        return found

    for template in _WELL_KNOWN_ADB_DIRS:
        expanded = Path(os.path.expandvars(template)) / "adb.exe"
        if "%" not in str(expanded) and expanded.is_file():
            return str(expanded)

    msg = (
        "No adb binary was found on this workstation. Install Android platform-tools "
        "or set the ADB path in the Agent's settings."
    )
    raise AdbNotFoundError(msg)


#: Candidate homes for ADB's RSA key, most preferred first.
#:
#: ADB writes ``adbkey``/``adbkey.pub`` under ``$ANDROID_USER_HOME`` (falling
#: back to ``%USERPROFILE%\\.android``) and refuses to authorise a device
#: without them.  A low-integrity process cannot write to ``%USERPROFILE%``,
#: and cannot write to plain ``%TEMP%`` either — Windows redirects a low-IL
#: process's writes to the ``Low`` subdirectory.  So the directory is not
#: guessed: each candidate is created and probed with a real write, and the
#: first that works is used.  This is the single most likely thing to behave
#: differently on real hardware than in a test, which is exactly why it is
#: decided by attempting the write rather than by reasoning about it.
_ADB_HOME_CANDIDATES = (
    r"%LOCALAPPDATA%\Low\WorkstationAgent\adb",
    r"%TEMP%\Low\WorkstationAgent-adb",
    r"%TEMP%\WorkstationAgent-adb",
    r"%LOCALAPPDATA%\WorkstationAgent\adb",
)


def _is_writable(directory: Path) -> bool:
    """Create *directory* and prove we can write a file in it."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".wsa-write-probe"
        probe.write_bytes(b"")
        probe.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def resolve_adb_home(candidates: tuple[str, ...] = _ADB_HOME_CANDIDATES) -> str | None:
    """Return a directory ADB can keep its key in, or ``None`` if there is none.

    ``None`` is a real outcome, not a bug: it means every candidate was
    unwritable, ADB will fall back to ``%USERPROFILE%\\.android``, and on a
    locked-down workstation the device will report ``unauthorized`` forever.
    The caller turns that into a sentence naming the cause instead of leaving
    the operator to guess.
    """
    for template in candidates:
        expanded = os.path.expandvars(template)
        if "%" in expanded:
            continue
        directory = Path(expanded)
        if _is_writable(directory):
            return str(directory)
    return None


def build_adb_env() -> dict[str, str]:
    """Environment for the ``adb`` child process.

    Starts from what this process actually has — which is already reduced to
    ``supervisor.ENV_WHITELIST`` plus ``WSA_PLUGIN_ID`` — and adds ADB's own
    variables.  Adding them *here* is the only place it can be done: the
    whitelist governs what the Agent hands the plugin, and the plugin governs
    what it hands ``adb``.
    """
    env = dict(os.environ)
    home = resolve_adb_home()
    if home is not None:
        env["ANDROID_USER_HOME"] = home
        # Old platform-tools honour $HOME/.android instead of ANDROID_USER_HOME.
        # Set, not setdefault: HOME is usually already present and pointing at
        # %USERPROFILE%, which is the one directory a low-integrity process is
        # certain it cannot write to — the exact failure this exists to avoid.
        env["HOME"] = home
    return env


# ---------------------------------------------------------------------------
# Running adb
# ---------------------------------------------------------------------------

#: How many ``adb`` child processes this plugin will have running at once.
#:
#: The plugin lives in a Job Object whose ``ActiveProcessLimit`` is
#: ``ResourceLimits.max_active_processes`` — 4 today, rising to at least 8 for
#: §5.4's eight concurrent jobs.  The arithmetic that matters: the plugin
#: itself is one process, and the *first* ``adb`` command forks a persistent
#: ``adb server`` daemon that stays alive, so a single tool call costs two
#: slots and leaves them at two.  At the limit of 4 that is one client plus one
#: server plus the plugin = 3, with exactly one slot spare.  Exceeding the
#: limit does not queue: ``CreateProcess`` fails outright, so the bound is
#: enforced here rather than discovered as a spawn error under load.
#:
#: **This constant must be revisited whenever ``max_active_processes``
#: changes.**
_MAX_CONCURRENT_ADB = 2

_adb_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_ADB)

#: §5.3 — a tool call must answer within 25 s of wall clock.
_MAX_CALL_SECONDS = 25
#: §5.4 — ``wait_s`` defaults to 20 and is capped at 25.
_DEFAULT_WAIT_S = 20
#: §6 — ``adb_logcat`` takes ``seconds`` up to 20.
_MAX_LOGCAT_SECONDS = 20
_DEFAULT_LOGCAT_SECONDS = 5

#: Extra seconds allowed on top of a requested capture before the subprocess is
#: killed, so ``adb`` gets a chance to shut down cleanly and produce output.
_KILL_GRACE_SECONDS = 3

_CREATE_NO_WINDOW = 0x08000000


@dataclass
class AdbRun:
    """The outcome of one ``adb`` invocation."""

    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    duration_s: float = 0.0


def run_adb(
    args: list[str],
    *,
    timeout_s: float,
    adb_path: str | None = None,
) -> AdbRun:
    """Run ``adb`` with *args* and capture its output as bytes.

    Output is captured as **bytes** and decoded later by :func:`decode_output`,
    never by ``subprocess``'s ``text=True``.  ``text=True`` decodes with the
    locale codec and ``errors="strict"`` only by accident of platform; capturing
    bytes is what makes "not valid UTF-8 is refused" a decision this family
    makes rather than a behaviour it inherits.
    """
    binary = adb_path if adb_path is not None else resolve_adb_path()
    started = time.monotonic()
    creationflags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
    with _adb_slots:
        try:
            completed = subprocess.run(  # noqa: S603 — argv list, never a shell string
                [binary, *args],
                capture_output=True,
                timeout=timeout_s,
                check=False,
                env=build_adb_env(),
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            return AdbRun(
                returncode=-1,
                stdout=exc.stdout or b"",
                stderr=exc.stderr or b"",
                timed_out=True,
                duration_s=time.monotonic() - started,
            )
    return AdbRun(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_s=time.monotonic() - started,
    )


#: Substrings ADB prints when its server cannot start or the key is unusable.
_DAEMON_TROUBLE = (
    "cannot connect to daemon",
    "failed to start daemon",
    "daemon not running",
    "protocol fault",
    "adb server version",
)


def _daemon_hint(stderr: str) -> str | None:
    """Return an explanation when ADB's failure looks like the sandbox's doing.

    The failure this catches is the one that cannot be reproduced without a
    phone and a low-integrity token, so it is detected by what ADB prints
    rather than by trying to predict it.
    """
    lowered = stderr.lower()
    if not any(marker in lowered for marker in _DAEMON_TROUBLE):
        return None
    if resolve_adb_home() is None:
        return (
            "The ADB server could not be started. The Agent runs its plugins at low "
            "integrity and could not find a folder it is allowed to write ADB's key "
            "into, so ADB has nowhere to store it."
        )
    return (
        "The ADB server could not be started or could not be reached. Try starting it "
        "outside the Agent, or check that no other ADB server is already running with "
        "a different version."
    )


# ---------------------------------------------------------------------------
# adb_devices
# ---------------------------------------------------------------------------

_DEVICE_LINE = re.compile(r"^(\S+)\s+(device|unauthorized|offline|bootloader|recovery|\S+)\b")
_MODEL_FIELD = re.compile(r"\bmodel:(\S+)")


def parse_devices_output(text: str) -> list[dict[str, Any]]:
    """Parse ``adb devices -l`` into §6.1's ``adb`` rows.

    Only ``device``, ``unauthorized`` and ``offline`` are §6.1 states; anything
    else ADB reports (``bootloader``, ``recovery``, ``sideload``) is passed
    through as it was printed rather than forced into one of the three, because
    silently relabelling a bootloader as ``offline`` would be a lie about what
    is attached.
    """
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("List of devices", "*", "adb server")):
            continue
        match = _DEVICE_LINE.match(line)
        if match is None:
            continue
        model_match = _MODEL_FIELD.search(line)
        rows.append({
            "serial": sanitise_text(match.group(1)),
            "state": sanitise_text(match.group(2)),
            "model": sanitise_text(model_match.group(1)) if model_match else None,
        })
    return rows


def adb_device_rows(adb_path: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
    """Return §6.1's ``adb`` rows plus a note when they could not be produced.

    Shared with the ``devices`` family, which needs the same list inside
    ``devices_list`` and must not fail its whole answer when ADB is missing.
    """
    try:
        run = run_adb(["devices", "-l"], timeout_s=10.0, adb_path=adb_path)
    except AdbNotFoundError as exc:
        return [], sanitise_reason(str(exc))
    except OSError as exc:
        return [], sanitise_reason(f"The adb binary could not be run: {exc}")

    if run.timed_out:
        return [], "ADB did not respond within 10 seconds."

    text, refusal = decode_output(run.stdout, what="adb devices")
    if text is None:
        return [], (refusal or {}).get("reason")

    if run.returncode != 0:
        stderr, _ = decode_output(run.stderr, what="adb devices")
        note = _daemon_hint(stderr or "") or sanitise_reason(
            (stderr or "").strip() or "adb devices failed.",
        )
        return [], note

    return parse_devices_output(text), None


def adb_devices(adb_path: str | None = None) -> dict[str, Any]:
    """``adb_devices()`` — §6.1's ``{"ok": true, "devices": [...]}``."""
    rows, note = adb_device_rows(adb_path=adb_path)
    if note is not None and not rows:
        return failure(CODE_NOT_FOUND, note)
    result: dict[str, Any] = {"ok": True, "devices": rows}
    if note is not None:
        result["notes"] = [note]
    return result


def resolve_serial(
    serial: str | None,
    *,
    adb_path: str | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    """Turn an optional serial into the ``-s <serial>`` prefix for an adb argv.

    §6: "``serial`` optional when exactly one device is attached."  Exactly one
    means exactly one — zero is ``not_found`` and two is an error naming both,
    because picking one for the operator is how a command meant for the test
    phone runs on the production one.
    """
    if serial:
        return ["-s", serial], None

    rows, note = adb_device_rows(adb_path=adb_path)
    usable = [r for r in rows if r.get("state") == "device"]
    if not usable:
        unauthorised = [r for r in rows if r.get("state") == "unauthorized"]
        if unauthorised:
            return [], failure(
                CODE_NOT_FOUND,
                "A device is attached but has not authorised this workstation. "
                "Unlock the phone and accept the USB debugging prompt.",
            )
        return [], failure(
            CODE_NOT_FOUND,
            note or "No Android device is attached to this workstation.",
        )
    if len(usable) > 1:
        serials = ", ".join(str(r["serial"]) for r in usable)
        return [], failure(
            CODE_ERROR,
            f"More than one Android device is attached ({serials}); "
            f"say which one to use.",
        )
    return ["-s", str(usable[0]["serial"])], None


# ---------------------------------------------------------------------------
# Jobs (§5.4) — this family's own registry
# ---------------------------------------------------------------------------
#
# §5.4's ``jobs_wait``/``jobs_output``/``jobs_list``/``jobs_kill`` belong to the
# ``jobs`` family, which is a *different plugin process*.  A job started here
# cannot be paged from there until the registry lives somewhere both can reach
# — the host, or a routing rule keyed on the job id.  The id is therefore
# prefixed with the family (``j-adb-…``) so that routing is mechanically
# possible without changing the shape §5.4 specifies, and the registry is kept
# behind :func:`job_snapshot` so it can be adopted wholesale.
#
# THIS REGISTRY IS PROCESS-GLOBAL AND SHARED BY EVERY CALLER.  ``host.invoke``
# carries a ``SessionContext`` as far as the permission evaluator, but nothing
# passes per-connection identity into the arguments a plugin receives, and one
# subprocess serves every caller.  So a job id minted for one caller is visible
# to, and pageable by, any other caller of this plugin.  That is stated rather
# than mitigated: a plugin cannot enforce an isolation the transport does not
# give it, and inventing a per-caller key here from something the plugin *can*
# see would be a guess dressed as a boundary.  Job ids are random, which is a
# speed bump and not a control.  Whoever adopts this registry into the host
# inherits the decision about whether jobs are per-session.


@dataclass
class AdbJob:
    """One backgrounded ``adb`` invocation."""

    job_id: str
    tool: str
    started: float
    state: str = "running"
    exit_code: int | None = None
    output: bytes = b""
    finished: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _process: subprocess.Popen[bytes] | None = field(default=None, repr=False)

    def append(self, chunk: bytes) -> None:
        """Append captured bytes under the lock."""
        with self._lock:
            self.output += chunk

    def snapshot(self) -> tuple[str, int | None, bytes]:
        """Return ``(state, exit_code, output)`` consistently."""
        with self._lock:
            return self.state, self.exit_code, self.output


_JOBS: dict[str, AdbJob] = {}
_JOBS_LOCK = threading.Lock()

#: §5.4 — at most 8 concurrent jobs; a ninth is refused with ``code: "error"``.
_MAX_JOBS = 8
#: §5.4 — finished jobs are kept 30 minutes.
_JOB_RETENTION_S = 30 * 60


def _reap_jobs() -> None:
    """Drop finished jobs older than §5.4's 30-minute retention."""
    now = time.monotonic()
    with _JOBS_LOCK:
        stale = [
            jid
            for jid, job in _JOBS.items()
            if job.finished is not None and now - job.finished > _JOB_RETENTION_S
        ]
        for jid in stale:
            del _JOBS[jid]


def job_snapshot() -> list[dict[str, Any]]:
    """Return §6.1's ``jobs_list`` rows for this family's jobs."""
    _reap_jobs()
    with _JOBS_LOCK:
        jobs = list(_JOBS.values())
    return [
        {
            "job_id": job.job_id,
            "tool": job.tool,
            "state": job.snapshot()[0],
            "started": job.started,
            "finished": job.finished,
        }
        for job in jobs
    ]


def _new_job(tool: str) -> AdbJob | None:
    """Register a job, or return ``None`` when §5.4's limit of 8 is reached."""
    _reap_jobs()
    with _JOBS_LOCK:
        running = sum(1 for j in _JOBS.values() if j.state == "running")
        if running >= _MAX_JOBS:
            return None
        job = AdbJob(job_id=f"j-adb-{uuid.uuid4().hex[:6]}", tool=tool, started=time.monotonic())
        _JOBS[job.job_id] = job
    return job


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


def _clamp_wait(wait_s: object) -> int:
    """Clamp ``wait_s`` into §5.4's 0..25 range, defaulting to 20."""
    if not isinstance(wait_s, int) or isinstance(wait_s, bool):
        return _DEFAULT_WAIT_S
    return max(0, min(wait_s, _MAX_CALL_SECONDS))


def _finished_shell_result(run: AdbRun) -> dict[str, Any]:
    """Build §6.1's finished ``adb_shell`` shape from a completed run."""
    stdout, refusal = decode_output(run.stdout, what="The command's output")
    if stdout is None:
        return refusal or failure(CODE_ERROR, "The command's output could not be decoded.")
    stderr, stderr_refusal = decode_output(run.stderr, what="The command's error output")
    if stderr is None:
        return stderr_refusal or failure(
            CODE_ERROR, "The command's error output could not be decoded.",
        )
    return fit_envelope({
        "ok": True,
        "job_id": None,
        "exit_code": run.returncode,
        "stdout": sanitise_text(stdout),
        "stderr": sanitise_text(stderr),
        "duration_s": round(run.duration_s, 3),
    })


def adb_shell(  # noqa: PLR0911 — one branch per §5.2 code; collapsing them hides which
    command: str,
    serial: str | None = None,
    wait_s: object = None,
    *,
    adb_path: str | None = None,
) -> dict[str, Any]:
    """``adb_shell(serial?, command, wait_s?)`` — job-capable per §5.4.

    This is §11 item 2's path: ``adb shell getprop ro.product.model`` prompts on
    the workstation (§7 puts ``adb_shell`` on the always-prompt list, enforced
    by the gate before this function is ever reached) and returns the model
    name.  That command answers in well under a second, so it takes the
    ``job_id: null`` branch and the job machinery never runs for it.
    """
    if not isinstance(command, str) or not command.strip():
        return failure(CODE_ERROR, "No command was given to run on the device.")
    prefix, refusal = resolve_serial(serial, adb_path=adb_path)
    if refusal is not None:
        return refusal

    wait = _clamp_wait(wait_s)
    argv = [*prefix, "shell", command]

    try:
        run = run_adb(argv, timeout_s=float(wait or 1), adb_path=adb_path)
    except AdbNotFoundError as exc:
        return failure(CODE_NOT_FOUND, str(exc))
    except OSError as exc:
        return failure(CODE_ERROR, f"The adb binary could not be run: {exc}")

    if run.timed_out:
        # The work outlived wait_s.  §5.4's contract is a job handle carrying
        # what has been produced so far -- not an error, and not a silent kill.
        job = _new_job("adb_shell")
        if job is None:
            return failure(
                CODE_ERROR,
                "This workstation is already running the maximum of 8 background jobs.",
            )
        partial = run.stdout or b""
        job.append(partial)
        job.state = "done" if run.returncode == 0 else "failed"
        job.exit_code = run.returncode
        job.finished = time.monotonic()
        text, decode_refusal = decode_output(partial, what="The command's output")
        if text is None:
            return decode_refusal or failure(
                CODE_ERROR, "The command's output could not be decoded.",
            )
        return fit_envelope({
            "ok": True,
            "job_id": job.job_id,
            "state": "running",
            "output": sanitise_text(text),
            "output_bytes": len(partial),
        })

    stderr_text, _ = decode_output(run.stderr, what="The command's error output")
    hint = _daemon_hint(stderr_text or "")
    if hint is not None:
        return failure(CODE_ERROR, hint)
    return _finished_shell_result(run)


def _local_file_check(workstation_path: str) -> dict[str, Any] | None:
    """Confirm the local file exists, without echoing its absolute path back.

    Root confinement is the gate's job and has already happened by the time
    this runs — ``workstation_path`` is declared ``ws_path`` and the manifest
    lists no confirmable conditions, so an out-of-roots path was denied.  What
    is left is the ordinary "it is not there" case, and §5.2 has a code for it.
    """
    if not isinstance(workstation_path, str) or not workstation_path.strip():
        return failure(CODE_ERROR, "No workstation file was named.")
    if not Path(workstation_path).is_file():
        return failure(
            CODE_NOT_FOUND,
            "That file does not exist on this workstation.",
        )
    return None


def adb_push(
    workstation_path: str,
    device_path: str,
    serial: str | None = None,
    *,
    adb_path: str | None = None,
) -> dict[str, Any]:
    """``adb_push(serial?, workstation_path, device_path)`` — §6.

    ``workstation_path`` is a **workstation** path and is confined to the
    declared roots by the gate; ``device_path`` is a phone path and is not
    compared to anything on this machine.
    """
    problem = _local_file_check(workstation_path)
    if problem is not None:
        return problem
    if not isinstance(device_path, str) or not device_path.strip():
        return failure(CODE_ERROR, "No destination path on the device was given.")

    prefix, refusal = resolve_serial(serial, adb_path=adb_path)
    if refusal is not None:
        return refusal

    try:
        run = run_adb(
            [*prefix, "push", workstation_path, device_path],
            timeout_s=float(_MAX_CALL_SECONDS),
            adb_path=adb_path,
        )
    except AdbNotFoundError as exc:
        return failure(CODE_NOT_FOUND, str(exc))
    except OSError as exc:
        return failure(CODE_ERROR, f"The adb binary could not be run: {exc}")

    return _transfer_result(run, verb="push", device_path=device_path)


def adb_install(
    workstation_path: str,
    serial: str | None = None,
    *,
    adb_path: str | None = None,
) -> dict[str, Any]:
    """``adb_install(serial?, workstation_path)`` — §6, roots-confined."""
    problem = _local_file_check(workstation_path)
    if problem is not None:
        return problem

    prefix, refusal = resolve_serial(serial, adb_path=adb_path)
    if refusal is not None:
        return refusal

    try:
        run = run_adb(
            [*prefix, "install", "-r", workstation_path],
            timeout_s=float(_MAX_CALL_SECONDS),
            adb_path=adb_path,
        )
    except AdbNotFoundError as exc:
        return failure(CODE_NOT_FOUND, str(exc))
    except OSError as exc:
        return failure(CODE_ERROR, f"The adb binary could not be run: {exc}")

    return _transfer_result(run, verb="install", device_path=None)


def _transfer_result(
    run: AdbRun,
    *,
    verb: str,
    device_path: str | None,
) -> dict[str, Any]:
    """Shared result assembly for ``adb_push`` and ``adb_install``."""
    if run.timed_out:
        return failure(CODE_TIMEOUT, f"The {verb} did not finish within 25 seconds.")

    stdout, stdout_refusal = decode_output(run.stdout, what=f"The {verb} output")
    if stdout is None:
        return stdout_refusal or failure(CODE_ERROR, f"The {verb} output could not be decoded.")
    stderr, stderr_refusal = decode_output(run.stderr, what=f"The {verb} error output")
    if stderr is None:
        return stderr_refusal or failure(
            CODE_ERROR, f"The {verb} error output could not be decoded.",
        )

    if run.returncode != 0:
        hint = _daemon_hint(stderr)
        return failure(CODE_ERROR, hint or (stderr.strip() or f"The {verb} failed."))

    result: dict[str, Any] = {
        "ok": True,
        "job_id": None,
        "exit_code": run.returncode,
        "stdout": sanitise_text(stdout),
        "stderr": sanitise_text(stderr),
        "duration_s": round(run.duration_s, 3),
    }
    if device_path is not None:
        result["device_path"] = sanitise_text(device_path)
    return fit_envelope(result)


def adb_pull(  # noqa: PLR0911 — one branch per §5.2 code; collapsing them hides which
    device_path: str,
    serial: str | None = None,
    *,
    adb_path: str | None = None,
) -> dict[str, Any]:
    """``adb_pull(serial?, device_path)`` → text ≤ cap. Text-only in v1 (§10).

    Implemented as ``adb exec-out cat`` rather than ``adb pull`` to a temporary
    file.  ``adb pull`` would write the device's bytes onto this workstation
    before anyone had decided whether they are text — which is a binary
    transfer into the workstation in all but name, and §10 defers binary into
    the *workspace* precisely so that does not happen quietly.  ``exec-out``
    keeps the bytes in a pipe, where the UTF-8 test in :func:`decode_output`
    decides whether they may travel at all.
    """
    if not isinstance(device_path, str) or not device_path.strip():
        return failure(CODE_ERROR, "No path on the device was given.")

    prefix, refusal = resolve_serial(serial, adb_path=adb_path)
    if refusal is not None:
        return refusal

    try:
        run = run_adb(
            [*prefix, "exec-out", "cat", device_path],
            timeout_s=float(_MAX_CALL_SECONDS),
            adb_path=adb_path,
        )
    except AdbNotFoundError as exc:
        return failure(CODE_NOT_FOUND, str(exc))
    except OSError as exc:
        return failure(CODE_ERROR, f"The adb binary could not be run: {exc}")

    if run.timed_out:
        return failure(
            CODE_TIMEOUT,
            "Reading the file from the device took longer than 25 seconds.",
        )

    stderr, _ = decode_output(run.stderr, what="The device's error output")
    if run.returncode != 0:
        hint = _daemon_hint(stderr or "")
        lowered = (stderr or "").lower()
        if "no such file" in lowered or "not found" in lowered:
            return failure(CODE_NOT_FOUND, "That file does not exist on the device.")
        return failure(
            CODE_ERROR,
            hint or ((stderr or "").strip() or "The file could not be read."),
        )

    text, decode_refusal = decode_output(run.stdout, what="The file")
    if text is None:
        return decode_refusal or failure(CODE_ERROR, "The file could not be decoded.")

    total = len(run.stdout)
    if len(text) > MAX_RESULT_CHARS:
        # A *file* over the cap is `ok: false` per §5.3, not a truncated
        # success: a half-file that says it succeeded is worse than a refusal,
        # because nothing downstream can tell it is half.
        return failure(
            CODE_ERROR,
            f"That file is {total} bytes, over the 60,000-character limit; "
            f"binary transfer is not available yet.",
        )

    return fit_envelope({
        "ok": True,
        "device_path": sanitise_text(device_path),
        "bytes": total,
        "total_bytes": total,
        "content": sanitise_text(text),
        "truncated": False,
    })


def _clamp_logcat_seconds(seconds: object) -> int:
    """Clamp ``seconds`` into §6's 1..20 range, defaulting to 5."""
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        return _DEFAULT_LOGCAT_SECONDS
    return max(1, min(seconds, _MAX_LOGCAT_SECONDS))


def adb_logcat(  # noqa: PLR0911 — one branch per §5.2 code; collapsing them hides which
    serial: str | None = None,
    seconds: object = None,
    log_filter: str | None = None,
    *,
    adb_path: str | None = None,
) -> dict[str, Any]:
    """``adb_logcat(serial?, seconds ≤ 20, filter?)`` — §6, redacted per §5.2.

    Android system logs carry crash stack traces and, whenever an app logs a
    request, authorisation tokens.  Both are on §5.2's forbidden list, so
    :func:`redact_log_text` removes them and the result says how many
    redactions were made.
    """
    prefix, refusal = resolve_serial(serial, adb_path=adb_path)
    if refusal is not None:
        return refusal

    capture = _clamp_logcat_seconds(seconds)
    argv = [*prefix, "logcat", "-d", "-t", f"{capture * 100}"]
    if isinstance(log_filter, str) and log_filter.strip():
        argv.extend(log_filter.split())

    try:
        run = run_adb(
            argv,
            timeout_s=float(min(capture + _KILL_GRACE_SECONDS, _MAX_CALL_SECONDS)),
            adb_path=adb_path,
        )
    except AdbNotFoundError as exc:
        return failure(CODE_NOT_FOUND, str(exc))
    except OSError as exc:
        return failure(CODE_ERROR, f"The adb binary could not be run: {exc}")

    if run.timed_out and not run.stdout:
        return failure(CODE_TIMEOUT, "The device did not produce any log output in time.")

    text, decode_refusal = decode_output(run.stdout, what="The device log")
    if text is None:
        return decode_refusal or failure(CODE_ERROR, "The device log could not be decoded.")

    if run.returncode != 0 and not text.strip():
        stderr, _ = decode_output(run.stderr, what="The device's error output")
        hint = _daemon_hint(stderr or "")
        return failure(CODE_ERROR, hint or ((stderr or "").strip() or "logcat failed."))

    redacted, count = redact_log_text(text)
    return fit_envelope({
        "ok": True,
        "seconds": capture,
        "lines": len(redacted.splitlines()),
        "redacted": count,
        "output": sanitise_text(redacted),
    })
