"""MCP server for the ``serial`` family (contract §5.5, §6, §6.1).

Runs as a line-delimited JSON-RPC 2.0 server over stdin/stdout, exactly like
every other bundled plugin (see ``plugins/filesystem/__main__.py``). The
five tools — ``serial.ports``, ``serial.open``, ``serial.write``,
``serial.read``, ``serial.close`` — are real, not stubs.

**Everything lives in this one file, deliberately.** The signature covering
a bundled plugin only hashes ``__init__.py`` and ``__main__.py``
(``mcp_host/loader.py:_resolve_module_paths`` — a ``-m <package>`` entry is
resolved to exactly those two files, nothing else in the package
directory). Splitting the session store or the tool logic into their own
modules would put real, security-relevant behaviour outside what the
signature actually covers, which is the opposite of what a "signed
manifest" is supposed to mean. Every other bundled plugin is single-file for
the same reason; this one stays single-file to not become the first
exception.

Sections below, top to bottom: the ``pyserial`` backend seam (so this module
never has to be run against a real device to be tested), session
bookkeeping (§5.5), the five tools' pure logic (§5.2/§5.3), and the
JSON-RPC wire harness.
"""
# ruff: noqa: ANN401, PLR0911, PLR0913, PLW2901

from __future__ import annotations

import codecs
import contextlib
import json
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast

import serial
import serial.tools.list_ports

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# ---------------------------------------------------------------------------
# Backend seam — the only place this plugin touches real hardware.
#
# ``pyserial`` (import name ``serial``) is a new dependency this subtask
# adds; see ``pyproject.toml`` for the licence record (BSD-3) and reasoning.
# Every function below that can reach a physical device takes its I/O
# through a parameter defaulting to the real backend, which is what lets the
# rest of this module be tested with **no serial hardware attached** — the
# situation this family was actually built under.
# ---------------------------------------------------------------------------


class SerialLike(Protocol):
    """The slice of ``serial.Serial`` this plugin actually uses.

    ``timeout`` is settable because pyserial re-reads it before every
    blocking ``read()`` rather than fixing it at construction time —
    :func:`_drain` relies on exactly that to poll several short reads inside
    one overall deadline.
    """

    timeout: float | None

    def write(self, data: bytes) -> int | None: ...

    def read(self, size: int = 1) -> bytes: ...

    def close(self) -> None: ...


class PortInfoLike(Protocol):
    """The slice of ``serial.tools.list_ports_common.ListPortInfo`` used here."""

    device: str
    description: str
    vid: int | None
    pid: int | None


def _open_serial_port(
    port: str,
    baud: int,
    *,
    bytesize: int = 8,
    parity: str = "N",
    stopbits: float = 1,
    timeout_s: float = 2,
) -> SerialLike:
    """Open *port* with ``pyserial``. Raises on failure; callers translate.

    This is the one function in the whole family that can actually reach a
    physical device, and it was not exercised against one in this build (no
    serial hardware was available) — see the test suite for what was
    verified against a fake instead, and the plugin.toml comment / final
    report for what remains unverified as a result.
    """
    # pyserial's own stub has `Serial.timeout` as a property and `write`
    # typed against `ReadableBuffer` rather than `bytes`, so it does not
    # structurally match the narrow `SerialLike` protocol this module
    # defines on purpose (see its docstring). The cast is the boundary: this
    # function is the only place `serial.Serial` and `SerialLike` meet.
    return cast(
        "SerialLike",
        serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=bytesize,
            parity=parity,
            stopbits=stopbits,
            timeout=timeout_s,
        ),
    )


def _list_serial_ports() -> Sequence[PortInfoLike]:
    """Return the COM ports ``pyserial`` can enumerate on this workstation."""
    return list(serial.tools.list_ports.comports())


# ---------------------------------------------------------------------------
# Sessions — contract §5.5.
#
# ``serial.open`` mints a session, ``serial.write`` / ``serial.read`` /
# ``serial.close`` use it. Everything here lives in **this plugin
# subprocess's own memory** and nowhere else:
#
# * it is a plain module-level store, so it is gone the instant the process
#   exits — which happens whenever the Agent does, because the plugin is a
#   child of the Agent's process tree and is spawned fresh on every
#   ``MCPHost.start()``. That alone satisfies "sessions die with the Agent"
#   and "an id from before the Agent last restarted": there is no file, no
#   registry key, nothing for a restart to find.
# * ``session_id`` is 128 bits from :func:`secrets.token_hex`, not a counter
#   or anything derived from caller-supplied input, so a session id cannot
#   be guessed or enumerated by another caller — and no tool in this family
#   lists open session ids (``serial_ports`` lists COM ports, not sessions).
# * idle sessions are reaped on every store access (§5.5's 10-minute idle
#   close), and at most 4 may be open at once (§5.5).
#
# On "sessions must not leak between callers": this Agent runs one
# ``serial`` plugin subprocess, shared by every caller that reaches
# ``MCPHost.invoke`` — there is exactly one process, one store. Nothing in
# ``host.py`` (out of this subtask's allowed paths, and unowned by it) puts
# a per-connection identity into the tool arguments a plugin receives —
# ``SessionContext`` reaches the permissions evaluator and the audit row,
# not the plugin. So the guarantee this module can actually make, and does
# make, is the one available at this layer: a session id cannot be guessed,
# is never enumerated, and never survives a restart. Partitioning sessions
# *per transport connection* would need session-identity plumbed from the
# host into tool arguments, which is a change to ``host.py`` this subtask is
# not permitted to make; it is recorded here as a known limitation rather
# than assumed away.
#
# A consequence of the same fact, worth stating separately: the 4-session
# cap (§5.5) is global to this one process, not per caller. A caller that
# opens 4 sessions and holds them (up to 10 minutes idle) denies every other
# caller's ``serial_open`` for that window — this is a real,
# resource-exhaustion-shaped exposure, and no per-caller isolation is
# possible from inside the plugin for the reason above. What this module
# does within that constraint: the reaper runs on every store access rather
# than on a timer, so a slot frees the instant it is next noticed idle
# rather than waiting for some separate sweep; and the cap refusal
# (``open_result``) names when the longest-idle session will free up, so the
# caller is told this is transient rather than left to guess. Neither
# changes who gets refused; both are containment, not a fix.
# ---------------------------------------------------------------------------

#: §5.5 — "An idle session is closed by the Agent after 10 minutes."
IDLE_TIMEOUT_S: float = 10 * 60

#: §5.5 — "At most 4 open sessions per family."
MAX_SESSIONS: int = 4

#: How many recently idle-closed session ids to remember, purely so the next
#: call on one can say *why* ("closed after 10 minutes idle at <time>")
#: instead of falling back to the generic "from before the Agent last
#: restarted" message. Bounded so idling out sessions forever cannot grow
#: this without limit.
_RECENT_CLOSED_CAP = 32


class SessionLimitExceededError(Exception):
    """Raised by :meth:`SessionStore.create` when §5.5's cap of 4 is hit."""


def _iso(epoch_s: float) -> str:
    """Render a wall-clock epoch time as ISO-8601 with a UTC offset."""
    return datetime.fromtimestamp(epoch_s, tz=UTC).isoformat()


@dataclass
class Session:
    """One open serial session."""

    session_id: str
    port: str
    baud: int
    handle: SerialLike
    opened_at: float
    last_used: float


class SessionStore:
    """Owns every open serial session for this plugin process.

    ``clock`` (monotonic-style) drives idle-timeout comparisons and
    ``wall_clock`` (epoch-seconds) drives the human-readable timestamps in
    refusal messages — both are injectable so tests can move time forward
    without a real ten-minute sleep.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._wall_clock = wall_clock
        self._sessions: dict[str, Session] = {}
        self._recent_closed: dict[str, tuple[float, bool]] = {}
        self._started_at = wall_clock()

    @property
    def max_sessions(self) -> int:
        """§5.5's per-family cap, exposed for refusal messages."""
        return MAX_SESSIONS

    @property
    def started_at_iso(self) -> str:
        """When this plugin process (hence this store) came up."""
        return _iso(self._started_at)

    def _reap_expired(self) -> None:
        now = self._clock()
        expired = [
            sid
            for sid, session in self._sessions.items()
            if now - session.last_used > IDLE_TIMEOUT_S
        ]
        for sid in expired:
            session = self._sessions.pop(sid)
            with contextlib.suppress(Exception):
                session.handle.close()
            self._note_closed(sid, idle=True)

    def _note_closed(self, session_id: str, *, idle: bool) -> None:
        # Distinguish *why* a session is gone: an idle reap says so ("closed
        # after 10 minutes idle"), an explicit `serial_close` does not — a
        # caller that closes its own session and then calls again on it is
        # not being told it went idle, which would be simply false.
        self._recent_closed[session_id] = (self._wall_clock(), idle)
        if len(self._recent_closed) > _RECENT_CLOSED_CAP:
            oldest = min(self._recent_closed, key=lambda k: self._recent_closed[k][0])
            del self._recent_closed[oldest]

    def create(self, *, port: str, baud: int, handle: SerialLike) -> Session:
        """Mint a new session, or raise :class:`SessionLimitExceededError`."""
        self._reap_expired()
        if len(self._sessions) >= MAX_SESSIONS:
            raise SessionLimitExceededError
        session_id = secrets.token_hex(16)
        now = self._clock()
        session = Session(
            session_id=session_id,
            port=port,
            baud=baud,
            handle=handle,
            opened_at=now,
            last_used=now,
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        """Return the live session for *session_id*, reaping idle ones first."""
        self._reap_expired()
        return self._sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        """Mark *session_id* as used just now, resetting its idle clock."""
        session = self._sessions.get(session_id)
        if session is not None:
            session.last_used = self._clock()

    def close(self, session_id: str) -> Session | None:
        """Remove and return *session_id*'s session, or ``None`` if unknown."""
        self._reap_expired()
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self._note_closed(session_id, idle=False)
        return session

    def count(self) -> int:
        """How many sessions are open right now, after reaping idle ones."""
        self._reap_expired()
        return len(self._sessions)

    def next_reap_in(self) -> float | None:
        """Seconds until the longest-idle open session is auto-reaped.

        ``None`` when no sessions are open. This does not change *who* gets
        refused at the §5.5 cap of 4 — the cap and the 10-minute idle
        timeout are both fixed by the contract, and this plugin has no
        caller identity to partition sessions by (see the module docstring)
        — but it turns a bare "close one first" refusal into one that says
        when relief arrives on its own, which is the one thing available at
        this layer to soften a global cap one caller can otherwise exhaust
        for everyone.
        """
        self._reap_expired()
        if not self._sessions:
            return None
        oldest_last_used = min(s.last_used for s in self._sessions.values())
        return max(0.0, IDLE_TIMEOUT_S - (self._clock() - oldest_last_used))

    def unknown_reason(self, session_id: str) -> str:
        """Explain why *session_id* is not open: idle-closed vs never-seen."""
        entry = self._recent_closed.get(session_id)
        if entry is not None:
            closed_at, idle = entry
            if idle:
                return f"closed after 10 minutes idle at {_iso(closed_at)}"
            return f"already closed at {_iso(closed_at)}"
        return f"from before the Agent last restarted at {self.started_at_iso}"


#: One store for the lifetime of this process. There is exactly one
#: ``serial`` plugin subprocess per running Agent, so a module-level
#: singleton is the store, not a convenience shortcut for one.
_STORE = SessionStore()


# ---------------------------------------------------------------------------
# Tool logic — contract §6/§6.1. Pure functions of their arguments plus the
# store; the only I/O is through ``open_fn`` / ``list_ports_fn``, both
# overridable, so every branch here is reachable from a test with no serial
# device attached.
# ---------------------------------------------------------------------------

#: §6.1 — ``max_bytes`` for ``serial_read`` is schema-capped at 60000, which
#: doubles as the hard ceiling used here even when the caller omits it. This
#: is a *byte* bound on what is drained from the device.
MAX_READ_BYTES = 60_000

#: §5.3 — the contract's cap is on the *text result*, in characters, which is
#: a different number from a byte bound whenever the content is not pure
#: ASCII. Kept as its own constant and enforced with an explicit post-decode
#: check (see ``read_result``) rather than relied on implicitly via
#: ``MAX_READ_BYTES`` happening to equal it today — so that tuning the byte
#: bound later cannot silently blow the character cap.
MAX_READ_CHARS = 60_000

#: §6.1 — "timeout_s defaults to 2, max 20."
DEFAULT_READ_TIMEOUT_S = 2.0
MAX_READ_TIMEOUT_S = 20.0

#: Poll granularity while scanning for an ``until`` marker: small enough
#: that the overall deadline is honoured to a fraction of a second, large
#: enough not to spin needlessly on a fake or a slow device.
_POLL_CHUNK_S = 0.05

_NOT_FOUND_HINTS = (
    "cannot find the file",
    "no such file",
    "filenotfounderror",
    "does not exist",
    "no such device",
)


def _fail(reason: str, *, code: str = "error") -> dict[str, Any]:
    return {"ok": False, "code": code, "reason": reason}


def _unknown_session(store: SessionStore, session_id: str) -> dict[str, Any]:
    # session_id is caller-supplied and never echoed back: it is either the
    # opaque hex this plugin minted (fine, but pointless to repeat) or a
    # guess/typo from the caller, and echoing arbitrary caller input into a
    # refusal reason is exactly the discipline `permissions.safe_name` and
    # `host.sanitise_reason` enforce elsewhere in this codebase.
    why = store.unknown_reason(session_id)
    return _fail(f"That serial session is not open ({why}).", code="unknown_session")


def _safe_decode(data: bytes) -> str:
    """Decode *data* as UTF-8, or "" — never mangle, never raise."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _decode_utf8_prefix(raw: bytes) -> tuple[str, int] | None:
    """Decode as much of *raw* as forms complete UTF-8 characters.

    Returns ``(text, consumed)`` with ``consumed <= len(raw)``, or ``None``
    when *raw* is not valid UTF-8 at all.

    The distinction matters: ``_drain`` stops on a byte cap or a timeout, not
    on a character boundary, so its last few bytes may be an incomplete —
    but otherwise perfectly valid — multi-byte sequence. That is the read
    being cut off, not the device sending something malformed, and reporting
    it as "not valid UTF-8" would blame the wrong thing. ``codecs`` gives
    this distinction for free: ``final=False`` is exactly the incremental
    decoder's contract of "don't fail on a trailing partial sequence, just
    tell me how much you actually consumed" — anything it still raises on
    (a bad lead byte, an overlong encoding, an encoded surrogate, an invalid
    byte in the middle of the buffer) is genuinely invalid, not truncated,
    and stays refused exactly as before.
    """
    try:
        # `final` is positional-only in the C-level codec function; there is
        # no keyword spelling available to satisfy FBT003 here.
        text, consumed = codecs.utf_8_decode(raw, "strict", False)  # noqa: FBT003
    except UnicodeDecodeError:
        return None
    return text, consumed


def _cap_read_text(text: str) -> str:
    """Enforce §5.3's *character* cap on a decoded read result.

    Independent of whatever byte bound produced ``text`` — see
    ``MAX_READ_CHARS``'s docstring for why this must not be assumed to fall
    out of the byte cap automatically.
    """
    return text[:MAX_READ_CHARS]


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _port_entry(port: PortInfoLike) -> dict[str, Any]:
    vid = getattr(port, "vid", None)
    pid = getattr(port, "pid", None)
    return {
        "port": str(getattr(port, "device", "")),
        "description": str(getattr(port, "description", "") or ""),
        "vid": f"{vid:04x}" if isinstance(vid, int) else None,
        "pid": f"{pid:04x}" if isinstance(pid, int) else None,
    }


def ports_result(*, list_ports_fn: Callable[[], Sequence[PortInfoLike]] | None = None) -> dict:
    """serial_ports: contract §6.1's ``com`` shape as ``{"ok": true, "ports": [...]}``."""
    fn = list_ports_fn or _list_serial_ports
    try:
        found = list(fn())
    except Exception as exc:  # noqa: BLE001 - enumerating ports must never crash the plugin
        return _fail(f"could not list serial ports: {type(exc).__name__}")
    return {"ok": True, "ports": [_port_entry(p) for p in found]}


def _open_failure(exc: Exception) -> dict:
    message = str(exc).lower()
    if any(hint in message for hint in _NOT_FOUND_HINTS):
        return _fail("No serial port by that name was found.", code="not_found")
    return _fail("The serial port could not be opened.")


def open_result(
    store: SessionStore,
    *,
    port: Any,
    baud: Any,
    bytesize: Any = 8,
    parity: Any = "N",
    stopbits: Any = 1,
    timeout_s: Any = 2,
    open_fn: Callable[..., SerialLike] | None = None,
) -> dict:
    """serial_open: validate, open the port, mint and store a session."""
    fn = open_fn or _open_serial_port

    if not isinstance(port, str) or not port.strip():
        return _fail("serial_open needs a port name, for example COM3.")
    if not isinstance(baud, int) or isinstance(baud, bool) or baud <= 0:
        return _fail("serial_open needs a positive integer baud rate.")

    try:
        bytesize_i = 8 if isinstance(bytesize, bool) or bytesize is None else int(bytesize)
        stopbits_f = 1.0 if isinstance(stopbits, bool) or stopbits is None else float(stopbits)
        timeout_f = 2.0 if isinstance(timeout_s, bool) or timeout_s is None else float(timeout_s)
        parity_s = "N" if parity is None else str(parity)
    except (TypeError, ValueError):
        return _fail("serial_open received a malformed connection setting.")

    try:
        handle = fn(
            port,
            baud,
            bytesize=bytesize_i,
            parity=parity_s,
            stopbits=stopbits_f,
            timeout_s=_clamp(timeout_f, 0.0, MAX_READ_TIMEOUT_S),
        )
    except Exception as exc:  # noqa: BLE001 - driver/hardware errors, translated below
        return _open_failure(exc)

    try:
        session = store.create(port=port, baud=baud, handle=handle)
    except SessionLimitExceededError:
        with contextlib.suppress(Exception):
            handle.close()
        reason = (
            f"At most {store.max_sessions} serial sessions may be open at once; "
            "close one first."
        )
        wait_s = store.next_reap_in()
        if wait_s is not None:
            # There is no per-caller isolation here (see the module
            # docstring): the cap is global to the whole plugin process, so
            # one caller holding 4 sessions open denies everyone else's
            # serial_open until one of those sessions is closed or goes
            # idle. Naming when the longest-idle one will be auto-reaped is
            # the best containment available at this layer without caller
            # identity — it turns a bare, opaque refusal into one that says
            # relief is coming and roughly when, rather than leaving the
            # caller to guess whether this is permanent.
            reason += (
                f" The longest-idle session will free up in about {wait_s:.0f}s if left unused."
            )
        return _fail(reason)

    return {"ok": True, "session_id": session.session_id, "port": port, "baud": baud}


def _build_write_payload(text: Any, hex_: Any) -> tuple[bytes | None, dict | None]:
    """Validate and encode ``serial_write``'s ``text``/``hex`` into bytes.

    Returns ``(payload, None)`` on success or ``(None, error_dict)`` — split
    out of :func:`write_result` purely to keep that function's branch count
    within the repo's complexity budget; the validation rules themselves are
    unchanged.
    """
    if text is not None and hex_ is not None:
        return None, _fail("serial_write takes text or hex, not both.")
    if text is None and hex_ is None:
        return None, _fail("serial_write needs text or hex to send.")

    if hex_ is not None:
        if not isinstance(hex_, str):
            return None, _fail("hex must be a string of lowercase hex digits.")
        try:
            return bytes.fromhex(hex_), None
        except ValueError:
            return None, _fail("hex must be lowercase hex digits with no separators.")

    if not isinstance(text, str):
        return None, _fail("text must be a string.")
    try:
        return text.encode("utf-8"), None
    except UnicodeEncodeError:
        # A lone/unpaired surrogate: `json.loads` happily produces one as a
        # string value, but UTF-8 cannot represent it. Same class of bug
        # fixed on the named-pipe token and the LAN endpoint's own body
        # validation — reject explicitly rather than let it raise out of
        # this function or fall through to `errors="replace"`.
        return None, _fail("text contains characters that cannot be represented.")


def write_result(
    store: SessionStore,
    *,
    session_id: Any,
    text: Any = None,
    hex_: Any = None,
) -> dict:
    """serial_write: send ``text`` or ``hex`` down an open session."""
    if not isinstance(session_id, str) or not session_id:
        return _fail("serial_write needs a session_id from serial_open.")

    session = store.get(session_id)
    if session is None:
        return _unknown_session(store, session_id)

    payload, error = _build_write_payload(text, hex_)
    if error is not None:
        return error
    if payload is None:  # pragma: no cover - invariant: error is None iff payload is set
        return _fail("serial_write needs text or hex to send.")

    try:
        written = session.handle.write(payload)
    except OSError:
        # Narrowed from a blanket `except Exception`: this must catch real
        # hardware/driver failures (`serial.SerialException` is an `OSError`
        # subclass) and must NOT catch a bug in this function's own logic
        # above, which would otherwise be misreported as "the port failed"
        # when the port was never touched.
        return _fail("The write to the serial port failed.")

    store.touch(session_id)
    n = written if isinstance(written, int) and 0 <= written <= len(payload) else len(payload)
    sent = payload[:n]
    return {
        "ok": True,
        "session_id": session_id,
        "bytes": n,
        "text": _safe_decode(sent),
        "hex": sent.hex(),
        "timed_out": False,
    }


def _drain(
    ser: SerialLike,
    *,
    until_bytes: bytes | None,
    cap: int,
    explicit_cap: bool,
    deadline: float,
) -> tuple[bytes, bool]:
    """Read from *ser* until a marker, a byte cap, or *deadline* (monotonic).

    §6.1: "with neither `until` nor a full `max_bytes` the read returns at
    the timeout with `timed_out: true`" — modelled directly. ``timed_out``
    is False only once a stop condition the *caller asked for* was actually
    reached (the marker matched, or an explicitly requested ``max_bytes``
    was filled); reading up to the internal safety ceiling with neither
    still counts as running out the clock.
    """
    buf = bytearray()

    if until_bytes is None:
        remaining = max(0.0, deadline - time.monotonic())
        ser.timeout = remaining
        buf.extend(ser.read(cap))
        reached_full = explicit_cap and len(buf) >= cap
        return bytes(buf), not reached_full

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return bytes(buf), True
        ser.timeout = min(remaining, _POLL_CHUNK_S)
        chunk = ser.read(1)
        if chunk:
            buf.extend(chunk)
            if buf.endswith(until_bytes):
                return bytes(buf), False
            if explicit_cap and len(buf) >= cap:
                return bytes(buf), False
            if len(buf) >= MAX_READ_BYTES:
                return bytes(buf), True


def _validate_until(until: Any) -> tuple[bytes | None, dict | None]:
    """Validate ``until`` and encode it, or return a §5.2 error.

    Split out of :func:`read_result` to keep its branch count within the
    repo's complexity budget. Two rules matter here, both fixed in the same
    rework: an empty string is rejected outright rather than silently
    reinterpreted as "no marker" (it trivially matches everywhere, which is
    not useful and not obviously what an empty string was even meant to
    say), and encoding is never allowed to raise — a lone/unpaired surrogate
    is the third appearance of this exact class in this build (the
    named-pipe token, the LAN endpoint's own body validation, now a read
    delimiter), rejected explicitly rather than left to raise out of this
    function and get relabelled "the read failed" by a broad except further
    down.
    """
    if until is None:
        return None, None
    if not isinstance(until, str):
        return None, _fail("until must be a string.")
    if until == "":
        return None, _fail("until must not be empty.")
    try:
        return until.encode("utf-8"), None
    except UnicodeEncodeError:
        return None, _fail("until contains characters that cannot be represented.")


def _validate_read_timeout(timeout_s: Any) -> tuple[float | None, dict | None]:
    """Validate and clamp ``timeout_s``, or return a §5.2 error."""
    raw_timeout = DEFAULT_READ_TIMEOUT_S if timeout_s is None else timeout_s
    if isinstance(raw_timeout, bool):
        return None, _fail("timeout_s must be a number.")
    try:
        timeout = float(raw_timeout)
    except (TypeError, ValueError):
        return None, _fail("timeout_s must be a number.")
    return _clamp(timeout, 0.0, MAX_READ_TIMEOUT_S), None


def read_result(
    store: SessionStore,
    *,
    session_id: Any,
    until: Any = None,
    max_bytes: Any = None,
    timeout_s: Any = None,
) -> dict:
    """serial_read: drain an open session, refusing anything not valid UTF-8."""
    if not isinstance(session_id, str) or not session_id:
        return _fail("serial_read needs a session_id from serial_open.")

    session = store.get(session_id)
    if session is None:
        return _unknown_session(store, session_id)

    until_bytes, error = _validate_until(until)
    if error is not None:
        return error

    bad_max_bytes = max_bytes is not None and (
        not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1
    )
    if bad_max_bytes:
        return _fail("max_bytes must be a positive integer.")

    timeout, error = _validate_read_timeout(timeout_s)
    if error is not None or timeout is None:
        return error if error is not None else _fail("timeout_s must be a number.")

    explicit_cap = max_bytes is not None
    cap = min(int(max_bytes), MAX_READ_BYTES) if explicit_cap else MAX_READ_BYTES

    try:
        raw, timed_out = _drain(
            session.handle,
            until_bytes=until_bytes,
            cap=cap,
            explicit_cap=explicit_cap,
            deadline=time.monotonic() + timeout,
        )
    except OSError:
        # Narrowed from a blanket `except Exception`. `_drain` no longer has
        # a path that raises anything else on its own (the `until`/encoding
        # validation above used to be able to reach `buf.endswith(...)` with
        # a bad value and have that logic bug reported as "the port failed"
        # by this same broad catch) — only `serial.SerialException`
        # (an `OSError` subclass) and other real I/O errors should ever
        # land here, and only those should be reported as a hardware fault.
        return _fail("The read from the serial port failed.")

    store.touch(session_id)

    decoded = _decode_utf8_prefix(raw)
    if decoded is None:
        # §5.3, restated for this family in the brief: binary never
        # travels. This is a genuine decode failure — bytes that are not
        # valid UTF-8 anywhere in the buffer, not merely a sequence cut
        # short at the end (see `_decode_utf8_prefix`). The bytes are gone
        # once drained from the device; there is nothing to "keep" for a
        # retry, and the honest answer is a refusal, not a mangled or
        # hex-only substitute smuggled through the `ok: true` path.
        return _fail(
            f"The device returned {len(raw)} bytes that are not valid UTF-8; "
            "binary transfer is not available yet.",
        )
    text, _consumed = decoded
    # `consumed < len(raw)` means the last few bytes are an incomplete —
    # but otherwise valid — multi-byte sequence, truncated by the byte cap
    # or the timeout. That is this function stopping mid-character, not the
    # device sending something invalid, so it is dropped from `text`
    # silently rather than reported as any kind of fault. `bytes`/`hex`
    # still reflect the complete drained buffer, so nothing is hidden —
    # a caller that cares can recover the undecoded tail from `hex`.
    text = _cap_read_text(text)

    return {
        "ok": True,
        "session_id": session_id,
        "bytes": len(raw),
        "text": text,
        "hex": raw.hex(),
        "timed_out": timed_out,
    }


def close_result(store: SessionStore, *, session_id: Any) -> dict:
    """serial_close: release the session and the underlying port."""
    if not isinstance(session_id, str) or not session_id:
        return _fail("serial_close needs a session_id from serial_open.")

    session = store.close(session_id)
    if session is None:
        return _unknown_session(store, session_id)

    with contextlib.suppress(Exception):
        session.handle.close()

    return {"ok": True, "session_id": session_id}


# ---------------------------------------------------------------------------
# JSON-RPC wire harness.
# ---------------------------------------------------------------------------


def _send(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _reply(request_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _rpc_error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


_SESSION_ID_SCHEMA = {"type": "string", "description": "A session id from serial_open."}

_TOOLS = [
    {
        "name": "serial.ports",
        "description": "List the COM ports on the workstation.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "serial.open",
        "description": "Open a serial port and return a session id for reading and writing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "string", "description": "The port name, for example COM3."},
                "baud": {"type": "integer", "description": "Baud rate, for example 115200."},
                "bytesize": {"type": "integer", "default": 8, "description": "Data bits."},
                "parity": {
                    "type": "string",
                    "enum": ["N", "E", "O", "M", "S"],
                    "default": "N",
                    "description": "Parity. Defaults to none.",
                },
                "stopbits": {"type": "number", "default": 1, "description": "Stop bits."},
                "timeout_s": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 20,
                    "default": 2,
                    "description": "Default read timeout for this session, in seconds.",
                },
            },
            "required": ["port", "baud"],
            "additionalProperties": False,
        },
    },
    {
        "name": "serial.write",
        "description": "Write text or raw bytes to an open serial session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": _SESSION_ID_SCHEMA,
                "text": {"type": "string", "description": "Text to write."},
                "hex": {
                    "type": "string",
                    "description": "Raw bytes as lowercase hex with no separators.",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "serial.read",
        "description": "Read from an open serial session until a marker, a byte count, "
        "or a timeout.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": _SESSION_ID_SCHEMA,
                "until": {
                    "type": "string",
                    "description": "A literal string to stop at, matched after decoding.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60000,
                    "description": "Most bytes to read. Capped at 60000.",
                },
                "timeout_s": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 20,
                    "default": 2,
                    "description": "Seconds to wait. Default 2, maximum 20.",
                },
            },
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "serial.close",
        "description": "Close an open serial session and release the port.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": _SESSION_ID_SCHEMA},
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
]


def _call_ports(_args: dict[str, Any]) -> dict[str, Any]:
    return ports_result()


def _call_open(args: dict[str, Any]) -> dict[str, Any]:
    return open_result(
        _STORE,
        port=args.get("port"),
        baud=args.get("baud"),
        bytesize=args.get("bytesize", 8),
        parity=args.get("parity", "N"),
        stopbits=args.get("stopbits", 1),
        timeout_s=args.get("timeout_s", 2),
    )


def _call_write(args: dict[str, Any]) -> dict[str, Any]:
    return write_result(
        _STORE,
        session_id=args.get("session_id"),
        text=args.get("text"),
        hex_=args.get("hex"),
    )


def _call_read(args: dict[str, Any]) -> dict[str, Any]:
    return read_result(
        _STORE,
        session_id=args.get("session_id"),
        until=args.get("until"),
        max_bytes=args.get("max_bytes"),
        timeout_s=args.get("timeout_s"),
    )


def _call_close(args: dict[str, Any]) -> dict[str, Any]:
    return close_result(_STORE, session_id=args.get("session_id"))


_DISPATCH: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "serial.ports": _call_ports,
    "serial.open": _call_open,
    "serial.write": _call_write,
    "serial.read": _call_read,
    "serial.close": _call_close,
}


def _text_block(payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": "text", "text": json.dumps(payload, separators=(",", ":"))}


def _handle_tools_call(request_id: Any, params: dict[str, Any]) -> None:
    tool_name = params.get("name")
    args = params.get("arguments")
    if not isinstance(args, dict):
        args = {}

    handler = _DISPATCH.get(tool_name) if isinstance(tool_name, str) else None
    if handler is None:
        payload = {"ok": False, "code": "error", "reason": f"unknown tool: {tool_name}"}
        _reply(request_id, {"content": [_text_block(payload)], "isError": True})
        return

    try:
        result = handler(args)
    except Exception:  # noqa: BLE001 - a tool must never crash the plugin process
        result = {"ok": False, "code": "error", "reason": "the tool failed unexpectedly"}

    _reply(
        request_id,
        {"content": [_text_block(result)], "isError": not bool(result.get("ok", False))},
    )


def _handle(msg: dict[str, Any]) -> bool:
    """Process one message; return False to stop the event loop."""
    method = msg.get("method")
    request_id = msg.get("id")

    if request_id is None:
        return True  # a notification from the client — nothing to reply to

    if method == "initialize":
        _reply(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "serial", "version": "0.1.0"},
            },
        )
        return True

    if method == "ping":
        _reply(request_id, {})
        return True

    if method == "tools/list":
        _reply(request_id, {"tools": _TOOLS})
        return True

    if method == "tools/call":
        _handle_tools_call(request_id, msg.get("params") or {})
        return True

    if method == "shutdown":
        _reply(request_id, {})
        return False

    _rpc_error(request_id, -32601, f"unknown method: {method}")
    return True


def main() -> None:
    """Main entry point: process stdin line by line."""
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not _handle(msg):
            break


if __name__ == "__main__":
    main()
