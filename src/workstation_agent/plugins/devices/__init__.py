"""The ``devices`` family — ``devices_list`` (contract §6, §6.1).

Copyright (c) 2024 PersonaCore-Agent contributors. See LICENSE for details.

One call answers "what is plugged into my workstation?" (§11 item 1) with three
lists: USB devices, ADB devices, and COM ports.

Why ctypes into ``setupapi.dll`` and not ``pywin32``
----------------------------------------------------
The design brief said "SetupAPI/WMI through ``pywin32``".  That is wrong, and it
was checked rather than assumed: ``pywin32`` ships **no** SetupAPI wrapper.
There is no ``win32setupapi``, no ``setupapi``, and no ``setup*`` module under
``win32`` in this project's venv (``importlib.import_module`` raises
``ModuleNotFoundError`` for each; a glob over ``site-packages`` returns nothing).

That leaves two ways to answer §6.1, and only one of them can:

* **WMI alone cannot.**  §6.1 requires ``present_since`` per USB device.
  ``Win32_PnPEntity`` is the only WMI class that enumerates PnP devices and its
  ``InstallDate`` is ``NULL`` for every USB device on this machine (checked with
  ``Get-CimInstance``), which is the documented norm — the CIM provider simply
  does not populate it.  No other property on the class carries an arrival or
  install timestamp.  A WMI implementation would therefore have to emit
  ``present_since: null`` for every device, which is a §6.1 defect
  indistinguishable from a working one.
* **SetupAPI can.**  ``SetupDiGetDevicePropertyW`` with
  ``DEVPKEY_Device_LastArrivalDate`` returns a ``FILETIME`` saying exactly when
  the device last arrived — which is what "present since" means.  Verified on
  this workstation: every enumerated USB device returned property type
  ``DEVPROP_TYPE_FILETIME`` (``0x10``) with a plausible value.

So: ctypes into ``setupapi.dll``.  WMI is not used at all, not even as a
fallback, because a fallback that cannot supply ``present_since`` would return a
list that looks complete and is not.  When SetupAPI is unavailable (a non-Windows
test runner) the USB list is empty and a ``notes`` entry says why — extra keys
are explicitly allowed by §6.1, and an empty list with a stated reason is honest
where a silently degraded list is not.

Result sanitisation (§5.3, §5.6) is enforced here, at this family's own
boundary, rather than assumed of the transport — see :func:`sanitise_text`.
"""

# pyserial ships type stubs but the package itself is not installed until B8
# declares the dependency; the optional import in enumerate_com() handles its
# absence at runtime, so the missing source is expected, not a defect.
# pyright: reportMissingModuleSource=false

from __future__ import annotations

import ctypes
import datetime as _dt
import json
import logging
import re
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

#: A source of §6.1 rows, injected by tests.  Spelled out rather than left
#: as ``Any`` so a test that returns the wrong shape fails at type-check
#: time rather than by producing a subtly malformed devices_list.
RowSource = "Callable[[], list[dict[str, Any]]]"
NotedRowSource = "Callable[[], tuple[list[dict[str, Any]], str | None]]"

log = logging.getLogger(__name__)

__all__ = [
    "MAX_RESULT_CHARS",
    "UsbDevice",
    "devices_list",
    "enumerate_usb",
    "fit_envelope",
    "sanitise_text",
    "strip_special_tokens",
]


# ---------------------------------------------------------------------------
# §5.3 / §5.6 — result sanitisation, owned by this family
# ---------------------------------------------------------------------------
#
# The plan is explicit that each family enforces this at its own boundary and
# does not assume the transport will.  The host has its own copy in
# ``mcp_host/host.py``; a plugin is a separate low-integrity *process* that
# should not import the host (it would drag the audit database, the permission
# gate and pywin32's job-object layer into the sandbox for three regexes), and
# only ``__init__.py`` and ``__main__.py`` are covered by the plugin signature,
# so the implementation lives here where it is signed.  ``tests/unit/plugins/
# test_sanitisation_parity.py`` drives this copy and the host's through one
# shared corpus so the two cannot drift.

#: §5.3 — text results are capped by the Agent at 60,000 characters.
MAX_RESULT_CHARS = 60_000

_ANGLE_PIPE_TOKEN = re.compile(r"<\|[^<>|]{0,64}\|>")
_BRACKET_TOKEN = re.compile(
    r"\[/?INST\]|\[/?SYS\]|<</?SYS>>|</?s>|<\|?/?im_(?:start|end)\|?>",
    re.IGNORECASE,
)
_STRIP_PASSES = 8


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


# ---------------------------------------------------------------------------
# SetupAPI via ctypes
# ---------------------------------------------------------------------------


class GUID(ctypes.Structure):
    """Windows ``GUID``."""

    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


class SP_DEVINFO_DATA(ctypes.Structure):  # noqa: N801 — the Win32 struct name
    """Windows ``SP_DEVINFO_DATA``."""

    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.POINTER(ctypes.c_ulonglong)),
    )


class DEVPROPKEY(ctypes.Structure):
    """Windows ``DEVPROPKEY``."""

    _fields_ = (
        ("fmtid", GUID),
        ("pid", wintypes.ULONG),
    )


_PBYTE = ctypes.POINTER(ctypes.c_ubyte)

#: ``SetupDiGetClassDevsW`` flags: present devices only, across all classes.
_DIGCF_PRESENT = 0x02
_DIGCF_ALLCLASSES = 0x04

#: ``SetupDiGetDeviceRegistryPropertyW`` property ids (``SPDRP_*``).
_SPDRP_DEVICEDESC = 0x00
_SPDRP_CLASS = 0x07
_SPDRP_FRIENDLYNAME = 0x0C
_SPDRP_LOCATION_INFORMATION = 0x0D

#: ``DEVPROP_TYPE_FILETIME`` — the type ``LastArrivalDate`` comes back as.
_DEVPROP_TYPE_FILETIME = 0x00000010

#: ``DEVPKEY_Device_LastArrivalDate``: when this device last arrived, which is
#: precisely §6.1's ``present_since``.  Nothing in WMI carries it.
_DEVPKEY_DEVICE_LAST_ARRIVAL_DATE = DEVPROPKEY(
    GUID(
        0x83DA6326,
        0x97A6,
        0x4088,
        (ctypes.c_ubyte * 8)(0x94, 0x53, 0xA1, 0x92, 0x3F, 0x57, 0x3B, 0x29),
    ),
    102,
)

#: Windows FILETIME epoch (1601-01-01) to Unix epoch, in 100-ns ticks.
_FILETIME_EPOCH_DELTA_100NS = 116_444_736_000_000_000
_TICKS_PER_SECOND = 10_000_000

#: Buffer size for every string property read.  Device descriptions and
#: instance ids are far shorter; an over-long value is truncated rather than
#: retried, because a device whose friendly name needs more than 1 KiB is
#: reporting something we do not want to relay verbatim anyway.
_STR_BUFFER_CHARS = 1024

#: Hard bound on the enumeration loop.  ``SetupDiEnumDeviceInfo`` terminates on
#: its own, but this list is built from data the OS reads off the bus and a
#: runaway loop in a low-integrity sandbox is not worth risking.
_MAX_DEVICES = 4096

_INSTANCE_ID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")


class UsbDevice(NamedTuple):
    """One row of §6.1's ``usb`` list."""

    vid: str | None
    pid: str | None
    name: str
    device_class: str
    port: str
    present_since: str | None

    def as_dict(self) -> dict[str, Any]:
        """Return the §6.1 key spelling (``class`` is a Python keyword)."""
        return {
            "vid": self.vid,
            "pid": self.pid,
            "name": self.name,
            "class": self.device_class,
            "port": self.port,
            "present_since": self.present_since,
        }


def _load_setupapi() -> ctypes.WinDLL | None:
    """Load ``setupapi.dll`` and bind argtypes, or return ``None``.

    Binding ``argtypes`` is not optional hygiene: ``SetupDiGetClassDevsW``
    returns a 64-bit ``HDEVINFO``, and without a declared ``restype`` ctypes
    truncates it to a C ``int`` and the very next call raises
    ``OverflowError: int too long to convert``.  That is the first thing that
    goes wrong when writing this by hand, and it goes wrong loudly, which is
    the only reason it is not still wrong here.
    """
    if sys.platform != "win32":
        return None
    try:
        dll = ctypes.WinDLL("setupapi", use_last_error=True)
    except (OSError, AttributeError):
        log.warning("setupapi.dll could not be loaded; USB enumeration unavailable")
        return None

    dll.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    dll.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.LPCWSTR,
        wintypes.HWND,
        wintypes.DWORD,
    ]
    dll.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    dll.SetupDiEnumDeviceInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    dll.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
    dll.SetupDiGetDeviceInstanceIdW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    dll.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
    dll.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        _PBYTE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    dll.SetupDiGetDevicePropertyW.restype = wintypes.BOOL
    dll.SetupDiGetDevicePropertyW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        ctypes.POINTER(DEVPROPKEY),
        ctypes.POINTER(wintypes.ULONG),
        _PBYTE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    dll.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    dll.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    return dll


def filetime_to_iso(ticks: int) -> str | None:
    """Convert a Windows ``FILETIME`` tick count to an ISO-8601 UTC string.

    Returns ``None`` for zero (the property exists but was never set) and for
    any value outside what :class:`datetime.datetime` can represent, rather
    than raising: one unreadable timestamp must not lose the whole device list.
    """
    if ticks <= 0:
        return None
    seconds = (ticks - _FILETIME_EPOCH_DELTA_100NS) / _TICKS_PER_SECOND
    try:
        moment = _dt.datetime.fromtimestamp(seconds, tz=_dt.UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat()


def parse_vid_pid(instance_id: str) -> tuple[str | None, str | None]:
    """Pull ``VID``/``PID`` out of a device instance id, lowercased.

    §6.1's example values are lowercase hex (``"1234"``, ``"abcd"``); Windows
    reports them uppercase, so they are normalised here rather than at every
    call site.
    """
    match = _INSTANCE_ID_RE.search(instance_id)
    if match is None:
        return None, None
    return match.group(1).lower(), match.group(2).lower()


def _read_string_property(
    dll: ctypes.WinDLL,
    handle: int,
    devinfo: SP_DEVINFO_DATA,
    prop: int,
) -> str | None:
    """Read one ``SPDRP_*`` string property, or ``None`` if it is absent."""
    buf = ctypes.create_unicode_buffer(_STR_BUFFER_CHARS)
    needed = wintypes.DWORD()
    ok = dll.SetupDiGetDeviceRegistryPropertyW(
        handle,
        ctypes.byref(devinfo),
        prop,
        None,
        ctypes.cast(buf, _PBYTE),
        ctypes.sizeof(buf),
        ctypes.byref(needed),
    )
    if not ok:
        return None
    return buf.value or None


def _read_arrival_date(
    dll: ctypes.WinDLL,
    handle: int,
    devinfo: SP_DEVINFO_DATA,
) -> str | None:
    """Read ``DEVPKEY_Device_LastArrivalDate`` as ISO-8601, or ``None``."""
    ticks = ctypes.c_ulonglong()
    prop_type = wintypes.ULONG()
    required = wintypes.DWORD()
    ok = dll.SetupDiGetDevicePropertyW(
        handle,
        ctypes.byref(devinfo),
        ctypes.byref(_DEVPKEY_DEVICE_LAST_ARRIVAL_DATE),
        ctypes.byref(prop_type),
        ctypes.cast(ctypes.byref(ticks), _PBYTE),
        ctypes.sizeof(ticks),
        ctypes.byref(required),
        0,
    )
    if not ok or prop_type.value != _DEVPROP_TYPE_FILETIME:
        # Some root hubs genuinely have no arrival date.  §6.1 wants the key
        # present; null is the honest value, and is not the same claim as an
        # omitted key.
        return None
    return filetime_to_iso(ticks.value)


def _iter_devinfo(
    dll: ctypes.WinDLL,
    handle: int,
) -> Iterator[SP_DEVINFO_DATA]:
    """Yield each present device in the set, bounded by :data:`_MAX_DEVICES`."""
    index = 0
    while index < _MAX_DEVICES:
        devinfo = SP_DEVINFO_DATA()
        devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        if not dll.SetupDiEnumDeviceInfo(handle, index, ctypes.byref(devinfo)):
            return
        yield devinfo
        index += 1
    log.warning("SetupDi enumeration hit the %d-device bound; list truncated", _MAX_DEVICES)


def _instance_id(dll: ctypes.WinDLL, handle: int, devinfo: SP_DEVINFO_DATA) -> str:
    """Return the device instance id, or an empty string."""
    buf = ctypes.create_unicode_buffer(_STR_BUFFER_CHARS)
    needed = wintypes.DWORD()
    ok = dll.SetupDiGetDeviceInstanceIdW(
        handle,
        ctypes.byref(devinfo),
        buf,
        _STR_BUFFER_CHARS,
        ctypes.byref(needed),
    )
    return buf.value if ok else ""


def enumerate_usb(dll: ctypes.WinDLL | None = None) -> list[dict[str, Any]]:
    """Return §6.1's ``usb`` list, or an empty list when SetupAPI is absent.

    Every string that leaves here has been through :func:`sanitise_text`: a
    device's friendly name is a string the *device* chose, so it is untrusted
    content in exactly the sense §5.6 means.
    """
    api = _load_setupapi() if dll is None else dll
    if api is None:
        return []

    handle = api.SetupDiGetClassDevsW(None, "USB", None, _DIGCF_PRESENT | _DIGCF_ALLCLASSES)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        log.warning("SetupDiGetClassDevsW returned no device set")
        return []

    rows: list[dict[str, Any]] = []
    try:
        for devinfo in _iter_devinfo(api, handle):
            instance = _instance_id(api, handle, devinfo)
            vid, pid = parse_vid_pid(instance)
            name = (
                _read_string_property(api, handle, devinfo, _SPDRP_FRIENDLYNAME)
                or _read_string_property(api, handle, devinfo, _SPDRP_DEVICEDESC)
                or instance
                or "Unknown device"
            )
            rows.append(
                UsbDevice(
                    vid=vid,
                    pid=pid,
                    name=sanitise_text(name),
                    device_class=sanitise_text(
                        _read_string_property(api, handle, devinfo, _SPDRP_CLASS) or "",
                    ),
                    port=sanitise_text(
                        _read_string_property(
                            api, handle, devinfo, _SPDRP_LOCATION_INFORMATION,
                        )
                        or "",
                    ),
                    present_since=_read_arrival_date(api, handle, devinfo),
                ).as_dict(),
            )
    finally:
        api.SetupDiDestroyDeviceInfoList(handle)
    return rows


# ---------------------------------------------------------------------------
# COM ports — pyserial (B8 owns the dependency; absence is not an error here)
# ---------------------------------------------------------------------------


def enumerate_com() -> tuple[list[dict[str, Any]], str | None]:
    """Return §6.1's ``com`` list and, when it is empty for a reason, that reason.

    ``pyserial`` is B8's dependency to declare.  Until it lands this returns an
    empty list plus a note, rather than failing the whole call: "what is plugged
    in?" should still answer for USB and ADB on a workstation where the serial
    family is not installed.
    """
    try:
        # pyserial ships type stubs but is not installed until B8 declares it,
        # so the ImportError below is the supported path, not an accident.
        from serial.tools import list_ports  # noqa: PLC0415
    except ImportError:
        return [], (
            "COM ports were not enumerated: the pyserial package is not installed "
            "on this workstation."
        )

    rows: list[dict[str, Any]] = []
    for port in list_ports.comports():
        vid = f"{port.vid:04x}" if getattr(port, "vid", None) is not None else None
        pid = f"{port.pid:04x}" if getattr(port, "pid", None) is not None else None
        rows.append({
            "port": sanitise_text(str(port.device or "")),
            "description": sanitise_text(str(port.description or "")),
            "vid": vid,
            "pid": pid,
        })
    return rows, None


# ---------------------------------------------------------------------------
# devices_list
# ---------------------------------------------------------------------------


def devices_list(
    *,
    usb_source: Callable[[], list[dict[str, Any]]] | None = None,
    adb_source: Callable[[], tuple[list[dict[str, Any]], str | None]] | None = None,
    com_source: Callable[[], tuple[list[dict[str, Any]], str | None]] | None = None,
) -> dict[str, Any]:
    """Build §6.1's ``devices_list`` result.

    The three sources are injectable so the assembly, the shape and the
    degradation notes are testable without a phone, without pyserial and
    without SetupAPI.  In production all three are ``None`` and the real
    enumerators run.

    A failure in one source never fails the whole call: §11 item 1 is "what is
    plugged into my workstation?", and answering for two buses out of three
    with a note saying why the third is missing is strictly more useful than a
    single error sentence.
    """
    notes: list[str] = []

    usb: list[dict[str, Any]] = []
    try:
        usb = list(enumerate_usb()) if usb_source is None else list(usb_source())
    except Exception:
        log.exception("USB enumeration failed")
        notes.append("USB devices could not be enumerated on this workstation.")
    if not usb and not notes:
        if sys.platform != "win32":
            notes.append("USB devices are only enumerated on Windows.")
        elif usb_source is None:
            notes.append("SetupAPI returned no USB devices.")

    adb: list[dict[str, Any]] = []
    try:
        from workstation_agent.plugins.adb import adb_device_rows  # noqa: PLC0415

        adb, adb_note = adb_device_rows() if adb_source is None else adb_source()
        if adb_note:
            notes.append(adb_note)
    except Exception:
        log.exception("ADB enumeration failed")
        notes.append("ADB devices could not be enumerated on this workstation.")

    com: list[dict[str, Any]] = []
    try:
        com, com_note = enumerate_com() if com_source is None else com_source()
        if com_note:
            notes.append(com_note)
    except Exception:
        log.exception("COM port enumeration failed")
        notes.append("COM ports could not be enumerated on this workstation.")

    result: dict[str, Any] = {"ok": True, "usb": usb, "adb": adb, "com": com}
    if notes:
        # An extra key; §6.1 allows them and ignores them.  It exists so a
        # degraded answer is visibly degraded instead of looking complete.
        result["notes"] = notes
    # This result is three *lists* and no long string, which is the shape an
    # earlier fit_envelope could not shrink at all: it collected only top-level
    # strings, found none, and returned the oversized envelope unchanged.  A
    # workstation with a large hub tree reaches the cap on device rows alone.
    return fit_envelope(result)
