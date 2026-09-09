"""Unit tests for the serial plugin's tool logic (contract §6, §6.1).

Every test here drives the pure `*_result` functions with a fake standing in
for `SerialLike` — no serial hardware is used or required anywhere in this
file, which is the whole point of the backend seam in
`workstation_agent.plugins.serial.__main__`.
"""

from __future__ import annotations

import pytest

from workstation_agent.plugins.serial import __main__ as serial_main
from workstation_agent.plugins.serial.__main__ import (
    MAX_READ_CHARS,
    MAX_READ_TIMEOUT_S,
    SessionStore,
    _cap_read_text,
    close_result,
    open_result,
    ports_result,
    read_result,
    write_result,
)


class ByteQueueSerial:
    """A fake `SerialLike` that returns queued bytes immediately, never
    really blocking. Good enough to drive the read loop deterministically:
    when a test wants the *timeout* branch to fire, the queue is simply
    left short and the (small, test-chosen) `timeout_s` does the waiting."""

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.timeout: float | None = None
        self.closed = False
        self.written = bytearray()
        self.raise_on_write: Exception | None = None
        self.raise_on_read: Exception | None = None

    def write(self, data: bytes) -> int:
        if self.raise_on_write is not None:
            raise self.raise_on_write
        self.written.extend(data)
        return len(data)

    def read(self, size: int = 1) -> bytes:
        if self.raise_on_read is not None:
            raise self.raise_on_read
        n = min(size, len(self._buf))
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self) -> None:
        self.closed = True


class _PortInfo:
    def __init__(self, device: str, description: str, vid: int | None, pid: int | None) -> None:
        self.device = device
        self.description = description
        self.vid = vid
        self.pid = pid


# ---------------------------------------------------------------------------
# serial_ports
# ---------------------------------------------------------------------------


def test_ports_result_lists_com_ports_with_hex_vid_pid() -> None:
    fake_ports = [
        _PortInfo("COM3", "USB Serial", 0x1234, 0xABCD),
        _PortInfo("COM1", "", None, None),
    ]
    result = ports_result(list_ports_fn=lambda: fake_ports)
    assert result == {
        "ok": True,
        "ports": [
            {"port": "COM3", "description": "USB Serial", "vid": "1234", "pid": "abcd"},
            {"port": "COM1", "description": "", "vid": None, "pid": None},
        ],
    }


def test_ports_result_never_crashes_the_plugin_on_a_listing_error() -> None:
    def _boom():
        msg = "enumeration failed"
        raise OSError(msg)

    result = ports_result(list_ports_fn=_boom)
    assert result["ok"] is False
    assert result["code"] == "error"


# ---------------------------------------------------------------------------
# serial_open
# ---------------------------------------------------------------------------


def test_open_result_success_mints_a_session() -> None:
    store = SessionStore()
    fake = ByteQueueSerial()
    result = open_result(store, port="COM3", baud=115200, open_fn=lambda *_a, **_kw: fake)
    assert result["ok"] is True
    assert result["port"] == "COM3"
    assert result["baud"] == 115200
    assert store.get(result["session_id"]) is not None


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        ({"port": "", "baud": 9600}, "empty port"),
        ({"port": 123, "baud": 9600}, "non-string port"),
        ({"port": "COM3", "baud": 0}, "zero baud"),
        ({"port": "COM3", "baud": -1}, "negative baud"),
        ({"port": "COM3", "baud": True}, "bool is not an int baud"),
        ({"port": "COM3", "baud": "115200"}, "string baud"),
    ],
)
def test_open_result_rejects_malformed_arguments(kwargs, why) -> None:
    store = SessionStore()
    result = open_result(store, open_fn=lambda *_a, **_kw: ByteQueueSerial(), **kwargs)
    assert result["ok"] is False, why
    assert result["code"] == "error"


def test_open_result_maps_a_missing_port_to_not_found() -> None:
    store = SessionStore()

    def _open_fn(*_a, **_kw):
        msg = (
            "could not open port 'COM231': FileNotFoundError(2, "
            "'The system cannot find the file specified.')"
        )
        raise Exception(msg)  # noqa: TRY002 - mirrors pyserial's own SerialException shape

    result = open_result(store, port="COM231", baud=9600, open_fn=_open_fn)
    assert result == {
        "ok": False,
        "code": "not_found",
        "reason": "No serial port by that name was found.",
    }


def test_open_result_maps_an_unrecognised_failure_to_error_without_leaking_the_message() -> None:
    store = SessionStore()

    def _open_fn(*_a, **_kw):
        msg = r"PermissionError(13, 'Access is denied.') at C:\secret\path"
        raise Exception(msg)  # noqa: TRY002

    result = open_result(store, port="COM3", baud=9600, open_fn=_open_fn)
    assert result["ok"] is False
    assert result["code"] == "error"
    assert r"C:\secret\path" not in result["reason"], "must never echo a path back"


def test_open_result_refuses_a_fifth_session_and_closes_the_unused_handle() -> None:
    store = SessionStore()
    handles = [ByteQueueSerial() for _ in range(5)]
    it = iter(handles)

    for _ in range(4):
        result = open_result(store, port="COM3", baud=9600, open_fn=lambda *_a, **_kw: next(it))
        assert result["ok"] is True

    fifth = open_result(store, port="COM3", baud=9600, open_fn=lambda *_a, **_kw: next(it))
    assert fifth["ok"] is False
    assert fifth["code"] == "error"
    assert "4 serial sessions" in fifth["reason"]
    assert handles[4].closed is True, "the unused 5th handle must not leak"


def test_open_result_clamps_timeout_to_twenty_seconds() -> None:
    store = SessionStore()
    seen: dict[str, float] = {}

    def _open_fn(_port, _baud, **kw):
        seen["timeout_s"] = kw["timeout_s"]
        return ByteQueueSerial()

    open_result(store, port="COM3", baud=9600, timeout_s=999, open_fn=_open_fn)
    assert seen["timeout_s"] == MAX_READ_TIMEOUT_S


# ---------------------------------------------------------------------------
# serial_write
# ---------------------------------------------------------------------------


def _opened_session(
    store: SessionStore, fake: ByteQueueSerial | None = None,
) -> tuple[str, ByteQueueSerial]:
    fake = fake or ByteQueueSerial()
    result = open_result(store, port="COM3", baud=9600, open_fn=lambda *_a, **_kw: fake)
    return result["session_id"], fake


def test_write_result_sends_text() -> None:
    store = SessionStore()
    session_id, fake = _opened_session(store)

    result = write_result(store, session_id=session_id, text="AT\r\n")
    assert result["ok"] is True
    assert result["bytes"] == 4
    assert result["text"] == "AT\r\n"
    assert result["hex"] == "41540d0a"
    assert result["timed_out"] is False
    assert bytes(fake.written) == b"AT\r\n"


def test_write_result_sends_hex() -> None:
    store = SessionStore()
    session_id, fake = _opened_session(store)

    result = write_result(store, session_id=session_id, hex_="deadbeef")
    assert result["ok"] is True
    assert result["bytes"] == 4
    assert result["hex"] == "deadbeef"
    assert bytes(fake.written) == b"\xde\xad\xbe\xef"


def test_write_result_hex_that_is_not_valid_utf8_gives_empty_text_not_mangled_text() -> None:
    """The write echo never mangles non-UTF-8 bytes into `text` — it is
    empty instead, same discipline as the read-side refusal, just not a
    whole-call failure since the operation itself (the write) succeeded."""
    store = SessionStore()
    session_id, _ = _opened_session(store)

    result = write_result(store, session_id=session_id, hex_="ff")
    assert result["ok"] is True
    assert result["text"] == ""
    assert result["hex"] == "ff"


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # neither text nor hex
        {"text": "a", "hex_": "00"},  # both
        {"hex_": "not-hex"},
        {"text": 5},
    ],
)
def test_write_result_rejects_malformed_payloads(kwargs) -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store)
    result = write_result(store, session_id=session_id, **kwargs)
    assert result["ok"] is False
    assert result["code"] == "error"


def test_write_result_unknown_session() -> None:
    store = SessionStore()
    result = write_result(store, session_id="nope", text="hi")
    assert result["ok"] is False
    assert result["code"] == "unknown_session"


def test_write_result_survives_a_hardware_failure() -> None:
    store = SessionStore()
    fake = ByteQueueSerial()
    fake.raise_on_write = OSError("device unplugged")
    session_id, _ = _opened_session(store, fake)

    result = write_result(store, session_id=session_id, text="hi")
    assert result["ok"] is False
    assert result["code"] == "error"


# ---------------------------------------------------------------------------
# serial_read — §5.3's binary rule is the point of this section.
# ---------------------------------------------------------------------------


def test_read_result_returns_decoded_text_and_hex() -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"OK\r\n"))

    result = read_result(store, session_id=session_id, max_bytes=4, timeout_s=1)
    assert result["ok"] is True
    assert result["text"] == "OK\r\n"
    assert result["hex"] == "4f4b0d0a"
    assert result["bytes"] == 4
    assert result["timed_out"] is False  # the requested max_bytes was filled


def test_read_result_reads_until_the_marker() -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"hello\nmore-data-not-read"))

    result = read_result(store, session_id=session_id, until="\n", timeout_s=1)
    assert result["ok"] is True
    assert result["text"] == "hello\n"
    assert result["timed_out"] is False


def test_read_result_with_no_until_and_no_max_bytes_times_out_by_definition() -> None:
    """§6.1: "with neither `until` nor a full `max_bytes` the read returns
    at the timeout with `timed_out: true`" — even though data did arrive."""
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"partial"))

    result = read_result(store, session_id=session_id, timeout_s=0.05)
    assert result["ok"] is True
    assert result["text"] == "partial"
    assert result["timed_out"] is True


def test_read_result_with_an_until_marker_never_seen_times_out() -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"no marker here"))

    result = read_result(store, session_id=session_id, until="XYZ", timeout_s=0.05)
    assert result["ok"] is True
    assert result["timed_out"] is True


def test_read_result_unknown_session() -> None:
    store = SessionStore()
    result = read_result(store, session_id="ghost")
    assert result["ok"] is False
    assert result["code"] == "unknown_session"


@pytest.mark.parametrize("max_bytes", [0, -1, True, "10"])
def test_read_result_rejects_a_bad_max_bytes(max_bytes) -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store)
    result = read_result(store, session_id=session_id, max_bytes=max_bytes)
    assert result["ok"] is False
    assert result["code"] == "error"


def test_read_result_clamps_timeout_to_twenty_seconds() -> None:
    store = SessionStore()
    fake = ByteQueueSerial(b"x")
    session_id, _ = _opened_session(store, fake)

    read_result(store, session_id=session_id, timeout_s=999, max_bytes=1)
    assert fake.timeout is not None
    assert fake.timeout <= MAX_READ_TIMEOUT_S


# --- The mutation-test the brief asks for: non-UTF-8 device output --------


def test_read_result_refuses_non_utf8_bytes_rather_than_mangling_or_passing_them_through() -> None:
    """This is the specific scenario the brief calls "the single most likely
    place in the whole build to return raw binary by accident": a device
    handing back bytes that are not valid UTF-8 (0xFF is not a valid UTF-8
    lead or continuation byte in any position).

    A broken implementation that did `raw.decode("utf-8", errors="replace")`
    or `errors="ignore"` would return `ok: true` here with mangled text —
    this test fails loudly against exactly that mutation, which was verified
    by hand during development (see the final report)."""
    store = SessionStore()
    non_utf8 = b"\xff\xfe\x00\x01garbage"
    session_id, _ = _opened_session(store, ByteQueueSerial(non_utf8))

    result = read_result(store, session_id=session_id, max_bytes=len(non_utf8), timeout_s=1)

    assert result["ok"] is False
    assert result["code"] == "error"
    assert "text" not in result
    assert "hex" not in result
    assert str(len(non_utf8)) in result["reason"]
    assert "binary transfer is not available yet" in result["reason"]


def test_read_result_survives_a_hardware_failure() -> None:
    store = SessionStore()
    fake = ByteQueueSerial()
    fake.raise_on_read = OSError("device unplugged")
    session_id, _ = _opened_session(store, fake)

    result = read_result(store, session_id=session_id, max_bytes=1, timeout_s=0.05)
    assert result["ok"] is False
    assert result["code"] == "error"


# --- Rework cycle 1, finding 1: a cap/timeout cutting mid-character must ---
# --- not be reported as the device's fault. -------------------------------


def test_read_result_truncated_multibyte_char_is_not_reported_as_a_device_fault() -> None:
    """A device sending perfectly valid non-ASCII UTF-8, cut off mid-character
    by the byte cap, must come back `ok: true` with the complete prefix — not
    `ok: false` blaming the device for something this function did to its own
    stream. `€` encodes as 3 bytes (`e2 82 ac`); capping at 4 of the 5 total
    bytes ("AB" + 2 of the euro sign's 3 bytes) is exactly that cut."""
    euro = "€".encode()
    raw = b"AB" + euro
    assert len(raw) == 5
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(raw))

    result = read_result(store, session_id=session_id, max_bytes=4, timeout_s=1)

    assert result["ok"] is True
    assert result.get("code") is None
    assert result["text"] == "AB", "the incomplete trailing sequence is dropped, not mangled"
    assert result["bytes"] == 4, "the full drained buffer is still reported"
    assert result["hex"] == raw[:4].hex(), "nothing is silently lost — it's in hex"
    assert result["timed_out"] is False  # the requested max_bytes was filled


def test_read_result_truncated_at_the_timeout_rather_than_the_cap_is_also_not_a_fault() -> None:
    """Same defect, reached via the other stop condition: no `max_bytes`
    given, the read stops at the timeout with whatever is in the buffer,
    which can just as easily end mid-character."""
    euro = "€".encode()
    raw = b"AB" + euro[:2]
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(raw))

    result = read_result(store, session_id=session_id, timeout_s=0.05)

    assert result["ok"] is True
    assert result["text"] == "AB"
    assert result["bytes"] == len(raw)
    assert result["timed_out"] is True  # neither `until` nor a full `max_bytes` — §6.1


# ---------------------------------------------------------------------------
# Rework cycle 1, finding 2: the 60,000-*character* cap is enforced
# independently of whatever byte bound produced the text.
# ---------------------------------------------------------------------------


def test_cap_read_text_enforces_the_character_cap() -> None:
    long_text = "x" * (MAX_READ_CHARS + 500)
    assert len(_cap_read_text(long_text)) == MAX_READ_CHARS


def test_cap_read_text_reads_the_limit_dynamically_not_at_import_time(monkeypatch) -> None:
    """Proves the post-decode check is a live guard, not a value baked in at
    definition time — so tuning `MAX_READ_BYTES` independently of the
    character cap (finding 2's actual worry) cannot silently exceed it."""
    monkeypatch.setattr(serial_main, "MAX_READ_CHARS", 3)
    assert _cap_read_text("abcdef") == "abc"


# ---------------------------------------------------------------------------
# Rework cycle 1, finding 3 & 4: `until=""` and a surrogate-bearing `until`.
# ---------------------------------------------------------------------------


def test_read_result_rejects_an_empty_until_explicitly() -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"data"))

    result = read_result(store, session_id=session_id, until="", timeout_s=0.05)

    assert result["ok"] is False
    assert result["code"] == "error"
    assert "until" in result["reason"]


def test_read_result_rejects_a_surrogate_bearing_until_without_crashing() -> None:
    store = SessionStore()
    session_id, _ = _opened_session(store, ByteQueueSerial(b"data"))

    result = read_result(store, session_id=session_id, until="\ud800", timeout_s=0.05)

    assert result["ok"] is False
    assert result["code"] == "error"
    assert "cannot be represented" in result["reason"]


def test_write_result_rejects_a_surrogate_bearing_text_without_crashing() -> None:
    """Same class of bug, same fix, on the write side's `text` argument —
    not one of the four numbered findings, but the same "assume any
    caller-supplied string can be surrogate-bearing" principle applied
    where the same `.encode("utf-8")` call exists."""
    store = SessionStore()
    session_id, _ = _opened_session(store)

    result = write_result(store, session_id=session_id, text="\ud800")

    assert result["ok"] is False
    assert result["code"] == "error"
    assert "cannot be represented" in result["reason"]


# ---------------------------------------------------------------------------
# Rework cycle 1, finding 5: the session cap's blast radius.
# ---------------------------------------------------------------------------


def test_open_result_refusal_names_when_the_oldest_session_will_free_up() -> None:
    store = SessionStore()
    handles = [ByteQueueSerial() for _ in range(5)]
    it = iter(handles)
    for _ in range(4):
        open_result(store, port="COM3", baud=9600, open_fn=lambda *_a, **_kw: next(it))

    fifth = open_result(store, port="COM3", baud=9600, open_fn=lambda *_a, **_kw: next(it))

    assert fifth["ok"] is False
    assert "free up in about" in fifth["reason"], (
        "the refusal should say relief is coming, even though no per-caller "
        "isolation is possible from the plugin side (see the module docstring)"
    )


# ---------------------------------------------------------------------------
# serial_close
# ---------------------------------------------------------------------------


def test_close_result_releases_the_port() -> None:
    store = SessionStore()
    fake = ByteQueueSerial()
    session_id, _ = _opened_session(store, fake)

    result = close_result(store, session_id=session_id)
    assert result == {"ok": True, "session_id": session_id}
    assert fake.closed is True
    assert store.get(session_id) is None


def test_close_result_unknown_session() -> None:
    store = SessionStore()
    result = close_result(store, session_id="ghost")
    assert result["ok"] is False
    assert result["code"] == "unknown_session"
