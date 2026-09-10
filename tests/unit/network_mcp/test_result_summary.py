"""The leading summary that survives the core's truncation.

The core spills a long tool result to a workspace file and shows the model only
the first ``long_item_chars`` characters — default 8,000, owner configurable,
and seen as low as 1,000 — plus a line saying where it was saved. The model is
not told to open the file. So a result whose answer is not in the first
1,000 characters is, in practice, a result that answered nothing.

**These tests simulate the truncation rather than asserting a key exists.** A
test that checks ``"summary" in envelope`` proves nothing about whether the
summary survives the cut; every test that matters here serialises exactly as
:func:`~workstation_agent.network_mcp.server._render` does — by calling it —
slices the result at 1,000 characters, and asserts on what is left.

All hardware in this file is invented. Vendor and product ids are made up, the
product names are fictional brands, and the shape (a hub tree, devices that
enumerate three or four times each) is modelled from the general behaviour of
USB enumeration on Windows, not from any particular machine.
"""

from __future__ import annotations

import json

import pytest

from workstation_agent.network_mcp.server import (
    MAX_SUMMARY_CHARS,
    RESULT_CHAR_CAP,
    _group_usb,
    _render,
    _with_summary,
)

#: What the core keeps of a long result in the worst configuration observed.
WINDOW = 1000

STAMP = "2031-04-02T09:15:44.201773+00:00"


def usb(vid: str | None, pid: str | None, name: str, cls: str = "USB", port: str = "P1") -> dict:
    """One §6.1 ``usb`` row. ``present_since`` is required and so is kept."""
    return {
        "vid": vid, "pid": pid, "name": name, "class": cls,
        "port": port, "present_since": STAMP,
    }


def populated_desktop() -> dict:
    """A synthetic ``devices_list`` envelope with the shape a real desk produces.

    Fifty-three entries; twenty of them hubs; eight recognisable devices, each
    of which enumerates three or four times under different classes; seven
    leftover interfaces Windows labels generically. The point of the fixture is
    the *ratio* — dozens of entries, under ten things a person would name.
    """
    rows: list[dict] = [
        usb("05e3", "0608", "Generic USB Hub", "USB", f"Port_#{i:04d}.Hub_#0001")
        for i in range(20)
    ]
    rows.extend(
        usb("2b1c", "4d01", "Orbital 4K Webcam", cls, "Port_#0021.Hub_#0002")
        for cls in ("MEDIA", "Image", "USB", "HIDClass")
    )
    rows.append(usb("3f7a", "1102", "USB Composite Device", "USB", "Port_#0022.Hub_#0002"))
    rows.append(usb("3f7a", "1102", "USB Input Device", "HIDClass", "Port_#0022.Hub_#0002"))
    rows.append(usb("3f7a", "1102", "USB Input Device", "HIDClass", "Port_#0022.Hub_#0002"))
    rows.append(usb("3f7a", "1102", "Aurora RGB Controller", "USB", "Port_#0022.Hub_#0002"))
    for vid, pid, name in (
        ("4c21", "9001", "Meridian Keyboard"),
        ("4c21", "9002", "Meridian Mouse"),
        ("7e30", "2200", "Vantage Audio Interface"),
        ("7e30", "3311", "Vantage Stream Deck"),
        ("6a11", "5001", "Falcon Wheel"),
        ("6a11", "5002", "Falcon Pedals"),
    ):
        rows.append(usb(vid, pid, "USB Composite Device", "USB", "Port_#0030.Hub_#0003"))
        rows.append(usb(vid, pid, "USB Input Device", "HIDClass", "Port_#0030.Hub_#0003"))
        rows.append(usb(vid, pid, name, "USB", "Port_#0030.Hub_#0003"))
    rows.extend(
        usb("1d6b", f"01{i:02d}", "USB Input Device", "HIDClass", f"0000.00{i}")
        for i in range(7)
    )
    return {
        "ok": True,
        "usb": rows,
        "adb": [],
        "com": [{"port": "COM4", "description": "A serial port", "vid": None, "pid": None}],
    }


def shell_result(stdout: str, stderr: str = "", exit_code: int = 0) -> dict:
    """A §6.1 ``shell_run`` envelope for a command that finished in time."""
    return {
        "ok": True, "job_id": None, "exit_code": exit_code,
        "stdout": stdout, "stderr": stderr, "duration_s": 1.25,
    }


def summary_of(text: str) -> str:
    """The summary as a reader of a *truncated* block would recover it.

    Decoded off the front of the raw text rather than by parsing the whole
    envelope, because the whole envelope is exactly what such a reader does not
    have: a result past §5.3's cap is cut mid-payload and is not valid JSON.
    That the leading summary is still readable when the rest is not is the
    property under test, so the helper must not depend on the rest.
    """
    assert text.startswith('{"summary": "'), text[:60]
    value, _end = json.JSONDecoder().raw_decode(text, len('{"summary": '))
    return value


# ---------------------------------------------------------------------------
# The property everything else depends on: the summary is FIRST
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "envelope"),
    [
        ("devices_list", populated_desktop()),
        ("shell_run", shell_result("done\n")),
    ],
)
def test_the_summary_begins_at_character_two_of_the_serialised_text(name, envelope):
    """Asserted on offsets, not on key presence.

    Dict insertion order is what puts the summary inside the core's window, and
    it is exactly the kind of property a later reordering breaks in silence. So
    this test pins the literal offset: the serialised text opens with the
    summary key and nothing else precedes it.
    """
    text = _render(name, envelope)
    assert text.startswith('{"summary": "'), text[:60]
    assert text.index('"summary"') == 1
    # Every payload key comes after it, by offset.
    for key in envelope:
        if key != "summary":
            assert text.index(f'"{key}"') > text.index('"summary"')


def test_the_summary_is_before_the_window_even_at_its_maximum_size():
    """A summary at its budget still leaves most of the window for payload."""
    text = _render("devices_list", populated_desktop())
    end_of_summary = text.index('", "ok"') + 1
    assert end_of_summary < WINDOW
    assert WINDOW - end_of_summary > 600, "the summary must not eat the window"


# ---------------------------------------------------------------------------
# devices_list: the answer survives the cut
# ---------------------------------------------------------------------------


def test_without_the_summary_the_window_answers_nothing():
    """The baseline this change exists to beat.

    Serialised without a summary, the first 1,000 characters of a populated
    desktop are a handful of hub entries: no count, no total, and not one name
    a person would recognise.
    """
    bare = json.dumps(populated_desktop(), ensure_ascii=False, default=str)[:WINDOW]
    assert "Orbital 4K Webcam" not in bare
    assert "Meridian Keyboard" not in bare
    assert bare.count('"name": "Generic USB Hub"') >= 3
    # No count of anything survives: the reader cannot even say how many entries
    # there are, because the list's end is 7,000 characters away.
    assert "53" not in bare


def test_the_device_counts_and_names_survive_a_1000_character_cut():
    """The test that matters: cut where the core cuts, then read the answer."""
    text = _render("devices_list", populated_desktop())
    assert len(text) > WINDOW * 8, "the fixture must actually overflow the window"

    window = text[:WINDOW]
    summary = summary_of(text)
    # The summary is wholly inside what the core would keep — asserted by
    # containment in the truncated window, not by presence in the envelope.
    assert summary in window

    assert "53 entries" in summary
    assert "8 named devices" in summary
    assert "20 hub entries" in summary
    assert "COM 1" in summary
    for name in (
        "Orbital 4K Webcam", "Aurora RGB Controller", "Meridian Keyboard",
        "Meridian Mouse", "Vantage Audio Interface", "Vantage Stream Deck",
        "Falcon Wheel", "Falcon Pedals",
    ):
        assert name in window, f"{name} fell outside the core's window"


def test_the_summary_collapses_enumeration_entries_into_distinct_devices():
    """Fifty-three entries are eight things. Reporting fifty-three reports noise."""
    named, unnamed, hubs, total = _group_usb(populated_desktop()["usb"])
    assert total == 53
    assert hubs == 20
    assert len(named) == 8
    assert unnamed == 7
    # The webcam enumerated four times and is one device with four entries.
    assert ("Orbital 4K Webcam", 4) in named


def test_a_device_is_listed_under_its_product_name_not_its_generic_interface():
    """The RGB controller enumerates three times generically and once by name."""
    named, _unnamed, _hubs, _total = _group_usb(populated_desktop()["usb"])
    names = [name for name, _ in named]
    assert "Aurora RGB Controller" in names
    assert "USB Composite Device" not in names
    assert "USB Input Device" not in names


def test_hub_entries_are_counted_never_listed():
    """Nobody plugged in a hub's enumeration structure; it is not an answer."""
    text = _render("devices_list", populated_desktop())
    summary = summary_of(text)
    assert "20 hub entries" in summary
    assert "Generic USB Hub" not in summary


def test_two_identical_models_collapse_and_the_summary_does_not_claim_otherwise():
    """The documented failure mode of grouping on vid/pid, pinned deliberately.

    Two of the same mouse share a vendor and product id, so they group into one
    entry. The summary therefore says "named devices", counted distinctly, and
    the payload keeps both rows — which is what makes the error recoverable.
    """
    envelope = {
        "ok": True,
        "usb": [
            usb("4c21", "9002", "Meridian Mouse", "HIDClass", "Port_#0001"),
            usb("4c21", "9002", "Meridian Mouse", "HIDClass", "Port_#0002"),
        ],
        "adb": [], "com": [],
    }
    named, _unnamed, _hubs, total = _group_usb(envelope["usb"])
    assert total == 2
    assert named == [("Meridian Mouse", 2)]
    # The payload still carries both, on their two different ports.
    result = json.loads(_render("devices_list", envelope))
    assert len(result["usb"]) == 2
    assert {row["port"] for row in result["usb"]} == {"Port_#0001", "Port_#0002"}


def test_a_degraded_enumeration_looks_degraded_in_the_summary():
    """Otherwise a reader reports "nothing attached" for "the enumerator failed"."""
    envelope = populated_desktop()
    envelope["notes"] = ["USB devices could not be enumerated on this workstation."]
    summary = summary_of(_render("devices_list", envelope))
    assert "Incomplete: 1 source" in summary


def test_the_summary_makes_no_claim_about_which_machine_answered():
    """The summary must not name the machine, and this pins that it does not.

    The core routed the call to one workstation and already knows which one
    replied, so an identity here answers nothing that was asked. The only
    identity this module can reach is the OS hostname, which is not necessarily
    the display name the owner typed at Join — and one machine under two names,
    in the field designed to be the part that always survives, is the same
    defect as ``shell_run`` versus ``shell.run``. If machine identity in a
    result is wanted later it comes from the *enrolled* identity, deliberately.
    """
    import platform

    from workstation_agent.network_mcp import server as mod

    summary = summary_of(_render("devices_list", populated_desktop()))
    assert summary.startswith("USB: ")
    assert platform.node() not in summary
    # And the endpoint has no machine-name helper to drift back in through.
    assert not hasattr(mod.NetworkMCPServer, "_hostname")
    assert not hasattr(mod, "platform")


def test_a_long_device_list_is_elided_rather_than_allowed_to_eat_the_window():
    envelope = {
        "ok": True,
        "usb": [usb(f"aa{i:02d}", "0001", f"Fictional Peripheral Model {i}") for i in range(40)],
        "adb": [], "com": [],
    }
    summary = summary_of(_render("devices_list", envelope))
    assert len(summary) <= MAX_SUMMARY_CHARS
    assert "more)" in summary
    assert "40 named devices" in summary, "the count is complete even when the list is not"


# ---------------------------------------------------------------------------
# shell_run: the verdict survives the cut
# ---------------------------------------------------------------------------


def test_the_shell_verdict_survives_a_1000_character_cut():
    noise = "\n".join(f"Copying file {i} of 4000..." for i in range(4000))
    envelope = shell_result(f"{noise}\nTotalPhysicalMemory : 68719476736\n")
    text = _render("shell_run", envelope)
    assert len(text) > WINDOW * 50

    window = text[:WINDOW]
    summary = summary_of(text)
    assert summary in window
    assert "exit 0 (succeeded)" in summary
    assert "TotalPhysicalMemory : 68719476736" in window


def test_the_summary_quotes_the_tail_because_the_verdict_is_at_the_end():
    """A command's answer is at the end; its banners and progress are at the start."""
    envelope = shell_result("BANNER LINE\nprogress\nprogress\nTHE ANSWER IS 42\n")
    summary = summary_of(_render("shell_run", envelope))
    assert "THE ANSWER IS 42" in summary
    assert "BANNER LINE" not in summary


def test_a_failing_command_quotes_stderr_and_says_it_failed():
    envelope = shell_result(
        "some output\n",
        stderr="Traceback (most recent call last):\n  ...\nValueError: no such widget\n",
        exit_code=1,
    )
    summary = summary_of(_render("shell_run", envelope))
    assert "exit 1 (FAILED)" in summary
    assert "ValueError: no such widget" in summary


def test_a_failing_command_with_a_silent_stderr_still_quotes_something():
    summary = summary_of(
        _render("shell_run", shell_result("the only clue\n", exit_code=9)),
    )
    assert "exit 9 (FAILED)" in summary
    assert "the only clue" in summary


def test_the_summary_reports_the_size_of_what_it_did_not_quote():
    envelope = shell_result("line\n" * 500)
    summary = summary_of(_render("shell_run", envelope))
    assert "stdout 500 lines/2500 chars" in summary
    assert "stderr 0 lines/0 chars" in summary


def test_a_job_that_outlived_its_wait_says_so_and_says_how_to_finish_it():
    """§5.4: there is no exit code yet, so the summary must not invent one."""
    envelope = {
        "ok": True, "job_id": "j-7f3a", "state": "running",
        "output": "still working\nnearly there\n", "output_bytes": 27,
    }
    summary = summary_of(_render("shell_run", envelope))
    assert summary.startswith("Still running as job j-7f3a")
    assert "27 bytes so far" in summary
    assert "jobs_wait" in summary
    assert "nearly there" in summary
    # No verdict is claimed, because there is not one yet.
    assert "succeeded" not in summary
    assert "FAILED" not in summary


def test_an_empty_command_output_summarises_without_a_quote():
    summary = summary_of(_render("shell_run", shell_result("")))
    assert "exit 0 (succeeded)" in summary
    assert "Last" not in summary


# ---------------------------------------------------------------------------
# The payload is added to, never substituted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "envelope"),
    [
        ("devices_list", populated_desktop()),
        ("shell_run", shell_result("hello\nworld\n", stderr="warn\n", exit_code=3)),
    ],
)
def test_the_payload_is_untouched_by_the_summary(name, envelope):
    """A caller who reads the whole block must be no worse off than before."""
    rendered = json.loads(_render(name, envelope))
    del rendered["summary"]
    assert rendered == envelope


def test_the_full_device_rows_including_their_provenance_still_arrive():
    """§6.1 requires ``present_since``; the summary does not license dropping it."""
    result = json.loads(_render("devices_list", populated_desktop()))
    assert len(result["usb"]) == 53
    assert all(row["present_since"] == STAMP for row in result["usb"])
    assert all("port" in row for row in result["usb"])


# ---------------------------------------------------------------------------
# Restraint: who gets a summary, how big, and what happens when it goes wrong
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "envelope"),
    [
        ("devices_list", populated_desktop()),
        ("shell_run", shell_result("x\n" * 2000, stderr="y\n" * 2000, exit_code=1)),
        # Every pressure that can inflate a device summary at once: many groups,
        # each with a name far past the per-name allowance, plus long tails.
        ("devices_list", {
            "ok": True,
            "usb": [usb(f"bb{i:02d}", "0001", f"Fictional Peripheral With A Very Long Name {i}")
                    for i in range(30)],
            "adb": [{"serial": f"SERIAL{i:04d}", "state": "device", "model": None}
                    for i in range(6)],
            "com": [{"port": f"COM{i}", "description": "d", "vid": None, "pid": None}
                    for i in range(9)],
            "notes": ["one source failed"],
        }),
    ],
)
def test_the_summary_stays_inside_its_budget(name, envelope):
    assert len(summary_of(_render(name, envelope))) <= MAX_SUMMARY_CHARS


@pytest.mark.parametrize(
    ("name", "envelope"),
    [
        # The four shapes, including the two that skip optional clauses.
        ("devices_list", populated_desktop()),
        ("devices_list", {"ok": True, "usb": [], "adb": [], "com": []}),
        ("shell_run", shell_result("output\n")),
        ("shell_run", shell_result("", stderr="", exit_code=4)),
        ("shell_run", {"ok": True, "job_id": "j-1", "state": "running",
                       "output": "working\n", "output_bytes": 8}),
        ("shell_run", {"ok": True, "job_id": "j-1", "state": "running",
                       "output": "", "output_bytes": 0}),
    ],
)
def test_no_summary_shape_leaves_a_stray_separator(name, envelope):
    """Dropping the machine-name prefix must not leave a dangling ": " or gap."""
    summary = summary_of(_render(name, envelope))
    assert summary == summary.strip()
    assert "  " not in summary
    # No leading or dangling separator where the machine-name prefix used to be.
    assert not summary.startswith((":", ".", ",", "|", " "))
    assert not summary.endswith((":", ",", "|"))
    for stray in (": .", " .", " ,", "..", ",,", "| |", ": :", " :"):
        assert stray not in summary, f"stray {stray!r} in {summary!r}"
    # A clause that ends in a quoted tail ends with whatever the command
    # printed; every other shape ends with its own full stop.
    assert summary.endswith((".", "…")) or ": " in summary


@pytest.mark.parametrize(
    "name", ["workstation_status", "files_read", "jobs_list", "serial_read", "adb_devices"],
)
def test_a_tool_without_a_summariser_is_serialised_exactly_as_before(name):
    envelope = {"ok": True, "hostname": "W", "uptime_s": 5}
    assert _render(name, envelope) == json.dumps(
        envelope, ensure_ascii=False, default=str,
    )


@pytest.mark.parametrize("code", ["denied", "unconfirmed", "not_found", "timeout", "error"])
def test_a_failure_envelope_gets_no_summary(code):
    """It is already short and already answers itself; a summary would only cost."""
    envelope = {"ok": False, "code": code, "reason": "It did not work."}
    assert _with_summary("devices_list", envelope) == envelope


@pytest.mark.parametrize(
    "envelope",
    [
        {"ok": True},
        {"ok": True, "usb": "not a list", "adb": [], "com": []},
        {"ok": True, "usb": [None, 3, "x"], "adb": [], "com": []},
        {"ok": True, "usb": [{}], "adb": [], "com": []},
        {"ok": True, "stdout": None, "stderr": None, "exit_code": None},
    ],
)
def test_a_malformed_result_is_never_made_worse_by_summarising_it(envelope):
    for name in ("devices_list", "shell_run"):
        out = _with_summary(name, dict(envelope))
        assert out["ok"] is True
        for key, value in envelope.items():
            assert out[key] == value


def test_a_summariser_that_raises_never_costs_the_caller_the_result(monkeypatch):
    from workstation_agent.network_mcp import server as mod

    def explode(_envelope):
        msg = "the summariser is broken"
        raise RuntimeError(msg)

    monkeypatch.setitem(mod._SUMMARISERS, "devices_list", explode)
    envelope = populated_desktop()
    assert _with_summary("devices_list", envelope) == envelope


def test_a_summary_a_plugin_supplied_itself_is_hoisted_but_not_rewritten():
    """Position is ours to fix; wording is the plugin's to keep."""
    envelope = {"ok": True, "summary": "The plugin said it better.", "usb": [], "adb": [],
                "com": []}
    text = _render("devices_list", envelope)
    assert text.index('"summary"') == 1
    assert summary_of(text) == "The plugin said it better."


# ---------------------------------------------------------------------------
# §5.3 still holds with the summary on
# ---------------------------------------------------------------------------


def test_the_serialised_text_never_leaves_the_workstation_over_the_cap():
    """The summary adds characters, so the cap is enforced on what actually leaves."""
    envelope = shell_result("z" * (RESULT_CHAR_CAP - 100))
    text = _render("shell_run", envelope)
    assert len(text) <= RESULT_CHAR_CAP
    assert "more characters; use jobs_output to page" in text


def test_a_result_inside_the_cap_is_not_touched_by_the_cap():
    envelope = shell_result("small\n")
    text = _render("shell_run", envelope)
    assert "more characters" not in text
    assert json.loads(text)["stdout"] == "small\n"
