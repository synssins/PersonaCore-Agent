"""The ``adb`` family, driven through a fake ``adb`` that really executes.

Every test that touches a tool spawns a real subprocess with real argv, real
pipes and a real exit code — see ``conftest.FakeAdb``.  Patching
``subprocess.run`` would skip exactly the layer the brief warns about.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from tests.unit.plugins.conftest import (
    NO_DEVICES,
    ONE_DEVICE,
    TWO_DEVICES,
    UNAUTHORISED,
)
from workstation_agent.plugins import adb

# ---------------------------------------------------------------------------
# Finding adb.exe
# ---------------------------------------------------------------------------


def test_the_configured_path_wins_over_path(tmp_path, monkeypatch):
    binary = tmp_path / "adb.exe"
    binary.write_bytes(b"")
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    (appdata / "config.toml").write_text(
        f'[adb]\nbinary_path = "{binary.as_posix()}"\n', encoding="utf-8",
    )
    monkeypatch.setenv("PC_AGENT_APPDATA", str(appdata))
    assert Path(adb.resolve_adb_path()) == binary


def test_a_configured_path_that_does_not_exist_is_an_error_not_a_silent_fallback(
    tmp_path, monkeypatch,
):
    """An operator who pointed the Agent at a specific ADB and silently got a
    different one would have no way to tell."""
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    (appdata / "config.toml").write_text(
        '[adb]\nbinary_path = "C:/nope/adb.exe"\n', encoding="utf-8",
    )
    monkeypatch.setenv("PC_AGENT_APPDATA", str(appdata))
    with pytest.raises(adb.AdbNotFoundError) as excinfo:
        adb.resolve_adb_path()
    assert "does not exist" in str(excinfo.value)


def test_no_adb_anywhere_names_the_remedy(tmp_path, monkeypatch):
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))
    monkeypatch.setattr(adb.shutil, "which", lambda _name: None)
    monkeypatch.setattr(adb, "_WELL_KNOWN_ADB_DIRS", ())
    with pytest.raises(adb.AdbNotFoundError) as excinfo:
        adb.resolve_adb_path()
    assert "platform-tools" in str(excinfo.value)


def test_a_malformed_config_file_falls_back_rather_than_crashing(tmp_path, monkeypatch):
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    (appdata / "config.toml").write_text("this is not toml = = =", encoding="utf-8")
    monkeypatch.setenv("PC_AGENT_APPDATA", str(appdata))
    monkeypatch.setattr(adb.shutil, "which", lambda _name: "C:/found/adb.exe")
    assert adb.resolve_adb_path() == "C:/found/adb.exe"


# ---------------------------------------------------------------------------
# Where ADB may keep its key — the low-integrity failure mode
# ---------------------------------------------------------------------------


def test_the_adb_home_is_chosen_by_writing_not_by_guessing(tmp_path, monkeypatch):
    """A low-integrity process cannot write to %USERPROFILE% or plain %TEMP%.

    Which candidate works is a property of the running token, so it is decided
    by attempting the write rather than by reasoning about the path.
    """
    unwritable = tmp_path / "unwritable"
    monkeypatch.setattr(adb, "_is_writable", lambda p: "good" in str(p))
    home = adb.resolve_adb_home((str(unwritable), str(tmp_path / "good")))
    assert home is not None
    assert "good" in home


def test_no_writable_adb_home_is_reported_as_none_not_papered_over(monkeypatch):
    """``None`` means ADB will fall back to %USERPROFILE%\\.android, fail to
    write its key, and report every device as ``unauthorized`` forever."""
    monkeypatch.setattr(adb, "_is_writable", lambda _p: False)
    assert adb.resolve_adb_home(("%TEMP%\\a", "%TEMP%\\b")) is None


def test_a_candidate_with_an_unexpanded_variable_is_skipped(monkeypatch):
    monkeypatch.setattr(adb, "_is_writable", lambda _p: True)
    assert adb.resolve_adb_home(("%NO_SUCH_VARIABLE_AT_ALL%\\adb",)) is None


def test_the_adb_child_env_carries_android_user_home(monkeypatch, tmp_path):
    monkeypatch.setattr(adb, "resolve_adb_home", lambda: str(tmp_path))
    env = adb.build_adb_env()
    assert env["ANDROID_USER_HOME"] == str(tmp_path)
    assert env["HOME"] == str(tmp_path)


def test_the_env_whitelist_cannot_carry_an_adb_setting():
    """Why the adb path is read from disk and not from the environment.

    ``supervisor.ENV_WHITELIST`` is an exact list and B6 owns that file, so a
    ``PC_AGENT_ADB_PATH`` variable would never reach the child.  ``APPDATA``
    is on it, so the config file is reachable.  If this ever stops being true
    the simpler design becomes available and this test says so.
    """
    from workstation_agent.mcp_host.supervisor import ENV_WHITELIST

    assert "APPDATA" in ENV_WHITELIST
    assert not any(name.startswith("PC_AGENT") for name in ENV_WHITELIST)
    assert not any("ADB" in name.upper() for name in ENV_WHITELIST)


# ---------------------------------------------------------------------------
# adb devices
# ---------------------------------------------------------------------------


def test_devices_output_is_parsed_into_section_6_1_rows():
    rows = adb.parse_devices_output(ONE_DEVICE)
    assert rows == [{"serial": "R58N12ABCDE", "state": "device", "model": "SM_G973F"}]


def test_a_device_with_no_model_reports_null_not_an_empty_string():
    rows = adb.parse_devices_output(UNAUTHORISED)
    assert rows == [{"serial": "R58N12ABCDE", "state": "unauthorized", "model": None}]


def test_a_state_section_6_1_does_not_list_is_passed_through_not_relabelled():
    """Calling a bootloader "offline" would be a lie about what is attached."""
    rows = adb.parse_devices_output(
        "List of devices attached\nR58N12ABCDE   bootloader\n",
    )
    assert rows[0]["state"] == "bootloader"


def test_adb_devices_runs_the_real_binary_and_returns_the_list(one_device):
    result = adb.adb_devices(adb_path=one_device.path)
    assert result["ok"] is True
    assert result["devices"][0]["serial"] == "R58N12ABCDE"
    assert one_device.calls[0] == ["devices", "-l"]


def test_adb_devices_with_no_binary_is_not_found():
    result = adb.adb_devices(adb_path=str(Path("C:/definitely/not/here/adb.exe")))
    assert result["ok"] is False
    assert result["code"] == "not_found"


# ---------------------------------------------------------------------------
# Serial resolution — §6: "optional when exactly one device is attached"
# ---------------------------------------------------------------------------


def test_one_attached_device_needs_no_serial(one_device):
    prefix, refusal = adb.resolve_serial(None, adb_path=one_device.path)
    assert refusal is None
    assert prefix == ["-s", "R58N12ABCDE"]


def test_two_attached_devices_refuse_rather_than_choose(fake_adb):
    """Picking one for the operator is how a command meant for the test phone
    runs on the production one."""
    fake_adb.script([fake_adb.devices(TWO_DEVICES)])
    prefix, refusal = adb.resolve_serial(None, adb_path=fake_adb.path)
    assert prefix == []
    assert refusal is not None
    assert refusal["ok"] is False
    assert "R58N12ABCDE" in refusal["reason"]
    assert "emulator-5554" in refusal["reason"]


def test_no_attached_device_is_not_found(fake_adb):
    fake_adb.script([fake_adb.devices(NO_DEVICES)])
    _prefix, refusal = adb.resolve_serial(None, adb_path=fake_adb.path)
    assert refusal is not None
    assert refusal["code"] == "not_found"


def test_an_unauthorised_device_says_to_unlock_the_phone(fake_adb):
    fake_adb.script([fake_adb.devices(UNAUTHORISED)])
    _prefix, refusal = adb.resolve_serial(None, adb_path=fake_adb.path)
    assert refusal is not None
    assert refusal["code"] == "not_found"
    assert "USB debugging" in refusal["reason"]


def test_an_explicit_serial_skips_enumeration_entirely(fake_adb):
    prefix, refusal = adb.resolve_serial("EXPLICIT1", adb_path=fake_adb.path)
    assert refusal is None
    assert prefix == ["-s", "EXPLICIT1"]
    assert fake_adb.calls == []


# ---------------------------------------------------------------------------
# adb_shell — §11 item 2's path
# ---------------------------------------------------------------------------


def test_getprop_returns_the_model_name(fake_adb):
    """Contract §11 item 2, minus the prompt (§7's always-prompt list is B3's).

    This is the done-when criterion that runs through this family.
    """
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["shell", "getprop ro.product.model"], "stdout": "SM-G973F\n"},
    ])
    result = adb.adb_shell("getprop ro.product.model", adb_path=fake_adb.path)
    assert result["ok"] is True
    assert result["job_id"] is None, "§5.4: finished inside wait_s means job_id null"
    assert result["exit_code"] == 0
    assert result["stdout"].strip() == "SM-G973F"
    assert set(result) >= {"ok", "job_id", "exit_code", "stdout", "stderr", "duration_s"}
    assert ["-s", "R58N12ABCDE", "shell", "getprop ro.product.model"] in fake_adb.calls


def test_a_command_that_outlives_wait_s_returns_a_job_handle(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["shell"], "sleep": 3, "stdout": "partial"},
    ])
    result = adb.adb_shell("sleep 30", wait_s=1, adb_path=fake_adb.path)
    assert result["ok"] is True
    assert result["job_id"].startswith("j-adb-")
    assert result["state"] == "running"
    assert "output" in result
    assert "output_bytes" in result


def test_an_empty_command_is_refused_before_a_process_is_spawned(fake_adb):
    result = adb.adb_shell("   ", adb_path=fake_adb.path)
    assert result["ok"] is False
    assert fake_adb.calls == []


def test_a_nonzero_exit_code_is_still_ok_true_with_the_code(fake_adb):
    """A command that failed on the phone is a successful tool call that
    reports a failure — §6.1 puts ``exit_code`` in the result for that."""
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["shell"], "stdout": "", "stderr": "nope\n", "returncode": 1},
    ])
    result = adb.adb_shell("false", adb_path=fake_adb.path)
    assert result["ok"] is True
    assert result["exit_code"] == 1
    assert result["stderr"].strip() == "nope"


# ---------------------------------------------------------------------------
# §5.3 — binary never travels.  One test per tool that captures raw output.
# ---------------------------------------------------------------------------

_NOT_UTF8 = [0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE, 0x00, 0x80, 0x81]


def test_shell_output_that_is_not_utf8_is_refused_not_mangled(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["shell"], "stdout": _NOT_UTF8},
    ])
    result = adb.adb_shell("cat /sdcard/x.png", adb_path=fake_adb.path)
    assert result["ok"] is False
    assert result["code"] == "error"
    assert "not valid UTF-8" in result["reason"]
    assert "binary transfer is not available yet" in result["reason"]
    assert str(len(_NOT_UTF8)) in result["reason"], "§5.3 wants the size"
    assert "\ufffd" not in json.dumps(result), "errors='replace' would hide this"


def test_pull_output_that_is_not_utf8_is_refused(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["exec-out"], "stdout": _NOT_UTF8},
    ])
    result = adb.adb_pull("/sdcard/DCIM/x.jpg", adb_path=fake_adb.path)
    assert result["ok"] is False
    assert result["code"] == "error"
    assert "binary transfer is not available yet" in result["reason"]


def test_logcat_output_that_is_not_utf8_is_refused(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _NOT_UTF8},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert result["ok"] is False
    assert result["code"] == "error"
    assert "binary transfer is not available yet" in result["reason"]


def test_decode_output_never_substitutes_replacement_characters():
    text, refusal = adb.decode_output(bytes(_NOT_UTF8), what="The file")
    assert text is None
    assert refusal is not None
    assert refusal["ok"] is False


# ---------------------------------------------------------------------------
# adb_pull — text only in v1 (§10)
# ---------------------------------------------------------------------------


def test_pull_reads_a_text_file_through_exec_out_not_onto_the_disk(fake_adb):
    """``adb pull`` would write the device's bytes onto this workstation before
    anyone decided whether they are text.  ``exec-out cat`` keeps them in a
    pipe where the UTF-8 test decides whether they may travel."""
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["exec-out", "cat"], "stdout": "hello from the phone\n"},
    ])
    result = adb.adb_pull("/sdcard/note.txt", adb_path=fake_adb.path)
    assert result["ok"] is True
    assert result["content"] == "hello from the phone\n"
    assert result["total_bytes"] == 21
    assert any("exec-out" in call for call in fake_adb.calls)
    assert not any("pull" in call for call in fake_adb.calls)


def test_pull_of_a_missing_device_file_is_not_found(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["exec-out"], "stderr": "cat: /sdcard/nope: No such file or directory\n",
         "returncode": 1},
    ])
    result = adb.adb_pull("/sdcard/nope", adb_path=fake_adb.path)
    assert result["ok"] is False
    assert result["code"] == "not_found"


def test_a_file_over_the_cap_is_refused_not_silently_halved(fake_adb):
    """A half-file that says it succeeded is worse than a refusal, because
    nothing downstream can tell it is half."""
    big = "x" * (adb.MAX_RESULT_CHARS + 10)
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["exec-out"], "stdout": big},
    ])
    result = adb.adb_pull("/sdcard/big.txt", adb_path=fake_adb.path)
    assert result["ok"] is False
    assert result["code"] == "error"
    assert "binary transfer is not available yet" in result["reason"]


# ---------------------------------------------------------------------------
# adb_push / adb_install — workstation paths
# ---------------------------------------------------------------------------


def test_push_of_a_missing_local_file_is_not_found_without_echoing_the_path(fake_adb):
    result = adb.adb_push(
        workstation_path=str(Path("C:/nope/secret-project/plan.txt")),
        device_path="/sdcard/plan.txt",
        adb_path=fake_adb.path,
    )
    assert result["ok"] is False
    assert result["code"] == "not_found"
    assert "secret-project" not in result["reason"], "§5.2: no absolute path in a reason"


def test_push_sends_the_local_path_and_the_device_path_in_that_order(fake_adb, tmp_path):
    local = tmp_path / "note.txt"
    local.write_text("hi", encoding="utf-8")
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["push"], "stdout": "1 file pushed\n"},
    ])
    result = adb.adb_push(str(local), "/sdcard/note.txt", adb_path=fake_adb.path)
    assert result["ok"] is True
    push_call = next(c for c in fake_adb.calls if "push" in c)
    assert push_call[-2:] == [str(local), "/sdcard/note.txt"]


def test_install_passes_the_apk_and_reports_failure_text(fake_adb, tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not really an apk")
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["install"], "stderr": "adb: failed to install: INSTALL_FAILED\n",
         "returncode": 1},
    ])
    result = adb.adb_install(str(apk), adb_path=fake_adb.path)
    assert result["ok"] is False
    assert "INSTALL_FAILED" in result["reason"]


# ---------------------------------------------------------------------------
# adb_logcat — the redaction the brief requires
# ---------------------------------------------------------------------------

_CRASHY_LOG = """\
09-08 12:00:01.100  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main
09-08 12:00:01.100  1234  1234 E AndroidRuntime: java.lang.NullPointerException: boom
\tat com.example.app.MainActivity.onCreate(MainActivity.java:42)
\tat android.app.Activity.performCreate(Activity.java:8051)
Caused by: java.lang.IllegalStateException: inner
\t... 17 more
09-08 12:00:02.200  1234  1300 D OkHttp  : --> GET /v1/me
09-08 12:00:02.201  1234  1300 D OkHttp  : Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.verysecret
09-08 12:00:02.202  1234  1300 D OkHttp  : api_key=abcd1234efgh5678
09-08 12:00:03.300  1234  1300 I App     : done
"""


def test_logcat_removes_java_stack_frames(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _CRASHY_LOG},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert result["ok"] is True
    assert "MainActivity.java:42" not in result["output"]
    assert "Activity.performCreate" not in result["output"]
    assert "Caused by" not in result["output"]
    assert "... 17 more" not in result["output"]


def test_logcat_removes_a_bearer_token(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _CRASHY_LOG},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert "verysecret" not in result["output"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in result["output"]


def test_logcat_removes_a_credential_keyed_value(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _CRASHY_LOG},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert "abcd1234efgh5678" not in result["output"]


def test_logcat_says_how_much_it_redacted(fake_adb):
    """Silent redaction would be worse than none: it makes a truncated log look
    complete."""
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _CRASHY_LOG},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert result["redacted"] > 0


def test_logcat_keeps_the_ordinary_lines(fake_adb):
    """Redaction that ate the whole log would be safe and useless."""
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["logcat"], "stdout": _CRASHY_LOG},
    ])
    result = adb.adb_logcat(adb_path=fake_adb.path)
    assert "FATAL EXCEPTION" in result["output"]
    assert "done" in result["output"]


@pytest.mark.parametrize(
    "survives",
    [
        # Wrapped across two lines, with nothing on the second line the
        # patterns can key on.  (A wrapped value that still says "Bearer" IS
        # caught, by _BEARER — the line-by-line limitation only bites when the
        # keyword and the value are separated *and* the value is unremarkable.)
        "D OkHttp: Authorization:\nD OkHttp: abc123def456",
        # Under the 40-char floor and next to no keyword at all.
        "I App: sent tok_a1b2c3d4e5 upstream",
        # A key nobody listed.
        "I App: shibboleth: swordfish",
    ],
    ids=["wrapped", "short-and-unkeyed", "unlisted-key"],
)
def test_redaction_is_best_effort_and_these_known_cases_get_through(survives):
    """Recorded as a limitation rather than implied by its absence.

    Pattern redaction over arbitrary app-authored log lines cannot be made
    complete.  The mitigation is the ``redacted`` count plus the core's
    untrusted-content fence — not a claim that a redacted log is clean.  If
    someone later treats ``adb_logcat`` output as sanitised-by-guarantee, this
    test is the counter-example.
    """
    redacted, _count = adb.redact_log_text(survives)
    leaked = [
        token
        for token in ("abc123def456", "tok_a1b2c3d4e5", "swordfish")
        if token in survives and token in redacted
    ]
    assert leaked, "this case is documented as surviving; if it no longer does, tighten the docs"


def test_a_clean_log_is_reported_as_zero_redactions():
    text, count = adb.redact_log_text("09-08 12:00:03.300 I App : nothing to see\n")
    assert count == 0
    assert "nothing to see" in text


def test_logcat_seconds_is_clamped_to_the_contract_range():
    assert adb._clamp_logcat_seconds(999) == 20
    assert adb._clamp_logcat_seconds(0) == 1
    assert adb._clamp_logcat_seconds(None) == 5
    assert adb._clamp_logcat_seconds("20") == 5, "a string is not an integer"
    assert adb._clamp_logcat_seconds(True) == 5, "a bool is not a count"  # noqa: FBT003


def test_wait_s_is_clamped_to_section_5_4s_range():
    assert adb._clamp_wait(None) == 20
    assert adb._clamp_wait(99) == 25
    assert adb._clamp_wait(-5) == 0
    assert adb._clamp_wait(True) == 20, "a bool is not a duration"  # noqa: FBT003


# ---------------------------------------------------------------------------
# The envelope, not just the field
# ---------------------------------------------------------------------------


def test_a_result_is_capped_as_a_whole_so_the_json_stays_parseable():
    """§5.3 caps the rendered text, and the JSON wrapper counts toward it.

    Capping only the field leaves the serialised object over the cap, the
    host's own cap fires on the string, and the model receives truncated —
    that is, invalid — JSON.
    """
    result = adb.fit_envelope({
        "ok": True,
        "seconds": 5,
        "output": "y" * (adb.MAX_RESULT_CHARS + 5_000),
    })
    serialised = json.dumps(result, separators=(",", ":"))
    assert len(serialised) <= adb.MAX_RESULT_CHARS
    assert json.loads(serialised)["ok"] is True
    assert result["truncated"] is True
    assert "more characters; use jobs_output to page" in result["output"]


def test_a_small_result_is_left_exactly_as_it_was():
    original = {"ok": True, "output": "short"}
    assert adb.fit_envelope(dict(original)) == original


# ---------------------------------------------------------------------------
# §5.2 — never a stack trace, never an absolute path
# ---------------------------------------------------------------------------


def test_a_reason_never_carries_a_traceback():
    traceback_text = (
        'Traceback (most recent call last):\n'
        '  File "C:\\Projects\\GameTest\\src\\thing.py", line 3, in f\n'
        "ValueError: boom"
    )
    reason = adb.sanitise_reason(traceback_text)
    assert "\n" not in reason
    assert "thing.py" not in reason


@pytest.mark.parametrize(
    "leaky",
    [
        r"cannot stat 'C:\Users\Administrator\.ssh\id_rsa'",
        r"open \\fileserver\payroll\2026.xlsx failed",
        "cannot read C:secrets.txt",
    ],
)
def test_a_reason_never_carries_an_absolute_path(leaky):
    assert "<path>" in adb.sanitise_reason(leaky)


@pytest.mark.parametrize(
    ("leaky", "secret"),
    [
        (
            'adb: curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef"',
            "eyJhbGciOiJIUzI1NiJ9.abcdef",
        ),
        ("adb: rejected api_key=abcd1234efgh5678", "abcd1234efgh5678"),
        ("adb: password=hunter2 refused", "hunter2"),
        ("adb: set-cookie: session=deadbeefcafe", "deadbeefcafe"),
    ],
)
def test_a_reason_never_carries_a_credential(leaky, secret):
    """§5.2's forbidden list ends "or the token".

    ``adb`` echoes the command it was running, and a command can carry one, so
    the reason scrubber needs the same patterns the logcat redactor uses
    rather than a hope that no message ever contains a credential.
    """
    scrubbed = adb.sanitise_reason(leaky)
    assert secret not in scrubbed
    assert "[redacted]" in scrubbed


def test_an_ordinary_adb_error_still_reads_as_plain_english():
    """§11 item 6 wants refusals in plain English.

    The path pattern used to match the bare ``adb:`` that begins most of this
    family's messages, rendering every one of them as "ad<path> ..." — and
    destroying the ``Authorization:`` keyword before the credential pattern
    could key on it.
    """
    reason = adb.sanitise_reason("adb: failed to install app.apk: INSTALL_FAILED")
    assert reason == "adb: failed to install app.apk: INSTALL_FAILED"


def test_a_reason_is_bounded_with_the_ellipsis_counted():
    """The ellipsis counts toward the bound, exactly as the cap marker counts
    toward the cap in ``_truncate_to``.

    The host appends it *after* slicing to 300 and lands on 301; that
    off-by-one is the same defect as the cap overshoot, and is corrected here.
    """
    bounded = adb.sanitise_reason("word " * 2_000)
    assert len(bounded) == 300
    assert bounded.endswith("…")


def test_a_long_unbroken_blob_in_a_reason_is_treated_as_a_credential():
    """40+ characters with no spaces is credential-shaped, not prose, and a
    §5.2 reason is not the place to find out which."""
    assert adb.sanitise_reason("z" * 5_000) == "[redacted]"


def test_an_empty_reason_still_says_something():
    assert adb.sanitise_reason("") == "the tool failed without a message"


def test_a_plugin_exception_becomes_a_sanitised_error_not_a_traceback(monkeypatch):
    """The JSON-RPC layer must never put a traceback on the wire."""
    from workstation_agent.plugins.adb import __main__ as adb_main

    def explode(*_a, **_k):
        msg = r"failed reading C:\Users\Administrator\secret.txt"
        raise RuntimeError(msg)

    monkeypatch.setattr(adb_main, "adb_devices", explode)
    sent: list[dict] = []
    monkeypatch.setattr(adb_main, "_send", sent.append)
    adb_main.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "adb.devices", "arguments": {}}})
    payload = json.loads(sent[0]["result"]["content"][0]["text"])
    assert payload["ok"] is False
    assert "secret.txt" not in payload["reason"]
    assert "Traceback" not in payload["reason"]


# ---------------------------------------------------------------------------
# Jobs (§5.4)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_jobs():
    adb._JOBS.clear()
    yield
    adb._JOBS.clear()


def test_the_ninth_concurrent_job_is_refused():
    for _ in range(adb._MAX_JOBS):
        assert adb._new_job("adb_shell") is not None
    assert adb._new_job("adb_shell") is None, "§5.4: at most 8 concurrent jobs"


def test_a_finished_job_stops_counting_against_the_limit():
    jobs = [adb._new_job("adb_shell") for _ in range(adb._MAX_JOBS)]
    first = jobs[0]
    assert first is not None
    first.state = "done"
    first.finished = 0.0
    assert adb._new_job("adb_shell") is not None


def test_job_ids_are_namespaced_so_a_shared_registry_can_route_them():
    """§5.4's ``jobs_*`` live in a different plugin process.

    Until the registry moves somewhere both can reach, the id has to say which
    family owns it or ``jobs_output`` cannot find the job.
    """
    job = adb._new_job("adb_shell")
    assert job is not None
    assert job.job_id.startswith("j-adb-")


def test_the_job_registry_is_process_global_and_not_per_caller():
    """A limitation, asserted so nobody builds on an isolation that is absent.

    ``host.invoke`` carries a ``SessionContext`` as far as the permission
    evaluator, but no per-connection identity reaches the arguments a plugin
    receives, and one subprocess serves every caller.  A job started by one
    caller is therefore visible to every caller of this plugin.  If this test
    ever needs changing, session identity has reached the plugin and the
    registry can finally be keyed on it.
    """
    import inspect

    job = adb._new_job("adb_shell")
    assert job is not None
    assert any(row["job_id"] == job.job_id for row in adb.job_snapshot())

    for name in ("adb_shell", "adb_pull", "adb_logcat", "adb_push", "adb_install"):
        params = inspect.signature(getattr(adb, name)).parameters
        assert "session" not in params
        assert "session_id" not in params


def test_jobs_list_rows_carry_the_keys_section_6_1_names():
    adb._new_job("adb_shell")
    row = adb.job_snapshot()[0]
    assert set(row) == {"job_id", "tool", "state", "started", "finished"}


# ---------------------------------------------------------------------------
# The sandbox arithmetic
# ---------------------------------------------------------------------------


def test_the_adb_concurrency_bound_fits_inside_the_job_objects_process_limit():
    """``adb`` forks a persistent server, so one call costs two process slots.

    The plugin itself is one more.  Exceeding ``ActiveProcessLimit`` does not
    queue — ``CreateProcess`` fails — so the bound is enforced in this plugin
    rather than discovered as a spawn error under load.  If B6 raises
    ``max_active_processes`` this test is where the arithmetic is restated.
    """
    from workstation_agent.mcp_host.supervisor import ResourceLimits

    limit = ResourceLimits().max_active_processes
    plugin_process = 1
    adb_server = 1
    assert adb._MAX_CONCURRENT_ADB + plugin_process + adb_server <= limit


def test_concurrent_adb_calls_are_bounded_by_the_semaphore():
    """Asserted by exhausting it, not by reading a private counter: what
    matters is that the (N+1)th caller actually waits."""
    held = [adb._adb_slots.acquire(blocking=False) for _ in range(adb._MAX_CONCURRENT_ADB)]
    try:
        assert all(held)
        assert adb._adb_slots.acquire(blocking=False) is False
    finally:
        for _ in range(sum(1 for h in held if h)):
            adb._adb_slots.release()


@pytest.mark.skipif(sys.platform != "win32", reason="the flag is a Win32 creation flag")
def test_the_adb_child_gets_no_console_window():
    """A plugin running headless must not flash a console on the operator's
    desktop for every device poll."""
    assert adb._CREATE_NO_WINDOW == 0x08000000


def test_a_timeout_is_reported_as_a_timeout_not_an_empty_success(fake_adb):
    fake_adb.script([
        fake_adb.devices(ONE_DEVICE),
        {"match": ["exec-out"], "sleep": 3, "stdout": "too late"},
    ])
    original = adb._MAX_CALL_SECONDS
    try:
        adb._MAX_CALL_SECONDS = 1
        result = adb.adb_pull("/sdcard/slow.txt", adb_path=fake_adb.path)
    finally:
        adb._MAX_CALL_SECONDS = original
    assert result["ok"] is False
    assert result["code"] == "timeout"


def test_run_adb_captures_bytes_not_decoded_text(fake_adb):
    """``text=True`` would decode with the locale codec and make "not valid
    UTF-8 is refused" a behaviour this family inherits rather than decides."""
    fake_adb.script([], default={"stdout": _NOT_UTF8})
    run = adb.run_adb(["devices"], timeout_s=10.0, adb_path=fake_adb.path)
    assert isinstance(run.stdout, bytes)
    assert run.stdout == bytes(_NOT_UTF8)


def test_the_adb_binary_is_never_invoked_through_a_shell():
    """A command that runs on the phone is still a string this workstation
    passes to CreateProcess; going through cmd.exe would make phone-side
    quoting a workstation-side injection."""
    import inspect

    source = inspect.getsource(adb.run_adb)
    assert "shell=True" not in source
    assert "[binary, *args]" in source


def test_os_environ_is_not_mutated_by_building_the_child_env(monkeypatch, tmp_path):
    monkeypatch.setattr(adb, "resolve_adb_home", lambda: str(tmp_path))
    before = dict(os.environ)
    adb.build_adb_env()
    assert dict(os.environ) == before
