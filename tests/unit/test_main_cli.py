"""Subtask B5 -- the export-registration console entry point.

Covers the CLI dispatch (`_cmd_export_registration`), the argparse wiring for
the `export-registration` subcommand, and the console-attach helper's no-op
guards (the actual Windows console APIs are not exercised here -- this is a
non-frozen interpreter run, which is exactly the case `_attach_console` must
leave alone).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from workstation_agent import __main__ as main_mod

# ---------------------------------------------------------------------------
# argparse: the export-registration subcommand
# ---------------------------------------------------------------------------


def test_export_registration_is_a_recognised_subcommand():
    args = main_mod._build_parser().parse_args(["export-registration"])
    assert args.command == "export-registration"
    assert args.output is None


def test_export_registration_accepts_an_output_directory():
    args = main_mod._build_parser().parse_args(["export-registration", "-o", "C:/out"])
    assert args.command == "export-registration"
    assert args.output == "C:/out"

    long_form = main_mod._build_parser().parse_args(
        ["export-registration", "--output", "C:/out2"],
    )
    assert long_form.output == "C:/out2"


def test_the_default_invocation_has_no_subcommand():
    """Running with no args still runs the full app -- args.command is None."""
    args = main_mod._build_parser().parse_args([])
    assert getattr(args, "command", None) is None


def test_existing_flags_still_parse_alongside_the_new_subparser():
    args = main_mod._build_parser().parse_args(["--diag", "--fake-backends"])
    assert args.diag is True
    assert args.fake_backends is True
    assert getattr(args, "command", None) is None


# ---------------------------------------------------------------------------
# _cmd_export_registration: reports its output path or a real error
# ---------------------------------------------------------------------------


def test_cmd_export_registration_reports_the_path_on_success(tmp_path, monkeypatch, capsys):
    from workstation_agent.registration_export import RegistrationResult

    fake_result = RegistrationResult(
        path=tmp_path / "workstation-registration.zip",
        tool_names=("workstation_status", "devices_list"),
        url="https://127.0.0.1:8765/mcp",
        fingerprint="sha256:" + "ab" * 32,
    )

    class _FakeConfig:
        network_mcp = object()

    monkeypatch.setattr("workstation_agent.config.store.load", _FakeConfig)
    monkeypatch.setattr(
        "workstation_agent.registration_export.export_registration",
        lambda *_a, **_k: fake_result,
    )

    rc = main_mod._cmd_export_registration(None)
    out = capsys.readouterr()
    assert rc == 0
    assert str(fake_result.path) in out.out
    assert "2 tools" in out.out
    assert out.err == ""


def test_cmd_export_registration_reports_a_real_error_on_failure(monkeypatch, capsys):
    class _FakeConfig:
        network_mcp = object()

    monkeypatch.setattr("workstation_agent.config.store.load", _FakeConfig)

    def _boom(*_a, **_k):
        msg = "port already bound"
        raise RuntimeError(msg)

    monkeypatch.setattr(
        "workstation_agent.registration_export.export_registration", _boom,
    )

    rc = main_mod._cmd_export_registration(None)
    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert "port already bound" in out.err


@pytest.mark.parametrize(
    ("exc_type", "message"),
    [
        (ValueError, "fingerprint must be 'sha256:' + 64 hex characters"),
        (RuntimeError, "the served-tool table violates contract"),
        (OSError, "no space left on device"),
    ],
)
def test_cmd_export_registration_reports_every_raised_type_not_a_traceback(
    monkeypatch, capsys, exc_type, message,
):
    """Finding 5: build_manifest_text/export_registration raise ValueError,
    RuntimeError and OSError respectively -- all three must come back as a
    reported error and exit 1, never an uncaught traceback."""

    class _FakeConfig:
        network_mcp = object()

    def _boom(*_a, **_k):
        raise exc_type(message)

    monkeypatch.setattr("workstation_agent.config.store.load", _FakeConfig)
    monkeypatch.setattr("workstation_agent.registration_export.export_registration", _boom)

    rc = main_mod._cmd_export_registration(None)
    out = capsys.readouterr()
    assert rc == 1
    assert out.out == ""
    assert message in out.err
    assert "Traceback" not in out.err


def test_cmd_export_registration_survives_a_bad_config_load(monkeypatch, capsys):
    """A well-formed caller is not assumed: config loading itself can fail."""

    def _boom():
        msg = "config.toml is corrupt"
        raise ValueError(msg)

    monkeypatch.setattr("workstation_agent.config.store.load", _boom)

    rc = main_mod._cmd_export_registration(None)
    out = capsys.readouterr()
    assert rc == 1
    assert "config.toml is corrupt" in out.err


def test_cmd_export_registration_passes_the_output_dir_through(monkeypatch, tmp_path):
    captured: dict = {}

    class _FakeConfig:
        network_mcp = object()

    def _fake_export(_config, *, output_dir=None, **_k):
        captured["output_dir"] = output_dir
        from workstation_agent.registration_export import RegistrationResult

        return RegistrationResult(
            path=(output_dir or tmp_path) / "workstation-registration.zip",
            tool_names=("workstation_status",),
            url="https://127.0.0.1:8765/mcp",
            fingerprint="sha256:" + "ab" * 32,
        )

    monkeypatch.setattr("workstation_agent.config.store.load", _FakeConfig)
    monkeypatch.setattr(
        "workstation_agent.registration_export.export_registration", _fake_export,
    )

    rc = main_mod._cmd_export_registration(str(tmp_path / "somewhere"))
    assert rc == 0
    assert captured["output_dir"] == Path(str(tmp_path / "somewhere"))


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------


def test_main_dispatches_export_registration(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["Agent.exe", "export-registration"])
    monkeypatch.setattr(main_mod, "_cmd_export_registration", lambda _output: 42)
    # Keep the console-attach / stream-setup no-ops for a normal interpreter run.
    monkeypatch.setattr(main_mod, "_attach_console", lambda: None)
    assert main_mod.main() == 42


# ---------------------------------------------------------------------------
# The console-attach guard rails
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["export-registration"], True),
        (["export-registration", "-o", "x"], True),
        (["--diag"], True),
        (["--check-updates"], True),
        (["--rollback"], True),
        (["--rollback", "1.2.3"], True),
        ([], False),
        (["--autostart"], False),
        (["--fake-backends"], False),
    ],
)
def test_wants_console_matches_report_and_exit_commands(argv, expected):
    assert main_mod._wants_console(argv) is expected


def test_attach_console_is_a_noop_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    # Must not raise, and must not touch sys.stdout.
    original = sys.stdout
    main_mod._attach_console()
    assert sys.stdout is original


def test_attach_console_is_a_noop_when_not_frozen(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32", raising=False)
    monkeypatch.delattr(sys, "frozen", raising=False)
    original = sys.stdout
    main_mod._attach_console()
    assert sys.stdout is original


def test_attach_console_is_a_noop_when_stdout_already_live(monkeypatch):
    """A real interpreter run (tests, `python -m workstation_agent`) already
    has a terminal; the attach must never run in that case."""
    monkeypatch.setattr(sys, "platform", "win32", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert sys.stdout is not None
    original = sys.stdout
    main_mod._attach_console()
    assert sys.stdout is original
