"""Subtask P7 -- exporting from the live endpoint, and the pre-flight that guards it.

Two additions to ``registration_export``:

* :func:`export_registration_from_endpoint` -- export from a live
  ``NetworkMCPServer.info()`` rather than from a server rebuilt from config, so
  the manifest names the port the endpoint is really on.
* :func:`registration_problems` -- the reasons a registration would not work,
  as sentences the UI shows before writing anything.

The second is advisory by design. ``export_registration`` and the
``export-registration`` CLI subcommand must keep exporting whatever they are
asked to: a scripted export that suddenly started refusing would be a worse
regression than a registration the operator was warned about.
"""

from __future__ import annotations

import tomllib
import zipfile

import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp.tools import served_tool_names
from workstation_agent.registration_export import (
    MANIFEST_ARCNAME,
    REGISTRATION_ZIP_NAME,
    export_registration,
    export_registration_from_endpoint,
    is_loopback_host,
    registration_problems,
)


class _Info:
    def __init__(self, **kwargs) -> None:
        defaults = {
            "url": "https://192.168.1.50:8765/mcp",
            "bind_host": "192.168.1.50",
            "port": 8765,
            "fingerprint": "sha256:" + "ab" * 32,
            "token": "t" * 64,
            "certificate_sans": ("192.168.1.50",),
            "tool_names": served_tool_names(),
            "running": True,
        }
        defaults.update(kwargs)
        self.__dict__.update(defaults)


# ---------------------------------------------------------------------------
# export_registration_from_endpoint
# ---------------------------------------------------------------------------


def test_it_writes_the_live_url_verbatim(tmp_path):
    result = export_registration_from_endpoint(
        _Info(url="https://192.168.1.50:49731/mcp", port=49731), output_dir=tmp_path,
    )
    with zipfile.ZipFile(result.path) as zf:
        doc = tomllib.loads(zf.read(MANIFEST_ARCNAME).decode("utf-8"))
    assert doc["plugin"]["url"] == "https://192.168.1.50:49731/mcp"
    assert doc["permissions"]["network"] == ["192.168.1.50"]


def test_it_still_refuses_a_tool_list_that_disagrees_with_what_is_served(tmp_path):
    """The symmetry check is the module's whole promise; a second entry point
    must not be a way around it."""
    with pytest.raises(RuntimeError, match="disagree"):
        export_registration_from_endpoint(
            _Info(tool_names=("workstation_status",)), output_dir=tmp_path,
        )
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_it_still_refuses_a_malformed_fingerprint(tmp_path):
    with pytest.raises(ValueError, match="fingerprint"):
        export_registration_from_endpoint(_Info(fingerprint="nope"), output_dir=tmp_path)


def test_the_config_entry_point_is_unchanged_and_still_works(tmp_path):
    """The CLI path. ``Agent.exe export-registration`` must keep working."""
    cfg = NetworkMcpConfig(bind_host="192.168.1.50", port=8765)
    result = export_registration(cfg, output_dir=tmp_path, state_dir=tmp_path)
    assert result.path.is_file()
    assert result.url == "https://192.168.1.50:8765/mcp"
    assert result.tool_names == served_tool_names()


def test_a_contract_violating_tool_table_is_refused_before_anything_is_created(
    tmp_path, monkeypatch,
):
    """``info()`` generates the certificate and token on demand.

    Refusing only *after* building the server would leave credentials on disk
    for an export that was never going to be written.
    """
    from workstation_agent import registration_export as mod

    monkeypatch.setattr(mod, "validate_tool_names", lambda: ["bad name"])
    with pytest.raises(RuntimeError, match="contract"):
        export_registration(NetworkMcpConfig(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# registration_problems
# ---------------------------------------------------------------------------


def test_a_healthy_endpoint_has_no_problems():
    assert registration_problems(_Info()) == ()


def test_a_stopped_endpoint_is_reported():
    problems = registration_problems(_Info(running=False))
    assert any("not running" in p for p in problems)


def test_running_can_be_overridden_by_the_caller():
    assert registration_problems(_Info(running=False), running=True) == ()


def test_loopback_is_reported_with_why_it_cannot_work():
    problems = registration_problems(
        _Info(bind_host="127.0.0.1", certificate_sans=("127.0.0.1",)),
    )
    joined = " ".join(problems)
    assert "loopback" in joined
    assert "PersonaCore itself" in joined


def test_port_zero_is_reported_as_a_registration_that_goes_stale():
    problems = registration_problems(_Info(port=0))
    assert any("port is 0" in p.lower() for p in problems)


def test_a_san_that_does_not_cover_the_bind_host_is_reported_honestly():
    """Honestly: the core pins the fingerprint, so it will most likely connect.

    Claiming the endpoint is broken would be wrong, and would push the operator
    into rotating a fingerprint that works.
    """
    problems = registration_problems(_Info(certificate_sans=("10.0.0.1",)))
    joined = " ".join(problems)
    assert "does not cover" in joined
    assert "pins the fingerprint" in joined


def test_problems_are_read_from_a_duck_typed_object_with_missing_attributes():
    """Assume neither a well-formed caller nor a well-formed environment.

    A stub endpoint in someone else's test, or a future info object that drops
    a field, must produce a report rather than an AttributeError inside the
    export button.
    """

    class _Bare:
        pass

    assert registration_problems(_Bare())  # reports, does not raise


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),  # all of 127/8
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("LocalHost", True),
        ("192.168.1.50", False),
        ("workstation.lan", False),
        ("", False),
    ],
)
def test_loopback_detection(host, loopback):
    assert is_loopback_host(host) is loopback


# ---------------------------------------------------------------------------
# san_covers, defended against a caller that hands it the wrong shape
# ---------------------------------------------------------------------------


def test_a_bare_string_san_is_not_iterated_character_by_character():
    """The quiet failure this guards.

    ``certificate_sans`` reaches ``san_covers`` from a duck-typed ``info``. A
    bare ``str`` is an iterable of one-character strings, so a SAN handed in as
    ``"192.168.1.50"`` rather than ``("192.168.1.50",)`` would be compared as
    "1", "9", "2", "." ... -- reporting "not covered" for a certificate that
    covers the host exactly, and pushing the operator to rotate a fingerprint
    that was fine.
    """
    from workstation_agent.registration_export import san_covers

    assert san_covers("192.168.1.50", ("192.168.1.50",)) is True
    assert san_covers("192.168.1.50", "192.168.1.50") is False
    assert san_covers("1", "192.168.1.50") is False  # not a character match either


def test_a_non_sequence_san_is_treated_as_no_coverage_not_a_crash():
    from workstation_agent.registration_export import san_covers

    assert san_covers("192.168.1.50", None) is False
    assert san_covers("192.168.1.50", object()) is False
    assert san_covers("192.168.1.50", 42) is False


def test_the_reported_san_list_matches_what_was_actually_compared():
    """The message must not describe a comparison that did not happen."""
    problems = registration_problems(_Info(certificate_sans="192.168.1.50"))
    joined = " ".join(problems)
    assert "does not cover" in joined
    assert "SAN is empty" in joined  # not "1, 9, 2, ., 1, 6, 8, ..."
