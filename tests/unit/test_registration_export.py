"""Subtask B5 — export-registration and the served-set/registration symmetry.

The highest-value assertion in this file is
``test_the_exported_set_equals_the_served_set``: a tool the endpoint serves
that the registration does not list, or the reverse, is a **terminal load
failure** on the PersonaCore core (contract §2) -- the plugin refuses to
load outright, not degrades. Both directions are asserted with a real set
equality, not a subset check.
"""

from __future__ import annotations

import re
import tomllib
import zipfile

import pytest

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp.tools import SERVED_TOOLS, served_tool_names
from workstation_agent.registration_export import (
    MANIFEST_ARCNAME,
    REGISTRATION_ZIP_NAME,
    RegistrationResult,
    build_manifest_text,
    export_registration,
)

# Contract §2, anchored with \A/\Z the way tools.py does -- $ also matches
# just before a trailing newline in Python, which would wrongly accept
# "files-read\n".
_MANIFEST_NAME_PATTERN = re.compile(r"\A[a-z][a-z0-9-]{1,63}\Z")


def _cfg(**overrides) -> NetworkMcpConfig:
    overrides.setdefault("bind_host", "192.168.1.50")
    overrides.setdefault("port", 8765)
    return NetworkMcpConfig(**overrides)


def _read_manifest(zip_path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        assert zf.namelist() == [MANIFEST_ARCNAME]
        raw = zf.read(MANIFEST_ARCNAME)
    return tomllib.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# The symmetry test -- both directions, real equality
# ---------------------------------------------------------------------------


def test_the_exported_set_equals_the_served_set(tmp_path):
    """A name on one side and not the other is a terminal load failure."""
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    manifest = _read_manifest(result.path)

    exported_names = set(manifest["tools"].keys())
    served_names = set(served_tool_names())

    # Not a subset check either direction -- exact equality, asserted as
    # two separate one-directional checks so a regression names which side
    # broke.
    missing_from_registration = served_names - exported_names
    extra_in_registration = exported_names - served_names
    assert missing_from_registration == set(), (
        f"served but not exported: {missing_from_registration}"
    )
    assert extra_in_registration == set(), (
        f"exported but not served: {extra_in_registration}"
    )
    assert exported_names == served_names


def test_the_exported_set_matches_served_tool_names_order_independent(tmp_path):
    """Same assertion via the function name B5 is required to generate from."""
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert set(result.tool_names) == set(served_tool_names())
    assert result.tool_names == served_tool_names()


def test_a_served_name_dropped_from_the_registration_would_fail():
    """Build a manifest from a deliberately incomplete list and prove the
    symmetry test catches it -- pins the assertion's own sensitivity."""
    incomplete = served_tool_names()[:-1]
    manifest_text = build_manifest_text(
        url="https://192.168.1.50:8765/mcp",
        bind_host="192.168.1.50",
        fingerprint="sha256:" + "ab" * 32,
        tool_names=incomplete,
    )
    exported_names = {
        line.split("[tools.")[1].split("]")[0]
        for line in manifest_text.splitlines()
        if line.startswith("[tools.")
    }
    assert exported_names != set(served_tool_names())


def test_a_duplicated_served_name_is_caught_not_exported(tmp_path, monkeypatch):
    """Finding 1 (verifier round 1): a name duplicated *identically* on
    both sides of the symmetry check compares equal as a tuple and as a
    set, so neither form of that comparison alone can see it -- and TOML
    rejects two ``[tools.<name>]`` tables sharing a name outright, which is
    the terminal load failure this whole module exists to prevent, arriving
    through the one comparison meant to catch exactly this."""
    from workstation_agent import registration_export as mod
    from workstation_agent.network_mcp import server as network_mcp_server_mod

    real_names = served_tool_names()
    duplicated = (*real_names, real_names[0])
    monkeypatch.setattr(mod, "served_tool_names", lambda: duplicated)

    class _FakeInfo:
        tool_names = duplicated
        url = "https://192.168.1.50:8765/mcp"
        bind_host = "192.168.1.50"
        fingerprint = "sha256:" + "ab" * 32

    class _FakeServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def info(self):
            return _FakeInfo()

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _FakeServer)

    # Sanity check on the test's own premise: the naive comparison this
    # replaces would NOT have caught this case.
    assert tuple(duplicated) == tuple(duplicated)
    assert set(duplicated) == set(real_names)

    with pytest.raises(RuntimeError, match="duplicate"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_a_duplicate_on_only_the_served_side_is_also_caught(tmp_path, monkeypatch):
    from workstation_agent import registration_export as mod

    real_names = served_tool_names()
    monkeypatch.setattr(mod, "served_tool_names", lambda: (*real_names, real_names[0]))

    with pytest.raises(RuntimeError, match="duplicate"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_build_manifest_text_rejects_duplicate_tool_names():
    with pytest.raises(ValueError, match="duplicate"):
        build_manifest_text(
            url="https://host:1/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status", "devices_list", "workstation_status"),
        )


def test_export_registration_refuses_a_bare_string_tool_names_from_type_confusion(
    tmp_path, monkeypatch,
):
    """Round 2, finding 5: set("abc") == set(("a","b","c")) is True in
    Python, so if served_tool_names() were ever a bare string instead of a
    sequence of names, a set-equality check alone would not notice -- and
    would silently export a registration for three single-letter "tools"
    instead of refusing outright."""
    from workstation_agent import registration_export as mod
    from workstation_agent.network_mcp import server as network_mcp_server_mod

    monkeypatch.setattr(mod, "served_tool_names", lambda: "abc")

    class _FakeInfo:
        tool_names = ("a", "b", "c")
        url = "https://192.168.1.50:8765/mcp"
        bind_host = "192.168.1.50"
        fingerprint = "sha256:" + "ab" * 32

    class _FakeServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def info(self):
            return _FakeInfo()

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _FakeServer)

    # Sanity check on the premise: the naive comparison this replaces would
    # not have caught this case.
    assert set("abc") == {"a", "b", "c"}

    with pytest.raises(TypeError, match="must be a tuple or list"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_export_registration_refuses_a_bare_string_on_the_other_side_too(
    tmp_path, monkeypatch,
):
    """The type check must guard both operands, not just served_tool_names()."""
    from workstation_agent.network_mcp import server as network_mcp_server_mod

    class _FakeInfo:
        tool_names = "abc"
        url = "https://192.168.1.50:8765/mcp"
        bind_host = "192.168.1.50"
        fingerprint = "sha256:" + "ab" * 32

    class _FakeServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def info(self):
            return _FakeInfo()

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _FakeServer)

    with pytest.raises(TypeError, match="must be a tuple or list"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


# ---------------------------------------------------------------------------
# Contract §2 naming
# ---------------------------------------------------------------------------


def test_every_exported_name_matches_the_pattern_after_translation(tmp_path):
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    for name in result.tool_names:
        manifest_name = name.replace("_", "-")
        assert _MANIFEST_NAME_PATTERN.match(manifest_name), (
            f"{name!r} -> {manifest_name!r} does not match the contract §2 pattern"
        )


def test_no_exported_name_contains_a_dot(tmp_path):
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert all("." not in name for name in result.tool_names)


# ---------------------------------------------------------------------------
# Every tool is rated safe
# ---------------------------------------------------------------------------


def test_every_served_tool_is_rated_safe():
    assert all(t.risk == "safe" for t in SERVED_TOOLS)


def test_every_manifest_tool_block_is_rated_safe(tmp_path):
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    manifest = _read_manifest(result.path)
    assert manifest["tools"], "expected at least one exported tool"
    for name, table in manifest["tools"].items():
        assert table["risk"] == "safe", f"{name} is not rated safe"


# ---------------------------------------------------------------------------
# The token never appears in the zip
# ---------------------------------------------------------------------------


def test_the_token_never_appears_in_the_zip(tmp_path):
    from workstation_agent.network_mcp.server import NetworkMCPServer

    cfg = _cfg()
    # Prime the token/certificate under the same state_dir export_registration
    # will read, so we know the exact live token to search for.
    server = NetworkMCPServer(cfg, state_dir=tmp_path)
    token = server.info().token
    assert len(token) > 0

    result = export_registration(cfg, output_dir=tmp_path, state_dir=tmp_path)
    raw = result.path.read_bytes()
    assert token.encode("ascii") not in raw

    manifest = _read_manifest(result.path)
    assert manifest["plugin"]["auth_secret"] == "workstation_token"  # noqa: S105 -- a secret name
    # The registration references the secret's *name*, never its value.
    assert manifest["plugin"]["auth_secret"] != token


def test_build_manifest_text_has_no_parameter_that_accepts_a_token():
    import inspect

    params = set(inspect.signature(build_manifest_text).parameters)
    assert not {p for p in params if "token" in p.lower()}


# ---------------------------------------------------------------------------
# Manifest shape (contract §2)
# ---------------------------------------------------------------------------


def test_manifest_carries_the_fields_the_core_loads(tmp_path):
    cfg = _cfg(bind_host="10.0.0.5", port=9100)
    result = export_registration(cfg, output_dir=tmp_path, state_dir=tmp_path)
    manifest = _read_manifest(result.path)

    plugin = manifest["plugin"]
    assert plugin["name"] == "workstation"
    assert plugin["transport"] == "http"
    assert plugin["url"] == "https://10.0.0.5:9100/mcp"
    assert plugin["url"].startswith("https://")
    assert plugin["tls_fingerprint"].startswith("sha256:")
    assert plugin["auth_secret"] == "workstation_token"  # noqa: S105 -- a secret name
    assert isinstance(plugin["version"], str)
    assert plugin["version"]

    perms = manifest["permissions"]
    assert perms["network"] == ["10.0.0.5"]
    assert perms["secrets"] == []
    assert perms["paths"] == []

    events = manifest["events"]
    assert events["publishes"] == []
    assert events["subscribes"] == []


def test_manifest_is_written_at_the_documented_arcname(tmp_path):
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    with zipfile.ZipFile(result.path) as zf:
        assert MANIFEST_ARCNAME in zf.namelist()
    assert result.path.name == REGISTRATION_ZIP_NAME


def test_build_manifest_text_rejects_a_malformed_fingerprint():
    with pytest.raises(ValueError, match="fingerprint"):
        build_manifest_text(
            url="https://host:1/mcp",
            bind_host="host",
            fingerprint="not-a-fingerprint",
            tool_names=("workstation_status",),
        )


def test_build_manifest_text_rejects_an_empty_tool_list():
    with pytest.raises(ValueError, match="empty"):
        build_manifest_text(
            url="https://host:1/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=(),
        )


def test_build_manifest_text_rejects_a_non_https_url():
    with pytest.raises(ValueError, match="https"):
        build_manifest_text(
            url="http://host:1/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )


# ---------------------------------------------------------------------------
# Finding 6: validation errors must not echo the value into a message
# ---------------------------------------------------------------------------


def test_a_malformed_fingerprint_error_never_echoes_the_value():
    secret_like = "sk-supersecrettoken-should-never-reach-a-log"  # noqa: S105
    with pytest.raises(ValueError, match="fingerprint") as excinfo:
        build_manifest_text(
            url="https://host:1/mcp",
            bind_host="host",
            fingerprint=secret_like,
            tool_names=("workstation_status",),
        )
    assert secret_like not in str(excinfo.value)
    # Round 2, finding 3: not even a short prefix survives -- an earlier
    # revision kept the first 8 characters ("sk-super" here).
    assert secret_like[:8] not in str(excinfo.value)


def test_a_malformed_url_error_never_echoes_the_value():
    secret_like = "http://admin:hunter2@evil.example/mcp"  # noqa: S105
    with pytest.raises(ValueError, match="https") as excinfo:
        build_manifest_text(
            url=secret_like,
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )
    assert "hunter2" not in str(excinfo.value)
    assert secret_like not in str(excinfo.value)
    assert secret_like[:8] not in str(excinfo.value)


def test_safe_repr_never_emits_any_part_of_the_value():
    """Round 2, finding 3: length and type only -- no prefix at all."""
    from workstation_agent.registration_export import _safe_repr

    value = "this-is-a-fairly-long-secret-looking-value-12345"
    rendered = _safe_repr(value)
    assert value not in rendered
    for start in range(len(value) - 3):
        assert value[start : start + 4] not in rendered, (
            f"a 4-character substring of the value leaked into {rendered!r}"
        )
    assert str(len(value)) in rendered


# ---------------------------------------------------------------------------
# Finding 7: a URL carrying credentials is refused outright
# ---------------------------------------------------------------------------


def test_a_url_with_userinfo_is_refused():
    with pytest.raises(ValueError, match="userinfo"):
        build_manifest_text(
            url="https://user:pass@host:8765/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )


def test_a_url_with_only_a_username_is_also_refused():
    with pytest.raises(ValueError, match="userinfo"):
        build_manifest_text(
            url="https://user@host:8765/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )


def test_a_url_with_userinfo_error_never_echoes_the_credential():
    with pytest.raises(ValueError, match="userinfo") as excinfo:
        build_manifest_text(
            url="https://attacker:hunter2@host:8765/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )
    assert "hunter2" not in str(excinfo.value)
    assert "attacker" not in str(excinfo.value)


def test_a_urlsplit_crashing_authority_is_reported_not_leaked_or_uncaught():
    """Round 2, finding 1: urlsplit() itself raises ValueError on this exact
    URL, with the offending fragment quoted verbatim in its own message
    (verified: urlsplit("https://[SECRETTOKEN123]/mcp") raises
    "'SECRETTOKEN123' does not appear to be an IPv4 or IPv6 address").
    Uncaught, that both leaks the fragment and crashes the export instead
    of reporting a normal, contained error."""
    with pytest.raises(ValueError, match="could not be parsed") as excinfo:
        build_manifest_text(
            url="https://[SECRETTOKEN123]/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )
    assert "SECRETTOKEN123" not in str(excinfo.value)


def test_a_different_urlsplit_crash_shape_is_also_reported_not_uncaught():
    """The other authority shape that crashes urlsplit() -- an unterminated
    IPv6 literal -- raises "Invalid IPv6 URL" with nothing quoted, but must
    still come back as a normal ValueError from this module, not an
    unhandled exception straight out of urlsplit()."""
    with pytest.raises(ValueError, match="could not be parsed"):
        build_manifest_text(
            url="https://[::1/mcp",
            bind_host="host",
            fingerprint="sha256:" + "ab" * 32,
            tool_names=("workstation_status",),
        )


def test_export_registration_reports_a_urlsplit_crash_end_to_end(tmp_path, monkeypatch):
    """Same reproduction, through export_registration()'s real call path
    with a fake NetworkMCPServer.info() -- proves it never escapes as an
    uncaught exception at the point this module actually calls urlsplit."""
    from workstation_agent.network_mcp import server as network_mcp_server_mod

    class _FakeInfo:
        tool_names = served_tool_names()
        url = "https://[SECRETTOKEN123]/mcp"
        bind_host = "192.168.1.50"
        fingerprint = "sha256:" + "ab" * 32

    class _FakeServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def info(self):
            return _FakeInfo()

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _FakeServer)

    with pytest.raises(ValueError, match="could not be parsed") as excinfo:
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert "SECRETTOKEN123" not in str(excinfo.value)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_a_normal_url_without_userinfo_is_accepted():
    text = build_manifest_text(
        url="https://192.168.1.50:8765/mcp",
        bind_host="192.168.1.50",
        fingerprint="sha256:" + "ab" * 32,
        tool_names=("workstation_status",),
    )
    assert "https://192.168.1.50:8765/mcp" in text


def test_export_registration_refuses_a_userinfo_bearing_url(tmp_path, monkeypatch):
    """End-to-end: NetworkEndpointInfo.url is B4's to build, but this
    module refuses to export one carrying embedded credentials regardless."""
    from workstation_agent.network_mcp import server as network_mcp_server_mod

    class _FakeInfo:
        tool_names = served_tool_names()
        url = "https://oops:leaked@192.168.1.50:8765/mcp"
        bind_host = "192.168.1.50"
        fingerprint = "sha256:" + "ab" * 32

    class _FakeServer:
        def __init__(self, *_a, **_k) -> None:
            pass

        def info(self):
            return _FakeInfo()

    monkeypatch.setattr(network_mcp_server_mod, "NetworkMCPServer", _FakeServer)

    with pytest.raises(ValueError, match="userinfo"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


# ---------------------------------------------------------------------------
# Robustness: bad callers, bad state
# ---------------------------------------------------------------------------


def test_export_refuses_when_the_served_table_violates_the_contract(tmp_path, monkeypatch):
    from workstation_agent import registration_export as mod

    monkeypatch.setattr(
        mod, "validate_tool_names",
        lambda: ["served name contains a dot (contract §2 forbids it): 'bad.name'"],
    )
    with pytest.raises(RuntimeError, match="violates contract"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert list(tmp_path.glob(REGISTRATION_ZIP_NAME)) == []


def test_export_refuses_when_the_two_sources_of_the_served_set_disagree(tmp_path, monkeypatch):
    """Defence in depth: even if this ever became possible, refuse rather
    than export a registration that would not match what the endpoint
    actually serves."""
    from workstation_agent import registration_export as mod

    monkeypatch.setattr(mod, "served_tool_names", lambda: ("not_the_real_set",))
    with pytest.raises(RuntimeError, match="disagree"):
        export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)


def test_export_creates_the_output_directory_if_missing(tmp_path):
    out_dir = tmp_path / "nested" / "dest"
    result = export_registration(_cfg(), output_dir=out_dir, state_dir=tmp_path)
    assert result.path.parent == out_dir
    assert result.path.exists()


def test_export_defaults_to_the_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = export_registration(_cfg(), state_dir=tmp_path)
    assert result.path == tmp_path / REGISTRATION_ZIP_NAME


def test_result_is_a_frozen_dataclass_matching_what_it_wrote(tmp_path):
    result = export_registration(_cfg(), output_dir=tmp_path, state_dir=tmp_path)
    assert isinstance(result, RegistrationResult)
    assert result.fingerprint.startswith("sha256:")
    assert result.url.startswith("https://")
