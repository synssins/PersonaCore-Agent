"""The ``devices`` and ``adb`` plugins as the host actually runs them.

Two interfaces meet here and both have been wrong before:

* the plugin is a **subprocess** speaking line-delimited JSON-RPC over stdio,
  and the tool names it advertises must be the dotted ones the gate declares —
  a mismatch produces tools the host cannot resolve;
* the result the plugin writes goes through ``host.conform_result``, which
  derives ``ok`` from ``isError`` and re-applies the §5.3 cap.  A result that
  is valid on its own but loses its meaning there is not a working tool.

These run the real ``python -m workstation_agent.plugins.<family>`` process.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from workstation_agent.mcp_host.host import MAX_RESULT_CHARS, conform_result
from workstation_agent.mcp_host.loader import _discover_bundled, _manifest_dict
from workstation_agent.mcp_host.permissions import parse_declarations

_REPO = Path(__file__).resolve().parents[3]
_PLUGINS_DIR = _REPO / "src" / "workstation_agent" / "plugins"


class Plugin:
    """A running plugin subprocess, spoken to the way the host speaks to it."""

    def __init__(self, module: str) -> None:
        self._proc = subprocess.Popen(  # noqa: S603 — argv is this test file's own constant
            [sys.executable, "-m", module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(_REPO),
            text=True,
            encoding="utf-8",
        )
        self._next_id = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        assert line, "the plugin closed stdout without answering"
        return json.loads(line)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.request("shutdown")
        self._proc.kill()
        self._proc.wait(timeout=10)


@pytest.fixture
def devices_plugin():
    plugin = Plugin("workstation_agent.plugins.devices")
    try:
        yield plugin
    finally:
        plugin.close()


@pytest.fixture
def adb_plugin():
    plugin = Plugin("workstation_agent.plugins.adb")
    try:
        yield plugin
    finally:
        plugin.close()


# ---------------------------------------------------------------------------
# Handshake and advertisement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_the_plugin_initialises_over_stdio(family, request):
    plugin = request.getfixturevalue(f"{family}_plugin")
    result = plugin.request("initialize")["result"]
    assert result["serverInfo"]["name"] == family
    assert "tools" in result["capabilities"]


def test_the_devices_plugin_advertises_the_dotted_name(devices_plugin):
    tools = devices_plugin.request("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["devices.list"]


def test_the_adb_plugin_advertises_all_six_dotted_names(adb_plugin):
    tools = adb_plugin.request("tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == {
        "adb.devices", "adb.shell", "adb.push", "adb.pull", "adb.install", "adb.logcat",
    }


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_what_the_running_plugin_advertises_matches_its_signed_declaration(family, request):
    """The gate reads the manifest, the host resolves against the advertisement.

    If they disagree, one of them refuses every call — and default-deny means
    the failure is total and silent until someone tries the tool.
    """
    plugin = request.getfixturevalue(f"{family}_plugin")
    advertised = {t["name"] for t in plugin.request("tools/list")["result"]["tools"]}
    manifest = next(m for m in _discover_bundled() if m.id == family)
    assert advertised == set(parse_declarations(manifest))


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_an_unknown_method_is_an_error_not_a_crash(family, request):
    plugin = request.getfixturevalue(f"{family}_plugin")
    response = plugin.request("no/such/method")
    assert response["error"]["code"] == -32601
    # The process is still alive and still answering.
    assert plugin.request("ping")["result"] == {}


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_a_notification_is_ignored_without_answering(family, request):
    """A message with no id must not produce a reply line, or every subsequent
    read is off by one."""
    plugin = request.getfixturevalue(f"{family}_plugin")
    assert plugin._proc.stdin is not None
    plugin._proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}) + "\n")
    plugin._proc.stdin.flush()
    assert plugin.request("ping")["result"] == {}


# ---------------------------------------------------------------------------
# devices_list, for real, over the wire
# ---------------------------------------------------------------------------


def test_devices_list_answers_with_section_6_1s_shape(devices_plugin):
    """§11 item 1, as far as it can go without a phone or pyserial."""
    result = devices_plugin.request(
        "tools/call", {"name": "devices.list", "arguments": {}},
    )["result"]
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is True
    assert {"usb", "adb", "com"} <= set(payload)
    assert result["isError"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="SetupAPI is a Windows API")
def test_devices_list_over_the_wire_carries_present_since(devices_plugin):
    """The end-to-end version of the SetupAPI decision: a real subprocess, the
    real bus, and ``present_since`` surviving JSON serialisation."""
    result = devices_plugin.request(
        "tools/call", {"name": "devices.list", "arguments": {}},
    )["result"]
    payload = json.loads(result["content"][0]["text"])
    if not payload["usb"]:
        pytest.skip("no USB devices present")
    assert any(row["present_since"] for row in payload["usb"])


def test_an_unknown_tool_in_the_family_is_a_result_not_an_exception(devices_plugin):
    result = devices_plugin.request(
        "tools/call", {"name": "devices.nope", "arguments": {}},
    )["result"]
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["code"] == "not_found"


def test_adb_with_no_binary_reports_not_found_rather_than_crashing(adb_plugin):
    """There is no ``adb`` on this workstation, which is itself a case the
    family has to answer for."""
    result = adb_plugin.request(
        "tools/call", {"name": "adb.devices", "arguments": {}},
    )["result"]
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["code"] == "not_found"
    assert "adb" in payload["reason"].lower()


# ---------------------------------------------------------------------------
# Through the host's conformance layer
# ---------------------------------------------------------------------------


def test_a_failure_keeps_its_meaning_through_conform_result(adb_plugin):
    """``conform_result`` derives ``ok`` from ``isError``.

    A plugin that returned ``ok: false`` with ``isError: false`` would reach
    the model looking like a success.
    """
    raw = adb_plugin.request(
        "tools/call", {"name": "adb.devices", "arguments": {}},
    )["result"]
    conformed = conform_result(raw)
    assert conformed.ok is False
    assert conformed.is_error is True


def test_a_success_keeps_its_meaning_through_conform_result(devices_plugin):
    raw = devices_plugin.request(
        "tools/call", {"name": "devices.list", "arguments": {}},
    )["result"]
    conformed = conform_result(raw)
    assert conformed.ok is True
    payload = json.loads(conformed.content[0]["text"])
    assert payload["ok"] is True


def test_the_result_the_plugin_writes_is_under_the_cap_before_the_host_touches_it(
    devices_plugin,
):
    """If the family's own cap did not land first, the host's cap would cut the
    JSON mid-string and hand the model something unparseable."""
    raw = devices_plugin.request(
        "tools/call", {"name": "devices.list", "arguments": {}},
    )["result"]
    text = raw["content"][0]["text"]
    assert len(text) <= MAX_RESULT_CHARS
    json.loads(text)


# ---------------------------------------------------------------------------
# The manifests as shipped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_the_bundled_loader_discovers_the_family(family):
    assert any(m.id == family for m in _discover_bundled())


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_the_manifest_entry_points_at_a_module_that_actually_runs(family):
    manifest = next(m for m in _discover_bundled() if m.id == family)
    assert manifest.entry == ["-m", f"workstation_agent.plugins.{family}"]
    completed = subprocess.run(  # noqa: S603 — argv is this test file's own constant
        [sys.executable, "-c", f"import workstation_agent.plugins.{family}"],
        capture_output=True,
        check=False,
        cwd=str(_REPO),
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_the_signature_covers_every_importable_file_in_the_package(family):
    """What the signature actually protects, asserted rather than assumed.

    The v2 scheme (``30d1b48``) covers every importable file in the package
    tree, recursively — ``.py``, ``.pyw``, sourceless ``.pyc``, and native
    ``.pyd``/``.so``. Before that only ``__init__.py`` and ``__main__.py``
    were hashed, so dropping a ``submodule.pyd`` beside them was arbitrary
    native code executing under a ``valid`` signature. This asserts the whole
    tree is covered rather than the two files that used to be.
    """
    from workstation_agent.mcp_host import loader

    plugin_dir = _PLUGINS_DIR / family
    manifest = next(m for m in _discover_bundled() if m.id == family)
    covered = {p.resolve() for p in loader._entry_file_paths(manifest.entry, plugin_dir)}

    importable = {
        p.resolve()
        for p in plugin_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() in loader._IMPORTABLE_SUFFIXES
        and "__pycache__" not in p.relative_to(plugin_dir).parts
    }
    assert importable, f"{family} ships no importable files at all"
    assert importable <= covered, (
        f"{family} ships importable files the signature does not cover: "
        f"{sorted(str(p) for p in importable - covered)}"
    )


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_neither_family_ships_a_file_that_would_need_a_gitattributes_pin(family):
    """Only Python source is newline-normalised before hashing.

    Anything else in the covered set is hashed byte-for-byte, so its signature
    validity would depend on the checkout's ``core.autocrlf`` — the exact
    defect the v2 scheme exists to remove. ``.gitattributes`` says such a file
    "MUST be pinned here". Neither family ships one today; this fails the day
    one is added, which is when the pin is needed.
    """
    from workstation_agent.mcp_host import loader

    manifest = next(m for m in _discover_bundled() if m.id == family)
    covered = loader._entry_file_paths(manifest.entry, _PLUGINS_DIR / family)
    unnormalised = [p for p in covered if p.suffix.lower() not in loader._SOURCE_SUFFIXES]
    assert not unnormalised, (
        f"{family} ships non-source files in its signed set; they are hashed raw and "
        f"need a .gitattributes pin: {sorted(str(p) for p in unnormalised)}"
    )


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_a_planted_native_module_would_change_the_signing_message(family, tmp_path):
    """The hole the v2 scheme closed, demonstrated on this family's own tree.

    A ``.pyd`` dropped into the package is code CPython will import. If the
    message did not change when one appeared, ``verify()`` would still say
    ``valid`` while arbitrary native code ran.
    """
    import shutil

    from workstation_agent.mcp_host import loader

    manifest = next(m for m in _discover_bundled() if m.id == family)
    staged = tmp_path / family
    shutil.copytree(_PLUGINS_DIR / family, staged, ignore=shutil.ignore_patterns("__pycache__"))

    before = loader._covered_files(["-m", "x"], staged)
    (staged / "evil.pyd").write_bytes(b"MZ\x90\x00native")
    after = loader._covered_files(["-m", "x"], staged)

    assert len(after) == len(before) + 1
    assert any(label == "evil.pyd" for label, _ in after)
    assert manifest.id == family


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_the_shipped_signature_verifies_under_the_first_party_key(family):
    from workstation_agent.mcp_host.loader import verify
    from workstation_agent.security.first_party_pubkey import FIRST_PARTY_PUBKEY

    manifest = next(m for m in _discover_bundled() if m.id == family)
    result = verify(manifest, [FIRST_PARTY_PUBKEY])
    assert result.status == "valid", result.reason


@pytest.mark.parametrize("family", ["devices", "adb"])
def test_editing_the_manifest_invalidates_the_signature(family):
    """The property the re-signing step exists to preserve."""
    from workstation_agent.mcp_host.loader import _verify_inner
    from workstation_agent.security.first_party_pubkey import FIRST_PARTY_PUBKEY

    manifest = next(m for m in _discover_bundled() if m.id == family)
    raw_sig = manifest.signature_file.read_bytes()
    assert _verify_inner(manifest, [FIRST_PARTY_PUBKEY], raw_sig).status == "valid"

    tampered = tomllib.loads((manifest.plugin_dir / "plugin.toml").read_text(encoding="utf-8"))
    manifest.declared_permissions.append("path:C:\\")
    assert _verify_inner(manifest, [FIRST_PARTY_PUBKEY], raw_sig).status == "invalid"
    assert "declared_permissions" in _manifest_dict(manifest)
    assert tampered["id"] == family
