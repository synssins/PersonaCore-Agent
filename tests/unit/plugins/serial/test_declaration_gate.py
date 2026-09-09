"""The serial plugin's own contribution to the declaration-gate tests.

``tests/unit/mcp_host/test_argument_declarations.py`` already parametrises
over every shipped ``plugin.toml`` (including this one) and proves the two
generic properties: every declared tool has an ``args:`` entry, and no
``args:`` entry names an undeclared tool. What is specific to this family,
and worth its own test, is the classification the brief calls out by name:
``text``, ``hex`` and ``until`` are serial *payloads* — they live in the
device's namespace, not the workstation's — and must be declared ``foreign``,
never ``ws_path``. This file proves both directions: the real, shipped
declaration lets a legitimate write through, and a manifest that
misclassifies the payload as ``ws_path`` denies that same legitimate write.
That second half is the mutation test PLAN-BUILD.md asks for, kept in the
suite rather than only run by hand once.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from workstation_agent.mcp_host.loader import PluginManifest
from workstation_agent.mcp_host.permissions import classify, evaluate

_PLUGIN_DIR = (
    Path(__file__).resolve().parents[4] / "src" / "workstation_agent" / "plugins" / "serial"
)


def _load_manifest(declared_permissions: list[str] | None = None) -> PluginManifest:
    """The real shipped ``plugin.toml``, optionally with its declarations swapped out."""
    data = tomllib.loads((_PLUGIN_DIR / "plugin.toml").read_text(encoding="utf-8"))
    declared = declared_permissions if declared_permissions is not None else list(
        data["declared_permissions"],
    )
    return PluginManifest(
        id=data["id"],
        name=data["name"],
        version=data["version"],
        runtime=data["runtime"],
        entry=list(data.get("entry", [])),
        plugin_dir=_PLUGIN_DIR,
        signature_file=_PLUGIN_DIR / "signature.sig",
        declared_permissions=declared,
        confirmable_conditions=list(data.get("confirmable_conditions", [])),
        compat=dict(data.get("compat", {})),
    )


_GRANTED = {
    "tool:serial.ports",
    "tool:serial.open",
    "tool:serial.write",
    "tool:serial.read",
    "tool:serial.close",
}


def test_shipped_manifest_classifies_write_payloads_as_foreign() -> None:
    manifest = _load_manifest()
    classified = classify(manifest, "serial.write", {"session_id": "abc", "text": "AT\r\n"})
    assert classified.paths == (), "a serial payload must never be compared to a Windows root"
    assert not classified.undeclared
    assert not classified.missing


def test_shipped_manifest_classifies_until_as_foreign() -> None:
    manifest = _load_manifest()
    classified = classify(manifest, "serial.read", {"session_id": "abc", "until": "OK\r\n"})
    assert classified.paths == ()


def test_shipped_manifest_classifies_session_id_port_baud_as_opaque() -> None:
    manifest = _load_manifest()
    # opaque and foreign are mechanically identical (both exempt from the
    # workstation allowlists) — what matters here is that neither `session_id`
    # nor `port`/`baud` is a ws_path candidate either.
    open_classified = classify(manifest, "serial.open", {"port": "COM3", "baud": 115200})
    assert open_classified.paths == ()
    assert not open_classified.undeclared


def test_shipped_manifest_allows_a_legitimate_write() -> None:
    manifest = _load_manifest()
    decision = evaluate(
        manifest,
        "serial.write",
        {"session_id": "abc123", "text": "AT\r\n"},
        _GRANTED,
    )
    assert decision == "allow"


def test_shipped_manifest_allows_a_legitimate_read_with_until() -> None:
    manifest = _load_manifest()
    decision = evaluate(
        manifest,
        "serial.read",
        {"session_id": "abc123", "until": "OK\r\n"},
        _GRANTED,
    )
    assert decision == "allow"


# ---------------------------------------------------------------------------
# The mutation: declare the payload as ws_path instead of foreign.
# ---------------------------------------------------------------------------


def test_mutation_declaring_the_write_payload_as_ws_path_breaks_every_legitimate_write() -> None:
    """This is the exact mistake item 2 of the brief warns about: if `text`
    were declared `ws_path`, it would be compared against this plugin's
    declared roots — of which there are none, because this family has no
    workstation paths at all — and `_outside_declared_paths` denies outright
    (a declared class with zero declared roots is "no path access", not "no
    restriction"). A legitimate `AT\\r\\n` write is not a Windows path, is
    never found inside any root, and the call denies.

    If this test ever passes with `decision == "allow"`, the manifest's
    payload classification silently regressed to ws_path (or something
    equally wrong) and every real serial_write would be broken in
    production — which is exactly why this must fail loudly, not quietly."""
    mutated = [
        "tool:serial.write",
        "args:serial.write:action:!session_id=opaque,text=ws_path,hex=foreign",
    ]
    manifest = _load_manifest(declared_permissions=mutated)

    decision = evaluate(
        manifest,
        "serial.write",
        {"session_id": "abc123", "text": "AT\r\n"},
        {"tool:serial.write"},
    )
    assert decision == "deny", (
        "declaring a serial payload as ws_path must break the call — proving "
        "why the real manifest declares it foreign instead"
    )


def test_mutation_declaring_until_as_ws_path_breaks_a_legitimate_read() -> None:
    mutated = [
        "tool:serial.read",
        "args:serial.read:read:!session_id=opaque,until=ws_path",
    ]
    manifest = _load_manifest(declared_permissions=mutated)

    decision = evaluate(
        manifest,
        "serial.read",
        {"session_id": "abc123", "until": "OK\r\n"},
        {"tool:serial.read"},
    )
    assert decision == "deny"
