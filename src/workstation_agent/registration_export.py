"""Generates ``workstation-registration.zip`` (contract §2) — subtask B5.

The zip holds a single file, ``workstation/manifest.toml``, and no code. It is
what ``Agent.exe export-registration`` writes and what PersonaCore's Plugins
page installs into ``plugins-http.d/``.

**The whole point of this module is where its data comes from.** The tool
list is read from
:func:`workstation_agent.network_mcp.tools.served_tool_names` — the exact
function :class:`~workstation_agent.network_mcp.server.NetworkMCPServer`
serves ``tools/list`` from — so the registration this writes and the set the
endpoint answers with are provably the same list, not two lists someone has
to remember to keep in sync. See ``tests/unit/test_registration_export.py``
for the equality test in both directions.

Never touches the network_mcp package's internals beyond its two public
reads (``served_tool_names`` / ``validate_tool_names`` and
``NetworkMCPServer.info()``); this module generates from that package, it
does not edit it.
"""
# ruff: noqa: PLC0415
# PLC0415: NetworkMCPServer and importlib.metadata are imported lazily so this
# module stays cheap to import from the CLI path (no mcp/uvicorn import just
# to build a manifest string) -- the same deferral network_mcp/server.py uses
# for the same reason.

from __future__ import annotations

import io
import ipaddress
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from workstation_agent.network_mcp.tools import served_tool_names, validate_tool_names

if TYPE_CHECKING:
    from workstation_agent.config.schema import NetworkMcpConfig

#: The zip's on-disk name (contract §2).
REGISTRATION_ZIP_NAME = "workstation-registration.zip"

#: The single file the zip carries.
MANIFEST_ARCNAME = "workstation/manifest.toml"

_PLUGIN_NAME = "workstation"
_CONTRACT_VERSION = "2.x"
_DESCRIPTION = "Acts on the owner's workstation and the devices plugged into it."

#: Contract §3: the *name* of the secret in the core's store, never the
#: token's value. The registration references it; it never carries it.
_AUTH_SECRET_NAME = "workstation_token"  # noqa: S105 — a secret's name, not a credential


@dataclass(frozen=True)
class RegistrationResult:
    """What :func:`export_registration` produced, for the CLI to report."""

    path: Path
    tool_names: tuple[str, ...]
    url: str
    fingerprint: str


def _agent_version() -> str:
    """The Agent's version, written into ``manifest.toml``.

    Contract §2: "its ``version`` is the Agent's" — regenerated on every
    release that changes a tool.
    """
    try:
        from importlib.metadata import version

        return version("workstation-agent")
    except Exception:  # noqa: BLE001 — a frozen build may have no metadata
        return "0.0.0"


def _safe_repr(value: str) -> str:
    """A description of *value* safe to interpolate into an error message.

    Never echoes any part of *value* — not the whole thing, and not even a
    short prefix. An earlier revision kept the first 8 characters, on the
    theory that a partial prefix was harmless; for a 32-byte token that is
    roughly 32 bits of the value handed to a log or console for no
    functional benefit (not catastrophic on its own, but there is no upside
    to keeping it, so none is kept). Only the type and length are reported:
    enough to recognise a genuine format mistake (an empty string, a value
    the wrong length) without reproducing any part of the value itself.
    """
    return f"<{type(value).__name__}, {len(value)} chars>"


def _reject_userinfo(url: str) -> None:
    """Refuse a URL carrying a userinfo section (``user:pass@host``).

    B4 builds ``NetworkEndpointInfo.url`` as ``https://<host>:<port>/mcp``
    with no credentials, so this is defence in depth rather than a live
    leak today. But the registration is a ZIP file that gets copied around
    and installed on another machine's Plugins page, and a URL is exactly
    where a credential hides in plain sight. The message deliberately does
    not echo *url* — if it does carry a credential, this is the one place
    that must not put it in a log.

    ``urlsplit`` itself is not safe to call blind: a malformed authority can
    make it raise ``ValueError`` with the offending fragment quoted verbatim
    (verified: ``urlsplit("https://[SECRETTOKEN123]/mcp")`` raises
    ``ValueError("'SECRETTOKEN123' does not appear to be an IPv4 or IPv6
    address")`` — the exact class of leak this function exists to prevent,
    coming out of the parser we would be calling to prevent it, and
    uncaught it would also crash the export instead of reporting it). Not
    every malformed authority echoes like that (``https://[::1/mcp`` raises
    a plain ``"Invalid IPv6 URL"`` with nothing quoted), so this catches the
    whole exception class rather than special-casing the one shape that
    happens to leak.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        msg = f"the url could not be parsed, got {_safe_repr(url)}"
        raise ValueError(msg) from None
    if parts.username is not None or parts.password is not None:
        msg = (
            "the url contains an embedded credential (a userinfo section); "
            "refusing to export a registration that could carry one"
        )
        raise ValueError(msg)


def _assert_no_duplicates(
    names: tuple[str, ...], *, label: str, exc_type: type[Exception] = RuntimeError,
) -> None:
    """Raise if *names* contains a repeated entry.

    Two lists with the same duplicate compare equal to each other (and as
    sets), so neither a tuple-equality nor a set-equality check between
    :func:`served_tool_names` and :attr:`NetworkEndpointInfo.tool_names` can
    see a duplicate that appears identically on both sides. TOML cannot:
    two ``[tools.<name>]`` tables sharing a name is a parse failure on the
    core, which is the terminal load failure this whole module exists to
    prevent — arriving, undetected, through the one comparison meant to
    catch exactly this class of mismatch. Checked independently here rather
    than assumed clean by the earlier :func:`validate_tool_names` call,
    which checks the same property on the live ``SERVED_TOOLS`` table but
    is a separate call this function must not silently depend on.

    Args:
        exc_type: The exception class to raise — ``ValueError`` from
            :func:`build_manifest_text` (an input-shape problem, consistent
            with its other validation), ``RuntimeError`` (the default) from
            :func:`export_registration` (a wiring/contract problem).
    """
    seen: set[str] = set()
    dupes: set[str] = set()
    for name in names:
        if name in seen:
            dupes.add(name)
        seen.add(name)
    if dupes:
        msg = f"{label} contains duplicate tool names: {sorted(dupes)}"
        raise exc_type(msg)


def _assert_is_name_sequence(value: object, *, label: str) -> None:
    """Guard against ``set("abc") == set(("a", "b", "c"))``-style confusion.

    A bare ``str`` is itself an iterable of one-character strings, so
    ``set()`` over a 3-character string and ``set()`` over a 3-tool tuple
    can compare equal by accident — a bug that hands a caller's typo (a
    string where a sequence of names was meant) straight through the
    symmetry check and exports a registration that has nothing to do with
    what is actually served. Explicitly reject ``str``/``bytes`` and
    anything that is not a ``tuple``/``list`` before either side is turned
    into a set, so this fails loudly and immediately rather than silently
    comparing the wrong thing.
    """
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        msg = f"{label} must be a tuple or list of tool names, got {type(value).__name__}"
        raise TypeError(msg)


def _toml_string(value: str) -> str:
    """Render *value* as a quoted TOML basic string.

    Every value that reaches this (the description, the url, a hostname) is
    a fixed literal or a value already validated elsewhere (the fingerprint
    format, the URL scheme) — no user-authored free text reaches the
    manifest — but escaping backslash and quote is cheap insurance against a
    future caller that is less careful.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_manifest_text(
    *,
    url: str,
    bind_host: str,
    fingerprint: str,
    tool_names: tuple[str, ...],
    version: str | None = None,
) -> str:
    """Render ``manifest.toml`` text for the workstation plugin (contract §2).

    Args:
        url: ``https://<host>:<port>/mcp`` — from
            :attr:`NetworkEndpointInfo.url`.
        bind_host: The operator-chosen interface, for the ``[permissions]``
            network declaration.
        fingerprint: ``sha256:<64 hex>`` of the endpoint's leaf certificate.
        tool_names: The served set, in serving order —
            :func:`~workstation_agent.network_mcp.tools.served_tool_names`.
        version: Overrides the Agent version written into the manifest.
            Exposed for tests; production callers leave it as
            :func:`_agent_version`.

    Raises:
        ValueError: if *fingerprint* is not ``sha256:`` + hex, if
            *tool_names* is empty (an empty registration would install a
            plugin the core cannot ever call anything on), if *url* is not
            ``https://``, if *url* carries a userinfo section, or if
            *tool_names* contains a duplicate (contract §2: two
            ``[tools.<name>]`` tables sharing a name is invalid TOML).

    **Never accepts a token.** There is no parameter for one — the
    registration carries only the *name* of the secret
    (``auth_secret = "workstation_token"``) the operator pastes the value
    into on the PersonaCore side (contract §3), so there is no argument here
    a caller could accidentally wire the live token into.
    """
    if not fingerprint.startswith("sha256:") or len(fingerprint) != len("sha256:") + 64:
        msg = f"fingerprint must be 'sha256:' + 64 hex characters, got {_safe_repr(fingerprint)}"
        raise ValueError(msg)
    if not tool_names:
        msg = "cannot build a manifest with an empty tool list"
        raise ValueError(msg)
    _assert_no_duplicates(tool_names, label="tool_names", exc_type=ValueError)
    if not url.startswith("https://"):
        msg = f"url must be https:// (contract §3), got {_safe_repr(url)}"
        raise ValueError(msg)
    _reject_userinfo(url)

    ver = version if version is not None else _agent_version()

    lines: list[str] = [
        "[plugin]",
        f"name            = {_toml_string(_PLUGIN_NAME)}",
        f"version         = {_toml_string(ver)}",
        f"contract        = {_toml_string(_CONTRACT_VERSION)}",
        'transport       = "http"',
        f"url             = {_toml_string(url)}",
        f"auth_secret     = {_toml_string(_AUTH_SECRET_NAME)}",
        f"tls_fingerprint = {_toml_string(fingerprint)}",
        f"description     = {_toml_string(_DESCRIPTION)}",
        "",
        "[permissions]",
        f"network = [{_toml_string(bind_host)}]",
        "secrets = []",
        "paths   = []",
        "",
    ]
    # Contract §2's own literal example puts the header and the key/value
    # pair on one line ("[tools.workstation_status]  risk = \"safe\""),
    # which is not valid TOML -- a table header cannot share its line with
    # a key. A dotted inline key (``tools.name = { risk = "safe" }``) looked
    # like a one-line fix but is not one either: written here, with no table
    # header of its own, it would still be parsed as *nested inside* the
    # still-open ``[permissions]`` table above (blank lines do not close a
    # table; only the next ``[header]`` does), landing at
    # ``permissions.tools.<name>`` instead of the root-level ``tools.<name>``
    # the core actually reads. An explicit ``[tools.<name>]`` header is
    # unambiguous regardless of what table was open before it, so each tool
    # gets a real two-line block instead.
    for name in tool_names:
        lines.append(f"[tools.{name}]")
        lines.append('risk = "safe"')
    lines.extend([
        "",
        "[events]",
        "publishes  = []",
        "subscribes = []",
        "",
    ])
    return "\n".join(lines)


def export_registration(
    config: NetworkMcpConfig,
    *,
    output_dir: Path | None = None,
    state_dir: Path | None = None,
) -> RegistrationResult:
    """Write ``workstation-registration.zip`` and return where it landed.

    Args:
        config: The endpoint's :class:`NetworkMcpConfig` (bind host / port).
            Read regardless of ``config.enabled`` — the registration
            describes where the endpoint *would* answer, independent of
            whether the operator has switched it on yet.
        output_dir: Directory to write the zip into. Defaults to the
            current working directory.
        state_dir: Overrides where the certificate/token live. Tests pass a
            ``tmp_path``; production leaves this as the default
            (``%APPDATA%\\WorkstationAgent\\network-mcp``).

    Returns:
        The path written and what went into it.

    Raises:
        RuntimeError: if the served-tool table itself violates contract §2
            (checked here, so a bad table is refused before anything is
            written to disk rather than shipped as a manifest the core
            rejects at load), if either route to the served set contains a
            duplicate name, or if the two routes to the served set — this
            module's :func:`served_tool_names` and
            :meth:`NetworkMCPServer.info` — ever disagree.
        TypeError: if either route to the served set is not a ``tuple``/
            ``list`` of names (guards against ``set("abc") ==
            set(("a","b","c"))``-style type confusion before either side is
            turned into a set).
        ValueError: from :func:`build_manifest_text` if *info* carries a
            malformed fingerprint or URL.
        OSError: if *output_dir* cannot be created or the zip cannot be
            written.
    """
    # Checked here as well as in export_registration_from_endpoint, and
    # deliberately *before* the server is built: `info()` generates the
    # certificate and token if they do not exist yet, and a table that
    # violates contract §2 should be refused before anything is created on
    # disk, not after.
    problems = validate_tool_names()
    if problems:
        msg = (
            "cannot export a registration: the served-tool table violates "
            "contract §2: " + "; ".join(problems)
        )
        raise RuntimeError(msg)

    # Imported here, not at module scope: NetworkMCPServer's constructor
    # touches no network or web-server import at all (those are deferred to
    # .start(), which this never calls), but keeping the import local keeps
    # this module cheap to import from the CLI path regardless.
    from workstation_agent.network_mcp.server import NetworkMCPServer

    server = NetworkMCPServer(config, state_dir=state_dir)
    return export_registration_from_endpoint(server.info(), output_dir=output_dir)


def export_registration_from_endpoint(
    info: Any,  # noqa: ANN401 — duck-typed NetworkEndpointInfo, never imported here
    *,
    output_dir: Path | None = None,
) -> RegistrationResult:
    """Write the registration for an endpoint whose live identity is *info*.

    :func:`export_registration` builds a throwaway
    :class:`~workstation_agent.network_mcp.server.NetworkMCPServer` from a
    config and exports *that* server's ``info()``. That is right for the CLI,
    which has no running Agent to ask, but it is wrong for the UI while the
    endpoint is actually up, for a reason that bites in practice: a server
    constructed from config reports ``config.port``, and ``port = 0`` means
    "let the OS pick" — so exporting from config while the real endpoint is
    listening on an OS-assigned port writes ``https://host:0/mcp``, a
    registration for an endpoint that does not exist. The same applies to any
    drift between what is saved and what the running server was constructed
    with. This entry point takes the live
    :class:`~workstation_agent.network_mcp.server.NetworkEndpointInfo`
    instead, so the exported registration describes the endpoint the core will
    actually reach.

    *info* is duck-typed on purpose: this module must not import the
    network_mcp server package at module scope (see the module docstring), and
    the only attributes read are ``url``, ``bind_host``, ``fingerprint`` and
    ``tool_names``.

    Args:
        info: The live endpoint identity — ``NetworkMCPServer.info()``.
        output_dir: Directory to write the zip into. Defaults to the current
            working directory.

    Returns:
        The path written and what went into it.

    Raises:
        RuntimeError, TypeError, ValueError, OSError: exactly as
            :func:`export_registration` documents.
    """
    problems = validate_tool_names()
    if problems:
        msg = (
            "cannot export a registration: the served-tool table violates "
            "contract §2: " + "; ".join(problems)
        )
        raise RuntimeError(msg)

    tool_names = served_tool_names()
    # Type-checked before either side is turned into a set: set("abc") ==
    # set(("a", "b", "c")) is True in Python, so if `info.tool_names` were
    # ever a bare string a set-equality check alone would not notice, and
    # would export a registration with nothing to do with what is served.
    _assert_is_name_sequence(tool_names, label="served_tool_names()")
    _assert_is_name_sequence(info.tool_names, label="NetworkMCPServer.info().tool_names")
    # Checked independently on *both* sides before the equality check below:
    # a name duplicated identically on both sides compares equal whether the
    # comparison is by tuple or by set, so an equality check alone cannot
    # see it -- and TOML rejects two `[tools.<name>]` tables sharing a name
    # outright, which is a parse failure on the core (contract §2).
    _assert_no_duplicates(tool_names, label="served_tool_names()")
    _assert_no_duplicates(info.tool_names, label="NetworkMCPServer.info().tool_names")
    if set(tool_names) != set(info.tool_names):
        # Both are, today, `tuple(t.name for t in SERVED_TOOLS)` read two
        # different ways. Asserting them equal here is what turns "they
        # happen to agree" into "a refusal to export catches it the day
        # they don't" — which is the entire promise this module makes.
        msg = (
            "served_tool_names() and NetworkMCPServer.info().tool_names disagree "
            "-- refusing to export a registration that would not match what the "
            "endpoint actually serves"
        )
        raise RuntimeError(msg)

    manifest_text = build_manifest_text(
        url=info.url,
        bind_host=info.bind_host,
        fingerprint=info.fingerprint,
        tool_names=tool_names,
    )

    out_dir = output_dir if output_dir is not None else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / REGISTRATION_ZIP_NAME

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_ARCNAME, manifest_text)
    zip_path.write_bytes(buffer.getvalue())

    return RegistrationResult(
        path=zip_path,
        tool_names=tool_names,
        url=info.url,
        fingerprint=info.fingerprint,
    )


# ---------------------------------------------------------------------------
# Pre-flight: would this registration actually work on the core?
# ---------------------------------------------------------------------------

#: Hostnames that resolve to the loopback interface. Checked by name because a
#: bind_host is a string, not a resolved address, and ``localhost`` is the one
#: name an operator is likely to type meaning "this machine".
_LOOPBACK_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


def is_loopback_host(host: str) -> bool:
    """True if *host* names the loopback interface.

    A registration whose ``url`` points at loopback is syntactically perfect
    and functionally useless: PersonaCore runs on another machine, and
    ``127.0.0.1`` there means *that* machine. Recognising it is what lets the
    UI say so before the operator installs a plugin that can never connect.
    """
    stripped = host.strip().strip("[]").lower()
    if not stripped:
        return False
    if stripped in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(stripped).is_loopback
    except ValueError:
        return False


def san_covers(host: str, sans: object) -> bool:
    """True if *host* is covered by the certificate SAN entries *sans*.

    Compared two ways, because a SAN carries DNS names and IP addresses as text
    and the two are not interchangeable: a name matches case-insensitively (DNS
    is case-insensitive), while an address is parsed on both sides and compared
    as an address, so ``::1`` matches ``0:0:0:0:0:0:0:1`` and ``[192.168.1.50]``
    matches ``192.168.1.50``. No wildcard or suffix matching -- a certificate
    covering ``foo.example`` does not cover ``bar.foo.example``, and guessing
    otherwise would produce a reassuring UI for a broken endpoint.

    An empty *host* is treated as covered: there is nothing to check, and the
    schema refuses an empty ``bind_host`` anyway.

    *sans* is typed ``object`` and defended rather than trusted. It reaches
    here from a duck-typed ``info.certificate_sans``, and the failure mode if
    it is not the expected sequence is quiet rather than loud: a bare ``str``
    iterates as single characters, so a SAN of ``"192.168.1.50"`` handed in as
    a string instead of a one-element tuple would compare ``"1"``, ``"9"``,
    ``"2"`` ... against the host and report "not covered" for a certificate
    that covers it perfectly -- pushing the operator to rotate a fingerprint
    that was fine. Anything that is not a real sequence of entries is treated
    as no coverage information at all.
    """
    stripped = host.strip().strip("[]")
    if not stripped:
        return True
    if isinstance(sans, (str, bytes)) or not isinstance(sans, Sequence):
        return False
    entries = [str(s).strip().strip("[]") for s in sans]
    try:
        wanted = ipaddress.ip_address(stripped)
    except ValueError:
        return any(e.lower() == stripped.lower() for e in entries)
    for entry in entries:
        try:
            if ipaddress.ip_address(entry) == wanted:
                return True
        except ValueError:
            continue
    return False


def registration_problems(
    info: Any,  # noqa: ANN401 — duck-typed NetworkEndpointInfo, never imported here
    *,
    running: bool | None = None,
) -> tuple[str, ...]:
    """Reasons the registration built from *info* would not work, in order.

    Returned as operator-facing sentences rather than codes: every one of them
    is something the person exporting has to read and decide about, and there
    is exactly one consumer (the UI's export pre-flight). An empty tuple means
    "nothing here would stop the core connecting".

    Deliberately advisory, not enforcing -- this function refuses nothing.
    :func:`export_registration` and the ``export-registration`` CLI keep
    exporting whatever they are asked to, because a scripted export that
    suddenly started failing would be a worse regression than a registration
    the operator was warned about. The UI is what turns these into a
    confirmation step.

    Args:
        info: A live ``NetworkMCPServer.info()``.
        running: Whether the endpoint is actually serving. Defaults to
            ``info.running``; passed explicitly when the caller knows better
            than the snapshot does.
    """
    problems: list[str] = []

    is_running = bool(getattr(info, "running", False)) if running is None else bool(running)
    if not is_running:
        problems.append(
            "The endpoint is not running, so nothing has bound the address in this "
            "registration. PersonaCore would install the plugin and then fail to "
            "connect until the endpoint is switched on.",
        )

    bind_host = str(getattr(info, "bind_host", "") or "")
    if is_loopback_host(bind_host):
        problems.append(
            f"The endpoint is bound to {bind_host!r}, the loopback interface. A "
            "registration pointing at loopback is reachable only from this "
            "workstation -- on PersonaCore's machine that address means "
            "PersonaCore itself. Choose this machine's LAN address instead.",
        )

    if getattr(info, "port", None) == 0:
        problems.append(
            "The port is 0, which asks the operating system to pick a free port at "
            "every start. The port written into this registration is the one in use "
            "right now and will be wrong after the next Agent restart. Set a fixed "
            "port.",
        )

    raw_sans = getattr(info, "certificate_sans", ()) or ()
    # Normalised the same way :func:`san_covers` normalises it, so the message
    # lists what was actually compared. A bare string would otherwise be joined
    # character by character into "1, 9, 2, ." and read as a corrupt certificate.
    sans: Sequence[object] = (
        raw_sans
        if not isinstance(raw_sans, (str, bytes)) and isinstance(raw_sans, Sequence)
        else ()
    )
    if not san_covers(bind_host, raw_sans):
        listed = ", ".join(str(s) for s in sans) or "empty"
        problems.append(
            f"The certificate does not cover {bind_host!r} (its SAN is {listed}). "
            "PersonaCore pins the fingerprint rather than checking the name, so it "
            "will most likely still connect, but any client that verifies hostnames "
            "will reject this endpoint.",
        )

    return tuple(problems)
