"""Runtime permissions evaluation for MCP plugin tool calls.

Every tool invocation passes through :func:`evaluate` before being dispatched.
The decision is one of:

* ``"allow"``   — the call is within all declared permissions and no
                  confirmable condition is triggered.
* ``"deny"``    — the call violates a hard constraint (tool not in granted
                  permissions, path outside declared scope, unknown condition,
                  or a *read* whose path lies outside the declared roots).
* ``"confirm"`` — the call is allowed in principle but a confirmable condition
                  is triggered; the host must present a user prompt.

Built-in condition checkers are registered in :data:`CONDITION_CHECKERS`.  Each
checker receives ``(manifest, tool, args)`` and returns ``True`` when the
condition is met (i.e. the call *would* violate the guard).

The read/action split (contract §11 item 6)
-------------------------------------------
A **read** whose path argument falls outside the plugin's declared roots is
``deny``.  It is never ``confirm``: the operator must not be trained to
approve reads of arbitrary paths, and there is no legitimate reading of
somewhere the plugin was never granted.

That rule is implemented as an **explicit short-circuit** in :func:`evaluate`
(see ``_READ_OUTSIDE_ROOTS`` below), and deliberately *not* by making
:func:`_outside_declared_paths` return ``False`` for reads.  Returning
``False`` there would skip the confirmable-condition branch **and** the
hard-guard loop — the loop skips any guard the plugin declares as a
confirmable condition, and ``filesystem`` declares ``outside_declared_paths``
— so the call would fall through to the trailing ``return "allow"``.  That
turns "a read outside the roots prompts" into "a read outside the roots
silently succeeds", which is strictly worse than the behaviour being fixed.
The short-circuit returns ``"deny"`` before either branch can be reached.

``_outside_declared_paths`` itself stays tool-independent on purpose: "is this
path inside the declared roots" is a property of the path, not of the verb.
The verb-dependence lives in one place, in :func:`evaluate`, where it can be
read and tested as a single rule.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .loader import PluginManifest

log = logging.getLogger(__name__)

PermissionDecision = Literal["allow", "deny", "confirm"]

_ConditionChecker = Callable[["PluginManifest", str, dict[str, Any]], bool]

_HARD_GUARDS = ("outside_declared_paths", "command_outside_allowlist", "domain_outside_allowlist")


# ---------------------------------------------------------------------------
# Session context — the identifier B3's "remember for this session" needs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionContext:
    """Identity of the transport connection a tool call arrived on.

    ``MCPHost.invoke`` accepted no session identifier, and the HTTP endpoint
    is stateless, so §7's per-tool "remember for this session" had nothing to
    key on.  This carries that key from the transport (a named-pipe
    connection, an HTTP session) down to :func:`evaluate`.

    B2 only *plumbs* it: nothing here remembers anything.  B3 implements the
    remembering on top of ``session_id``.

    Attributes:
        session_id: Stable identifier for the connection/session.  Minted by
            the transport, unique per connection, and never reused across
            agent restarts (sessions die with the agent, §5.5).
        transport: Which transport minted it (``"named_pipe"``, ``"http"``,
            ``"internal"``).  Two transports can never collide on an id
            because each mints a random one, but recording the origin makes
            the audit rows readable.
        request_id: The MCP request id of the call, when the transport has
            one (§5.7 requires it in the audit row).
        peer: Optional human-readable description of the far end.
    """

    session_id: str
    transport: str = "unknown"
    request_id: str | None = None
    peer: str | None = None


# ---------------------------------------------------------------------------
# Read / action classification
# ---------------------------------------------------------------------------

#: Tools that only observe.  Matched on the fully-qualified name.
_READ_ONLY_TOOLS: frozenset[str] = frozenset({
    # this repo's first-party plugins
    "filesystem.read",
    "filesystem.list",
    # contract §6 family names (built by B6/B7/B8)
    "files_read",
    "files_list",
    "workstation_status",
    "devices_list",
    "serial_ports",
    "serial_read",
    "adb_devices",
    "adb_logcat",
    "jobs_list",
    "jobs_output",
    "jobs_wait",
})

#: Verbs that only observe.  Matched on the last segment of the tool name.
_READ_ONLY_VERBS: frozenset[str] = frozenset({
    "read",
    "list",
    "get",
    "stat",
    "info",
    "status",
    "exists",
    "ports",
    "devices",
    "output",
    "search",
    "find",
    "head",
    "tail",
    "logcat",
})

#: Machine-readable rule name for the read/action short-circuit.
_READ_OUTSIDE_ROOTS = "read_outside_declared_paths"

#: Tools whose contract §6 signature has a **mandatory** path parameter.
#:
#: This is the classification the empty-allowlist denial keys on, and it is
#: keyed on the *tool*, deliberately, rather than on whether path extraction
#: happened to find something.  For these tools "no path argument was
#: detected" is a scanner failure, not a call without paths: every legitimate
#: call has one, so the absence of a detected path means the extractor missed
#: it and the call must not be waved through.
#:
#: ``shell_run`` is **not** here even though §6 gives it a ``cwd``: that
#: parameter is optional, so a ``shell_run`` with no ``cwd`` is a normal call
#: with genuinely no path, and denying it would be wrong.  Same for
#: ``adb_pull``, whose ``device_path`` is on the phone, not the workstation
#: (§6: "adb_push, adb_install and files_* take workstation paths").
_PATH_REQUIRED_TOOLS: frozenset[str] = frozenset({
    # this repo's first-party plugin
    "filesystem.read",
    "filesystem.list",
    "filesystem.write",
    "filesystem.delete",
    # contract §6 families (built by B6/B7)
    "files_list",
    "files_read",
    "files_write",
    "adb_push",
    "adb_install",
})

#: Whole families where every verb takes a workstation path, so a verb added
#: later is covered without editing the set above.
_PATH_REQUIRED_PREFIXES: tuple[str, ...] = ("filesystem.", "files_")


#: Argument names that name something in a **foreign** namespace — somewhere
#: that is not this workstation — keyed by tool-family prefix.  Covers paths
#: and commands alike: ``adb_shell(serial, command)`` runs its command on the
#: phone, so judging it against the workstation's ``cmd:`` allowlist denies
#: every legitimate call in exactly the way judging ``device_path`` against
#: the workstation's ``path:`` roots does.  (§7 puts ``adb_shell`` on the
#: always-prompt list; that is B3's gate, and the right one for it.)
#:
#: Contract §6: "adb_push, adb_install and files_* take workstation paths",
#: which says by implication that the rest of the adb family does not.
#: ``adb_pull(serial, device_path)`` names a file on the phone;
#: ``/sdcard/DCIM/x.jpg`` can never be inside a Windows root and comparing it
#: to one denies every legitimate call.
#:
#: This is an **allowlist of exempt argument names, not of checked ones**,
#: and that direction is deliberate.  Exempting "everything in adb_ except
#: ``workstation_path``" would mean a family that spelled its workstation
#: argument differently — ``src``, ``local``, anything — silently escaped
#: root confinement.  Naming the device-side arguments instead means an
#: unrecognised argument stays checked: the failure mode is an over-denial
#: that shows up immediately, not a bypass that does not.
#:
#: ``serial_`` is included pre-emptively on the same §6 reasoning: a serial
#: payload (``text``/``hex``) is not a workstation path either, and B8 would
#: otherwise hit this identical bug the first time it wrote ``/status\r\n``
#: to a device.  Flagged as pre-emptive; drop it if you would rather B8
#: found it.
#: ``(owning plugin id, tool-name prefix, exempt argument names)``.
#:
#: **Both** halves must match.  Keying the exemption on the tool name alone
#: made it inheritable by anyone: a third-party plugin shipping a tool called
#: ``adb_run`` or ``serial_send`` picked up the exemptions and had its
#: ``command`` argument skipped by the workstation command allowlist —
#: precisely the bypass the exemption was scoped to avoid.  The tool name is
#: caller-supplied; ``manifest.id`` comes from a signed ``plugin.toml``, so
#: the plugin genuinely providing the family is the thing worth anchoring to.
_FOREIGN_ARGS: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("adb", "adb_", frozenset({"device_path", "remote_path", "command", "filter"})),
    ("serial", "serial_", frozenset({"text", "hex", "data", "until"})),
)


def foreign_args(manifest: PluginManifest, tool: str) -> frozenset[str]:
    """Argument names of *tool* that name something not on this workstation.

    Empty unless *manifest* is the plugin that owns the family **and** *tool*
    is named within it.  A plugin that is not the family owner gets no
    exemption whatever it calls its tools.
    """
    if not isinstance(tool, str):
        return frozenset()
    name = tool.strip().lower()
    plugin_id = str(getattr(manifest, "id", "")).strip().lower()
    for owner, prefix, keys in _FOREIGN_ARGS:
        if plugin_id == owner and name.startswith(prefix):
            return keys
    return frozenset()


def requires_path(tool: str) -> bool:
    """Return True when *tool*'s signature always includes a workstation path.

    Used by :func:`_outside_declared_paths` to decide the empty-allowlist
    case on the tool rather than on the extractor's output — see
    :data:`_PATH_REQUIRED_TOOLS` for why that distinction is the point.
    """
    if not isinstance(tool, str):
        return False
    name = tool.strip().lower()
    if not name:
        return False
    if name in _PATH_REQUIRED_TOOLS:
        return True
    return name.startswith(_PATH_REQUIRED_PREFIXES)


def is_read_only_tool(tool: str) -> bool:
    """Return True when *tool* only observes and never changes the machine.

    Classification is a strict **allowlist**.  Anything unrecognised is
    treated as an action, which is the safe default here: the only thing this
    classification does is turn an out-of-roots *path* from ``confirm`` into
    ``deny``.  Mistaking an action for a read therefore denies (safe);
    mistaking a read for an action prompts (the pre-existing behaviour, and
    never more permissive than before).  There is no direction in which a
    misclassification here can produce ``allow``.

    The argument is not assumed to be a well-formed tool id: anything that is
    not a non-empty string is an action.
    """
    if not isinstance(tool, str):
        return False
    name = tool.strip().lower()
    if not name:
        return False
    if name in _READ_ONLY_TOOLS:
        return True
    # ``family.verb`` (this repo) or ``family_verb`` (contract §6).  Only fall
    # back to the underscore split when there is no dot, so
    # ``filesystem.list_recent`` does not decompose to ``recent``.
    verb = name.rsplit(".", 1)[-1] if "." in name else name.rsplit("_", 1)[-1]
    return verb in _READ_ONLY_VERBS


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

#: Argument names that are paths even when the value carries no separator
#: (``{"path": "notes.txt"}`` must still be checked against the roots).
_PATH_ARG_KEYS: frozenset[str] = frozenset({
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filepath",
    "file_path",
    "dir",
    "directory",
    "folder",
    "cwd",
    "src",
    "source",
    "dst",
    "dest",
    "destination",
    "target",
    "workstation_path",
    "device_path",
    "local_path",
    "remote_path",
    "input_path",
    "output_path",
})

#: Substrings that make an argument *name* path-ish even when it is not in
#: the exact list above — ``file_to_read``, ``target_directory``,
#: ``dest_folder``.  Deliberately over-inclusive: the exact-name list will
#: always lag whatever a future family calls its arguments, and a false
#: positive here costs a denial while a false negative costs the machine.
_PATHISH_KEY_FRAGMENTS: tuple[str, ...] = (
    "path", "file", "dir", "folder", "cwd", "root", "location", "name",
)

_MAX_PATH_RECURSION = 8
_MAX_PATH_CANDIDATES = 512

#: A candidate that could not be fully inspected (recursion or count bound
#: hit, or an argument of a type this module does not understand).  It is a
#: *value*, not a flag, so it flows through the same comparison as a real
#: path — and it can never be inside any declared root, so "I could not look
#: at all of this" resolves to a violation rather than to silence.
UNINSPECTABLE = "\x00uninspectable"

#: ``\\?\`` (extended-length) and ``\\.\`` (device namespace).  Win32 does
#: **not** normalise these — ``..`` is passed through literally and trailing
#: dots/spaces are not stripped — so the rules modelled below simply do not
#: apply to them.  Rather than model two contradictory rule sets, any such
#: path is treated as outside every root: ``\\.\PhysicalDrive0`` and
#: ``\\?\GLOBALROOT\...`` are never a legitimate declared root anyway.
_DEVICE_NAMESPACE = re.compile(r"^[\\/]{2}[?.][\\/]")

#: ``C:`` — including the drive-*relative* ``C:secret.txt`` form, which has
#: no separator at all and resolves against that drive's current directory.
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")

#: A real URI scheme (two or more characters, so it can never be a drive
#: letter).  ``http://`` is the domain allowlist's business, not the path
#: allowlist's; ``file://`` is unambiguously a path.
_URI_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]+)://")


def _key_is_pathish(key: str) -> bool:
    """Return True when an argument *name* says its value is a path."""
    lowered = key.lower()
    if lowered in _PATH_ARG_KEYS:
        return True
    return any(fragment in lowered for fragment in _PATHISH_KEY_FRAGMENTS)


def _value_is_unambiguously_a_path(text: str) -> bool:
    """Return True for shapes that are a filesystem path whatever the key.

    Only the unmistakable forms are matched here — a drive-letter prefix, a
    leading separator (which covers UNC and the device namespace), and
    ``file://``.

    The weaker signals (a separator *somewhere* inside the string, a colon
    somewhere inside the string) are deliberately **not** in this function;
    they are applied only under a path-ish key, by
    :func:`_value_is_pathish_under_key`.  Applying them unconditionally
    would make every ``powershell.run`` command containing a backslash and
    every ``clipboard.set`` text containing a colon into a path argument,
    and — once a plugin with no declared roots refuses all path arguments —
    that is not an over-inclusion anyone can whitelist per argument, it is
    those tools ceasing to work.  A plugin that genuinely must accept
    arbitrary path-shaped values declares ``path:/`` and says so in its
    manifest, where it can be audited.
    """
    stripped = text.strip()
    if not stripped:
        return False
    if _DRIVE_PREFIX.match(stripped):
        return True
    if stripped[0] in "/\\":
        return True
    scheme = _URI_SCHEME.match(stripped)
    if scheme is not None:
        return scheme.group(1).lower() == "file"
    return False


def _value_is_pathish_under_key(text: str) -> bool:
    """Weaker path signals, trusted only when the argument name agrees.

    A colon that is not part of a URI scheme covers the NTFS alternate data
    stream form (``secret.txt:Zone.Identifier``), which carries no separator
    and would otherwise be invisible.
    """
    stripped = text.strip()
    if not stripped:
        return False
    if "/" in stripped or "\\" in stripped:
        return True
    return ":" in stripped and _URI_SCHEME.match(stripped) is None


def _strip_windows_padding(segment: str) -> str:
    """Remove the trailing dots and spaces Win32 discards from a component.

    ``C:\\root\\.. \\Windows`` and ``C:\\root\\...\\Windows`` reach the
    filesystem as ``C:\\root\\..\\Windows``: Win32 strips trailing spaces
    and dots from every component before resolving it.  Comparing segments
    with ``==`` against ``".."`` therefore misses both spellings, treats
    them as ordinary directory names, and concludes the path stays inside
    the root while the OS walks straight out of it.
    """
    return segment.rstrip(" .")


def _classify_segment(segment: str) -> str:
    """Return ``".."``, ``"."`` or the cleaned segment name.

    A component made only of dots and spaces with **two or more** dots is a
    parent reference however it is spelled: ``..``, ``.. ``, ``...``,
    ``.. .``.  One dot is the current directory; nothing but spaces is
    discarded the same way.
    """
    cleaned = _strip_windows_padding(segment)
    if cleaned:
        return cleaned
    return ".." if segment.count(".") >= 2 else "."  # noqa: PLR2004


def normalise_path(value: str) -> str:
    """Lexically normalise a path for comparison against a declared root.

    Expands ``%VAR%`` and ``~`` (declared roots in ``plugin.toml`` are written
    as ``path:%USERPROFILE%\\Documents``, while real arguments arrive already
    expanded), unifies separators, resolves ``.`` and ``..`` **without
    touching the filesystem**, and lower-cases (the target is Windows, whose
    paths are case-insensitive).

    Resolving ``..`` lexically is the point of this function, not a
    nicety: without it ``%USERPROFILE%/Documents/../../Windows/System32``
    starts with the declared root as a string and passes a naive prefix
    test, which would make the deny below trivially bypassable.

    ``Path.resolve()`` is deliberately not used: it consults the filesystem
    and anchors relative paths to the process's cwd, so the answer would
    depend on where the agent happens to be running.
    """
    # os.path, not pathlib: this is deliberately pure string work.  Building a
    # Path here would normalise separators per the *running* platform and
    # invite a later .resolve(), which is exactly what must not happen.
    if value == UNINSPECTABLE:
        return UNINSPECTABLE
    # os.path, not pathlib: this is deliberately pure string work.  Building a
    # Path here would normalise separators per the *running* platform and
    # invite a later .resolve(), which is exactly what must not happen.
    text = os.path.expanduser(os.path.expandvars(value)).replace("\\", "/")  # noqa: PTH111
    if _DEVICE_NAMESPACE.match(value) or _DEVICE_NAMESPACE.match(text):
        # Win32 does not normalise these, so nothing below models them
        # correctly.  Resolve to a value no declared root can contain.
        return UNINSPECTABLE
    # A UNC path (\\server\share) keeps its doubled leading separator all the
    # way through.  Collapsing it to a single one — which is what dropping
    # empty segments used to do — makes \\server\share indistinguishable from
    # the *local* path \server\share, so a plugin granted `path:\server`
    # reached arbitrary network shares.  Plain UNC is neither \\?\ nor \\.\,
    # so the device-namespace branch above never sees it.
    if text.startswith("//"):
        leading = "//"
    elif text.startswith("/"):
        leading = "/"
    else:
        leading = ""
    segments: list[str] = []
    for raw_seg in text.split("/"):
        seg = _classify_segment(raw_seg)
        if seg == ".":
            continue
        if seg == "..":
            if segments and segments[-1] != "..":
                segments.pop()
            elif not leading:
                # A relative path climbing above its own base stays visible as
                # "..", so it can never accidentally match a declared root.
                segments.append("..")
            # With a leading "/", ".." at the root is dropped: you cannot
            # climb above the root, which is what the OS does too.
            continue
        segments.append(seg)
    joined = (leading + "/".join(segments)).rstrip("/").lower()
    return joined or leading


#: A normalised drive-*absolute* path: ``c:/users/me``.  The drive-relative
#: ``c:secret.txt`` deliberately does not match — it resolves against that
#: drive's current directory, which this gate has no way to know.
_DRIVE_ABSOLUTE = re.compile(r"^[a-z]:/")


def _is_unc(path: str) -> bool:
    """True for a normalised UNC path (``//server/share/...``)."""
    return path.startswith("//")


def is_absolute_path(path: str) -> bool:
    """True when a normalised path names one location, independent of cwd.

    Relative paths have **no well-defined meaning at this gate**.  Resolving
    one requires a base directory, and the only base available is the
    agent's own working directory — which is precisely why
    :func:`normalise_path` refuses ``Path.resolve()``.  A gate that
    interpreted them would be confining paths against a base that varies
    with how the agent happened to be launched.

    So a relative candidate is refused rather than interpreted.  Note this
    changes almost nothing in practice: a relative candidate never matched a
    (necessarily absolute) declared root anyway, so it already denied.  The
    one case it *does* change is the empty string — see
    :func:`_outside_declared_paths`.
    """
    if not path or path == UNINSPECTABLE:
        return False
    return path.startswith("/") or bool(_DRIVE_ABSOLUTE.match(path))


def _is_within(candidate: str, root: str) -> bool:
    """Return True when normalised *candidate* is at or under normalised *root*.

    Compares on **segment boundaries**, so a root of ``/safe`` does not
    swallow ``/safeguard``.

    Three refusals happen before any comparison, in this order:

    * :data:`UNINSPECTABLE` is never inside anything.  It stands for "this
      argument could not be read" and for the device namespace, and it used
      to be admitted by the ``root == "/"`` fast path below — so a plugin
      declaring ``path:/`` was handed uninspectable arguments and
      ``\\\\.\\PhysicalDrive0`` alike, flatly contradicting the design that
      says those resolve to a value no root can contain.  ``path:/`` means
      "every path", not "things that are not paths at all".
    * A UNC candidate is inside only a UNC root, and vice versa.  Local and
      network paths never satisfy each other, whatever they look like.
    * ``root == "/"`` (the explicit "everywhere" declaration) covers every
      *local* path and no UNC path: a network share is not on this machine,
      and granting the whole workstation should not silently grant the whole
      network too.  A plugin that needs a share declares it as a UNC root.
    """
    if not root or not candidate:
        return False
    if UNINSPECTABLE in (candidate, root):
        return False
    if _is_unc(candidate) != _is_unc(root):
        return False
    if root == "/":
        return True
    return candidate == root or candidate.startswith(root + "/")


#: Scalars that can never be a path.  Everything *else* that is not a string,
#: bytes, a PathLike or a container is treated as a path we could not read —
#: an unrecognised type must not vanish silently.
_NON_PATH_SCALARS = (bool, int, float, type(None))


def _decode_bytes(value: bytes | bytearray) -> str:
    """Decode a bytes path argument without ever raising.

    ``surrogateescape`` keeps undecodable bytes round-trippable instead of
    dropping them, so a path that is not valid UTF-8 still produces a
    candidate to compare rather than an empty list.
    """
    try:
        return bytes(value).decode("utf-8", errors="surrogateescape")
    except (UnicodeDecodeError, ValueError):  # pragma: no cover — defensive
        return UNINSPECTABLE


def _scalar_path_candidates(value: object, key: str) -> list[str]:  # noqa: PLR0911
    """Path candidates from a single non-container argument value.

    One ``return`` per argument type, deliberately: each is a distinct
    fail-open the collapsed version used to have, and reading them as a
    list is the point.

    ``bytes`` and ``os.PathLike`` are handled properly rather than falling
    off the end: JSON transport cannot produce either, but ``invoke`` is
    called in-process too, and "the path arrived as a ``Path`` object" must
    not mean "there were no paths".  A type this module has never seen
    yields :data:`UNINSPECTABLE` — an unrecognised argument must not
    evaporate into a silent allow.
    """
    if isinstance(value, str):
        if _value_is_unambiguously_a_path(value):
            return [value]
        if _key_is_pathish(key) and (value.strip() or _value_is_pathish_under_key(value)):
            return [value]
        return []

    if isinstance(value, (bytes, bytearray)):
        return _scalar_path_candidates(_decode_bytes(value), key)

    if isinstance(value, os.PathLike):
        # A PathLike is a path by construction; the key is irrelevant.
        try:
            raw = os.fspath(value)
        except (TypeError, ValueError):  # pragma: no cover — defensive
            return [UNINSPECTABLE]
        return [_decode_bytes(raw) if isinstance(raw, bytes) else raw]

    if isinstance(value, _NON_PATH_SCALARS):
        return []

    log.warning(
        "path check: unrecognised argument type %s; treating as a path",
        type(value).__name__,
    )
    return [UNINSPECTABLE]


def _is_exemptible_scalar(value: object) -> bool:
    """True when an exempt argument's value is simple enough to skip.

    The exemption says "this *string* names something in a foreign
    namespace".  A dict or a list under an exempt key is not a foreign path
    — it is something that cannot be classified at all, and skipping it
    pruned a whole subtree: ``remote_path={"local_target":
    "C:/Windows/System32/config/SAM"}`` removed a genuine workstation path
    from root comparison.  Only scalars are skipped; anything else resolves
    to :data:`UNINSPECTABLE`, keeping the failure mode a visible
    over-denial rather than a silent bypass.
    """
    return isinstance(value, (str, bytes, bytearray, *_NON_PATH_SCALARS))


def _iter_keyed_values(  # noqa: C901
    args: object,
    keys: frozenset[str],
    *,
    depth: int = 0,
    exempt_keys: frozenset[str] = frozenset(),
) -> list[object]:
    """Collect values stored under any of *keys*, **at any depth**.

    The command and domain checkers used ``args.get(key)``, which sees only
    top-level keys: a command or URL nested one level down
    (``{"config": {"cmd": "..."}}``) was not present, so both checkers
    returned "no violation" and the call was allowed.  The path extractor
    always recursed; that inconsistency was the bug, and no shipped tool
    nests today, which is exactly how it would have been introduced without
    anyone noticing.

    Bounds and the :data:`UNINSPECTABLE` sentinel match the path extractor,
    so "I could not finish looking" is a violation here too.
    """
    if depth > _MAX_PATH_RECURSION:
        return [UNINSPECTABLE]

    if isinstance(args, dict):
        found: list[object] = []
        for k, v in args.items():
            if len(found) >= _MAX_PATH_CANDIDATES:
                return [*found, UNINSPECTABLE]
            name = str(k).strip().lower()
            if name in exempt_keys:
                if not _is_exemptible_scalar(v):
                    found.append(UNINSPECTABLE)
                continue
            if name in keys:
                found.append(v)
                continue
            found.extend(
                _iter_keyed_values(v, keys, depth=depth + 1, exempt_keys=exempt_keys),
            )
        return found

    if isinstance(args, (list, tuple, set, frozenset)):
        found = []
        for item in args:
            if len(found) >= _MAX_PATH_CANDIDATES:
                return [*found, UNINSPECTABLE]
            found.extend(
                _iter_keyed_values(item, keys, depth=depth + 1, exempt_keys=exempt_keys),
            )
        return found

    return []


def _iter_path_values(
    args: object,
    *,
    key: str = "",
    depth: int = 0,
    exempt_keys: frozenset[str] = frozenset(),
) -> list[str]:
    """Collect every argument value that should be treated as a workstation path.

    Fail-closed where the first cut was not: exceeding the recursion or
    candidate bound yields :data:`UNINSPECTABLE` rather than truncating
    silently, so burying a path nine levels deep denies instead of passing.
    Detection is also widened — see :func:`_value_is_unambiguously_a_path`
    and :func:`_key_is_pathish`.

    ``exempt_keys`` names arguments that are paths in a *foreign* namespace
    (:func:`foreign_args`) and so cannot meaningfully be compared to a
    workstation root.  It defaults to empty, so no caller gets an exemption
    it did not ask for by naming a tool.

    The exemption is narrow on purpose.  It removes an argument from **root
    comparison only** — it does not make the call unexamined:
    :func:`requires_path` still demands that a tool whose signature carries a
    mandatory workstation path produce one, so exempting an argument can
    never turn "this tool must show me a path" into "no paths here, carry
    on".  ``adb_push`` with only a ``device_path`` therefore denies rather
    than sailing through.
    """
    if depth > _MAX_PATH_RECURSION:
        return [UNINSPECTABLE]

    if isinstance(args, dict):
        found: list[str] = []
        for k, v in args.items():
            if len(found) >= _MAX_PATH_CANDIDATES:
                return [*found, UNINSPECTABLE]
            if str(k).strip().lower() in exempt_keys:
                # Scalars only: a structure under an exempt key is not a
                # foreign path, it is unclassifiable.  See
                # `_is_exemptible_scalar`.
                if not _is_exemptible_scalar(v):
                    found.append(UNINSPECTABLE)
                continue
            found.extend(
                _iter_path_values(v, key=str(k), depth=depth + 1, exempt_keys=exempt_keys),
            )
        return found

    if isinstance(args, (list, tuple, set, frozenset)):
        found = []
        for item in args:
            if len(found) >= _MAX_PATH_CANDIDATES:
                return [*found, UNINSPECTABLE]
            found.extend(
                _iter_path_values(item, key=key, depth=depth + 1, exempt_keys=exempt_keys),
            )
        return found

    return _scalar_path_candidates(args, key)


def declared_roots(manifest: PluginManifest) -> list[str]:
    """Return the plugin's declared path roots, normalised.

    ``path:/`` and ``path:*`` are the explicit "everywhere" declarations —
    the deliberate, auditable opt-out from root confinement.  Absence of any
    ``path:`` entry is the opposite of that, and means no path access at all
    (see :func:`_outside_declared_paths`).
    """
    roots: list[str] = []
    for perm in manifest.declared_permissions:
        if not isinstance(perm, str) or not perm.startswith("path:"):
            continue
        raw = perm[5:].strip()
        if raw in ("*", "/", "\\"):
            roots.append("/")
            continue
        normalised = normalise_path(raw)
        if not normalised or normalised == UNINSPECTABLE:
            continue
        if not is_absolute_path(normalised):
            # A relative root would be anchored to the agent's working
            # directory, so what it confined to would depend on how the agent
            # was launched.  Dropped rather than honoured.
            log.warning(
                "plugin=%s declares relative root %r; ignoring it", manifest.id, perm,
            )
            continue
        if _is_unc(normalised) and len(normalised.strip("/").split("/")) < 2:  # noqa: PLR2004
            # `path:\\server` names a host but no share, so it would grant
            # every share on that machine.  A UNC root must pin host AND
            # share to be usable; anything less is dropped rather than
            # honoured generously.
            log.warning(
                "plugin=%s declares UNC root %r with no share; ignoring it",
                manifest.id,
                perm,
            )
            continue
        roots.append(normalised)
    return roots


def _outside_declared_paths(  # noqa: PLR0911
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if any path argument is outside the declared allowed paths.

    Each ``return`` below is a distinct rule, and several of them are holes
    that were found in verification.  Collapsing them would hide which is
    which.

    **A plugin that declares no ``path:`` root has no path access.**  An
    early version returned ``False`` when the manifest listed no roots, which
    read as "no restriction to violate" and meant a plugin granted
    ``tool:filesystem.read`` while declaring no roots could read anywhere on
    the machine.  ``path:/`` is how a plugin says "everywhere" on purpose.

    That denial used to sit *behind* the empty-candidates short-circuit,
    which made it evadable by reshaping the call: a bare filename under an
    argument name the extractor does not consider path-ish produced no
    candidates, returned ``False`` on the line above, and never reached the
    denial at all.  The empty-allowlist case is therefore decided on the
    **tool** (:func:`requires_path`) and not on whether extraction happened
    to succeed — for a tool whose signature always carries a path, "no path
    detected" means the scanner missed it.

    Deliberately *not* fixed by swapping the two checks: that would deny
    every call to every plugin with no ``path:`` declaration, including
    ``hello_world.echo``, which has no business with the filesystem at all.
    Calls that genuinely carry no path, to tools that genuinely take no
    path, stay allowed.
    """
    roots = declared_roots(manifest)
    candidates = _iter_path_values(args, exempt_keys=foreign_args(manifest, tool))
    path_required = requires_path(tool)

    if not roots:
        if candidates:
            log.warning(
                "path argument supplied to plugin=%s, which declares no path: root",
                manifest.id,
            )
            return True
        if path_required:
            log.warning(
                "plugin=%s tool=%s takes a path but declares no path: root",
                manifest.id,
                tool,
            )
            return True
        # No path argument, and none in this tool's signature: nothing to
        # confine, nothing to violate.
        return False

    # Roots exist.  The same scanner-failure reasoning applies here: a tool
    # that always takes a path, called with no path this module can find,
    # has not been shown to be inside the roots — and "not shown to be
    # inside" must not resolve to "allowed".  (This goes one step beyond the
    # empty-allowlist case the finding described; it is the same hole with
    # roots present, and no legitimate call to these tools omits its path.)
    if path_required and not candidates:
        log.warning(
            "plugin=%s tool=%s takes a path but no path argument could be identified",
            manifest.id,
            tool,
        )
        return True

    for raw in candidates:
        candidate = normalise_path(raw)
        # A path that normalises away — ".", "./.", "foo/.." all resolve to
        # their own base and used to come back as "" — hit `continue` here,
        # so the loop ended having found nothing and the call was allowed.
        # `filesystem.read {"path": "."}` therefore read the agent's working
        # directory, which is outside every declared root.  "The path
        # normalised away" is the same scanner failure as "the path was never
        # found" and lands on the same denial, not on `continue`.
        #
        # The same branch refuses a relative path, which has no well-defined
        # meaning here at all (see `is_absolute_path`).
        if not is_absolute_path(candidate):
            log.warning(
                "plugin=%s tool=%s: path argument is not absolute (%s); refusing",
                manifest.id,
                tool,
                "normalised to nothing" if not candidate else "relative",
            )
            return True
        if not any(_is_within(candidate, root) for root in roots):
            log.debug("path argument outside declared roots %s", roots)
            return True
    return False


def _command_outside_allowlist(
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if a command argument is not in the declared command allowlist.

    An empty ``cmd:`` allowlist denies every command rather than permitting
    every command — see :func:`_outside_declared_paths` for the same
    inversion and the same reasoning.  ``cmd:.*`` is how a plugin declares
    "anything" on purpose.

    **``cmd:`` patterns are regexes, not globs**, and deliberately so —
    unlike ``domain:``, which is a glob and had a broken glob-to-regex
    translation (see :func:`_domain_pattern_to_regex`).  This path never had
    that defect because it never translated: it has always passed the
    pattern to :func:`re.fullmatch` unchanged.  The shipped ``powershell``
    manifest depends on that, declaring ``cmd:.*``.

    The consequence, stated plainly rather than left implicit: a dot in a
    ``cmd:`` pattern is a regex dot.  ``cmd:git.exe`` matches ``gitXexe``.
    That is the documented semantics of a regex allowlist rather than a
    translation bug, and the fix is in the manifest — write ``cmd:git\\.exe``
    — not here.  Escaping the pattern would silently break ``cmd:.*``.
    """
    cmd_patterns = [p[4:] for p in manifest.declared_permissions if p.startswith("cmd:")]

    # A command that runs somewhere else is not this workstation's to
    # allowlist.  `adb_shell(serial, command)` executes on the phone, so
    # matching it against `cmd:` denied every legitimate call — the same
    # mistake as judging `device_path` against the workstation's roots.
    exempt = foreign_args(manifest, tool)
    present = [
        v for v in _iter_keyed_values(args, _COMMAND_KEYS, exempt_keys=exempt)
        if v is not None
    ]
    if not present:
        return False

    if not cmd_patterns:
        log.warning(
            "command argument supplied to plugin=%s, which declares no cmd: allowlist",
            manifest.id,
        )
        return True

    for val in present:
        # Checked before the isinstance below: the sentinel IS a str, so a
        # permissive pattern like `cmd:.*` would otherwise match it and turn
        # "I could not inspect this" into "allowed".
        if val == UNINSPECTABLE:
            log.warning("uninspectable command argument for plugin=%s", manifest.id)
            return True
        if not isinstance(val, str):
            # A command that is not a string cannot be matched against the
            # allowlist, so it cannot be shown to be inside it.
            log.warning("non-string command argument for plugin=%s", manifest.id)
            return True
        if not any(_fullmatch(pat, val) for pat in cmd_patterns):
            log.debug("command %r not in allowlist %s", val, cmd_patterns)
            return True
    return False


def _domain_outside_allowlist(
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if a URL/domain argument is not in the declared domain allowlist.

    An empty ``domain:`` allowlist denies every domain rather than
    permitting every domain — the same inversion fixed in
    :func:`_outside_declared_paths`.  ``domain:*`` is how a plugin declares
    "anywhere" on purpose.

    Note this makes the shipped ``browser`` manifest, which declares
    ``domain_outside_allowlist`` as a confirmable condition but lists no
    ``domain:`` permission at all, prompt for every navigation instead of
    silently allowing it.  That is what its manifest actually says.
    """
    domain_patterns = [p[7:] for p in manifest.declared_permissions if p.startswith("domain:")]

    exempt = foreign_args(manifest, tool)
    present = [
        v for v in _iter_keyed_values(args, _DOMAIN_KEYS, exempt_keys=exempt)
        if v is not None
    ]
    if not present:
        return False

    if not domain_patterns:
        log.warning(
            "domain argument supplied to plugin=%s, which declares no domain: allowlist",
            manifest.id,
        )
        return True

    for val in present:
        if val == UNINSPECTABLE or not isinstance(val, str):
            log.warning("uninspectable domain argument for plugin=%s", manifest.id)
            return True
        domain = url_host(val)
        if domain == UNINSPECTABLE:
            # Userinfo present, or not resolvable to a host at all.  Refused
            # rather than interpreted — see `url_host`.
            return True
        if not any(_domain_matches(pat, domain) for pat in domain_patterns):
            log.debug("domain %r not in allowlist %s", domain, domain_patterns)
            return True
    return False


_TRAILING_DOTS = re.compile(r"\.+$")

#: Argument names whose value is a command, and whose value is a URL/host.
_COMMAND_KEYS: frozenset[str] = frozenset({"command", "cmd", "shell", "executable"})
_DOMAIN_KEYS: frozenset[str] = frozenset({"url", "domain", "host", "endpoint"})


def url_host(value: str) -> str:
    """Return the host a client would actually connect to, or the sentinel.

    Replaces ``val.split("//")[-1].split("/")[0].split(":")[0]``, which is
    not a URL parser and disagreed with every real HTTP client.  Given
    ``http://allowed.com:password@evil.com/`` that expression returned
    ``allowed.com`` — the *userinfo* — so an allowlist of ``allowed.com``
    passed a request that connects to ``evil.com``.

    Handled by parsing properly rather than splitting:

    * **userinfo** — refused outright rather than interpreted.  No
      legitimate call here needs a username in a URL, and any attempt to
      decide "which half is the host" is the bug above.
    * **case** — hosts are case-insensitive; ``EVIL.COM`` and ``evil.com``
      compare identically.
    * **trailing dot** — ``evil.com.`` is the same host as ``evil.com``
      (fully-qualified form) and must not read as a different one.
    * **IDN / punycode** — normalised to ASCII punycode, so an allowlist
      entry and a value written in different forms compare consistently.
      A Unicode homograph (a Cyrillic lookalike of the letter "a" leading
      "allowed.com") encodes to a different ``xn--`` label and never
      matches the ASCII original.
    * **IPv6 literals** — ``[::1]:80`` yields ``::1``, the brackets and
      port removed, so a bracketed literal cannot masquerade as a name.

    Anything that cannot be resolved to a host returns :data:`UNINSPECTABLE`,
    which the caller treats as a violation — a value supplied under a URL
    argument that is not a URL has not been shown to be inside the allowlist.
    """
    text = value.strip()
    if not text:
        return UNINSPECTABLE
    # A bare "example.com" or "host:8080" has no scheme; giving it the "//"
    # prefix makes urlsplit read it as an authority instead of a path.
    candidate = text if "//" in text else "//" + text
    try:
        parts = urlsplit(candidate)
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            log.warning("URL argument carries a userinfo section; refusing")
            return UNINSPECTABLE
        host = parts.hostname
    except ValueError:
        # Malformed authority — an unclosed IPv6 bracket, an invalid port.
        return UNINSPECTABLE
    if not host:
        return UNINSPECTABLE

    host = _TRAILING_DOTS.sub("", host.strip().lower())
    if not host:
        return UNINSPECTABLE
    # IP literals and other non-DNS labels have no IDNA form; the
    # lower-cased text is already the comparable value.
    with contextlib.suppress(UnicodeError, ValueError):
        host = host.encode("idna").decode("ascii")
    return host


#: What ``*`` means inside a ``domain:`` pattern: **one label**, matching the
#: convention everyone already knows from TLS wildcard certificates.
#: ``*.example.com`` covers ``api.example.com`` and not ``a.b.example.com``,
#: and never the apex ``example.com`` — the same rules a browser applies to a
#: wildcard certificate.  Chosen over ``.*`` deliberately: it is the more
#: restrictive reading, it is the one a manifest author is likely to mean,
#: and a plugin that genuinely wants any depth can say so with more patterns
#: or with a bare ``domain:*``.
_DOMAIN_WILDCARD = "[^.]*"


def _domain_pattern_to_regex(pattern: str) -> str | None:
    """Translate a ``domain:`` glob to an anchored regex, or None for "any".

    ``pattern.replace("*", ".*")`` was not a translation, it was a
    corruption: it left every **literal** dot as a regex ``.``, so
    ``domain:*.example.com`` became ``.*.example.com`` in which the dots
    match any character.  ``evil-example.com`` then matched — ``.*`` took
    ``evil``, the unescaped dot took ``-`` — and a subdomain restriction
    was bypassable by registering a lookalike domain.

    The literal text is escaped first and only the wildcard is translated
    afterwards, so a dot in a pattern can only ever mean a dot.
    """
    text = pattern.strip().lower()
    if text == "*":
        # The explicit "anywhere" declaration.  Kept as a special case: with
        # single-label semantics a bare "*" would otherwise fail to match any
        # host containing a dot, i.e. every real host.
        return None
    return re.escape(text).replace(re.escape("*"), _DOMAIN_WILDCARD)


def _domain_matches(pattern: str, domain: str) -> bool:
    """True when *domain* satisfies one declared ``domain:`` pattern."""
    regex = _domain_pattern_to_regex(pattern)
    if regex is None:
        return True
    return _fullmatch(regex, domain)


def _fullmatch(pattern: str, value: str) -> bool:
    """``re.fullmatch`` that treats a malformed manifest pattern as no-match.

    A plugin manifest is data, not code: an unparseable regex in one must not
    raise out of the permission evaluator, because an exception here would
    propagate past every decision and land wherever the caller happens to
    catch it.  A pattern that cannot be compiled matches nothing, which
    resolves to "outside the allowlist" — fail-closed.
    """
    try:
        return re.fullmatch(pattern, value) is not None
    except re.error:
        log.warning("malformed allowlist pattern %r; treating as no-match", pattern)
        return False


CONDITION_CHECKERS: dict[str, _ConditionChecker] = {
    "outside_declared_paths": _outside_declared_paths,
    "command_outside_allowlist": _command_outside_allowlist,
    "domain_outside_allowlist": _domain_outside_allowlist,
}


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------


#: Everything a legitimate tool id may contain, end to end.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_NAME_CHARS = 64
_GENERIC_NAME = "the requested tool"


def safe_name(name: object) -> str:
    """Scrub a caller-supplied identifier before it is echoed back.

    ``tool`` reaches :func:`evaluate_detailed` from the caller and used to be
    interpolated straight into the plain-English ``reason``, so a caller
    naming its tool ``C:/Windows/System32/config/SAM`` had that string
    reflected back to it — the absolute-path echo §5.2 forbids, delivered by
    the very message that refuses the call.  Separators, colons and
    everything else outside a tool id's character set are removed, and the
    result is bounded.

    A name is echoed **only if it is entirely a well-formed tool id** and
    within the length bound.  Deleting the offending characters instead was
    the first attempt and is not good enough: ``C:/Windows/.../SAM`` becomes
    ``CWindowsSystem32configSAM``, which is no longer a resolvable path but
    still reflects the caller's own string back in the refusal.  Anything
    that is not already a plain tool id is replaced wholesale.

    ``host.sanitise_reason`` scrubs the finished sentence at the boundary as
    well; this is the same discipline applied at the source, so
    ``PermissionOutcome.reason`` is safe for B3 (and anyone else) to use
    directly rather than only being safe once it has been through the host.
    """
    text = str(name)
    if len(text) > _MAX_NAME_CHARS or not _SAFE_NAME.match(text):
        return _GENERIC_NAME
    return text


@dataclass(frozen=True)
class PermissionOutcome:
    """A decision plus why it was reached.

    ``reason`` is written for a person and for the model: one plain-English
    sentence, and it **never quotes a path**.  §5.2 forbids returning an
    absolute path outside a declared root, and the denial reason is the one
    place where such a path would otherwise be handed straight back to the
    caller that asked for it.
    """

    decision: PermissionDecision
    rule: str
    reason: str
    condition: str = ""


_ALLOW = PermissionOutcome(decision="allow", rule="allowed", reason="")


def evaluate_detailed(
    plugin: PluginManifest,
    tool: str,
    args: dict[str, Any],
    granted: set[str],
    *,
    session: SessionContext | None = None,
) -> PermissionOutcome:
    """Evaluate *plugin* calling *tool* with *args*, with the reasoning attached.

    ``session`` identifies the transport connection the call arrived on.  B2
    plumbs it so B3 can key §7's "remember for this session" on it; nothing
    here reads it for a decision yet, and a call with no session is evaluated
    exactly as before.
    """
    # Scrubbed once, here, and used for every reason built below.  The raw
    # `tool` is still what the gate *decides* on — only what is echoed back
    # to the caller is scrubbed.
    shown_tool = safe_name(tool)
    shown_plugin = safe_name(plugin.id)

    tool_decision = _check_tool_permission(plugin, tool, granted)
    if tool_decision == "deny":
        return PermissionOutcome(
            decision="deny",
            rule="tool_not_granted",
            reason=(
                f"The tool {shown_tool!r} is not among the permissions granted to the "
                f"{shown_plugin!r} plugin on this workstation."
            ),
        )

    # ---- The read/action split (contract §11 item 6) -------------------
    # This MUST come before both loops below and MUST return "deny"
    # explicitly.  See the module docstring for why weakening
    # _outside_declared_paths instead would fall through to "allow".
    if is_read_only_tool(tool) and _outside_declared_paths(plugin, tool, args):
        log.warning(
            "deny (read outside declared roots): plugin=%s tool=%s session=%s",
            plugin.id,
            tool,
            session.session_id if session else None,
        )
        return PermissionOutcome(
            decision="deny",
            rule=_READ_OUTSIDE_ROOTS,
            reason=(
                f"{shown_tool} was refused: it only has access to the folders this plugin "
                f"declares, and the path asked for is outside them. This is not "
                f"something that can be approved at the prompt — ask for something "
                f"inside the allowed folders instead."
            ),
        )

    for condition_name in plugin.confirmable_conditions:
        checker = CONDITION_CHECKERS.get(condition_name)
        if checker is None:
            log.warning(
                "unknown confirmable_condition=%r for plugin=%s; denying",
                condition_name,
                plugin.id,
            )
            return PermissionOutcome(
                decision="deny",
                rule="unknown_condition",
                reason=(
                    f"The {shown_plugin!r} plugin declares a permission condition this "
                    f"workstation does not recognise, so the call was refused."
                ),
                condition=str(condition_name),
            )
        if checker(plugin, tool, args):
            log.debug(
                "condition=%s triggered for plugin=%s tool=%s; requesting confirm",
                condition_name,
                plugin.id,
                tool,
            )
            return PermissionOutcome(
                decision="confirm",
                rule=condition_name,
                reason=_CONFIRM_REASONS.get(
                    condition_name,
                    f"{shown_tool} needs to be confirmed on the workstation.",
                ),
                condition=condition_name,
            )

    for guard_name in _HARD_GUARDS:
        if guard_name in plugin.confirmable_conditions:
            continue
        checker = CONDITION_CHECKERS[guard_name]
        if checker(plugin, tool, args):
            log.warning(
                "deny (hard guard): %s triggered for plugin=%s tool=%s",
                guard_name,
                plugin.id,
                tool,
            )
            return PermissionOutcome(
                decision="deny",
                rule=guard_name,
                reason=_GUARD_REASONS.get(
                    guard_name,
                    f"{shown_tool} was refused by the workstation's permissions.",
                ),
            )

    return _ALLOW


_CONFIRM_REASONS: dict[str, str] = {
    "outside_declared_paths": (
        "This touches a location outside the folders the plugin declares, "
        "so it needs to be confirmed on the workstation."
    ),
    "command_outside_allowlist": (
        "This runs a command the plugin does not declare, so it needs to be "
        "confirmed on the workstation."
    ),
    "domain_outside_allowlist": (
        "This reaches a site the plugin does not declare, so it needs to be "
        "confirmed on the workstation."
    ),
}

_GUARD_REASONS: dict[str, str] = {
    "outside_declared_paths": (
        "The path asked for is outside the folders this plugin is allowed to use."
    ),
    "command_outside_allowlist": (
        "The command asked for is not one this plugin is allowed to run."
    ),
    "domain_outside_allowlist": (
        "The site asked for is not one this plugin is allowed to reach."
    ),
}


def _check_tool_permission(
    plugin: PluginManifest,
    tool: str,
    granted: set[str],
) -> PermissionDecision:
    """Evaluate the tool-identity gate: declared AND granted.

    Default-deny: a plugin with no declared permissions (or no tool-scoped
    permissions) is NEVER allowed to invoke tools.  The only path to
    ``"allow"`` is that ``tool:<name>`` (or ``"*"``) appears in BOTH the
    plugin's ``declared_permissions`` AND the caller-supplied ``granted`` set.

    Decision table (only cell 1 permits the call to proceed):
    * declared AND granted           → allow
    * declared AND NOT granted       → deny (user hasn't authorised)
    * NOT declared AND granted       → deny (plugin never declared it)
    * NOT declared AND NOT granted   → deny (security default)
    """
    if not plugin.declared_permissions:
        log.warning(
            "deny: plugin=%s has no declared_permissions; default-deny",
            plugin.id,
        )
        return "deny"
    tool_perm = f"tool:{tool}"
    declared_tool_perms = {
        p for p in plugin.declared_permissions if p.startswith("tool:") or p == "*"
    }
    if not declared_tool_perms:
        log.warning(
            "deny: plugin=%s declared no tool-scoped permissions; default-deny",
            plugin.id,
        )
        return "deny"
    declared_ok = tool_perm in declared_tool_perms or "*" in declared_tool_perms
    granted_ok = tool_perm in granted or "*" in granted
    if not declared_ok:
        log.warning(
            "deny: tool=%s not in declared_permissions for plugin=%s",
            tool, plugin.id,
        )
        return "deny"
    if not granted_ok:
        log.warning(
            "deny: tool=%s declared but not granted for plugin=%s",
            tool, plugin.id,
        )
        return "deny"
    return "allow"


def evaluate(
    plugin: PluginManifest,
    tool: str,
    args: dict[str, Any],
    granted: set[str],
    *,
    session: SessionContext | None = None,
) -> PermissionDecision:
    """Evaluate whether *plugin* may call *tool* with *args*.

    Args:
        plugin: The manifest of the plugin making the call.
        tool: Fully-qualified tool name (e.g. ``hello_world.echo``).
        args: Arguments passed to the tool.
        granted: Set of permission strings that have been explicitly granted to
                 this plugin by the user (from config or prior confirmation).
        session: The transport connection the call arrived on, when known.

    Returns:
        ``"allow"``, ``"deny"``, or ``"confirm"``.
    """
    return evaluate_detailed(plugin, tool, args, granted, session=session).decision
