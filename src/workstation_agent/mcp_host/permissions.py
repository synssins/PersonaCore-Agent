"""Runtime permissions evaluation for MCP plugin tool calls.

Every tool invocation passes through :func:`evaluate` before being dispatched.
The decision is one of:

* ``"allow"``   — the call is within all declared permissions and no
                  confirmable condition is triggered.
* ``"deny"``    — the call violates a hard constraint (tool not in granted
                  permissions, tool or argument not declared, a missing
                  required argument, a path outside declared scope, an unknown
                  condition, or a *read* whose path lies outside the declared
                  roots).
* ``"confirm"`` — the call is allowed in principle but a confirmable condition
                  is triggered; the host must present a user prompt.

Built-in condition checkers are registered in :data:`CONDITION_CHECKERS`.  Each
checker receives ``(manifest, tool, args)`` and returns ``True`` when the
condition is met (i.e. the call *would* violate the guard).

Two layers, and only one of them changed
----------------------------------------
This module does two separable jobs, and it is worth naming them because the
first was rewritten and the second was carried across untouched.

**Classification** — "what IS this argument?"  Until B2b this was inferred
from the *shape* of the value and the *spelling* of the key: does the string
start with a drive letter, does the key contain the substring ``file``, does
the tool name start with ``adb_``.  Six verification rounds each found the
same bug in a new costume — the classifier met an argument shape nobody had
anticipated.  Some shapes permitted, some denied, and which was not
predictable in advance.  A control whose failure direction is unpredictable
cannot be reasoned about, only patched.

Classification is now **declared**, per tool, per argument, in the signed
``plugin.toml`` — see :func:`parse_declarations`.  There is no sniffing left:
an argument is a workstation path because its plugin's signed manifest says
so, and for no other reason.

**Comparison** — "is this path inside that root?"  Unchanged, deliberately.
``normalise_path``, ``_is_within``, ``url_host``, ``_classify_segment``,
``is_absolute_path``, ``declared_roots``, the UNC rules, the device-namespace
rules, the trailing-padding rules, the :data:`UNINSPECTABLE` semantics and the
glob escaping are each a closed, mutation-proven finding.  They were moved
across verbatim.  Declaring what an argument *is* does nothing whatever about
``..``, UNC, trailing dots or userinfo — those live entirely after
classification, and weakening them on the theory that the declaration makes
them unnecessary would reopen every one of them.

Default-deny on absence
-----------------------
A tool with no ``args:`` declaration is **refused**, and so is a call carrying
an argument its tool's declaration does not name.  This is the property that
makes the declaration a control rather than an opt-in bypass: if absence meant
"allow", any plugin could escape the gate by declaring nothing at all, which
is strictly worse than the heuristic this replaces.  Both refusals are
explicit ``deny`` returns in :func:`evaluate_detailed`, ahead of both loops —
see the trap below for why "ahead of both loops" is load-bearing.

The declaration is anchored in the manifest, never self-reported
----------------------------------------------------------------
The only source of a declaration is ``manifest.declared_permissions``, which
comes from ``plugin.toml`` and is covered by the plugin signature
(``loader._manifest_dict``).  A tool's own MCP ``inputSchema`` — which the
plugin sends over its own stdio pipe at ``tools/list`` time — is **never**
consulted here, and must never be: a hostile plugin would simply announce
that its ``path`` argument is none of the gate's business and walk out of
confinement.  Changing a declaration means changing a signed file, which is
the same bar as changing ``path:`` or ``cmd:``.

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
— so the call would fall through to the trailing ``return _ALLOW``.  That
turns "a read outside the roots prompts" into "a read outside the roots
silently succeeds", which is strictly worse than the behaviour being fixed.
The short-circuit returns ``"deny"`` before either branch can be reached.

``_outside_declared_paths`` itself stays tool-independent on purpose: "is this
path inside the declared roots" is a property of the path, not of the verb.
The verb-dependence lives in one place, in :func:`evaluate`, where it can be
read and tested as a single rule.

Which tools are reads is now declared (``:read`` in the ``args:`` entry)
rather than guessed from the verb.  That is a manifest-controlled input to the
split, and worth stating plainly: a manifest that declares a read as an
``action`` gets a prompt where a denial was due.  It grants no authority that
was not already there — a plugin reaches the prompt only by *also* declaring
``outside_declared_paths`` confirmable, which has always been a manifest
choice — and the opposite direction (declaring an action a read) only ever
tightens, turning a prompt into a refusal.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from collections.abc import Callable, Mapping
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
# The sentinel, and the scalar types the comparison layer understands
#
# Moved across from the heuristic implementation unchanged.  UNINSPECTABLE is
# a *value*, not a flag, so it flows through the same comparison as a real
# path — and it can never be inside any declared root, so "I could not look at
# this" resolves to a violation rather than to silence.
# ---------------------------------------------------------------------------

#: A candidate that could not be inspected (a structure where a scalar was
#: declared, a type this module does not understand, a list longer than the
#: bound).  Never inside any root, never matched by any allowlist pattern.
UNINSPECTABLE = "\x00uninspectable"

#: Scalars that are not text.  Under a *declared* path/command/domain argument
#: these are uninspectable rather than absent: the manifest said this argument
#: is a path, so a value that cannot be compared to a root has not been shown
#: to be inside one.  ``None`` is handled separately — it means "not supplied".
_NON_TEXT_SCALARS = (bool, int, float)

#: The most elements a declared list-valued argument may carry before the
#: whole argument resolves to :data:`UNINSPECTABLE`.
_MAX_ARG_CANDIDATES = 512


# ---------------------------------------------------------------------------
# The declaration — what each argument of each tool IS
# ---------------------------------------------------------------------------

#: The five things an argument can be, as far as this gate is concerned.
#:
#: * ``ws_path``     — a path on **this workstation**; compared against the
#:                     plugin's ``path:`` roots.
#: * ``ws_command``  — a command executed on **this workstation**; compared
#:                     against the plugin's ``cmd:`` allowlist.
#: * ``web_target``  — a URL or host **this workstation** will connect to;
#:                     compared against the plugin's ``domain:`` allowlist.
#: * ``foreign``     — names something in another namespace entirely: a path
#:                     on a phone, a command that runs on a phone, a payload
#:                     written down a serial line.  Comparing it to a Windows
#:                     root or to the workstation's command allowlist denies
#:                     every legitimate call, so it is compared to neither.
#: * ``opaque``      — none of the gate's business: free text, a flag, a
#:                     count, a CSS selector, a job id.
#:
#: ``foreign`` and ``opaque`` differ in intent, not in mechanism, and both are
#: kept because the audit reader needs to see *why* an argument is exempt.  An
#: argument that is exempt because it names a phone path is a different claim
#: from one that is exempt because it is a line of prose.
ARG_CLASSES: frozenset[str] = frozenset({
    "ws_path",
    "ws_command",
    "web_target",
    "foreign",
    "opaque",
})

#: Classes whose values are handed to a workstation allowlist.
_CHECKED_CLASSES: frozenset[str] = frozenset({"ws_path", "ws_command", "web_target"})

#: Classes that are exempt from every workstation allowlist.  Exempt for
#: **scalars only**: a mapping or a nested list under an exempt argument is
#: not a foreign path and not a line of prose, it is something that cannot be
#: classified at all — and skipping it once pruned a whole subtree, hiding
#: ``remote_path={"local_target": "C:/Windows/System32/config/SAM"}`` from
#: root comparison.  Anything that is not a flat scalar (or a flat list of
#: them) resolves to :data:`UNINSPECTABLE` instead.
_EXEMPT_CLASSES: frozenset[str] = frozenset({"foreign", "opaque"})

#: The two modes a tool can be in.  ``read`` drives the read/action split.
_MODES: frozenset[str] = frozenset({"read", "action"})

#: The permission-string prefix that carries a declaration.
_ARGS_PREFIX = "args:"

#: Marks an argument as **required**: absent (or ``None``) is a refusal.
#:
#: This is the declared replacement for the old ``requires_path`` table, and
#: generalises it.  The rule it preserves: for a tool whose signature always
#: carries a workstation path, "no path was found in the arguments" is a
#: scanner failure, not a call without paths — every legitimate call has one,
#: so its absence must not be waved through.  Stating it per argument rather
#: than per tool means ``shell_run``'s *optional* ``cwd`` is correctly not
#: required while ``files_read``'s ``path`` is, without a second table
#: explaining the exceptions.
_REQUIRED_MARKER = "!"


@dataclass(frozen=True)
class ToolDeclaration:
    """What one tool's arguments are, as declared in its signed manifest.

    Attributes:
        tool: The tool id this declaration covers, case-folded.
        read_only: ``True`` when the manifest declares the tool a ``read``.
            Drives the read/action split (contract §11 item 6).
        arguments: Case-folded argument name → one of :data:`ARG_CLASSES`.
            An argument absent from this mapping is **not** unclassified, it
            is undeclared, and an undeclared argument refuses the call.
        required: Case-folded names that must be present and non-``None``.
    """

    tool: str
    read_only: bool
    arguments: Mapping[str, str]
    required: frozenset[str]


def _parse_one_declaration(  # noqa: C901, PLR0911
    perm: str,
) -> tuple[str | None, ToolDeclaration | None]:
    """Parse one ``args:`` string into ``(claimed tool, declaration or None)``.

    Grammar::

        args:<tool>:<mode>[:<argspec>[,<argspec>]*]
        <argspec> = [!]<name>=<class>

    ``<mode>`` is ``read`` or ``action``; ``<class>`` is one of
    :data:`ARG_CLASSES`; a leading ``!`` marks the argument required.  The
    argument list may be omitted entirely for a tool that takes no arguments
    (``args:clipboard.get:read``), which is a real declaration — it says "this
    tool has no arguments", and any argument supplied to it is therefore
    undeclared and refuses the call.

    A malformed entry yields ``declaration=None``, and the **claimed tool name
    is still returned** whenever it can be extracted.  Both halves matter, and
    the second is the fix for a real hole: returning only ``None`` let
    :func:`parse_declarations` skip a malformed entry silently, so a manifest
    carrying both ``args:files.read:NOTAMODE:!path=ws_path`` and
    ``args:files.read:read:!path=opaque`` produced a working ``files.read``
    declaration built from the second.  A malformed entry is still a *claim*
    about that tool; discarding it is how you pick the other one, which is
    exactly the guessing this layer exists to remove.

    ``tool`` is ``None`` only when the entry names no tool at all (``args:``,
    ``args::action:...``).  Such an entry cannot be attributed, so it cannot
    be made to poison one tool — see :func:`parse_declarations`.
    """
    body = perm[len(_ARGS_PREFIX):]
    parts = body.split(":", 2)
    tool = parts[0].strip().lower() or None

    min_fields = 2
    if len(parts) < min_fields:
        log.warning("malformed args: declaration %r (needs a tool and a mode)", perm)
        return tool, None
    if tool is None:
        log.warning("malformed args: declaration %r (empty tool name)", perm)
        return None, None

    mode = parts[1].strip().lower()
    if mode not in _MODES:
        log.warning("args: declaration %r has unknown mode %r", perm, mode)
        return tool, None

    arguments: dict[str, str] = {}
    required: set[str] = set()
    spec_text = parts[2].strip() if len(parts) > min_fields else ""
    for raw_spec in spec_text.split(","):
        spec = raw_spec.strip()
        if not spec:
            continue
        name, sep, klass = spec.partition("=")
        if not sep:
            log.warning("args: declaration %r has an argument with no class: %r", perm, spec)
            return tool, None
        name = name.strip().lower()
        is_required = name.startswith(_REQUIRED_MARKER)
        if is_required:
            name = name[len(_REQUIRED_MARKER):].strip()
        klass = klass.strip().lower()
        if not name:
            log.warning("args: declaration %r has an unnamed argument", perm)
            return tool, None
        if klass not in ARG_CLASSES:
            log.warning("args: declaration %r gives %r the unknown class %r", perm, name, klass)
            return tool, None
        if name in arguments:
            # Two claims about one argument is not a declaration.
            log.warning("args: declaration %r names %r twice", perm, name)
            return tool, None
        arguments[name] = klass
        if is_required:
            required.add(name)

    return tool, ToolDeclaration(
        tool=tool,
        read_only=mode == "read",
        arguments=arguments,
        required=frozenset(required),
    )


def parse_declarations(manifest: PluginManifest) -> dict[str, ToolDeclaration]:
    """Return every usable tool declaration in *manifest*, keyed by tool id.

    Read exclusively from ``manifest.declared_permissions`` — the signed
    ``plugin.toml``.  Nothing a plugin says about itself at runtime reaches
    this function; see the module docstring for why that is the single most
    important property of the declaration.

    Three ways a tool loses its declaration, all with the same reasoning:
    **two claims about one tool is not a declaration, it is a contradiction,
    and resolving it means guessing which the author meant.**

    * Declared **twice**.
    * Declared once **malformed** — a malformed entry is still a claim, and
      silently dropping it would resolve the contradiction in favour of
      whichever entry happened to parse.
    * Declared malformed and validly, in either order.  The set below is
      order-independent for exactly this reason.

    An entry that names **no tool at all** (``args:``, ``args::action:...``)
    cannot be attributed to one tool, so it poisons **every** declaration in
    the manifest.  That is deliberately blunt, and it is the honest reading:
    the alternative is to discard a security claim the gate could not parse,
    which is the same failure as above with the scope unknown instead of
    known.  The blast radius is bounded and loud — every tool in that one
    plugin refuses at its first call with rule ``undeclared_tool`` — and it
    can never be a bypass.  The manifest is signed, so reaching this state
    means someone signed a broken file, and a broken security manifest should
    not run.
    """
    found: dict[str, ToolDeclaration] = {}
    poisoned: set[str] = set()
    unattributable = False

    for perm in manifest.declared_permissions:
        if not isinstance(perm, str) or not perm.lower().startswith(_ARGS_PREFIX):
            continue
        tool, decl = _parse_one_declaration(perm)
        if decl is None:
            if tool is None:
                unattributable = True
            else:
                log.warning(
                    "plugin=%s has a malformed declaration for tool=%s; refusing the tool",
                    manifest.id,
                    tool,
                )
                poisoned.add(tool)
            continue
        if decl.tool in found or decl.tool in poisoned:
            log.warning(
                "plugin=%s declares tool=%s twice; refusing the tool",
                manifest.id,
                decl.tool,
            )
            poisoned.add(decl.tool)
            continue
        found[decl.tool] = decl

    if unattributable:
        log.warning(
            "plugin=%s has an args: declaration naming no tool; refusing every "
            "declaration in the manifest",
            manifest.id,
        )
        return {}
    for tool in poisoned:
        found.pop(tool, None)
    return found


def tool_declaration(manifest: PluginManifest, tool: object) -> ToolDeclaration | None:
    """Return *tool*'s declaration from *manifest*, or None if it has none.

    ``None`` is the default-deny case.  The caller must refuse; it must never
    read as "nothing declared, so nothing to check".
    """
    if not isinstance(tool, str):
        return None
    name = tool.strip().lower()
    if not name:
        return None
    return parse_declarations(manifest).get(name)


# ---------------------------------------------------------------------------
# Classification — routing declared arguments to the right allowlist
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassifiedArgs:
    """The arguments of one call, sorted by what the manifest says they are.

    Attributes:
        paths: Values to compare against the plugin's ``path:`` roots.
        commands: Values to compare against the ``cmd:`` allowlist.
        domains: Values to compare against the ``domain:`` allowlist.
        undeclared: Argument names the tool's declaration does not mention.
            Non-empty means the call must be refused outright.
        missing: Required argument names that were absent or ``None``.
        malformed: True when ``args`` was not a mapping at all.
        declared: True when the tool had a declaration.  False is the
            default-deny case and every checker treats it as a violation.
    """

    paths: tuple[object, ...] = ()
    commands: tuple[object, ...] = ()
    domains: tuple[object, ...] = ()
    undeclared: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    malformed: bool = False
    declared: bool = True


#: What a call whose tool has no declaration classifies to.  Every checker
#: reads ``declared=False`` as a violation, so a direct caller of a checker
#: fails closed exactly as :func:`evaluate_detailed` does.
_UNDECLARED = ClassifiedArgs(declared=False)


def _decode_bytes(value: bytes | bytearray) -> str:
    """Decode a bytes argument without ever raising.

    ``surrogateescape`` keeps undecodable bytes round-trippable instead of
    dropping them, so a path that is not valid UTF-8 still produces a
    candidate to compare rather than an empty list.
    """
    try:
        return bytes(value).decode("utf-8", errors="surrogateescape")
    except (UnicodeDecodeError, ValueError):  # pragma: no cover — defensive
        return UNINSPECTABLE


def _text_candidate(value: object) -> str:
    """Reduce one scalar to text for comparison, or to the sentinel.

    Only the shapes a real path/command/URL can arrive as are accepted.
    ``bytes`` and ``os.PathLike`` are handled properly rather than falling off
    the end: JSON transport cannot produce either, but ``invoke`` is called
    in-process too, and "the path arrived as a ``Path`` object" must not mean
    "there were no paths".

    Everything else — an int, a bool, a class nobody anticipated — becomes
    :data:`UNINSPECTABLE`.  The manifest declared this argument a path; a
    value that cannot be compared to a root has not been shown to be inside
    one, and an unrecognised argument must not evaporate into a silent allow.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return _decode_bytes(value)
    if isinstance(value, os.PathLike):
        try:
            raw = os.fspath(value)
        except (TypeError, ValueError):  # pragma: no cover — defensive
            return UNINSPECTABLE
        return _decode_bytes(raw) if isinstance(raw, bytes) else raw
    if isinstance(value, _NON_TEXT_SCALARS):
        return UNINSPECTABLE
    log.warning(
        "argument of unrecognised type %s under a checked class; refusing to guess",
        type(value).__name__,
    )
    return UNINSPECTABLE


def _is_container(value: object) -> bool:
    """True for the shapes that hold other values."""
    return isinstance(value, (Mapping, list, tuple, set, frozenset))


def _is_exemptible_scalar(value: object) -> bool:
    """True when an exempt argument's value is simple enough to skip.

    The exemption says "this *string* names something in a foreign namespace"
    or "this *string* is prose".  A dict or a list under an exempt argument is
    not a foreign path — it is something that cannot be classified at all, and
    skipping it pruned a whole subtree: ``remote_path={"local_target":
    "C:/Windows/System32/config/SAM"}`` removed a genuine workstation path
    from root comparison.  Only scalars are skipped; anything else resolves to
    :data:`UNINSPECTABLE`, keeping the failure mode a visible over-denial
    rather than a silent bypass.

    Moved across from the heuristic implementation unchanged, including the
    deliberate omission of ``os.PathLike``: a ``Path`` under an exempt
    argument is not a phone path either.
    """
    return isinstance(value, (str, bytes, bytearray, type(None), *_NON_TEXT_SCALARS))


def _checked_candidates(value: object) -> list[object]:
    """Candidates from one argument declared ``ws_path``/``ws_command``/``web_target``.

    A scalar yields one candidate — including ``bytes`` and ``os.PathLike``,
    which :func:`_text_candidate` reduces properly rather than dropping.  A
    **flat** list, tuple or set yields one per element:
    ``filesystem.list {"paths": [...]}`` is a real shape and must be checked
    element-wise rather than skipped for not being a string.

    Anything deeper is :data:`UNINSPECTABLE`.  Contract §5.1 is explicit that
    arguments are flat, so a mapping or a nested list under a declared path is
    not a shape the gate has to model — and the one thing it must not do is
    model it by guessing, which is how the recursive extractor acquired both a
    recursion bound and a bug below it.

    **An EMPTY container is also** :data:`UNINSPECTABLE`, and that is the
    whole of a real bypass.  Every guard below asks "was each candidate shown
    to be inside the allowlist?", which is an ``all()`` over the candidates —
    and ``all()`` over nothing is vacuously true.  ``{"path": []}`` therefore
    produced zero candidates, ran no comparison, found no violation, and
    escaped root confinement entirely.  Note the required-argument marker does
    not catch it: ``[]`` is *present*, so ``!path`` is satisfied.

    Converting "zero values" into "one value that is inside nothing" is the
    same move cycle 3 made for a path that normalised away, and it lands on
    the same guard with the same consequences — a hard deny, or a prompt for a
    plugin that declares the condition confirmable.  The sentinel is used
    rather than a fourth refusal in :func:`_declaration_outcome` because its
    refusal semantics are already closed and mutation-proven everywhere that
    matters: ``_is_within`` refuses it against every root *including*
    ``path:/``, and both the command and domain checkers refuse it explicitly
    before their type check, so a permissive ``cmd:*`` cannot match it.
    """
    if isinstance(value, (list, tuple, set, frozenset)):
        if not value or len(value) > _MAX_ARG_CANDIDATES:
            return [UNINSPECTABLE]
        return [
            UNINSPECTABLE if _is_container(item) else _text_candidate(item)
            for item in value
        ]
    if _is_container(value):
        return [UNINSPECTABLE]
    return [_text_candidate(value)]


def _exempt_candidates(value: object) -> list[object]:
    """Candidates from an argument declared ``foreign`` or ``opaque``.

    Empty for a scalar — that is what the exemption means.  Anything else,
    a list included, resolves to :data:`UNINSPECTABLE` *in the path list*, so
    it is refused rather than silently skipped.  See
    :func:`_is_exemptible_scalar`.
    """
    return [] if _is_exemptible_scalar(value) else [UNINSPECTABLE]


def _absent(value: object) -> bool:
    """True when a supplied argument counts as "not supplied".

    Only ``None``.  A JSON client sending ``"cwd": null`` for an omitted
    optional is the ordinary shape, and treating it as a path would deny a
    legitimate call.  Note this is *not* a hole for a required argument:
    ``!path`` with a ``None`` value lands on ``missing`` and refuses.
    """
    return value is None


def classify(
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> ClassifiedArgs:
    """Sort *args* according to what *manifest* declares them to be.

    This function is the whole classification layer.  It looks at no value
    shapes and guesses at no key spellings: every routing decision below comes
    from the signed declaration, and an argument the declaration does not name
    is recorded as undeclared rather than examined.
    """
    decl = tool_declaration(manifest, tool)
    if decl is None:
        return _UNDECLARED

    if not isinstance(args, Mapping):
        # Not a shape a tool call can have.  Refused rather than coerced.
        return ClassifiedArgs(malformed=True)

    paths: list[object] = []
    commands: list[object] = []
    domains: list[object] = []
    undeclared: list[str] = []
    seen: set[str] = set()

    for raw_key, value in args.items():
        name = str(raw_key).strip().lower()
        klass = decl.arguments.get(name)
        if klass is None:
            undeclared.append(name)
            continue
        if not _absent(value):
            seen.add(name)
        if _absent(value):
            continue
        if klass in _EXEMPT_CLASSES:
            paths.extend(_exempt_candidates(value))
        elif klass == "ws_path":
            paths.extend(_checked_candidates(value))
        elif klass == "ws_command":
            commands.extend(_checked_candidates(value))
        else:  # web_target — the only class left
            domains.extend(_checked_candidates(value))

    return ClassifiedArgs(
        paths=tuple(paths),
        commands=tuple(commands),
        domains=tuple(domains),
        undeclared=tuple(undeclared),
        missing=tuple(sorted(decl.required - seen)),
    )


# ---------------------------------------------------------------------------
# Path normalisation — moved across from the heuristic implementation
# unchanged.  Every function below is a closed, mutation-proven finding.
# ---------------------------------------------------------------------------

#: ``\\?\`` (extended-length) and ``\\.\`` (device namespace).  Win32 does
#: **not** normalise these — ``..`` is passed through literally and trailing
#: dots/spaces are not stripped — so the rules modelled below simply do not
#: apply to them.  Rather than model two contradictory rule sets, any such
#: path is treated as outside every root: ``\\.\PhysicalDrive0`` and
#: ``\\?\GLOBALROOT\...`` are never a legitimate declared root anyway.
_DEVICE_NAMESPACE = re.compile(r"^[\\/]{2}[?.][\\/]")


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


# ---------------------------------------------------------------------------
# The three guards.  Comparison bodies moved across unchanged; only where
# their candidates come from has changed — from a sniffing extractor to the
# declaration.
# ---------------------------------------------------------------------------


def _outside_declared_paths(
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if any declared path argument is outside the declared roots.

    **A plugin that declares no ``path:`` root has no path access.**  An
    early version returned ``False`` when the manifest listed no roots, which
    read as "no restriction to violate" and meant a plugin granted
    ``tool:filesystem.read`` while declaring no roots could read anywhere on
    the machine.  ``path:/`` is how a plugin says "everywhere" on purpose.

    Calls that genuinely carry no path, to tools that genuinely declare no
    ``ws_path`` argument, stay allowed — ``hello_world.echo`` has no business
    with the filesystem and is not denied for saying so.

    The scanner-failure rule the heuristic version needed ("this tool always
    takes a path, so no path found means the extractor missed it") is gone
    from here, because there is no extractor left to fail.  Its job is done
    upstream and better: ``!path=ws_path`` in the manifest makes an absent
    path a refusal in :func:`evaluate_detailed`, per argument rather than per
    tool, so ``shell_run``'s optional ``cwd`` is not caught by it.
    """
    classified = classify(manifest, tool, args)
    if not classified.declared or classified.malformed:
        # No declaration, or arguments that are not arguments.  Not shown to
        # be inside the roots, therefore outside them.
        return True

    roots = declared_roots(manifest)
    if not classified.paths:
        return False
    if not roots:
        log.warning(
            "path argument supplied to plugin=%s, which declares no path: root",
            manifest.id,
        )
        return True

    for raw in classified.paths:
        candidate = normalise_path(raw) if isinstance(raw, str) else UNINSPECTABLE
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


def _command_outside_allowlist(  # noqa: PLR0911
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if a declared command argument is not in the ``cmd:`` allowlist.

    An empty ``cmd:`` allowlist denies every command rather than permitting
    every command — see :func:`_outside_declared_paths` for the same
    inversion and the same reasoning.  ``cmd:*`` is how a plugin declares
    "anything" on purpose.

    A command that runs somewhere else is not this workstation's to
    allowlist, and is simply never in ``classified.commands``:
    ``adb_shell(serial, command)`` executes on the phone, so its manifest
    declares that ``command`` is ``foreign`` and it is compared to nothing
    here.  (§7 puts ``adb_shell`` on the always-prompt list; that is B3's
    gate, and the right one for it.)  Under the heuristic this was a
    hard-coded family table keyed on ``manifest.id`` and a tool-name prefix;
    it is now the plugin's own signed statement about its own argument.
    """
    classified = classify(manifest, tool, args)
    if not classified.declared or classified.malformed:
        return True
    if not classified.commands:
        return False

    cmd_patterns = [p[4:] for p in manifest.declared_permissions if p.startswith("cmd:")]
    if not cmd_patterns:
        log.warning(
            "command argument supplied to plugin=%s, which declares no cmd: allowlist",
            manifest.id,
        )
        return True

    for val in classified.commands:
        # Checked before the isinstance below: the sentinel IS a str, so a
        # permissive pattern like `cmd:*` would otherwise match it and turn
        # "I could not inspect this" into "allowed".
        if val == UNINSPECTABLE:
            log.warning("uninspectable command argument for plugin=%s", manifest.id)
            return True
        if not isinstance(val, str):  # pragma: no cover — classify() guarantees str
            log.warning("non-string command argument for plugin=%s", manifest.id)
            return True
        if not any(_command_matches(pat, val) for pat in cmd_patterns):
            log.debug("command %r not in allowlist %s", val, cmd_patterns)
            return True
    return False


def _domain_outside_allowlist(  # noqa: PLR0911
    manifest: PluginManifest,
    tool: str,
    args: dict[str, Any],
) -> bool:
    """Return True if a declared URL argument is not in the ``domain:`` allowlist.

    An empty ``domain:`` allowlist denies every domain rather than
    permitting every domain — the same inversion fixed in
    :func:`_outside_declared_paths`.  ``domain:*`` is how a plugin declares
    "anywhere" on purpose.

    Note this makes the shipped ``browser`` manifest, which declares
    ``domain_outside_allowlist`` as a confirmable condition but lists no
    ``domain:`` permission at all, prompt for every navigation instead of
    silently allowing it.  That is what its manifest actually says.
    """
    classified = classify(manifest, tool, args)
    if not classified.declared or classified.malformed:
        return True
    if not classified.domains:
        return False

    domain_patterns = [p[7:] for p in manifest.declared_permissions if p.startswith("domain:")]
    if not domain_patterns:
        log.warning(
            "domain argument supplied to plugin=%s, which declares no domain: allowlist",
            manifest.id,
        )
        return True

    for val in classified.domains:
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


# ---------------------------------------------------------------------------
# URL host extraction — moved across unchanged
# ---------------------------------------------------------------------------

_TRAILING_DOTS = re.compile(r"\.+$")


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


# ---------------------------------------------------------------------------
# Allowlist pattern matching — one language, one escaper, one escape hatch
#
# THE cmd:/domain: SPLIT, RESOLVED.  Before B2b these were two different
# pattern languages in the same manifest with nothing marking which was
# which: `cmd:` was passed to re.fullmatch raw (so `cmd:git.exe` matched
# `gitXexe`, a regex dot silently) while `domain:` was a glob (so
# `domain:.*.example.com` matched nothing, failing closed but confusingly).
# Nothing in the manifest told an author which they were writing.
#
# Resolution, in three parts:
#
#   1. **Untagged patterns are globs in both classes.**  One default
#      language, and the literal text is escaped before any wildcard is
#      substituted — so a dot can only ever mean a dot, in either class.
#   2. **`re:` is the explicit, spelled-out escape hatch**, in both classes.
#      `cmd:re:.*` is a regex; `cmd:.*` is now a glob meaning "a literal dot
#      then anything".  Third-party manifests written for the old semantics
#      therefore *tighten* rather than loosen — a visible over-denial, never
#      a bypass — and the one shipped manifest that relied on regex `.*`
#      (`powershell`) is changed to `cmd:*` in the same commit.
#   3. **One translator**, `_glob_to_regex`, shared by both classes.  The
#      unescaped `.replace("*", ".*")` that let `domain:*.example.com` admit
#      `evil-example.com` can now exist in exactly one place, and that place
#      is already fixed and mutation-proven.
#
# What deliberately still differs is the SCOPE of `*`, and only that:
# hostnames have a label structure and command lines do not.  It is one
# constant per class, named below, rather than two implementations.
# ---------------------------------------------------------------------------

#: What ``*`` means inside a ``domain:`` pattern: **one label**, matching the
#: convention everyone already knows from TLS wildcard certificates.
#: ``*.example.com`` covers ``api.example.com`` and not ``a.b.example.com``,
#: and never the apex ``example.com`` — the same rules a browser applies to a
#: wildcard certificate.  Chosen over ``.*`` deliberately: it is the more
#: restrictive reading, it is the one a manifest author is likely to mean,
#: and a plugin that genuinely wants any depth can say so with more patterns
#: or with a bare ``domain:*``.
_DOMAIN_WILDCARD = "[^.]*"

#: What ``*`` means inside a ``cmd:`` pattern: **any run of characters**.  A
#: command line has no label structure to stop at, and ``cmd:git *`` meaning
#: "git followed by anything" is the only reading an author could intend.
_COMMAND_WILDCARD = ".*"

#: The explicit "this pattern is a regex" marker, in either class.  A DNS
#: label cannot contain a colon and no shell command begins ``re:``, so the
#: marker cannot collide with a literal; a pattern that genuinely must match
#: the text ``re:foo`` writes ``re:re:foo``.
_REGEX_MARKER = "re:"


def _glob_to_regex(pattern: str, wildcard: str) -> str:
    """Translate a glob to an anchored regex body.

    ``pattern.replace("*", ".*")`` was not a translation, it was a
    corruption: it left every **literal** dot as a regex ``.``, so
    ``domain:*.example.com`` became ``.*.example.com`` in which the dots
    match any character.  ``evil-example.com`` then matched — ``.*`` took
    ``evil``, the unescaped dot took ``-`` — and a subdomain restriction
    was bypassable by registering a lookalike domain.

    The literal text is escaped first and only the wildcard is translated
    afterwards, so a character in a pattern can only ever mean itself.
    """
    return re.escape(pattern).replace(re.escape("*"), wildcard)


def _matches_pattern(pattern: str, value: str, *, wildcard: str, fold_case: bool) -> bool:
    """True when *value* satisfies one declared allowlist *pattern*."""
    text = pattern.strip()
    if text[: len(_REGEX_MARKER)].lower() == _REGEX_MARKER:
        return _fullmatch(text[len(_REGEX_MARKER):], value)
    if fold_case:
        text = text.lower()
    if text == "*":
        # The explicit "anything" declaration.  Kept as a special case: with
        # single-label domain semantics a bare "*" would otherwise fail to
        # match any host containing a dot, i.e. every real host.
        return True
    return _fullmatch(_glob_to_regex(text, wildcard), value)


def _domain_matches(pattern: str, domain: str) -> bool:
    """True when *domain* satisfies one declared ``domain:`` pattern."""
    return _matches_pattern(pattern, domain, wildcard=_DOMAIN_WILDCARD, fold_case=True)


def _command_matches(pattern: str, command: str) -> bool:
    """True when *command* satisfies one declared ``cmd:`` pattern."""
    return _matches_pattern(pattern, command, wildcard=_COMMAND_WILDCARD, fold_case=False)


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

#: Machine-readable rule name for the read/action short-circuit.
_READ_OUTSIDE_ROOTS = "read_outside_declared_paths"

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


def _declaration_outcome(
    plugin: PluginManifest,
    tool: str,
    args: dict[str, Any],
    shown_tool: str,
    shown_plugin: str,
) -> PermissionOutcome | None:
    """Enforce default-deny on absence.  Returns a denial, or None to continue.

    Three refusals, each of which must be a ``deny`` and must be reached
    before either loop in :func:`evaluate_detailed`.  If any of them resolved
    to "carry on", the declaration would become an opt-in bypass: a plugin
    could escape the gate by declaring nothing, or by omitting one argument
    from an otherwise complete declaration — strictly worse than the
    heuristic this layer replaces, because the heuristic at least looked.
    """
    decl = tool_declaration(plugin, tool)
    if decl is None:
        log.warning(
            "deny (no argument declaration): plugin=%s tool=%s", plugin.id, tool,
        )
        return PermissionOutcome(
            decision="deny",
            rule="undeclared_tool",
            reason=(
                f"The {shown_plugin!r} plugin does not declare what {shown_tool}'s "
                f"arguments are, so this workstation cannot check the call and "
                f"refused it."
            ),
        )

    classified = classify(plugin, tool, args)
    if classified.malformed:
        return PermissionOutcome(
            decision="deny",
            rule="malformed_arguments",
            reason=(
                f"{shown_tool} was called with something that is not a set of named "
                f"arguments, so the call was refused."
            ),
        )
    if classified.undeclared:
        log.warning(
            "deny (undeclared argument): plugin=%s tool=%s args=%s",
            plugin.id,
            tool,
            sorted(classified.undeclared),
        )
        return PermissionOutcome(
            decision="deny",
            rule="undeclared_argument",
            reason=(
                f"{shown_tool} was called with an argument the {shown_plugin!r} plugin "
                f"does not declare, so this workstation could not tell what it was "
                f"and refused the call."
            ),
        )
    if classified.missing:
        log.warning(
            "deny (missing required argument): plugin=%s tool=%s missing=%s",
            plugin.id,
            tool,
            list(classified.missing),
        )
        return PermissionOutcome(
            decision="deny",
            rule="missing_required_argument",
            reason=(
                f"{shown_tool} was called without an argument it always requires, "
                f"so the call was refused."
            ),
        )
    return None


def evaluate_detailed(  # noqa: PLR0911
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

    Order matters and is asserted by tests:

    1. tool identity (declared **and** granted) — an ungranted tool never
       reaches the argument layer, so a caller cannot probe a plugin's
       declaration by calling tools it was never granted;
    2. the declaration gate (default-deny on absence);
    3. the read/action split — ``deny``, ahead of both loops;
    4. confirmable conditions;
    5. hard guards;
    6. allow.
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

    # ---- Default-deny on absence --------------------------------------
    # Must precede both loops below, and every branch inside must be a
    # `deny`.  See _declaration_outcome.
    refusal = _declaration_outcome(plugin, tool, args, shown_tool, shown_plugin)
    if refusal is not None:
        return refusal

    # ---- The read/action split (contract §11 item 6) -------------------
    # This MUST come before both loops below and MUST return "deny"
    # explicitly.  See the module docstring for why weakening
    # _outside_declared_paths instead would fall through to "allow".
    declaration = tool_declaration(plugin, tool)
    is_read = declaration is not None and declaration.read_only
    if is_read and _outside_declared_paths(plugin, tool, args):
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

    ``"*"`` here grants tool **identity** only.  It is emphatically not a
    wildcard argument declaration: a plugin that declares ``*`` still needs an
    ``args:`` entry per tool, or every call to it is refused.  Letting ``*``
    stand in for the argument declaration would be exactly the opt-in bypass
    default-deny exists to prevent.
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
