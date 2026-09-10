"""The static families-only allowlist served on the network endpoint.

This module is **the** authority on which tools leave this workstation. It is a
frozen, hand-maintained table, not a runtime query — that is the whole point.

Why static
----------
The brief's "every tool the loaded families expose" was rejected during review
(``working/brief-review/REVIEW-SUMMARY.md`` §3 item 1) and the plan records the
replacement as a standing decision:

* Taken literally it would put ``screen.*``, ``clipboard.*``, ``desktop.*`` and
  ``browser.*`` on the LAN, while contract §10 defers screenshots-the-model-can-see
  and voice to v2/v3.
* Three runtime mechanisms (plugin enable/disable, signature verification, a
  plugin crashing) can change what ``MCPHost.tools()`` returns without a release.
  The core reconciles the registration's tool list against the served list at load
  and **a mismatch is a terminal load failure** (contract §2). A served set that
  can drift at runtime therefore guarantees the failure the contract forbids.

So the served set comes from one list, in one place, that changes only when
someone edits this file — and subtask B5 generates ``workstation-registration.zip``
from this same list, which is what makes the two provably equal rather than
coincidentally equal.

``agent.*`` internal tools (``agent.speak``, ``agent.toast``, ``agent.status``,
``agent.last_transcript``, ``agent.pause_listening``, ``agent.execute_local``) are
**never** in this table. They are the local named pipe's surface, not the LAN's.

Naming
------
Contract §2: tool names must match ``^[a-z][a-z0-9-]{1,63}$`` after ``_`` → ``-``,
and **no dots**. The Agent's internal names are ``family.verb``; the wire names are
``family_verb``. Both are stored explicitly on each entry rather than derived by
splitting, because a verb containing an underscore would make the split ambiguous
and a silent mistranslation is worse than a verbose table.

Tools whose family is not yet loaded (``shell``, ``files``, ``jobs``, ``devices``,
``adb``, ``serial`` land in B6-B8) are still advertised: the registration and the
served list must agree, and a call to a missing family answers with the §5.2
``error`` envelope rather than disappearing from ``tools/list``.
"""

# ruff: noqa: ANN401
# ANN401: _freeze/_thaw walk arbitrary JSON Schema values -- dict, list, str,
# int, bool, None. Any is what a JSON document actually is.

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

#: Contract §2 / ``contracts/manifest.py:16,470-478``. Applied to the wire name
#: after ``_`` → ``-``.
#:
#: Anchored with ``\A``/``\Z``, not ``^``/``$``. In Python ``$`` also matches
#: immediately *before* a trailing newline, so ``^[a-z][a-z0-9-]{1,63}$`` happily
#: accepts ``"files-read\n"``. The core applies its own regex to the manifest, and
#: a name that passes here but fails there is a **terminal load failure**
#: (contract §2) — the one class of disagreement this pattern exists to prevent.
TOOL_NAME_PATTERN: Final = re.compile(r"\A[a-z][a-z0-9-]{1,63}\Z")


def wire_name(internal_name: str) -> str:
    """Contract §2's translation of a dotted internal id into the wire spelling.

    ``"shell.run"`` → ``"shell_run"``.  One line, and it is here rather than
    inlined at each caller because this direction is the *only* unambiguous one
    and the codebase should have exactly one spelling of it: a dotted name has
    exactly one dot separating family from verb, so replacing it can never lose
    information.  :func:`internal_name_for_wire` is the other direction, and it
    is a table lookup rather than a string operation for precisely that reason.

    This is the name the operator meets everywhere outside the Agent's own
    internals — PersonaCore's tool list, its logs, the §7 confirmation policy
    (``shell_run``, ``jobs_*``) — so any surface that shows him a tool name has
    to be able to produce it.  :func:`validate_tool_names` checks the served
    table against this function, so the table and the translation cannot drift.

    A name with no dot is returned unchanged: it is either already a wire name
    or not a tool id at all, and inventing a separator would be worse than
    passing it through.
    """
    return internal_name.replace(".", "_")


def tool_family(internal_name: str) -> str:
    """The family half of a dotted internal id (``"shell.run"`` → ``"shell"``).

    A name with no dot is its own family.  That is the honest reading — an
    ungrouped tool is a group of one — and it keeps every caller free of a
    "what if there is no family" branch that would otherwise be duplicated
    wherever tools are grouped for the operator.
    """
    return internal_name.split(".", 1)[0] if "." in internal_name else internal_name


def _freeze(value: Any) -> Any:
    """Return a deeply immutable view of *value*.

    Mappings become :class:`~types.MappingProxyType` over a *fresh* dict — fresh
    so nothing else holds a mutable reference to what the proxy wraps — and
    sequences become tuples. Scalars are already immutable.

    This exists because a schema shared by reference is a schema that can be
    edited in place. ``_WAIT_S`` alone appears in four tools; without freezing,
    ``tool.input_schema["properties"]["wait_s"]["maximum"] = 9999`` would silently
    change what four *other* tools advertise, and the live tool list would drift
    from the registration B5 froze at export time. A drift between the two is a
    terminal load failure on the core (contract §2), so the served schemas are
    made unwriteable rather than merely not-written-to.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """Return a fresh, mutable, plain-``dict``/``list`` copy of a frozen schema.

    ``json.dumps`` and pydantic both reject :class:`~types.MappingProxyType`
    (neither is a ``dict`` subclass), and the caller owns whatever it gets back,
    so serialisation goes through here rather than through the frozen view.
    """
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class ServedTool:
    """One tool the network endpoint serves.

    Attributes:
        name: The wire name (contract §2 ``family_verb``). What the core calls.
        internal_name: The Agent-internal ``family.verb`` id passed to
            :meth:`workstation_agent.mcp_host.host.MCPHost.invoke`.
        family: The family this tool belongs to.
        description: Sent to the model verbatim (§5.1).
        input_schema: JSON Schema for the arguments (§5.1), **deeply immutable**.
            Every property has a ``description``; booleans default to the safe
            value. Use :meth:`json_schema` for anything that needs a real dict.
        risk: The risk level B5 writes into the registration. Always ``"safe"`` —
            contract §4: the core cannot prompt (issue #6), so *the Agent is the
            gate* and every tool is declared ``safe`` to the core. This is weaker
            than the spec's risk model and the contract says so in as many words.
    """

    name: str
    internal_name: str
    family: str
    description: str
    input_schema: Mapping[str, Any]
    risk: str = "safe"

    @property
    def manifest_name(self) -> str:
        """The name as contract §2's pattern sees it (``_`` → ``-``)."""
        return self.name.replace("_", "-")

    def json_schema(self) -> dict[str, Any]:
        """A fresh, mutable copy of :attr:`input_schema`, safe to serialise.

        A new object every call, so a caller that edits what it is handed cannot
        reach the served table.
        """
        return _thaw(self.input_schema)


def _obj(
    properties: Mapping[str, Mapping[str, Any]],
    required: list[str] | None = None,
) -> Mapping[str, Any]:
    """Build a flat, frozen JSON Schema object (§5.1: arguments are flat)."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": dict(properties),
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return _freeze(schema)


# Shared property fragments. Frozen at definition as well as deep-copied by
# _obj(), so neither the fragment nor any schema built from it can be edited: one
# of these appears in as many as four tools, and an in-place edit would rewrite
# all of them at once.
_PATH = _freeze({
    "type": "string",
    "description": "A path on the workstation, inside a declared root. "
                   "A path outside the declared roots is denied.",
})
_WAIT_S = _freeze({
    "type": "integer",
    "description": "Seconds to wait before returning a job handle instead of a result. "
                   "Default 20, maximum 25.",
    "minimum": 0,
    "maximum": 25,
    "default": 20,
})
_JOB_ID = _freeze({"type": "string", "description": "A job id from a previous call."})
_SESSION_ID = _freeze({"type": "string", "description": "A session id from serial_open."})
_ADB_SERIAL = _freeze({
    "type": "string",
    "description": "The ADB device serial. Optional when exactly one device is attached.",
})


#: The complete served set. Ordering is contract §6's ordering.
SERVED_TOOLS: Final[tuple[ServedTool, ...]] = (
    ServedTool(
        name="workstation_status",
        internal_name="workstation.status",
        family="workstation",
        description=(
            "Report the workstation's hostname, user, OS, uptime, Agent version, "
            "the capability families loaded, and how many jobs and sessions are open."
        ),
        input_schema=_obj({}),
    ),
    ServedTool(
        name="devices_list",
        internal_name="devices.list",
        family="devices",
        description=(
            "List everything currently attached to the workstation: USB devices, "
            "ADB devices, and COM ports."
        ),
        input_schema=_obj({}),
    ),
    ServedTool(
        name="shell_run",
        internal_name="shell.run",
        family="shell",
        description=(
            "Run a command on the workstation and return its exit code, stdout and stderr. "
            "Long-running commands return a job id instead; page the output with jobs_output."
        ),
        input_schema=_obj(
            {
                "command": {"type": "string", "description": "The command line to run."},
                "cwd": {
                    "type": "string",
                    "description": "Working directory. Defaults to a declared root.",
                },
                "shell": {
                    "type": "string",
                    "enum": ["powershell", "cmd"],
                    "default": "powershell",
                    "description": "Which shell interprets the command.",
                },
                "wait_s": _WAIT_S,
            },
            ["command"],
        ),
    ),
    ServedTool(
        name="files_list",
        internal_name="files.list",
        family="files",
        description="List the entries of a directory on the workstation, inside a declared root.",
        input_schema=_obj({"path": _PATH}, ["path"]),
    ),
    ServedTool(
        name="files_read",
        internal_name="files.read",
        family="files",
        description=(
            "Read a text file on the workstation, inside a declared root. "
            "Binary files are refused; large files are paged with from_byte."
        ),
        input_schema=_obj(
            {
                "path": _PATH,
                "from_byte": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Byte offset to start reading from.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60000,
                    "description": "Most bytes to return. Capped at 60000.",
                },
            },
            ["path"],
        ),
    ),
    ServedTool(
        name="files_write",
        internal_name="files.write",
        family="files",
        description=(
            "Write text to a file on the workstation, inside a declared root. "
            "Overwrites unless append is true."
        ),
        input_schema=_obj(
            {
                "path": _PATH,
                "content": {"type": "string", "description": "The text to write."},
                "append": {
                    "type": "boolean",
                    "default": False,
                    "description": "Append instead of overwriting. Defaults to false.",
                },
            },
            ["path", "content"],
        ),
    ),
    ServedTool(
        name="jobs_wait",
        internal_name="jobs.wait",
        family="jobs",
        description="Wait for a running job to finish, or until wait_s elapses.",
        input_schema=_obj({"job_id": _JOB_ID, "wait_s": _WAIT_S}, ["job_id"]),
    ),
    ServedTool(
        name="jobs_output",
        internal_name="jobs.output",
        family="jobs",
        description="Page the captured output of a job.",
        input_schema=_obj(
            {
                "job_id": _JOB_ID,
                "from_byte": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Byte offset to start reading from.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60000,
                    "description": "Most bytes to return. Capped at 60000.",
                },
            },
            ["job_id"],
        ),
    ),
    ServedTool(
        name="jobs_list",
        internal_name="jobs.list",
        family="jobs",
        description="List running jobs and jobs that finished in the last 30 minutes.",
        input_schema=_obj({}),
    ),
    ServedTool(
        name="jobs_kill",
        internal_name="jobs.kill",
        family="jobs",
        description="Terminate a running job and its process tree.",
        input_schema=_obj({"job_id": _JOB_ID}, ["job_id"]),
    ),
    ServedTool(
        name="adb_devices",
        internal_name="adb.devices",
        family="adb",
        description="List the Android devices ADB can see, with their state and model.",
        input_schema=_obj({}),
    ),
    ServedTool(
        name="adb_shell",
        internal_name="adb.shell",
        family="adb",
        description=(
            "Run a shell command on an attached Android device. "
            "Long-running commands return a job id."
        ),
        input_schema=_obj(
            {
                "serial": _ADB_SERIAL,
                "command": {"type": "string", "description": "The command to run on the device."},
                "wait_s": _WAIT_S,
            },
            ["command"],
        ),
    ),
    ServedTool(
        name="adb_push",
        internal_name="adb.push",
        family="adb",
        description=(
            "Copy a file from the workstation onto an attached Android device. "
            "The workstation path must be inside a declared root."
        ),
        input_schema=_obj(
            {
                "serial": _ADB_SERIAL,
                "workstation_path": _PATH,
                "device_path": {
                    "type": "string",
                    "description": "Destination path on the device.",
                },
            },
            ["workstation_path", "device_path"],
        ),
    ),
    ServedTool(
        name="adb_pull",
        internal_name="adb.pull",
        family="adb",
        description=(
            "Read a text file from an attached Android device. "
            "Binary transfer is not available yet."
        ),
        input_schema=_obj(
            {
                "serial": _ADB_SERIAL,
                "device_path": {"type": "string", "description": "Path on the device to read."},
            },
            ["device_path"],
        ),
    ),
    ServedTool(
        name="adb_install",
        internal_name="adb.install",
        family="adb",
        description=(
            "Install an APK from the workstation onto an attached Android device. "
            "The workstation path must be inside a declared root."
        ),
        input_schema=_obj(
            {"serial": _ADB_SERIAL, "workstation_path": _PATH},
            ["workstation_path"],
        ),
    ),
    ServedTool(
        name="adb_logcat",
        internal_name="adb.logcat",
        family="adb",
        description="Capture logcat from an attached Android device for a few seconds.",
        input_schema=_obj(
            {
                "serial": _ADB_SERIAL,
                "seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 5,
                    "description": "How long to capture. Maximum 20.",
                },
                "filter": {
                    "type": "string",
                    "description": "An optional logcat filter expression.",
                },
            },
        ),
    ),
    ServedTool(
        name="serial_ports",
        internal_name="serial.ports",
        family="serial",
        description="List the COM ports on the workstation.",
        input_schema=_obj({}),
    ),
    ServedTool(
        name="serial_open",
        internal_name="serial.open",
        family="serial",
        description="Open a serial port and return a session id for reading and writing.",
        input_schema=_obj(
            {
                "port": {"type": "string", "description": "The port name, for example COM3."},
                "baud": {"type": "integer", "description": "Baud rate, for example 115200."},
                "bytesize": {"type": "integer", "default": 8, "description": "Data bits."},
                "parity": {
                    "type": "string",
                    "enum": ["N", "E", "O", "M", "S"],
                    "default": "N",
                    "description": "Parity. Defaults to none.",
                },
                "stopbits": {"type": "number", "default": 1, "description": "Stop bits."},
                "timeout_s": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 20,
                    "default": 2,
                    "description": "Default read timeout for this session, in seconds.",
                },
            },
            ["port", "baud"],
        ),
    ),
    ServedTool(
        name="serial_write",
        internal_name="serial.write",
        family="serial",
        description="Write text or raw bytes to an open serial session.",
        input_schema=_obj(
            {
                "session_id": _SESSION_ID,
                "text": {"type": "string", "description": "Text to write."},
                "hex": {
                    "type": "string",
                    "description": "Raw bytes as lowercase hex with no separators.",
                },
            },
            ["session_id"],
        ),
    ),
    ServedTool(
        name="serial_read",
        internal_name="serial.read",
        family="serial",
        description="Read from an open serial session until a marker, a byte count, or a timeout.",
        input_schema=_obj(
            {
                "session_id": _SESSION_ID,
                "until": {
                    "type": "string",
                    "description": "A literal string to stop at, matched after decoding.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60000,
                    "description": "Most bytes to read. Capped at 60000.",
                },
                "timeout_s": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 20,
                    "default": 2,
                    "description": "Seconds to wait. Default 2, maximum 20.",
                },
            },
            ["session_id"],
        ),
    ),
    ServedTool(
        name="serial_close",
        internal_name="serial.close",
        family="serial",
        description="Close an open serial session and release the port.",
        input_schema=_obj({"session_id": _SESSION_ID}, ["session_id"]),
    ),
)


#: Wire name → descriptor. A read-only view, not a dict.
#:
#: This index is what :meth:`NetworkMCPServer._invoke` resolves an incoming tool
#: name through, while :func:`served_tool_names` — which B5 generates the
#: registration from — reads the frozen ``SERVED_TOOLS`` tuple. A writeable index
#: would therefore let anything running in-process add a tool to the *served* set
#: without adding it to the *exported* set: not only does that put an
#: out-of-scope tool on the LAN, it produces exactly the served-set/registration
#: mismatch that is a terminal load failure on the core (contract §2).
SERVED_TOOLS_BY_NAME: Final[Mapping[str, ServedTool]] = MappingProxyType(
    {t.name: t for t in SERVED_TOOLS},
)

def internal_name_for_wire(name: str) -> str | None:
    """The dotted internal id a wire name translates back to, or ``None``.

    A **table lookup**, deliberately not ``name.replace("_", ".")``: the wire
    spelling is lossy in this direction. ``"adb_install"`` could be
    ``adb.install`` or a family ``adb_install`` with no verb, and a verb
    containing an underscore makes the split outright ambiguous — which is the
    same reason :class:`ServedTool` writes both names out rather than deriving
    one. Guessing here would mistranslate a name silently, so an unknown wire
    name answers ``None`` and the caller keeps whatever it was given.

    Used by surfaces that accept a tool name *from the operator* — he types the
    wire spelling, because that is the one he is shown everywhere else, while
    what is stored (an audit row's ``tool_id``, a grant's ``tool:`` entry) is
    dotted.
    """
    tool = SERVED_TOOLS_BY_NAME.get(name.strip())
    return tool.internal_name if tool is not None else None


#: The families this endpoint is willing to serve at all.
SERVED_FAMILIES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(t.family for t in SERVED_TOOLS),
)


def served_tool_names() -> tuple[str, ...]:
    """Return the served wire names, in table order.

    This is the function subtask B5 generates ``workstation-registration.zip``
    from. It exists so B5 never has to reach into the table's internals, and so
    "the served set" has exactly one spelling in the codebase.
    """
    return tuple(t.name for t in SERVED_TOOLS)


def validate_tool_names() -> list[str]:
    """Return a list of contract §2 violations in the table; empty means clean.

    Called by :meth:`NetworkMCPServer.start`, not only by tests: every violation
    here is one the core reports as a **terminal load failure**, so refusing to
    bind is both cheaper and far more legible than shipping it.

    Two of these checks are subtler than they look:

    * **Uniqueness is checked on the manifest name, not the wire name.**
      ``"my_tool"`` and ``"my-tool"`` are distinct wire names and would pass a
      naive check, but both translate to ``"my-tool"`` — so the registration
      would carry a duplicate the core rejects while this table looked fine.
      Wire-name uniqueness is still checked as well, because two entries sharing
      a wire name would silently shadow one another in
      :data:`SERVED_TOOLS_BY_NAME`.
    * **The translation itself is checked.** ``name`` and ``internal_name`` are
      written out separately on purpose (a verb containing an underscore makes
      splitting ambiguous), but writing them separately is also what allows them
      to disagree. ``name="custom", internal_name="files.read"`` would otherwise
      pass every other rule here and quietly route one tool's calls to another's
      implementation — the exact silent mistranslation the explicit spelling
      exists to prevent.
    """
    problems: list[str] = []
    seen_wire: set[str] = set()
    seen_manifest: set[str] = set()
    for tool in SERVED_TOOLS:
        if tool.name in seen_wire:
            problems.append(f"duplicate served name: {tool.name!r}")
        seen_wire.add(tool.name)
        if tool.manifest_name in seen_manifest:
            problems.append(
                f"duplicate manifest name: {tool.name!r} -> {tool.manifest_name!r} "
                f"collides with an earlier tool after '_' -> '-'",
            )
        seen_manifest.add(tool.manifest_name)
        if "." in tool.name:
            problems.append(f"served name contains a dot (contract §2 forbids it): {tool.name!r}")
        if not TOOL_NAME_PATTERN.match(tool.manifest_name):
            problems.append(
                f"served name {tool.name!r} -> {tool.manifest_name!r} "
                f"does not match {TOOL_NAME_PATTERN.pattern}",
            )
        if tool.internal_name.count(".") != 1:
            problems.append(
                f"internal name {tool.internal_name!r} is not family.verb",
            )
        elif tool.internal_name.split(".", 1)[0] != tool.family:
            problems.append(
                f"internal name {tool.internal_name!r} does not start with family "
                f"{tool.family!r}",
            )
        expected = wire_name(tool.internal_name)
        if tool.name != expected:
            problems.append(
                f"served name {tool.name!r} is not the §2 translation of internal name "
                f"{tool.internal_name!r} (expected {expected!r})",
            )
        if tool.risk != "safe":
            problems.append(
                f"{tool.name!r} declares risk {tool.risk!r}; contract §4 requires 'safe'",
            )
    return problems
