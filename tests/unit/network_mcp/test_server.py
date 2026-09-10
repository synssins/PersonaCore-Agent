"""The endpoint's gate mapping, result shaping, operator surface and lifecycle."""
# ruff: noqa: ANN204, FBT002, TRY301
# The fakes mirror MCPHost's and ToolResultImpl's real signatures; a raise
# inside a test helper is the behaviour under test.

from __future__ import annotations

import asyncio
import contextlib
import json
import socket

import pytest
from pydantic import ValidationError

from workstation_agent.config.schema import AgentConfig, NetworkMcpConfig
from workstation_agent.network_mcp.server import (
    RESULT_CHAR_CAP,
    NetworkMCPServer,
    _cap,
    _envelope_from_result,
)


class Result:
    def __init__(self, content, is_error=False):
        self.content = content
        self.is_error = is_error


def text_result(text: str, *, is_error: bool = False) -> Result:
    return Result([{"type": "text", "text": text}], is_error=is_error)


class Host:
    """A stand-in MCPHost. ``behaviour`` is called with (tool_id, args)."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls: list[tuple[str, dict]] = []

    async def invoke(self, tool_id, args):
        self.calls.append((tool_id, args))
        outcome = self.behaviour(tool_id, args)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def server(behaviour=None, tmp_path=None, **cfg) -> tuple[NetworkMCPServer, Host | None]:
    host = Host(behaviour) if behaviour is not None else None
    cfg.setdefault("bind_host", "127.0.0.1")
    cfg.setdefault("port", 0)
    return NetworkMCPServer(NetworkMcpConfig(**cfg), mcp_host=host, state_dir=tmp_path), host


# ---------------------------------------------------------------------------
# Configuration: never 0.0.0.0, never plain HTTP
# ---------------------------------------------------------------------------


def test_the_endpoint_is_off_by_default():
    assert AgentConfig().network_mcp.enabled is False


def test_the_default_bind_is_not_a_wildcard():
    assert AgentConfig().network_mcp.bind_host == "127.0.0.1"


@pytest.mark.parametrize(
    "wildcard",
    ["0.0.0.0", "::", "[::]", "*", "", "   ", "0", "::0"],  # noqa: S104
)
def test_a_wildcard_bind_is_refused_outright(wildcard):
    """Contract §3 forbids 0.0.0.0 as a default; we refuse it as a value."""
    with pytest.raises(ValidationError, match="must name one interface"):
        NetworkMcpConfig(bind_host=wildcard)


@pytest.mark.parametrize("host", ["127.0.0.1", "192.168.1.75", "workstation.lan", "::1"])
def test_a_named_interface_is_accepted(host):
    assert NetworkMcpConfig(bind_host=host).bind_host == host


def test_there_is_no_setting_that_turns_tls_off():
    """TLS is structural, not configurable: no field can disable it."""
    fields = set(NetworkMcpConfig.model_fields)
    assert not {f for f in fields if "tls" in f or "ssl" in f or "insecure" in f}


def test_bounds_have_defensible_defaults():
    cfg = NetworkMcpConfig()
    assert cfg.max_request_bytes == 1024 * 1024
    assert cfg.max_json_depth == 64
    assert cfg.max_connections == 16
    assert cfg.body_read_timeout_seconds == 10.0


# ---------------------------------------------------------------------------
# §5.2 envelope mapping
# ---------------------------------------------------------------------------


async def test_a_successful_call_routes_through_the_host_by_internal_name(tmp_path):
    srv, host = server(lambda *_: text_result('{"ok": true, "hostname": "box"}'), tmp_path)
    envelope = await srv._invoke("workstation_status", {})
    assert host is not None
    assert host.calls == [("workstation.status", {})]
    assert envelope == {"ok": True, "hostname": "box"}


async def test_a_b2_shaped_envelope_is_passed_through_untouched(tmp_path):
    """Forward compatibility: once B2 lands, the result is already §5.2."""
    payload = {"ok": False, "code": "not_found", "reason": "no such port", "extra": [1, 2]}
    srv, _ = server(lambda *_: text_result(json.dumps(payload)), tmp_path)
    assert await srv._invoke("serial_open", {"port": "COM9", "baud": 9600}) == payload


async def test_a_pre_b2_result_is_wrapped_into_an_envelope(tmp_path):
    srv, _ = server(lambda *_: text_result("plain text from a plugin"), tmp_path)
    assert await srv._invoke("files_read", {"path": "x"}) == {
        "ok": True, "text": "plain text from a plugin",
    }


async def test_a_plugin_error_result_becomes_ok_false_error(tmp_path):
    srv, _ = server(lambda *_: text_result("it broke", is_error=True), tmp_path)
    envelope = await srv._invoke("files_read", {"path": "x"})
    assert envelope["ok"] is False
    assert envelope["code"] == "error"
    assert envelope["reason"] == "it broke"


@pytest.mark.parametrize(
    ("raised", "code"),
    [
        (PermissionError("tool 'files.write' denied by permissions model"), "denied"),
        (PermissionError("tool 'shell.run' rejected by user confirmation"), "unconfirmed"),
        (KeyError("no running plugin owns tool 'serial.open'"), "error"),
        (TimeoutError("too slow"), "timeout"),
        (RuntimeError("something odd"), "error"),
        (ValueError("bad argument"), "error"),
    ],
)
async def test_gate_outcomes_map_to_section_5_2_codes(tmp_path, raised, code):
    srv, _ = server(lambda *_: raised, tmp_path)
    envelope = await srv._invoke("shell_run", {"command": "dir"})
    assert envelope["ok"] is False
    assert envelope["code"] == code
    assert isinstance(envelope["reason"], str)
    assert envelope["reason"]


async def test_an_unknown_tool_is_not_found_and_never_reaches_the_host(tmp_path):
    srv, host = server(lambda *_: text_result("{}"), tmp_path)
    envelope = await srv._invoke("agent_execute_local", {})
    assert envelope == {
        "ok": False,
        "code": "not_found",
        "reason": "This workstation does not serve a tool called 'agent_execute_local'.",
    }
    assert host is not None
    assert host.calls == []


@pytest.mark.parametrize(
    "name",
    ["agent.speak", "agent_speak", "screen_capture", "clipboard_get", "desktop_click", ""],
)
async def test_internal_and_deferred_tools_cannot_be_invoked_over_the_network(tmp_path, name):
    srv, host = server(lambda *_: text_result("{}"), tmp_path)
    envelope = await srv._invoke(name, {})
    assert envelope["code"] == "not_found"
    assert host is not None
    assert host.calls == []


async def test_no_host_is_a_plain_error_not_a_crash(tmp_path):
    srv, _ = server(None, tmp_path)
    envelope = await srv._invoke("workstation_status", {})
    assert envelope["ok"] is False
    assert envelope["code"] == "error"


async def test_a_missing_family_names_the_family_not_a_stack_trace(tmp_path):
    srv, _ = server(lambda *_: KeyError("no running plugin owns tool 'adb.shell'"), tmp_path)
    envelope = await srv._invoke("adb_shell", {"command": "ls"})
    assert "'adb'" in envelope["reason"]
    assert "Traceback" not in envelope["reason"]


async def test_an_exception_never_leaks_a_traceback(tmp_path):
    def _explode(*_args):
        try:
            msg = "inner"
            raise ValueError(msg)
        except ValueError as exc:
            outer = RuntimeError("outer")
            outer.__cause__ = exc
            return outer

    srv, _ = server(_explode, tmp_path)
    envelope = await srv._invoke("shell_run", {"command": "x"})
    assert "Traceback" not in envelope["reason"]
    assert 'File "' not in envelope["reason"]
    assert len(envelope["reason"]) <= 500


async def test_the_bearer_token_is_scrubbed_from_a_result(tmp_path, caplog):
    """§5.2: the Agent never returns the token."""
    srv, _ = server(lambda *_: text_result("x"), tmp_path)
    token = srv.info().token
    with caplog.at_level("ERROR"):
        scrubbed = srv._scrub(f"the secret is {token} ok")
    assert token not in scrubbed
    assert "[redacted]" in scrubbed


# ---------------------------------------------------------------------------
# §5.3 cap
# ---------------------------------------------------------------------------


def test_short_text_is_untouched():
    assert _cap("hello") == "hello"
    assert _cap("x" * RESULT_CHAR_CAP) == "x" * RESULT_CHAR_CAP


def test_long_text_is_capped_with_the_documented_trailer():
    capped = _cap("x" * (RESULT_CHAR_CAP + 500))
    assert len(capped) <= RESULT_CHAR_CAP, "the cap includes the trailer (§5.3)"
    assert "more characters; use jobs_output to page" in capped
    kept, _, trailer = capped.partition("\n[... ")
    reported = int(trailer.split(" more")[0])
    assert reported == (RESULT_CHAR_CAP + 500) - len(kept)


def test_capping_is_idempotent():
    """B2 may cap earlier in the chain; capping twice must not double-truncate."""
    once = _cap("x" * (RESULT_CHAR_CAP + 500))
    assert _cap(once) == once


async def test_an_oversized_result_never_reaches_the_lan_uncapped(tmp_path):
    srv, _ = server(lambda *_: text_result("y" * (RESULT_CHAR_CAP * 2)), tmp_path)
    envelope = await srv._invoke("files_read", {"path": "big"})
    assert len(envelope["text"]) <= RESULT_CHAR_CAP


# ---------------------------------------------------------------------------
# _envelope_from_result edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        Result([]),
        Result(None),
        Result([{"type": "image", "data": "..."}]),
        Result([{"type": "text", "text": ""}]),
        Result([{"type": "text"}]),
        Result([{"type": "text", "text": "null"}]),
        Result([{"type": "text", "text": "[1,2,3]"}]),
        Result([{"type": "text", "text": '{"no_ok_key": 1}'}]),
        Result([{"type": "text", "text": "{not json"}]),
    ],
)
def test_envelope_from_result_always_produces_an_envelope(result):
    envelope = _envelope_from_result(result)
    assert isinstance(envelope, dict)
    assert "ok" in envelope


def test_envelope_joins_multiple_text_blocks():
    envelope = _envelope_from_result(
        Result([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]),
    )
    assert envelope == {"ok": True, "text": "a\nb"}


def test_deeply_nested_result_text_does_not_crash_the_envelope():
    """A plugin returning pathological JSON must not take the endpoint down."""
    envelope = _envelope_from_result(Result([{"type": "text", "text": "[" * 200_000}]))
    assert envelope["ok"] is True


# ---------------------------------------------------------------------------
# Operator surface and lifecycle
# ---------------------------------------------------------------------------


def test_info_works_before_start_and_gives_the_ui_what_it_needs(tmp_path):
    srv, _ = server(None, tmp_path, port=8765)
    info = srv.info()
    assert info.url == "https://127.0.0.1:8765/mcp"
    assert info.url.startswith("https://"), "never plain HTTP"
    assert info.fingerprint.startswith("sha256:")
    assert len(info.token) == 64
    assert len(info.tool_names) == 21
    assert info.running is False


def test_info_is_stable_across_calls(tmp_path):
    srv, _ = server(None, tmp_path)
    assert srv.info() == srv.info()


def test_an_ipv6_bind_is_bracketed_in_the_url(tmp_path):
    cfg = NetworkMcpConfig(bind_host="::1", port=9000)
    srv = NetworkMCPServer(cfg, state_dir=tmp_path)
    assert srv.info().url == "https://[::1]:9000/mcp"


def test_rotating_the_token_changes_it_and_persists(tmp_path):
    srv, _ = server(None, tmp_path)
    first = srv.info().token
    rotated = srv.rotate_token()
    assert rotated != first
    assert srv.info().token == rotated


def test_regenerating_the_certificate_changes_the_fingerprint(tmp_path):
    srv, _ = server(None, tmp_path)
    first = srv.info().fingerprint
    assert srv.regenerate_certificate().fingerprint != first


def test_served_tool_names_is_the_list_b5_generates_from(tmp_path):
    from workstation_agent.network_mcp.tools import served_tool_names

    srv, _ = server(None, tmp_path)
    assert srv.info().tool_names == served_tool_names()


async def test_stop_is_safe_when_never_started(tmp_path):
    srv, _ = server(None, tmp_path)
    await srv.stop()
    await srv.stop()
    assert srv.running is False


async def test_start_stop_start_reuses_the_same_credentials(tmp_path):
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    first = await srv.start()
    try:
        assert srv.running is True
    finally:
        await srv.stop()
    assert srv.running is False

    second = await srv.start()
    try:
        assert second.token == first.token
        assert second.fingerprint == first.fingerprint
    finally:
        await srv.stop()


async def test_a_contract_violating_tool_table_refuses_to_start(tmp_path, monkeypatch):
    """Refusing here beats a terminal load failure on the core (contract §2)."""
    from workstation_agent.network_mcp import server as server_mod

    monkeypatch.setattr(
        server_mod,
        "validate_tool_names",
        lambda: ["served name contains a dot (contract §2 forbids it): 'bad.name'"],
    )
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    with pytest.raises(RuntimeError, match="violates contract"):
        await srv.start()
    assert srv.running is False


async def test_starting_twice_is_refused(tmp_path):
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    await srv.start()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            await srv.start()
    finally:
        await srv.stop()


async def test_a_second_agent_on_the_same_port_fails_loudly(tmp_path):
    """Not silently: a bound port must surface, not leave a dead endpoint."""
    first, _ = server(lambda *_: text_result("{}"), tmp_path)
    info = await first.start()
    try:
        cfg = NetworkMcpConfig(bind_host="127.0.0.1", port=info.port)
        second = NetworkMCPServer(cfg, state_dir=tmp_path)
        # A SystemExit out of uvicorn would take the Agent's whole event loop
        # down; start() must surface it as an ordinary error instead.
        with pytest.raises(RuntimeError, match="could not bind"):
            await second.start()
        await second.stop()
        assert second.running is False
    finally:
        await first.stop()


async def test_stop_does_not_hang_when_a_client_holds_a_connection(tmp_path):
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    info = await srv.start()
    _reader, writer = await asyncio.open_connection("127.0.0.1", info.port)
    try:
        await asyncio.wait_for(srv.stop(), timeout=15)
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
    assert srv.running is False


# ---------------------------------------------------------------------------
# P24 defect A -- a listening socket must never outlive the thing serving on it
#
# The owner hit this on a shipped build: the page said "Enabled", Join refused
# with "the endpoint is not running", switching it off released nothing, and
# switching it back on reported a port in use that had been free minutes
# earlier. Every one of those is the same fact -- a socket this process opened
# and nobody was serving on -- seen from a different angle.
#
# These assert on whether the port can actually be bound by a *second* socket,
# never on what the endpoint says about itself: the whole defect was an object
# whose state disagreed with reality.
# ---------------------------------------------------------------------------


def port_is_free(host: str, port: int) -> bool:
    """True if a fresh socket can bind *host*:*port* right now.

    ``SO_REUSEADDR`` is deliberately not set, for the same reason
    ``listeners._bind_one`` does not set it on Windows: with it, this would
    answer "free" for a port another socket in this very process is still
    listening on, which is precisely the state under test.
    """
    probe = socket.socket()
    try:
        probe.bind((host, port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


async def end_the_serve_task(srv) -> None:
    """End the serve task from outside, the way it would end by itself.

    A lifespan that fails after startup, an error escaping uvicorn, a
    cancellation from the loop shutting down: the endpoint cannot tell them
    apart and must not need to. All that is true afterwards is that the task is
    over and nothing is serving -- and that is the whole precondition of the
    defect. The trailing yield lets the task's done callbacks run, which is
    what a real serve task ending mid-loop would also get.
    """
    task = srv._task
    assert task is not None, "nothing was serving to begin with"
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    await asyncio.sleep(0)


async def test_a_serve_task_that_dies_releases_every_socket_it_was_serving(tmp_path):
    """Nothing is serving, so nothing may still be listening.

    ``running`` going False while the port stays bound is the state the owner
    was in when the page said "Enabled" and Join said "not running".
    """
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    info = await srv.start()
    try:
        assert not port_is_free("127.0.0.1", info.port)

        # However the serve task ends -- a lifespan that later fails, an
        # unhandled error inside uvicorn, a cancellation -- it ends.
        await end_the_serve_task(srv)

        assert srv.running is False
        assert port_is_free("127.0.0.1", info.port)
    finally:
        await srv.stop()


async def test_the_port_is_reusable_after_the_serve_task_dies(tmp_path):
    """The owner's step 5, made unnecessary: a second endpoint binds the port.

    He had to change the port to get going again. Nothing was holding the old
    one except this process, and after the task died nothing was serving on it.
    """
    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    info = await srv.start()
    await end_the_serve_task(srv)

    cfg = NetworkMcpConfig(bind_host="127.0.0.1", port=info.port)
    second = NetworkMCPServer(cfg, mcp_host=None, state_dir=tmp_path)
    try:
        again = await second.start()
        assert again.port == info.port
        assert second.running is True
    finally:
        await second.stop()
        await srv.stop()


async def test_stop_releases_the_sockets_even_when_the_teardown_raises(tmp_path, monkeypatch):
    """A stop that fails partway must still not strand a listener.

    ``_stop_quietly`` in the UI router swallows the exception, so a release
    that happened only on the happy path would leak in silence -- which is the
    one failure mode the operator has no way at all to see.
    """
    from workstation_agent.network_mcp import join as join_mod

    srv, _ = server(lambda *_: text_result("{}"), tmp_path)
    info = await srv.start()

    def explode(_endpoint=None):
        msg = "the join registry is unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(join_mod, "unregister_endpoint", explode)
    with pytest.raises(RuntimeError, match="join registry"):
        await srv.stop()

    assert port_is_free("127.0.0.1", info.port)


async def test_a_partial_bind_releases_every_socket_when_serving_ends(tmp_path):
    """Several sockets are open at once; a leak on one of them is invisible.

    Two loopback spellings of the same machine, one port. Both bind, both are
    in ``_sockets``, and the death of the one serve task behind them has to
    release both -- a release that reached only the first would leave a port
    half-held, which is harder to see than the single-address case the owner
    already could not diagnose.
    """
    srv, _ = server(lambda *_: text_result("{}"), tmp_path, bind_hosts=("127.0.0.1",))
    info = await srv.start()
    try:
        assert len(srv._sockets) == len(info.urls)
        await end_the_serve_task(srv)

        assert srv._sockets == ()
        assert port_is_free("127.0.0.1", info.port)
    finally:
        await srv.stop()
