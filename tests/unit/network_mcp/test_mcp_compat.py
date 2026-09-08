"""The declared ``mcp`` dependency must describe the code that uses it.

This file exists because of a defect that got all the way to merge. The first
cut of ``network_mcp.server`` passed ``max_sessions=`` and
``session_idle_timeout=`` to ``Server.streamable_http_app()``. Both exist on
``mcp`` 2.2's signature. Neither exists on **2.1.1**, which is the version
PersonaCore's core runs (contract §12, introspected twice) — and the declared
floor was ``mcp>=2.1``, which a fresh resolve happily satisfied with 2.2.0. So
the constraint permitted a version the code could not run on, every test passed
in a freshly resolved worktree, and the failure only appeared as
``TypeError: ... unexpected keyword argument 'max_sessions'`` on a machine that
had 2.1.1 installed.

Worse, it silently undid the reason the package was adopted at all: DECISION.md
chose the SDK over hand-rolling the framing because running the *same* SDK on
both ends deletes a class of wire-protocol bugs that A6 (externally blocked)
would otherwise have to catch by hand. A 2.2 server against a 2.1.1 client is
not the same SDK on both ends.

So there are two separate obligations here, and a test for each:

1. **The constraint must permit only versions the code runs on.** Verified by
   parsing ``pyproject.toml`` and checking the *installed* version against it.
2. **The code must use only APIs present in the version it declares.** Verified
   by introspecting the installed SDK, and — the test that would actually have
   caught this — by recording the keyword arguments the code really passes and
   checking every one against the installed signature.
"""

from __future__ import annotations

import functools
import inspect
import tomllib
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from workstation_agent.config.schema import NetworkMcpConfig
from workstation_agent.network_mcp import server as server_mod

PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"

#: The version the core runs (contract §12). The declared range must include it.
CORE_MCP_VERSION = "2.1.1"


def _declared_mcp_requirement() -> Requirement:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    for raw in data["project"]["dependencies"]:
        requirement = Requirement(raw)
        if requirement.name == "mcp":
            return requirement
    pytest.fail("pyproject.toml does not declare 'mcp'")


def test_pyproject_declares_mcp_explicitly():
    """It is a direct dependency of this package, not an inherited accident."""
    assert _declared_mcp_requirement().name == "mcp"


def test_the_declared_range_admits_the_version_the_core_runs():
    """DECISION.md's whole argument is 'the same SDK on both ends'."""
    requirement = _declared_mcp_requirement()
    assert requirement.specifier.contains(CORE_MCP_VERSION), (
        f"the core runs mcp {CORE_MCP_VERSION} but this project declares "
        f"{requirement}, so the two would not be the same SDK"
    )


def test_the_installed_version_satisfies_the_declared_range():
    """Guards against testing on a version the constraint does not describe."""
    requirement = _declared_mcp_requirement()
    installed = version("mcp")
    assert requirement.specifier.contains(installed), (
        f"mcp {installed} is installed but pyproject declares {requirement}; "
        f"the suite is not testing what it ships"
    )


def test_the_installed_version_is_the_one_the_core_runs():
    """A narrower claim than the range: what was actually verified against."""
    assert Version(version("mcp")).release[:2] == Version(CORE_MCP_VERSION).release[:2]


# ---------------------------------------------------------------------------
# API presence
# ---------------------------------------------------------------------------


def test_every_streamable_http_app_kwarg_we_declare_exists():
    from mcp.server.lowlevel import Server

    params = inspect.signature(Server.streamable_http_app).parameters
    missing = [k for k in server_mod._REQUIRED_APP_KWARGS if k not in params]
    assert not missing, f"mcp {version('mcp')} lacks: {missing}"


def test_every_server_kwarg_we_declare_exists():
    from mcp.server.lowlevel import Server

    params = inspect.signature(Server.__init__).parameters
    missing = [k for k in server_mod._REQUIRED_SERVER_KWARGS if k not in params]
    assert not missing, f"mcp {version('mcp')} lacks: {missing}"


@pytest.mark.parametrize("removed", ["max_sessions", "session_idle_timeout"])
def test_we_do_not_declare_the_2_2_only_kwargs(removed):
    """The exact two that broke the merge. 2.1.1 has neither on this signature."""
    assert removed not in server_mod._REQUIRED_APP_KWARGS


def test_require_mcp_api_passes_against_the_installed_sdk():
    server_mod._require_mcp_api()


def test_require_mcp_api_fails_loudly_on_a_missing_api(monkeypatch):
    """A guard that cannot fail is not a guard."""
    monkeypatch.setattr(
        server_mod,
        "_REQUIRED_APP_KWARGS",
        (*server_mod._REQUIRED_APP_KWARGS, "a_kwarg_no_sdk_has"),
    )
    with pytest.raises(RuntimeError) as excinfo:
        server_mod._require_mcp_api()
    message = str(excinfo.value)
    assert "a_kwarg_no_sdk_has" in message
    assert version("mcp") in message, "the message must name the installed version"
    assert "pip install -e .[dev]" in message, "and say how to fix it"


def test_require_mcp_api_fails_loudly_on_a_missing_server_kwarg(monkeypatch):
    monkeypatch.setattr(
        server_mod,
        "_REQUIRED_SERVER_KWARGS",
        (*server_mod._REQUIRED_SERVER_KWARGS, "not_a_real_parameter"),
    )
    with pytest.raises(RuntimeError, match="not_a_real_parameter"):
        server_mod._require_mcp_api()


async def test_start_refuses_before_binding_when_an_api_is_missing(tmp_path, monkeypatch):
    """The check must run early enough that nothing is half-built."""
    monkeypatch.setattr(
        server_mod,
        "_REQUIRED_APP_KWARGS",
        (*server_mod._REQUIRED_APP_KWARGS, "a_kwarg_no_sdk_has"),
    )
    srv = server_mod.NetworkMCPServer(
        NetworkMcpConfig(bind_host="127.0.0.1", port=0), state_dir=tmp_path,
    )
    with pytest.raises(RuntimeError, match="missing APIs"):
        await srv.start()
    assert srv.running is False


# ---------------------------------------------------------------------------
# The test that would have caught the defect: what the code actually passes
# ---------------------------------------------------------------------------


async def test_the_kwargs_actually_passed_all_exist_in_the_installed_sdk(tmp_path):
    """Records the real call rather than trusting the declared list.

    ``_require_mcp_api`` checks a hand-maintained tuple, so it is only as good as
    someone remembering to update it. This intercepts
    ``Server.streamable_http_app`` and asserts every keyword the code genuinely
    passes exists in the installed signature — which fails on the next 2.2-only
    keyword somebody adds, whether or not they update the tuple.
    """
    from mcp.server.lowlevel import Server

    captured: dict[str, object] = {}
    real = Server.streamable_http_app
    params = inspect.signature(real).parameters

    @functools.wraps(real)
    def _spy(self, **kwargs):
        captured.update(kwargs)
        # Checked before delegating, so an unsupported keyword reports what is
        # wrong and against which version, rather than surfacing as the bare
        # ``TypeError: ... unexpected keyword argument`` that took a merge to find.
        unsupported = sorted(k for k in kwargs if k not in params)
        assert not unsupported, (
            f"the endpoint passes {unsupported} to streamable_http_app(), which "
            f"mcp {version('mcp')} does not accept"
        )
        return real(self, **kwargs)

    Server.streamable_http_app = _spy  # type: ignore[method-assign]
    try:
        srv = server_mod.NetworkMCPServer(
            NetworkMcpConfig(bind_host="127.0.0.1", port=0), state_dir=tmp_path,
        )
        await srv.start()
        await srv.stop()
    finally:
        Server.streamable_http_app = real  # type: ignore[method-assign]

    assert captured, "streamable_http_app was never called"
    assert "max_sessions" not in captured
    assert "session_idle_timeout" not in captured


async def test_idle_reaping_is_configured_on_the_session_manager(tmp_path):
    """``session_idle_timeout`` is set on the manager, since 2.1.1's app factory
    does not forward it. Without it the SDK drops sessions only on DELETE.
    """
    from mcp.server.lowlevel import Server

    seen: list[Any] = []
    real = Server.streamable_http_app

    @functools.wraps(real)
    def _spy(self, **kwargs):
        app = real(self, **kwargs)
        seen.append(self)
        return app

    Server.streamable_http_app = _spy  # type: ignore[method-assign]
    try:
        cfg = NetworkMcpConfig(bind_host="127.0.0.1", port=0, session_idle_seconds=123.0)
        srv = server_mod.NetworkMCPServer(cfg, state_dir=tmp_path)
        await srv.start()
        await srv.stop()
    finally:
        Server.streamable_http_app = real  # type: ignore[method-assign]

    assert seen, "streamable_http_app was never called"
    assert seen[0].session_manager.session_idle_timeout == 123.0
