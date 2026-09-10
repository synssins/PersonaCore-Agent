"""Scratch probe for P24."""
from __future__ import annotations

import asyncio
import contextlib
import re
import socket

import pytest

from tests.integration.test_network_mcp_ui_lifecycle import (
    _form,
    _free_port,
    _live_client,
    _tls_handshakes,
)

pytestmark = pytest.mark.usefixtures("sse_shutdown_latch_cleared")


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))


def _bindable(host: str, port: int) -> bool:
    s = socket.socket()
    try:
        s.bind((host, port))
    except OSError:
        return False
    finally:
        s.close()
    return True


async def _kill(srv):
    task = srv._task
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    await asyncio.sleep(0.2)


def _sans(tmp_path):
    from workstation_agent.network_mcp.certs import local_identities
    print("SANS:", local_identities())


def test_probe_sans(tmp_path):
    _sans(tmp_path)


def test_probe_a2_disable_with_rebind_after_task_death(tmp_path):
    """A2: dead task + a disable that counts as a rebind => orphaned sockets."""
    port, other = _free_port(), _free_port()
    with _live_client(tmp_path) as (client, ctx):
        client.post("/network-mcp/settings", data=_form(port))
        srv = ctx.network_mcp
        print("ENABLE1 running:", srv.running)
        client.portal.call(_kill, srv)
        print("AFTER KILL running:", srv.running, "bindable:", _bindable("127.0.0.1", port))

        # Disable, and in the same save change the port -- `rebind` is True.
        client.post("/network-mcp/settings", data=_form(other, enabled=False))
        print("DISABLE same obj:", ctx.network_mcp is srv,
              "old port bindable:", _bindable("127.0.0.1", port))

        r = client.post("/network-mcp/settings", data=_form(port))
        txt = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))
        m = re.search(r"(Saved, but[^<]{0,300})", txt)
        print("ENABLE2 running:", getattr(ctx.network_mcp, "running", None),
              "err:", m.group(1) if m else "none")
