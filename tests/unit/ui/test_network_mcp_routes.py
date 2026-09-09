"""Subtask B5 -- the credential surface: GET /network-mcp, rotate, regenerate.

Contract §3: the URL, certificate fingerprint and bearer token are shown
**once**, with a copy button each. These tests pin the "once" part -- the
raw token and fingerprint must not reappear on a second page load unless
the operator explicitly rotates or regenerates.
"""

from __future__ import annotations

import datetime as dt
import threading
import time
from pathlib import Path

import pytest

from tests.unit.ui.conftest import make_client
from workstation_agent.ui.backend import credential_reveal as credential_reveal_mod
from workstation_agent.ui.backend.credential_reveal import (
    RevealPersistenceError,
    consume_reveal,
)


class FakeNetworkMCPServer:
    """Stands in for NetworkMCPServer.info()/rotate_token()/regenerate_certificate()."""

    def __init__(self, *, token="t" * 64, fingerprint=None, running=True) -> None:
        self.token = token
        self.fingerprint = fingerprint or ("sha256:" + "ab" * 32)
        self.running = running
        self.rotate_calls = 0
        self.regenerate_calls = 0

    def info(self):
        return _Info(
            url="https://192.168.1.50:8765/mcp",
            bind_host="192.168.1.50",
            port=8765,
            fingerprint=self.fingerprint,
            token=self.token,
            certificate_sans=("192.168.1.50",),
            certificate_expires=dt.datetime.now(dt.UTC) + dt.timedelta(days=3650),
            tool_names=("workstation_status", "devices_list"),
            running=self.running,
        )

    def rotate_token(self):
        self.rotate_calls += 1
        self.token = "r" * 64
        return self.token

    def regenerate_certificate(self):
        self.regenerate_calls += 1
        self.fingerprint = "sha256:" + "cd" * 32
        return self.fingerprint


class _Info:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


@pytest.fixture(autouse=True)
def _isolated_reveal_state(tmp_path, monkeypatch):
    """Point the reveal-state file at tmp_path so tests never share state."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))


def test_disabled_endpoint_shows_not_running(tmp_path):
    client = make_client(tmp_path=tmp_path, network_mcp=None)
    resp = client.get("/network-mcp")
    assert resp.status_code == 200
    assert "not running" in resp.text.lower()


def test_first_visit_reveals_the_token_and_fingerprint(tmp_path):
    server = FakeNetworkMCPServer(token="firsttoken" * 6 + "ab", fingerprint="sha256:" + "11" * 32)
    client = make_client(tmp_path=tmp_path, network_mcp=server)

    resp = client.get("/network-mcp")
    assert resp.status_code == 200
    assert server.token in resp.text
    assert server.fingerprint in resp.text


def test_second_visit_does_not_reveal_the_same_token_again(tmp_path):
    server = FakeNetworkMCPServer(token="samevalue" * 7, fingerprint="sha256:" + "22" * 32)
    client = make_client(tmp_path=tmp_path, network_mcp=server)

    first = client.get("/network-mcp")
    assert server.token in first.text

    second = client.get("/network-mcp")
    assert server.token not in second.text
    assert server.fingerprint not in second.text
    assert "already shown" in second.text.lower()


def test_rotating_the_token_reveals_the_new_one_once(tmp_path):
    server = FakeNetworkMCPServer(token="original" * 8)
    client = make_client(tmp_path=tmp_path, network_mcp=server)

    client.get("/network-mcp")  # consume the original reveal

    resp = client.post("/network-mcp/rotate-token", follow_redirects=True)
    assert server.rotate_calls == 1
    assert resp.status_code == 200
    assert server.token in resp.text  # the new token, shown once

    again = client.get("/network-mcp")
    assert server.token not in again.text  # not shown a second time


def test_regenerating_the_certificate_reveals_the_new_fingerprint_once(tmp_path):
    server = FakeNetworkMCPServer(fingerprint="sha256:" + "33" * 32)
    client = make_client(tmp_path=tmp_path, network_mcp=server)

    client.get("/network-mcp")  # consume the original reveal

    resp = client.post("/network-mcp/regenerate-certificate", follow_redirects=True)
    assert server.regenerate_calls == 1
    assert server.fingerprint in resp.text

    again = client.get("/network-mcp")
    assert server.fingerprint not in again.text


def test_the_page_never_puts_the_token_in_a_form_action_or_redirect(tmp_path):
    """A copy-button flow must not leak the token into a URL/redirect target."""
    server = FakeNetworkMCPServer(token="leakcheck" * 7)
    client = make_client(tmp_path=tmp_path, network_mcp=server)
    resp = client.post("/network-mcp/rotate-token", follow_redirects=False)
    assert resp.status_code == 303
    assert server.token not in resp.headers["location"]


def test_a_reveal_persistence_failure_fails_closed_not_a_500(tmp_path, monkeypatch):
    """Finding 2: a write failure must hide the value and say why, never
    reveal it and never crash the page."""
    server = FakeNetworkMCPServer(token="wouldleak" * 7)
    client = make_client(tmp_path=tmp_path, network_mcp=server)

    def _boom(*_a, **_k):
        msg = "disk full"
        raise RevealPersistenceError(msg)

    monkeypatch.setattr(
        "workstation_agent.ui.backend.routers.network_mcp_routes.consume_reveal", _boom,
    )
    resp = client.get("/network-mcp")
    assert resp.status_code == 200
    assert server.token not in resp.text
    assert server.fingerprint not in resp.text
    assert "kept hidden" in resp.text.lower()


def test_a_broken_info_call_renders_an_error_not_a_500(tmp_path):
    class BrokenServer:
        def info(self):
            msg = "state file corrupt"
            raise RuntimeError(msg)

    client = make_client(tmp_path=tmp_path, network_mcp=BrokenServer())
    resp = client.get("/network-mcp")
    assert resp.status_code == 200
    assert "could not read" in resp.text.lower()


# ---------------------------------------------------------------------------
# consume_reveal itself
# ---------------------------------------------------------------------------


def test_consume_reveal_is_first_time_true_then_false(tmp_path):
    path = tmp_path / "reveal.json"
    assert consume_reveal("token", "abc", path=path) is True
    assert consume_reveal("token", "abc", path=path) is False


def test_consume_reveal_reveals_again_on_a_new_value(tmp_path):
    path = tmp_path / "reveal.json"
    assert consume_reveal("token", "abc", path=path) is True
    assert consume_reveal("token", "def", path=path) is True
    assert consume_reveal("token", "def", path=path) is False


def test_consume_reveal_kinds_are_independent(tmp_path):
    path = tmp_path / "reveal.json"
    assert consume_reveal("token", "same", path=path) is True
    assert consume_reveal("fingerprint", "same", path=path) is True


def test_a_missing_state_file_means_nothing_revealed_yet(tmp_path):
    """Finding 2 (verifier round 2): absence is the ordinary first-run
    state, not a failure -- it must not raise."""
    path = tmp_path / "does" / "not" / "exist" / "reveal.json"
    assert not path.exists()
    assert consume_reveal("token", "abc", path=path) is True


def test_a_corrupt_existing_state_file_fails_closed(tmp_path):
    """Finding 2 (verifier round 2): a file that *exists* and cannot be
    parsed (a torn write, a permissions change) used to be treated the
    same as "nothing revealed yet" and silently re-revealed everything --
    the opposite of what a fail-closed write path is for. It must now fail
    closed exactly like a write failure does, not fail open like a missing
    file legitimately does."""
    path = tmp_path / "reveal.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)


def test_a_state_file_holding_a_json_array_instead_of_an_object_fails_closed(tmp_path):
    path = tmp_path / "reveal.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)


# ---------------------------------------------------------------------------
# Finding 2 + 3: fail closed on a persistence failure, mkdir included
# ---------------------------------------------------------------------------


def test_a_write_failure_fails_closed_rather_than_revealing(tmp_path, monkeypatch):
    """Finding 2: an earlier revision swallowed the write failure and
    returned True anyway -- "shown once" silently became "shown always"."""
    path = tmp_path / "reveal.json"

    def _boom(_path, _data):
        msg = "no space left on device"
        raise OSError(msg)

    monkeypatch.setattr(credential_reveal_mod, "_save", _boom)

    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)
    # Not persisted -- the value was never durably recorded as revealed.
    assert not path.exists()


def test_a_write_failure_keeps_refusing_until_the_write_succeeds(tmp_path, monkeypatch):
    """A failed reveal must not get stuck claiming the value was already
    shown -- since nothing was persisted, retrying (once the underlying
    problem is fixed) must still reveal it, exactly once."""
    path = tmp_path / "reveal.json"
    real_save = credential_reveal_mod._save

    def _still_full(*_a):
        msg = "still full"
        raise OSError(msg)

    monkeypatch.setattr(credential_reveal_mod, "_save", _still_full)
    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)

    monkeypatch.setattr(credential_reveal_mod, "_save", real_save)
    assert consume_reveal("token", "abc", path=path) is True
    assert consume_reveal("token", "abc", path=path) is False


def test_a_mkdir_failure_is_reported_as_a_persistence_error_not_a_bare_oserror(
    tmp_path, monkeypatch,
):
    """Finding 3: mkdir used to sit outside the failure handling, so a
    directory-creation failure raised a bare, uncaught OSError instead of
    the same fail-closed contract every other write failure gets."""
    path = tmp_path / "somedir" / "reveal.json"

    def _boom_mkdir(self, *_a, **_k):  # noqa: ARG001
        msg = "access denied"
        raise OSError(msg)

    monkeypatch.setattr(Path, "mkdir", _boom_mkdir)

    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)


# ---------------------------------------------------------------------------
# Round 2, finding 4: the temp filename must not be static
# ---------------------------------------------------------------------------


def test_save_leaves_no_leftover_temp_file_after_success(tmp_path):
    path = tmp_path / "reveal.json"
    consume_reveal("token", "abc", path=path)
    consume_reveal("fingerprint", "def", path=path)
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == [], f"unexpected leftover temp files: {leftovers}"


def test_a_stuck_leftover_temp_file_does_not_block_a_future_write(tmp_path):
    """A static ``path.with_suffix('.tmp')`` name means one jammed leftover
    (antivirus holding a handle, a crashed process) blocks every future
    write to this path forever -- which, now that failures are fail-closed,
    means reveals disabled permanently until a human finds and deletes a
    file nobody knows about. A unique name per write means an old leftover
    simply sits there, unrelated to the next attempt."""
    path = tmp_path / "reveal.json"
    stale = path.with_suffix(".tmp")
    stale.write_text("stale leftover from a crashed previous run", encoding="utf-8")

    assert consume_reveal("token", "abc", path=path) is True
    assert stale.exists()  # untouched -- this call used its own unique name
    assert path.read_text(encoding="utf-8") != stale.read_text(encoding="utf-8")


def test_a_failed_write_cleans_up_its_own_temp_file(tmp_path, monkeypatch):
    """The temp file is written before the atomic replace; if replace fails,
    the half-finished temp file must not be left behind to accumulate."""
    path = tmp_path / "reveal.json"
    real_replace = Path.replace

    def _boom_replace(self, *args, **kwargs):
        if self.name.endswith(".tmp"):
            msg = "replace denied"
            raise OSError(msg)
        return real_replace(self, *args, **kwargs)

    monkeypatch.setattr(Path, "replace", _boom_replace)

    with pytest.raises(RevealPersistenceError):
        consume_reveal("token", "abc", path=path)

    assert list(tmp_path.glob("*.tmp")) == []


# ---------------------------------------------------------------------------
# Round 1 finding 4 / round 2 finding 6: the read-check-write is serialised
# ---------------------------------------------------------------------------


def test_concurrent_reveals_of_the_same_value_do_not_both_succeed(tmp_path):
    """Finding 4: two near-simultaneous requests (a double-clicked button
    is enough) must not both observe "not yet revealed" and both reveal.

    ``_save`` is slowed down so that, absent the module lock, the second
    thread's ``_load`` would run while the first is still mid-write and see
    the pre-update (empty) state -- exactly the race the lock forecloses by
    holding the whole read-check-write sequence, including the write, under
    one mutex.
    """
    path = tmp_path / "reveal.json"
    results: list[bool] = []
    real_save = credential_reveal_mod._save

    def _slow_save(save_path, data):
        time.sleep(0.1)
        real_save(save_path, data)

    def _worker():
        results.append(consume_reveal("token", "same-value", path=path))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(credential_reveal_mod, "_save", _slow_save)
        threads = [threading.Thread(target=_worker) for _ in range(2)]
        for t in threads:
            t.start()
            time.sleep(0.01)  # stagger the starts slightly, not eliminate the race
        for t in threads:
            t.join(timeout=5)

    assert sorted(results) == [False, True]
