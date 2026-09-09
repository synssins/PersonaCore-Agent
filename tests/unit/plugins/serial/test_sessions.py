"""Unit tests for the serial plugin's session bookkeeping (contract §5.5).

Everything here drives ``SessionStore`` directly, with injected clocks, so
the 10-minute idle timeout and the 4-session cap are provable without a real
sleep and without a serial device.
"""

from __future__ import annotations

from workstation_agent.plugins.serial.__main__ import (
    IDLE_TIMEOUT_S,
    MAX_SESSIONS,
    SessionLimitExceededError,
    SessionStore,
)


class _FakeHandle:
    def __init__(self) -> None:
        self.closed = False
        self.timeout: float | None = None

    def write(self, data: bytes) -> int:
        return len(data)

    def read(self, size: int = 1) -> bytes:  # noqa: ARG002
        return b""

    def close(self) -> None:
        self.closed = True


class _Clock:
    """A controllable monotonic-ish clock for tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _store() -> tuple[SessionStore, _Clock, _Clock]:
    clock = _Clock(1_000.0)
    wall = _Clock(1_700_000_000.0)
    return SessionStore(clock=clock, wall_clock=wall), clock, wall


def test_session_ids_are_unguessable_and_unique() -> None:
    store, _, _ = _store()
    ids = set()
    for _ in range(50):
        session = store.create(port="COM1", baud=9600, handle=_FakeHandle())
        ids.add(session.session_id)
        store.close(session.session_id)  # stay under the 4-session cap
    assert len(ids) == 50
    for sid in ids:
        assert len(sid) == 32  # secrets.token_hex(16)
        int(sid, 16)  # every character is a hex digit


def test_at_most_four_sessions_open_at_once() -> None:
    store, _, _ = _store()
    for i in range(MAX_SESSIONS):
        store.create(port=f"COM{i}", baud=9600, handle=_FakeHandle())
    assert store.count() == MAX_SESSIONS

    try:
        store.create(port="COM99", baud=9600, handle=_FakeHandle())
    except SessionLimitExceededError:
        pass
    else:
        msg = "a 5th session must be refused"
        raise AssertionError(msg)


def test_idle_session_is_reaped_after_ten_minutes_and_closes_the_handle() -> None:
    store, clock, _ = _store()
    handle = _FakeHandle()
    session = store.create(port="COM1", baud=9600, handle=handle)

    clock.advance(IDLE_TIMEOUT_S - 1)
    assert store.get(session.session_id) is not None
    assert handle.closed is False

    clock.advance(2)  # now just past the 10-minute idle bound
    assert store.get(session.session_id) is None
    assert handle.closed is True, "an idle-reaped session must release its port"


def test_touch_resets_the_idle_clock() -> None:
    store, clock, _ = _store()
    session = store.create(port="COM1", baud=9600, handle=_FakeHandle())

    clock.advance(IDLE_TIMEOUT_S - 1)
    store.touch(session.session_id)
    clock.advance(IDLE_TIMEOUT_S - 1)

    assert store.get(session.session_id) is not None, "touching must postpone the idle reap"


def test_unknown_session_before_any_open_blames_the_restart_time() -> None:
    store, _, _wall = _store()
    reason = store.unknown_reason("deadbeef" * 4)
    assert "from before the Agent last restarted at" in reason
    assert store.started_at_iso in reason


def test_unknown_session_after_idle_reap_names_the_idle_close() -> None:
    store, clock, _wall = _store()
    session = store.create(port="COM1", baud=9600, handle=_FakeHandle())
    clock.advance(IDLE_TIMEOUT_S + 1)
    store.get(session.session_id)  # triggers the reap as a side effect

    reason = store.unknown_reason(session.session_id)
    assert "closed after 10 minutes idle at" in reason


def test_unknown_session_after_explicit_close_does_not_claim_idle() -> None:
    """A caller that closes its own session is not told it "went idle" —
    that would be false, and was a real defect caught while writing this
    test (the first implementation used one blanket "idle" message for
    every kind of closure)."""
    store, _, _ = _store()
    session = store.create(port="COM1", baud=9600, handle=_FakeHandle())
    store.close(session.session_id)

    reason = store.unknown_reason(session.session_id)
    assert "idle" not in reason
    assert "already closed at" in reason


def test_sessions_are_scoped_to_one_store_instance() -> None:
    """The strongest guarantee available at this layer: a fresh store (a
    fresh process, i.e. an Agent restart) knows nothing about a previous
    store's sessions — this is what "sessions die with the Agent" reduces to
    at the unit level, since the real guarantee (process exit) cannot be
    exercised in-process."""
    store_a, _, _ = _store()
    session = store_a.create(port="COM1", baud=9600, handle=_FakeHandle())

    store_b, _, _ = _store()
    assert store_b.get(session.session_id) is None


# ---------------------------------------------------------------------------
# Rework cycle 1, finding 5: `next_reap_in` — the one blast-radius mitigation
# available without per-caller identity.
# ---------------------------------------------------------------------------


def test_next_reap_in_is_none_with_no_sessions_open() -> None:
    store, _, _ = _store()
    assert store.next_reap_in() is None


def test_next_reap_in_counts_down_from_the_idle_timeout() -> None:
    store, clock, _ = _store()
    store.create(port="COM1", baud=9600, handle=_FakeHandle())

    assert store.next_reap_in() == IDLE_TIMEOUT_S

    clock.advance(100)
    assert store.next_reap_in() == IDLE_TIMEOUT_S - 100


def test_next_reap_in_tracks_the_least_recently_used_session() -> None:
    store, clock, _ = _store()
    first = store.create(port="COM1", baud=9600, handle=_FakeHandle())
    clock.advance(60)
    store.create(port="COM2", baud=9600, handle=_FakeHandle())

    # The first session is the most idle, so it governs when the next slot
    # frees up — touching it should push that estimate back out.
    assert store.next_reap_in() == IDLE_TIMEOUT_S - 60

    store.touch(first.session_id)
    assert store.next_reap_in() == IDLE_TIMEOUT_S
