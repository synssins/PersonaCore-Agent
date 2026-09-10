"""Tests: the settings UI refuses state-changing requests that are not its own.

The hole these close: the app's only gate was "is the client 127.0.0.1", and a
form on any web page the owner visits submits to ``http://127.0.0.1:<port>/...``
*from* 127.0.0.1. Everything on this surface was reachable that way, including
``POST /network-mcp/enrolled/remove``, which rotates the bearer token and locks
out every enrolled PersonaCore.

The two tests that matter most are at the bottom:
:func:`test_every_state_changing_route_is_covered` sweeps the real route table
rather than a list written by hand, and
:func:`test_a_route_added_later_is_covered_without_being_told` pins the property
that makes this maintainable -- nobody has to remember.
"""

from __future__ import annotations

import re

import pytest
from starlette.websockets import WebSocketDisconnect

from tests.unit.ui.conftest import (
    TEST_ORIGIN,
    FakeConfigStore,
    _LoopbackASGI,
    make_client,
    ui_test_client,
)
from workstation_agent.ui.backend import csrf
from workstation_agent.ui.backend.app import BackendContext, create_app

_HOSTILE = "http://evil.example"


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    """Keep the first-run flag and anything else out of the real %APPDATA%."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))


# ---------------------------------------------------------------------------
# The decision function, on its own
# ---------------------------------------------------------------------------


def test_safe_methods_are_never_checked():
    """GET/HEAD/OPTIONS render pages; a CSRF check there protects nothing."""
    for method in ("GET", "HEAD", "OPTIONS", "TRACE", "get"):
        assert (
            csrf.refusal_for(method, "http", "evil.example", _HOSTILE, "cross-site")
            is None
        )


def test_matching_origin_passes():
    assert (
        csrf.refusal_for(
            "POST", "http", "127.0.0.1:51423", "http://127.0.0.1:51423", "same-origin",
        )
        is None
    )


def test_origin_comparison_includes_the_port():
    """A hostile server on another loopback port is a different origin."""
    refusal = csrf.refusal_for(
        "POST", "http", "127.0.0.1:51423", "http://127.0.0.1:9999", None,
    )
    assert refusal == csrf.CROSS_ORIGIN_REFUSAL


def test_sec_fetch_site_is_checked_even_when_origin_matches():
    """The two headers are independent; a request must survive both."""
    refusal = csrf.refusal_for(
        "POST", "http", "127.0.0.1:51423", "http://127.0.0.1:51423", "cross-site",
    )
    assert refusal == csrf.CROSS_ORIGIN_REFUSAL


def test_same_site_is_not_good_enough():
    """``same-site`` covers another port on the same loopback address."""
    refusal = csrf.refusal_for("POST", "http", "127.0.0.1:51423", None, "same-site")
    assert refusal == csrf.CROSS_ORIGIN_REFUSAL


def test_sec_fetch_site_alone_is_enough_when_origin_is_absent():
    """Either header can carry the request; they fail differently."""
    assert (
        csrf.refusal_for("POST", "http", "127.0.0.1:51423", None, "same-origin") is None
    )


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1:51423", "localhost:51423", "[::1]:51423", "127.0.0.1", "LOCALHOST:80"],
)
def test_loopback_host_forms_are_recognised(host):
    scheme_host = f"http://{host.strip().casefold()}"
    assert csrf.refusal_for("POST", "http", host, scheme_host, None) is None


def test_a_name_that_merely_points_at_loopback_is_refused():
    """DNS rebinding: without this the Origin comparison proves nothing.

    An attacker who points ``rebind.example.com`` at 127.0.0.1 and serves a page
    from ``http://rebind.example.com:<port>/`` gets a browser that reports
    ``Origin`` and ``Host`` as the same thing and ``Sec-Fetch-Site:
    same-origin``. Comparing Origin against whatever Host says would wave that
    through, which is why the expected origin only exists for a Host that is
    literally a loopback address.
    """
    refusal = csrf.refusal_for(
        "POST",
        "http",
        "rebind.example.com:51423",
        "http://rebind.example.com:51423",
        "same-origin",
    )
    assert refusal is not None
    assert "not the Agent's own" in refusal


def test_missing_host_is_refused():
    assert csrf.refusal_for("POST", "http", None, None, None) is not None


def test_untrusted_host_is_capped_in_the_refusal():
    """The Host is attacker-chosen text; it does not get to be a paragraph."""
    refusal = csrf.refusal_for("POST", "http", "a" * 500, None, None)
    assert refusal is not None
    assert "a" * 500 not in refusal


def test_untrusted_host_is_escaped_in_the_rendered_page():
    refusal = csrf.refusal_for("POST", "http", "<script>x</script>.example", None, None)
    assert refusal is not None
    body = bytes(csrf.refusal_response(refusal).body).decode()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


# ---------------------------------------------------------------------------
# The missing-header decision
#
# Documented in ui/backend/csrf.py under "The missing-header decision": a
# state-changing request carrying neither header is REFUSED. These tests are
# the executable statement of that choice, so a later change of mind has to be
# a deliberate one.
# ---------------------------------------------------------------------------


def test_a_post_with_no_origin_and_no_sec_fetch_site_is_refused():
    refusal = csrf.refusal_for("POST", "http", "127.0.0.1:51423", None, None)
    assert refusal == csrf.MISSING_ORIGIN_REFUSAL


def test_the_missing_origin_refusal_says_what_to_do():
    text = csrf.MISSING_ORIGIN_REFUSAL
    assert "without changing anything" in text  # nothing happened
    assert "tray icon" in text  # where to go instead
    assert "Origin header" in text  # what a program has to send


def test_the_cross_origin_refusal_says_what_to_do():
    """The most likely legitimate way to meet this is a stale Settings tab."""
    text = csrf.CROSS_ORIGIN_REFUSAL
    assert "nothing was changed" in text
    assert "restarted" in text  # why a page from before the restart fails
    assert "new address every time it starts" in text
    assert "open it again from the tray icon" in text
    assert "was stopped" in text  # what it means if it was not you


# ---------------------------------------------------------------------------
# Through the real application
# ---------------------------------------------------------------------------


def _app(tmp_path):
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    return _LoopbackASGI(create_app(ctx))


def _raw_client(tmp_path, **kwargs):
    """A client with *no* browser headers, speaking from a loopback Host."""
    from starlette.testclient import TestClient

    return TestClient(_app(tmp_path), base_url=TEST_ORIGIN, **kwargs)


def test_legitimate_same_origin_post_still_works(tmp_path):
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)
    resp = client.post("/config", data={"llm_model": "a-real-save"})
    assert resp.status_code == 200
    assert store.load().llm.model == "a-real-save"


def test_cross_origin_post_is_refused_and_changes_nothing(tmp_path):
    """The attack: a form on another site, submitted to the loopback port."""
    store = FakeConfigStore()
    before = store.load().llm.model
    ctx = BackendContext(config_store=store, log_dir=tmp_path / "logs")
    client = ui_test_client(_LoopbackASGI(create_app(ctx)))

    resp = client.post(
        "/config",
        data={"llm_model": "owned"},
        headers={"Origin": _HOSTILE, "Sec-Fetch-Site": "cross-site"},
    )

    assert resp.status_code == 403
    assert store.load().llm.model == before


def test_the_refusal_reaches_the_browser_as_readable_text(tmp_path):
    client = ui_test_client(_app(tmp_path))
    resp = client.post("/config", data={}, headers={"Origin": _HOSTILE})
    assert resp.status_code == 403
    assert "text/html" in resp.headers["content-type"]
    assert "Settings window" in resp.text
    assert "tray icon" in resp.text
    assert "was refused" in resp.text


def test_a_post_with_no_headers_at_all_is_refused_through_the_app(tmp_path):
    client = _raw_client(tmp_path)
    resp = client.post("/config", data={})
    assert resp.status_code == 403
    assert "did not say which page it came from" in resp.text


def test_get_requests_are_untouched(tmp_path):
    """Pages must render exactly as before -- including from a bare client."""
    client = _raw_client(tmp_path)
    for path in ("/config", "/dashboard", "/about", "/plugins", "/network-mcp"):
        assert client.get(path).status_code == 200


def test_the_loopback_guard_still_answers_first(tmp_path):
    """Existing behaviour: off-machine gets the loopback refusal, not this one."""
    from starlette.testclient import TestClient

    class _OffMachine:
        def __init__(self, inner: object) -> None:
            self._inner = inner

        async def __call__(self, scope, receive, send) -> None:
            if scope["type"] in {"http", "websocket"}:
                scope = {**scope, "client": ("10.0.0.1", 9999)}
            await self._inner(scope, receive, send)  # type: ignore[operator]

    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    client = TestClient(_OffMachine(create_app(ctx)), base_url=TEST_ORIGIN)
    resp = client.post("/config", data={}, headers={"Origin": _HOSTILE})
    assert resp.status_code == 403
    assert resp.text == "Forbidden: loopback only"


# ---------------------------------------------------------------------------
# Whole-surface coverage
# ---------------------------------------------------------------------------

#: Stand-ins for the path parameters on the parameterised routes. The values do
#: not have to name anything real: the CSRF check runs before routing resolves
#: them, which is the whole point of asserting on it here.
_PATH_PARAMS = {
    "plugin_id": "some-plugin",
    "perm": "some-perm",
    "family": "some-family",
}

#: Matches ``{name}`` and ``{name:convertor}`` alike. Starlette lets a path
#: parameter name a convertor -- ``{perm:path}``, which is how the permission
#: routes accept a permission string with a ``/`` in it -- and a substitution
#: that only understood the bare form would silently stop replacing that
#: parameter, leaving a ``{`` behind and failing the guard below for a reason
#: that has nothing to do with CSRF.
_PATH_PARAM_RE = re.compile(r"\{(\w+)(?::[^}]+)?\}")


def _walk(routes):
    """Flatten FastAPI's route tree into the leaf routes that carry methods.

    ``app.routes`` is not flat: ``include_router`` leaves a wrapper object whose
    own ``path`` is ``None`` and whose real, already-prefixed routes hang off
    ``original_router``. Walking it is what keeps the sweep honest -- a list of
    paths typed into this file would go stale the first time a route is added.
    """
    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            yield from _walk(included.routes)
        elif getattr(route, "path", None) is not None:
            yield route


def _state_changing_paths(app) -> list[tuple[str, str]]:
    """Every (method, path) on the real route table that changes state."""
    found: list[tuple[str, str]] = []
    for route in _walk(app.routes):
        methods = getattr(route, "methods", None) or set()
        for method in sorted(set(methods) - csrf.SAFE_METHODS):
            concrete = _PATH_PARAM_RE.sub(
                lambda m: _PATH_PARAMS.get(m.group(1), m.group(0)),
                route.path,
            )
            found.append((method, concrete))
    return found


def test_the_route_sweep_actually_finds_the_routes(tmp_path):
    """Guard the guard: an empty sweep would make the next test vacuous."""
    paths = _state_changing_paths(create_app(
        BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs"),
    ))
    assert len(paths) >= 20
    assert ("POST", "/network-mcp/enrolled/remove") in paths
    assert ("POST", "/config") in paths
    # The family-level permission routes: one click that writes several grants
    # is exactly the kind of route a cross-origin page would most like to reach.
    assert ("POST", "/plugins/some-plugin/grant-family/some-family") in paths
    assert ("POST", "/plugins/some-plugin/revoke-family/some-family") in paths
    assert not any("{" in path for _, path in paths)


def test_every_state_changing_route_is_covered(tmp_path):
    """No POST anywhere on this surface escapes the check.

    Driven off ``app.routes``, not off a list in this file, so a route added
    later is swept the day it is added rather than the day someone remembers to
    add it here.
    """
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)
    client = ui_test_client(_LoopbackASGI(app), raise_server_exceptions=False)

    escaped = []
    for method, path in _state_changing_paths(app):
        resp = client.request(
            method,
            path,
            headers={"Origin": _HOSTILE, "Sec-Fetch-Site": "cross-site"},
            follow_redirects=False,
        )
        if resp.status_code != 403 or "was refused" not in resp.text:
            escaped.append((method, path, resp.status_code))

    assert escaped == []


def test_every_state_changing_route_is_still_reachable_legitimately(tmp_path):
    """The failure mode of a CSRF fix is silently breaking a button.

    A same-origin request must never be turned away by *this* check. What the
    route then does with a stub body is its own business -- a 4xx from
    validation is fine, the refusal page is not.
    """
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)
    client = ui_test_client(_LoopbackASGI(app), raise_server_exceptions=False)

    blocked = []
    for method, path in _state_changing_paths(app):
        resp = client.request(method, path, data={}, follow_redirects=False)
        if resp.status_code == 403 and "was refused" in resp.text:
            blocked.append((method, path))

    assert blocked == []


def test_a_route_added_later_is_covered_without_being_told(tmp_path):
    """The property that makes this survive the next feature.

    The check is middleware over the whole app, not a token each form has to
    remember to carry, so a route registered after the fact is protected
    without its author knowing this module exists.
    """
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)

    @app.post("/a-route-nobody-thought-about")
    async def _new_route() -> dict[str, bool]:
        return {"ran": True}

    client = ui_test_client(_LoopbackASGI(app))

    hostile = client.post(
        "/a-route-nobody-thought-about", headers={"Origin": _HOSTILE},
    )
    assert hostile.status_code == 403

    legitimate = client.post("/a-route-nobody-thought-about")
    assert legitimate.status_code == 200
    assert legitimate.json() == {"ran": True}


def test_a_websocket_route_added_later_is_covered_too(tmp_path):
    """The exception the middleware choice would otherwise have hidden.

    Starlette's HTTP middleware is only ever handed an ``http`` scope, so a
    WebSocket route registered later would have slipped past this check *and*
    past the loopback guard, and cross-site WebSocket hijacking is not subject
    to the same-origin policy -- the browser opens it. This surface has no
    WebSocket routes, so the upgrade is refused outright, which is the honest
    answer today and a loud one for whoever adds a real one tomorrow.
    """
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)
    reached = []

    @app.websocket("/a-socket-nobody-thought-about")
    async def _new_socket(websocket) -> None:
        reached.append(True)
        await websocket.accept()

    client = ui_test_client(_LoopbackASGI(app))

    with (
        pytest.raises(WebSocketDisconnect) as caught,
        client.websocket_connect("/a-socket-nobody-thought-about"),
    ):
        pass

    assert caught.value.code == 1008
    assert reached == []  # the route never ran


def test_lifespan_scopes_pass_through(tmp_path):
    """Only http and websocket are judged; startup must not be swallowed."""
    ctx = BackendContext(config_store=FakeConfigStore(), log_dir=tmp_path / "logs")
    app = create_app(ctx)
    started = []

    @app.on_event("startup")
    async def _startup() -> None:
        started.append(True)

    with ui_test_client(_LoopbackASGI(app)) as client:
        assert client.get("/dashboard", follow_redirects=False).status_code == 200

    assert started == [True]


# ---------------------------------------------------------------------------
# The one internal non-browser caller
# ---------------------------------------------------------------------------


def test_the_tray_names_the_origin_it_is_calling(monkeypatch):
    """The tray is not a browser, so it says where it is calling from itself.

    Derived from the address it is already about to call -- read from the
    ``ui-port`` file at call time -- so it follows the Agent onto its new
    ephemeral port at every restart. There is nothing to configure.
    """
    from unittest.mock import MagicMock

    from workstation_agent.ui.systray.tray import SystemTray

    posts = MagicMock()
    monkeypatch.setattr("workstation_agent.ui.systray.tray.httpx.post", posts)

    with monkeypatch.context() as m:
        m.setattr("pystray.Icon", MagicMock())
        tray = SystemTray(
            webview_window=MagicMock(),
            url_provider=lambda: "http://127.0.0.1:51423",
            on_exit=lambda: None,
            logs_dir="/logs",
        )

    # Every menu item that makes a request. The mute toggle used to be one of
    # them; P23 removed its call entirely (there is no `muted` setting and no
    # route that owns one, so the request could only ever have destroyed the
    # configuration), so it is not listed here -- and the assertion below that
    # *every* post carries the header would catch it if it came back untreated.
    tray._make_session_mode_action("persistent")(None, None)
    tray._on_reload_plugins(None, None)
    tray._on_check_updates(None, None)

    assert posts.call_count == 3
    for call in posts.call_args_list:
        assert call.kwargs["headers"]["Origin"] == "http://127.0.0.1:51423"


def test_the_tray_headers_would_satisfy_the_check():
    """Not just present -- actually accepted, on the port it is calling."""
    from workstation_agent.ui.systray.tray import SystemTray

    base = "http://127.0.0.1:51423"
    headers = SystemTray._same_origin_headers(base)
    assert (
        csrf.refusal_for("POST", "http", "127.0.0.1:51423", headers["Origin"], None)
        is None
    )
