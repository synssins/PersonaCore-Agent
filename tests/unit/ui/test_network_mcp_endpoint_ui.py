"""Subtask P7 -- bringing the network endpoint up, and exporting it, from the UI.

The product requirement these pin down is one sentence from the owner: "at no
point should I EVER be required to touch a config file. EVERYTHING MUST BE
THROUGH A USER INTERFACE." Before this, bringing the workstation plugin up
meant hand-editing ``%APPDATA%\\WorkstationAgent\\config.toml`` to set
``network_mcp.enabled`` and then running ``Agent.exe export-registration`` at a
command prompt. Both are now buttons, and these tests are what stops them
quietly regressing into decoration -- every one of them asserts on the
*endpoint's* state or the *file* on disk, never only on the words the page
printed.
"""

from __future__ import annotations

import datetime as dt
import zipfile

import pytest

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.config.schema import AgentConfig
from workstation_agent.network_mcp.tools import served_tool_names
from workstation_agent.registration_export import MANIFEST_ARCNAME, REGISTRATION_ZIP_NAME
from workstation_agent.ui.backend.routers import network_mcp_routes


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    """Reveal state, and the exported zip, land under tmp_path -- never the profile."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path / "appdata"))


# ---------------------------------------------------------------------------
# A fake endpoint that behaves like NetworkMCPServer where it matters
# ---------------------------------------------------------------------------


class _Info:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


class FakeEndpoint:
    """Mirrors the slice of ``NetworkMCPServer`` this router actually calls.

    ``info()`` works before ``start()`` (the real one generates the token and
    certificate on demand so the UI can show them), ``start``/``stop`` are
    coroutines, and ``running`` is a real property rather than a stored flag --
    the router reads it after starting, and a plain attribute would let a fake
    "start" that did nothing still look successful.
    """

    #: Set on the class by a test to make every constructed endpoint fail.
    def __init__(  # noqa: PLR0913 — one knob per behaviour a test needs to stage
        self,
        config,
        *,
        start_error: Exception | None = None,
        sans: tuple[str, ...] = ("workstation", "192.168.1.50", "127.0.0.1"),
        bind_failures: tuple[object, ...] = (),
        regenerate_sans: tuple[str, ...] | None = None,
        shared: dict | None = None,
    ) -> None:
        self.config = config
        self.bind_failures = bind_failures
        #: What a regeneration is *able* to cover. ``None`` means "whatever was
        #: asked for", which is the normal case; a fixed tuple models a machine
        #: that cannot certify an address it does not have -- no certificate
        #: this machine generates will ever cover 203.0.113.9.
        self.regenerate_sans = regenerate_sans
        self._running = False
        self.start_calls = 0
        self.stop_calls = 0
        self.start_error = start_error
        # The certificate is a file on the machine, not a property of a server
        # object: a rebind builds a fresh NetworkMCPServer and it reads back the
        # same certificate. Sharing this dict across everything one Factory
        # builds is what makes the fake behave that way; without it, rotating
        # the certificate and then rebinding would silently un-rotate it.
        self._cert = shared if shared is not None else {}
        self._cert.setdefault("sans", sans)
        self._cert.setdefault("fingerprint", "sha256:" + "ab" * 32)
        self.token = "t" * 64
        self.assigned_port = config.port or 49152

    @property
    def sans(self) -> tuple[str, ...]:
        return self._cert["sans"]

    @sans.setter
    def sans(self, value) -> None:
        self._cert["sans"] = value

    @property
    def fingerprint(self) -> str:
        return self._cert["fingerprint"]

    @fingerprint.setter
    def fingerprint(self, value: str) -> None:
        self._cert["fingerprint"] = value

    @property
    def running(self) -> bool:
        return self._running

    async def start(self):
        self.start_calls += 1
        if self.start_error is not None:
            raise self.start_error
        self._running = True
        return self.info()

    async def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def info(self):
        hosts = tuple(self.config.bind_hosts)
        host = hosts[0]
        urls = tuple(
            f"https://[{h}]:{self.assigned_port}/mcp" if ":" in h
            else f"https://{h}:{self.assigned_port}/mcp"
            for h in hosts
        )
        return _Info(
            url=urls[0],
            urls=urls,
            bind_host=host,
            bind_hosts=hosts,
            bind_failures=tuple(self.bind_failures) if self._running else (),
            degraded=bool(self._running and self.bind_failures),
            port=self.assigned_port,
            fingerprint=self.fingerprint,
            token=self.token,
            certificate_sans=self.sans,
            certificate_expires=dt.datetime.now(dt.UTC) + dt.timedelta(days=3650),
            # The real served set, not a plausible-looking two. `export_registration`
            # refuses to write a registration whose tool list disagrees with
            # `served_tool_names()`, and a fake that shortcuts that would test the
            # export path with the one check that matters disabled.
            tool_names=served_tool_names(),
            running=self._running,
        )

    def rotate_token(self):
        self.token = "r" * 64
        return self.token

    def regenerate_certificate(self, *, for_hosts=None):
        self.fingerprint = "sha256:" + "cd" * 32
        # A regenerated certificate covers the hosts asked for -- the operator's
        # *pending* selection when the router passes one, which is the whole
        # point of offering the button on a SAN mismatch.
        if self.regenerate_sans is not None:
            self.sans = self.regenerate_sans
        else:
            self.sans = tuple(for_hosts) if for_hosts else tuple(self.config.bind_hosts)
        return self.fingerprint


class Factory:
    """Records every endpoint it builds, so a test can inspect the live one."""

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.built: list[FakeEndpoint] = []
        #: The one certificate on this "machine", shared by everything built.
        self.cert: dict = {}

    def __call__(self, config) -> FakeEndpoint:
        endpoint = FakeEndpoint(config, shared=self.cert, **self.kwargs)
        self.built.append(endpoint)
        return endpoint

    @property
    def last(self) -> FakeEndpoint:
        return self.built[-1]


def _form(**overrides):
    data = {
        "enabled": "true",
        "bind_host_choice": "192.168.1.50",
        "bind_host_other": "",
        "port": "8765",
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


# ---------------------------------------------------------------------------
# 1. Enabling from the UI brings the endpoint up -- no restart, no config file
# ---------------------------------------------------------------------------


def test_enabling_from_the_ui_actually_starts_the_endpoint(tmp_path):
    store = FakeConfigStore()
    factory = Factory()
    client, ctx = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory, return_ctx=True,
    )
    assert store.load().network_mcp.enabled is False

    resp = client.post("/network-mcp/settings", data=_form())

    assert resp.status_code == 200
    # The setting was persisted...
    assert store.load().network_mcp.enabled is True
    assert store.load().network_mcp.bind_host == "192.168.1.50"
    assert store.load().network_mcp.port == 8765
    # ...and the endpoint is genuinely listening, not merely promised.
    assert factory.last.start_calls == 1
    assert factory.last.running is True
    assert ctx.network_mcp is factory.last
    assert "listening" in resp.text.lower()


def test_the_started_endpoint_is_handed_back_to_the_composition_root(tmp_path):
    """Without this, a UI-started endpoint outlives Agent shutdown.

    ``Application._shutdown_async`` stops whatever ``_subs.network_mcp``
    holds. The router builds a *different* object from the one startup may
    have made, so unless the change is published the Agent exits with a TLS
    listener still bound to the LAN.
    """
    adopted: list[object] = []
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(),
        tmp_path=tmp_path,
        network_mcp_factory=factory,
        on_network_mcp_change=adopted.append,
    )

    client.post("/network-mcp/settings", data=_form())

    assert adopted == [factory.last]


def test_a_callback_that_raises_does_not_break_the_save(tmp_path):
    """The endpoint is up either way; a bad callback must not turn that into a 500."""

    def _boom(_server):
        msg = "composition root is unhappy"
        raise RuntimeError(msg)

    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(),
        tmp_path=tmp_path,
        network_mcp_factory=factory,
        on_network_mcp_change=_boom,
    )

    resp = client.post("/network-mcp/settings", data=_form())
    assert resp.status_code == 200
    assert factory.last.running is True


def test_disabling_from_the_ui_stops_the_running_endpoint(tmp_path):
    store = FakeConfigStore()
    factory = Factory()
    client, ctx = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory, return_ctx=True,
    )
    client.post("/network-mcp/settings", data=_form())
    started = factory.last
    assert started.running is True

    resp = client.post("/network-mcp/settings", data=_form(enabled=None))

    assert store.load().network_mcp.enabled is False
    assert started.running is False
    assert started.stop_calls == 1
    assert "no longer listening" in resp.text.lower()
    # The stopped endpoint is kept so the page can still show the fingerprint
    # and token the operator has to paste into PersonaCore.
    assert ctx.network_mcp is started


def test_changing_the_host_rebinds_rather_than_leaving_the_old_bind(tmp_path):
    store = FakeConfigStore()
    factory = Factory()
    client, ctx = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory, return_ctx=True,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="127.0.0.1"))
    first = factory.last

    client.post("/network-mcp/settings", data=_form(bind_host_choice="192.168.1.50"))
    second = factory.last

    assert second is not first
    assert first.stop_calls == 1
    assert first.running is False
    assert second.running is True
    assert second.config.bind_host == "192.168.1.50"
    assert ctx.network_mcp is second


def test_saving_an_unchanged_running_endpoint_does_not_drop_the_connection(tmp_path):
    """Rebinding kills whatever session the core is holding.

    Doing it on every save -- including a save that changed nothing -- would
    be a self-inflicted outage every time the operator clicked the button.
    """
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())
    started = factory.last

    resp = client.post("/network-mcp/settings", data=_form())

    assert len(factory.built) == 1
    assert started.stop_calls == 0
    assert started.start_calls == 1
    assert "already running" in resp.text.lower()


def test_a_bind_failure_is_reported_with_the_reason_not_swallowed(tmp_path):
    store = FakeConfigStore()
    factory = Factory(start_error=OSError("address already in use"))
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post("/network-mcp/settings", data=_form())

    assert resp.status_code == 200
    assert "address already in use" in resp.text
    assert "could not start" in resp.text.lower()
    # The configuration is still saved: it is what the operator asked for, and
    # a restart should honour it.
    assert store.load().network_mcp.enabled is True


def test_an_endpoint_that_cannot_be_started_from_here_says_restart_plainly(tmp_path):
    """"Say so plainly" -- never silently do nothing and look successful."""

    class _NoStart:
        def __init__(self, config) -> None:
            self.config = config

        def info(self):
            msg = "no identity"
            raise RuntimeError(msg)

    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=_NoStart,
    )
    resp = client.post("/network-mcp/settings", data=_form())

    assert resp.status_code == 200
    assert "restart the agent" in resp.text.lower()


def test_a_factory_that_explodes_is_reported_not_a_500(tmp_path):
    def _explode(_config):
        msg = "mcp SDK missing"
        raise ImportError(msg)

    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=_explode,
    )
    resp = client.post("/network-mcp/settings", data=_form())

    assert resp.status_code == 200
    assert "mcp SDK missing" in resp.text
    assert "restart the agent" in resp.text.lower()


def test_starting_without_a_plugin_host_says_tool_calls_will_fail(tmp_path):
    """Serving with no host answers every tools/call with an error envelope.

    Reporting "listening" and nothing else would look like a healthy endpoint.
    """
    factory = Factory()
    client, ctx = make_client(
        config_store=FakeConfigStore(),
        tmp_path=tmp_path,
        network_mcp_factory=factory,
        return_ctx=True,
    )
    ctx.mcp_host = None

    resp = client.post("/network-mcp/settings", data=_form())

    assert factory.last.running is True
    assert "no plugin host is attached" in resp.text


# ---------------------------------------------------------------------------
# 2. A wildcard bind is refused with a usable message, not a traceback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("wildcard", ["0.0.0.0", "::", "*", "[::]", "0", "::0"])  # noqa: S104
def test_a_wildcard_bind_is_refused_with_a_readable_message(tmp_path, wildcard):
    store = FakeConfigStore()
    factory = Factory()
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post(
        "/network-mcp/settings",
        data=_form(bind_host_choice=network_mcp_routes._OTHER, bind_host_other=wildcard),
    )

    assert resp.status_code == 200
    # The schema's own sentence, not pydantic's framing and not a traceback.
    assert "must name one interface" in resp.text
    assert "binds every interface on this machine" in resp.text
    assert "ValidationError" not in resp.text
    assert "Traceback" not in resp.text
    # Nothing was saved and nothing was started.
    assert store.load().network_mcp.bind_host == "127.0.0.1"
    assert store.load().network_mcp.enabled is False
    assert factory.built == []


def test_the_wildcard_message_is_the_schemas_own_wording(tmp_path):
    """One copy of that sentence.

    ``NetworkMcpConfig`` is the thing that actually refuses the value; if the
    router carried its own paraphrase the two would drift and the UI would
    start explaining a rule the schema no longer enforces.
    """
    from markupsafe import escape
    from pydantic import ValidationError

    from workstation_agent.config.schema import NetworkMcpConfig

    with pytest.raises(ValidationError) as excinfo:
        NetworkMcpConfig(bind_host="0.0.0.0")  # noqa: S104
    schema_sentence = excinfo.value.errors()[0]["msg"].removeprefix("Value error, ")

    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=Factory(),
    )
    resp = client.post(
        "/network-mcp/settings",
        data=_form(bind_host_choice=network_mcp_routes._OTHER, bind_host_other="0.0.0.0"),  # noqa: S104
    )
    # Escaped, because the sentence quotes the offending value and the template
    # autoescapes -- which is exactly what should happen to a value typed by a
    # user and echoed back into HTML.
    assert str(escape(schema_sentence)) in resp.text


def test_an_empty_bind_host_is_refused_before_pydantic_sees_it(tmp_path):
    store = FakeConfigStore()
    factory = Factory()
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post(
        "/network-mcp/settings",
        data=_form(bind_host_choice=network_mcp_routes._OTHER, bind_host_other="   "),
    )
    assert factory.built == []

    assert resp.status_code == 200
    assert "Choose the interface to bind" in resp.text
    assert store.load().network_mcp.enabled is False


@pytest.mark.parametrize("bad_port", ["", "eight thousand", "80.5", "99999", "-1"])
def test_a_bad_port_comes_back_as_a_message_not_a_422(tmp_path, bad_port):
    """A typed ``int`` form field would hand this to FastAPI, which answers 422
    with a JSON body -- a dead end in a webview with no way back to the form."""
    store = FakeConfigStore()
    factory = Factory()
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post("/network-mcp/settings", data=_form(port=bad_port))

    assert resp.status_code == 200
    assert "network mcp" in resp.text.lower()
    assert store.load().network_mcp.enabled is False
    # Nothing was built, so nothing tried to bind a port the operator did not
    # actually name. An empty field is the sharp edge here: FastAPI substitutes
    # a parameter default for an empty form value, so a default of "8765" would
    # have silently bound 8765.
    assert factory.built == []


def test_an_info_object_missing_certificate_sans_renders_rather_than_500s(tmp_path):
    """``info`` is whatever ``ctx.network_mcp`` returned.

    A stub endpoint, or a future field rename, must degrade to "we cannot
    confirm the certificate covers this address" -- never take the settings
    page down, which is the one page the operator needs in order to fix it.
    """

    class _Sparse:
        running = True

        def info(self):
            return _Info(token="t" * 64, fingerprint="sha256:" + "ff" * 32, running=True)

    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp=_Sparse())

    resp = client.get("/network-mcp")
    assert resp.status_code == 200
    assert "does not cover" in resp.text
    assert "SAN is empty" in resp.text


def test_a_port_typo_does_not_masquerade_as_the_port_zero_warning(tmp_path):
    """Substituting 0 for an unparseable port would attach the wrong lesson.

    "Port 0 asks the OS to pick a free port at every start" is a real warning
    about a real setting; showing it because the operator typed "876S" tells
    them to fix something they never did.
    """
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=Factory(),
    )
    resp = client.post("/network-mcp/settings", data=_form(port="876S"))

    assert "is not a whole number" in resp.text
    assert "asks the operating system to pick" not in resp.text


def test_a_genuine_port_zero_does_get_the_warning(tmp_path):
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=Factory(),
    )
    resp = client.post("/network-mcp/settings", data=_form(port="0"))

    assert "asks the operating system to pick" in resp.text


def test_the_page_offers_this_machines_addresses_and_marks_loopback(tmp_path):
    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)
    resp = client.get("/network-mcp")

    assert resp.status_code == 200
    # A multi-select: a machine that bridges networks has to answer on more
    # than one address, and which ones is the operator's choice from a list.
    assert 'name="bind_hosts"' in resp.text
    assert "multiple" in resp.text
    assert 'name="port"' in resp.text
    assert 'name="enabled"' in resp.text
    assert "NOT reachable from PersonaCore" in resp.text
    # The default config binds loopback, so the page must say that is wrong.
    assert "loopback address" in resp.text.lower()


def test_address_discovery_failing_still_renders_a_usable_page(tmp_path, monkeypatch):
    """A machine with no network must still get a form it can type into."""

    def _boom():
        msg = "no network stack"
        raise OSError(msg)

    monkeypatch.setattr(
        "workstation_agent.network_mcp.certs.local_identities", _boom,
    )
    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)
    resp = client.get("/network-mcp")

    assert resp.status_code == 200
    assert 'name="bind_host_other"' in resp.text


def test_the_configured_host_is_always_offered_even_if_this_machine_lost_it(tmp_path):
    cfg = AgentConfig()
    cfg.network_mcp.bind_host = "10.99.99.99"
    client = make_client(config_store=FakeConfigStore(cfg), tmp_path=tmp_path)

    resp = client.get("/network-mcp")
    assert "10.99.99.99" in resp.text


# ---------------------------------------------------------------------------
# 3. Changing the host must not leave a certificate that cannot match
# ---------------------------------------------------------------------------


def test_a_host_the_certificate_does_not_cover_is_flagged_with_the_fix(tmp_path):
    store = FakeConfigStore()
    factory = Factory(sans=("workstation", "192.168.1.50"))
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    resp = client.post("/network-mcp/settings", data=_form(bind_host_choice="10.0.0.7"))

    assert "does not cover 10.0.0.7" in resp.text
    assert "Regenerate Certificate for this address" in resp.text
    # The consequence of taking that offer is stated, not buried.
    assert "changes the fingerprint" in resp.text
    assert "re-exported" in resp.text


def test_the_certificate_is_never_regenerated_behind_the_operators_back(tmp_path):
    """The decision, and why it is this way round.

    The core pins ``tls_fingerprint``; it does not check the SAN. Silently
    regenerating on a host change would therefore *break a working connection*
    -- new fingerprint, failed pin -- to fix a name the core never looks at.
    Leaving the fingerprint alone and saying so keeps a working endpoint
    working and puts the trade-off in front of the person who can weigh it.
    """
    factory = Factory(sans=("192.168.1.50",))
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="192.168.1.50"))
    original = factory.last.fingerprint

    client.post("/network-mcp/settings", data=_form(bind_host_choice="10.0.0.7"))

    assert factory.last.fingerprint == original


def test_the_refusal_stands_on_a_second_attempt_too(tmp_path):
    """Refused is refused, not "warned once and then allowed through".

    The superseded behaviour saved the address and left a standing warning,
    which is the shape the owner ruled out: the failure has to be impossible to
    reach by clicking, not documented next to the click that reaches it.
    """
    store = FakeConfigStore()
    factory = Factory(sans=("192.168.1.50",))
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )

    for _ in range(2):
        resp = client.post("/network-mcp/settings", data=_form(bind_host_choice="10.0.0.7"))
        assert "does not cover 10.0.0.7" in resp.text
        assert store.load().network_mcp.bind_hosts == ("127.0.0.1",)
        assert store.load().network_mcp.enabled is False
    assert factory.built[-1].start_calls == 0


def test_taking_the_regenerate_offer_covers_the_address_and_saves(tmp_path):
    """The one sanctioned way through, and it goes all the way through.

    Regenerating for the *pending* selection is the point: rotating for what is
    already stored would produce a certificate that still does not cover the
    address being added, and the operator's next click would fail identically.
    """
    store = FakeConfigStore()
    factory = Factory(sans=("192.168.1.50",))
    client = make_client(
        config_store=store, tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="10.0.0.7"))
    before = factory.built[-1].fingerprint

    resp = client.post(
        "/network-mcp/settings",
        data={"enabled": "true", "bind_hosts": ["10.0.0.7"], "port": "8765",
              "regenerate": "true"},
    )

    assert "does not cover" not in resp.text
    assert store.load().network_mcp.bind_hosts == ("10.0.0.7",)
    assert factory.built[-1].fingerprint != before
    assert "10.0.0.7" in factory.built[-1].sans


def test_moving_from_loopback_to_a_covered_lan_address_needs_no_regeneration(tmp_path):
    """The common move, and the reason the check is a check and not a rule.

    ``certs.local_identities`` puts this machine's LAN address in the SAN even
    when the endpoint is bound to loopback, so 127.0.0.1 -> LAN usually leaves
    the certificate already correct. Asserting SAN coverage rather than
    assuming a host change invalidates the certificate is what avoids a
    pointless fingerprint rotation here.
    """
    factory = Factory(sans=("workstation", "192.168.1.50", "127.0.0.1"))
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="127.0.0.1"))

    resp = client.post("/network-mcp/settings", data=_form(bind_host_choice="192.168.1.50"))

    assert "does not cover" not in resp.text


@pytest.mark.parametrize(
    ("host", "sans", "covered"),
    [
        ("192.168.1.50", ("192.168.1.50",), True),
        ("192.168.1.50", ("192.168.1.51",), False),
        ("WORKSTATION", ("workstation",), True),  # DNS is case-insensitive
        ("::1", ("0:0:0:0:0:0:0:1",), True),  # same address, different spelling
        ("[192.168.1.50]", ("192.168.1.50",), True),
        ("bar.foo.example", ("foo.example",), False),  # no suffix guessing
        ("192.168.1.50", (), False),
    ],
)
def test_san_coverage_compares_names_as_names_and_addresses_as_addresses(host, sans, covered):
    from workstation_agent.registration_export import san_covers

    assert san_covers(host, sans) is covered


# ---------------------------------------------------------------------------
# 4. Export: reaches the owner, and refuses to be useless silently
# ---------------------------------------------------------------------------


def test_exporting_a_healthy_endpoint_writes_the_zip_and_shows_the_path(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())

    resp = client.post("/network-mcp/export-registration")

    zip_path = network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME
    assert zip_path.is_file()
    assert str(zip_path) in resp.text
    assert "/network-mcp/registration.zip" in resp.text
    with zipfile.ZipFile(zip_path) as zf:
        manifest = zf.read(MANIFEST_ARCNAME).decode("utf-8")
    assert 'url             = "https://192.168.1.50:8765/mcp"' in manifest
    assert 'network = ["192.168.1.50"]' in manifest


def test_the_export_carries_the_live_endpoints_port_not_the_configured_zero(tmp_path):
    """The bug this guards: ``port = 0`` means "let the OS choose".

    Exporting from the *config* would write ``https://host:0/mcp`` while the
    endpoint listens on an OS-assigned port -- a registration for an endpoint
    that does not exist. Exporting from the live ``info()`` writes the port
    actually in use.
    """
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(port="0"))
    live_port = factory.last.assigned_port
    assert live_port != 0

    client.post("/network-mcp/export-registration", data={"confirm": "true"})

    zip_path = network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME
    with zipfile.ZipFile(zip_path) as zf:
        manifest = zf.read(MANIFEST_ARCNAME).decode("utf-8")
    assert f":{live_port}/mcp" in manifest
    assert ":0/mcp" not in manifest


def test_exporting_while_bound_to_loopback_warns_instead_of_writing(tmp_path):
    """The owner's actual report: a registration pointing at 127.0.0.1, silently."""
    factory = Factory(sans=("127.0.0.1",))
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="127.0.0.1"))

    resp = client.post("/network-mcp/export-registration")

    assert not (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).exists()
    assert "loopback interface" in resp.text
    assert "Export Anyway" in resp.text


def test_exporting_while_stopped_warns_instead_of_writing(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())
    client.post("/network-mcp/settings", data=_form(enabled=None))  # switch off

    resp = client.post("/network-mcp/export-registration")

    assert not (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).exists()
    assert "endpoint is not running" in resp.text.lower()


def test_export_anyway_writes_it_and_keeps_the_problems_on_screen(tmp_path):
    """Legitimate use: preparing the registration before bringing the endpoint up.

    The problems must still be visible afterwards -- an operator who confirms
    past a warning should not then see a clean success page implying it was
    fine after all.
    """
    factory = Factory(sans=("127.0.0.1",))
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form(bind_host_choice="127.0.0.1"))

    resp = client.post("/network-mcp/export-registration", data={"confirm": "true"})

    assert (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).is_file()
    assert "loopback interface" in resp.text
    assert "problems unresolved" in resp.text


def test_exporting_with_no_endpoint_at_all_says_so(tmp_path):
    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path)

    resp = client.post("/network-mcp/export-registration")

    assert resp.status_code == 200
    assert "no endpoint to export" in resp.text.lower()


def test_a_broken_info_during_export_is_reported_not_a_500(tmp_path):
    class _Broken:
        def info(self):
            msg = "state file corrupt"
            raise RuntimeError(msg)

    client = make_client(config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp=_Broken())

    resp = client.post("/network-mcp/export-registration")
    assert resp.status_code == 200
    assert "could not read" in resp.text.lower()


def test_the_export_never_carries_the_token(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())
    client.post("/network-mcp/export-registration")

    zip_path = network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME
    assert factory.last.token.encode() not in zip_path.read_bytes()


def test_the_zip_downloads_with_a_filename_the_browser_will_save(tmp_path):
    """The webview delivery path.

    Verified by hand against pywebview 4.4.1 on the WebView2 runtime: a
    ``Content-Disposition: attachment`` response is downloaded to the user's
    Downloads folder. This pins the response that mechanism depends on.
    """
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())
    client.post("/network-mcp/export-registration")

    resp = client.get("/network-mcp/registration.zip")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert REGISTRATION_ZIP_NAME in resp.headers["content-disposition"]
    assert "attachment" in resp.headers["content-disposition"]
    with zipfile.ZipFile(__import__("io").BytesIO(resp.content)) as zf:
        assert zf.namelist() == [MANIFEST_ARCNAME]


def test_downloading_before_any_export_says_so_rather_than_generating_one(tmp_path):
    """A GET must not create the certificate and token as a side effect."""
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())

    resp = client.get("/network-mcp/registration.zip")

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "No registration has been exported yet" in resp.text
    assert not (network_mcp_routes.export_dir() / REGISTRATION_ZIP_NAME).exists()


def test_the_page_no_longer_tells_the_owner_to_run_a_command(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())

    text = client.get("/network-mcp").text
    assert "Agent.exe export-registration" not in text
    assert "Export Registration" in text


# ---------------------------------------------------------------------------
# The show-once contract must survive all of the above
# ---------------------------------------------------------------------------


def test_saving_settings_does_not_re_reveal_an_already_shown_token(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    first = client.post("/network-mcp/settings", data=_form())
    token = factory.last.token
    assert token in first.text  # shown once, on the render that created it

    again = client.post("/network-mcp/settings", data=_form())
    assert token not in again.text
    assert token not in client.get("/network-mcp").text


def test_no_route_leaks_the_token_into_the_exported_page_after_it_was_shown(tmp_path):
    factory = Factory()
    client = make_client(
        config_store=FakeConfigStore(), tmp_path=tmp_path, network_mcp_factory=factory,
    )
    client.post("/network-mcp/settings", data=_form())
    token = factory.last.token

    assert token not in client.post("/network-mcp/export-registration").text
    assert token not in client.get("/network-mcp").text
