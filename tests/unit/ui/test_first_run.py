"""Tests: first-run wizard flow."""

from __future__ import annotations

from typing import Self

from tests.unit.ui.conftest import FakeConfigStore, make_client
from workstation_agent.ui.backend.routers import first_run as first_run_module


def test_first_run_page_renders(tmp_path):
    """GET /first-run returns 200 with step 1 form."""
    client = make_client(tmp_path=tmp_path)
    resp = client.get("/first-run")
    assert resp.status_code == 200
    assert "First Run Wizard" in resp.text
    assert "Step 1" in resp.text


def test_first_run_llm_step_saves_config(tmp_path):
    """POST /first-run/llm saves LLM settings (host+port -> base_url) to store."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/first-run/llm",
        data={
            "llm_host": "example.com",
            "llm_port": "8053",
            "model": "my-model",
            "api_key_ref": "my-key",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert store._cfg.llm.model == "my-model"
    assert store._cfg.llm.api_key_ref == "my-key"
    # Backend assembled http://example.com:8053/v1 automatically.
    assert "example.com" in str(store._cfg.llm.base_url)
    assert "8053" in str(store._cfg.llm.base_url)
    assert str(store._cfg.llm.base_url).rstrip("/").endswith("/v1")


def test_first_run_llm_empty_model_shows_error(tmp_path):
    """POST /first-run/llm with empty model re-renders with error."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/first-run/llm",
        data={"llm_host": "example.com", "llm_port": "8053", "model": "  ", "api_key_ref": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "error" in resp.text.lower() or "required" in resp.text.lower()


def test_first_run_llm_accepts_full_url_pasted_into_host(tmp_path):
    """A user who pastes 'http://x.y:9000/v1' into Host still gets it parsed."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/first-run/llm",
        data={
            "llm_host": "http://api.example.com:9000/v1",
            "llm_port": "8053",   # ignored — port from the URL wins
            "model": "prose",
            "api_key_ref": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "api.example.com" in str(store._cfg.llm.base_url)
    assert "9000" in str(store._cfg.llm.base_url)


def test_first_run_wyoming_step_saves_config(tmp_path):
    """POST /first-run/wyoming saves Wyoming settings."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/first-run/wyoming",
        data={"wyoming_host": "10.0.0.1", "wyoming_port": "10400"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert store._cfg.wyoming.host == "10.0.0.1"
    assert store._cfg.wyoming.port == 10400


def test_first_run_wyoming_invalid_port(tmp_path):
    """POST /first-run/wyoming with port=0 shows validation error."""
    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post(
        "/first-run/wyoming",
        data={"wyoming_host": "10.0.0.1", "wyoming_port": "0"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "Port" in resp.text


def test_first_run_complete_writes_flag(tmp_path, monkeypatch):
    """POST /first-run/complete marks completion and redirects."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))

    store = FakeConfigStore()
    client = make_client(config_store=store, tmp_path=tmp_path)

    resp = client.post("/first-run/complete", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"
    assert (tmp_path / "first_run_completed").exists()


def test_root_redirects_to_first_run_when_flag_absent(tmp_path, monkeypatch):
    """GET / redirects to /first-run when first_run_completed flag is absent."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))
    client = make_client(tmp_path=tmp_path)

    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in {302, 307}
    assert "/first-run" in resp.headers["location"]


class _FakeResponse:
    """Minimal stand-in for an httpx.Response, status code + json() only."""

    def __init__(self, status_code) -> None:
        self.status_code = status_code

    def json(self):
        return {"data": []}


def _install_fake_llm_response(monkeypatch, status_code):
    """Patch httpx.AsyncClient in the first_run module to return status_code."""

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info) -> bool:
            return False

        async def get(self, url, headers=None):  # noqa: ARG002
            return _FakeResponse(status_code)

    monkeypatch.setattr(first_run_module.httpx, "AsyncClient", _FakeAsyncClient)


def test_detect_models_wrong_key_names_the_credential(tmp_path, monkeypatch):
    """A 401 WITH a key supplied says the API key was rejected, not just 'HTTP 401'."""
    client = make_client(tmp_path=tmp_path)
    _install_fake_llm_response(monkeypatch, 401)

    resp = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053", "api_key": "sk-wrong"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["models"] == []
    assert "API key" in data["error"]
    assert "sk-wrong" not in data["error"]


def test_detect_models_missing_key_names_the_credential(tmp_path, monkeypatch):
    """A 401 with NO key supplied says a key is required and the field is empty."""
    client = make_client(tmp_path=tmp_path)
    _install_fake_llm_response(monkeypatch, 401)

    resp = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["models"] == []
    assert "API key" in data["error"]
    assert "empty" in data["error"].lower()


def test_detect_models_wrong_key_and_missing_key_messages_differ(tmp_path, monkeypatch):
    """The two 401 cases must not share a message -- different operator actions."""
    client = make_client(tmp_path=tmp_path)
    _install_fake_llm_response(monkeypatch, 401)

    with_key = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053", "api_key": "sk-wrong"},
    ).json()["error"]
    without_key = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053"},
    ).json()["error"]
    assert with_key != without_key


def test_detect_models_403_does_not_assert_the_key_is_wrong(tmp_path, monkeypatch):
    """A 403 is ambiguous -- it must not claim the key was rejected outright.

    Consistent with workstation_agent.llm.client's LLMAccessDeniedError: a
    403 can also mean a WAF/IP/geo block, a quota limit, or a valid key
    without permission for the model, so this must not tell the operator
    to replace the key with the same confidence a 401 does.
    """
    client = make_client(tmp_path=tmp_path)
    _install_fake_llm_response(monkeypatch, 403)

    resp = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053", "api_key": "sk-maybe"},
    )
    data = resp.json()
    assert data["models"] == []
    assert "not necessarily" in data["error"].lower() or "does not" in data["error"].lower()
    assert "was rejected" not in data["error"]
    assert "sk-maybe" not in data["error"]


def test_detect_models_401_and_403_with_key_have_different_confidence(tmp_path, monkeypatch):
    """401 (unambiguous) and 403 (ambiguous) must not share the same wording."""
    client = make_client(tmp_path=tmp_path)

    _install_fake_llm_response(monkeypatch, 401)
    msg_401 = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053", "api_key": "sk-x"},
    ).json()["error"]

    _install_fake_llm_response(monkeypatch, 403)
    msg_403 = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053", "api_key": "sk-x"},
    ).json()["error"]

    assert msg_401 != msg_403


def test_detect_models_other_error_keeps_status_code(tmp_path, monkeypatch):
    """A non-auth error (e.g. 500) stays informative -- the code is kept visible."""
    client = make_client(tmp_path=tmp_path)
    _install_fake_llm_response(monkeypatch, 500)

    resp = client.get(
        "/first-run/detect-models",
        params={"host": "example.com", "port": "8053"},
    )
    data = resp.json()
    assert data["models"] == []
    assert "500" in data["error"]


def test_root_redirects_to_dashboard_when_flag_present(tmp_path, monkeypatch):
    """GET / redirects to /dashboard when first_run_completed flag exists."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))
    (tmp_path / "first_run_completed").touch()

    client = make_client(tmp_path=tmp_path)
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in {302, 307}
    assert "/dashboard" in resp.headers["location"]
