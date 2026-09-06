"""Tests: first-run wizard flow."""

from __future__ import annotations

from tests.unit.ui.conftest import FakeConfigStore, make_client


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


def test_root_redirects_to_dashboard_when_flag_present(tmp_path, monkeypatch):
    """GET / redirects to /dashboard when first_run_completed flag exists."""
    monkeypatch.setenv("PC_AGENT_APPDATA", str(tmp_path))
    (tmp_path / "first_run_completed").touch()

    client = make_client(tmp_path=tmp_path)
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in {302, 307}
    assert "/dashboard" in resp.headers["location"]
