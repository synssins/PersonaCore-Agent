"""Tests for config.store — load, save, atomic writes, secret round-trips."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from workstation_agent.config import store
from workstation_agent.config.schema import AgentConfig, default


@pytest.fixture
def tmp_appdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point PC_AGENT_APPDATA at a temp dir for test isolation."""
    appdata = tmp_path / "WorkstationAgent"
    appdata.mkdir()
    monkeypatch.setenv("PC_AGENT_APPDATA", str(appdata))
    return appdata


@pytest.fixture
def patched_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch store to use the fake DPAPI via monkeypatching the module."""
    import workstation_agent.security.dpapi as _dpapi_mod
    from tests.fakes import fake_dpapi as _fake

    monkeypatch.setattr(_dpapi_mod, "protect", _fake.protect)
    monkeypatch.setattr(_dpapi_mod, "unprotect", _fake.unprotect)


def test_paths_returns_expected_keys(tmp_appdata: Path) -> None:
    """paths() returns all expected path keys."""
    _ = tmp_appdata
    p = store.paths()
    for key in (
        "config_file",
        "secrets_dir",
        "plugins_dir",
        "audit_db",
        "conversations_db",
        "logs_dir",
    ):
        assert key in p
        assert isinstance(p[key], Path)


def test_load_creates_default_when_missing(tmp_appdata: Path) -> None:
    """load() writes a default config and returns it when file is absent."""
    cfg = store.load()
    assert isinstance(cfg, AgentConfig)
    assert (tmp_appdata / "config.toml").exists()


def test_load_returns_saved_values(tmp_appdata: Path) -> None:
    """load() returns previously saved values."""
    _ = tmp_appdata
    cfg = default()
    cfg.wyoming.port = 12345
    store.save(cfg)

    loaded = store.load()
    assert loaded.wyoming.port == 12345


def test_save_preserves_comments(tmp_appdata: Path) -> None:
    """save() preserves existing TOML comments on round-trip."""
    cfg_path = tmp_appdata / "config.toml"

    manual_toml = textwrap.dedent("""\
        # Top-level comment
        [wyoming]
        # Wyoming host comment
        host = "192.168.1.150"
        port = 10300
        tts_voice = "en-us-amy-low"
        asr_model = "tiny-int8"
    """)
    cfg_path.write_text(manual_toml, encoding="utf-8")

    cfg = store.load()
    store.save(cfg)

    result = cfg_path.read_text(encoding="utf-8")
    assert "# Top-level comment" in result
    assert "# Wyoming host comment" in result


def test_save_atomic_no_tmp_on_failure(tmp_appdata: Path) -> None:
    """If Path.replace fails, the final config.toml is not corrupted."""
    cfg_path = tmp_appdata / "config.toml"
    cfg = default()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    with patch("pathlib.Path.replace", side_effect=OSError("disk full")), pytest.raises(
        OSError, match="disk full",
    ):
        store.save(cfg)

    assert not cfg_path.exists()


def test_secret_round_trip(tmp_appdata: Path, patched_store: None) -> None:
    """save_secret + load_secret returns original plaintext (fake DPAPI)."""
    _ = tmp_appdata
    _ = patched_store
    store.save_secret("my_api_key", b"top-secret-value")
    result = store.load_secret("my_api_key")
    assert result == b"top-secret-value"


def test_load_secret_missing_raises_key_error(tmp_appdata: Path, patched_store: None) -> None:
    """load_secret raises KeyError for unknown names."""
    _ = tmp_appdata
    _ = patched_store
    with pytest.raises(KeyError):
        store.load_secret("nonexistent")


def test_delete_secret(tmp_appdata: Path, patched_store: None) -> None:
    """delete_secret removes the file; subsequent load_secret raises KeyError."""
    _ = tmp_appdata
    _ = patched_store
    store.save_secret("to_delete", b"bye")
    store.delete_secret("to_delete")
    with pytest.raises(KeyError):
        store.load_secret("to_delete")


def test_delete_secret_nonexistent_is_noop(tmp_appdata: Path) -> None:
    """delete_secret on missing name silently succeeds."""
    _ = tmp_appdata
    store.delete_secret("never_existed")


def test_secret_file_is_created(tmp_appdata: Path, patched_store: None) -> None:
    """save_secret creates the .dpapi file in secrets/."""
    _ = patched_store
    store.save_secret("test_key", b"value")
    dest = tmp_appdata / "secrets" / "test_key.dpapi"
    assert dest.exists()


def test_save_secret_hardens_tmp_before_writing_content(
    tmp_appdata: Path,  # noqa: ARG001
    patched_store: None,
) -> None:
    """harden_file is called on the tmp file BEFORE the blob is written into it.

    This verifies the TOCTOU fix: the temp file's ACL is locked down while it
    is still empty, so a Low-IL process can never observe the plaintext/blob
    through the default-ACL window.
    """
    _ = patched_store
    call_log: list[str] = []

    real_harden = store.harden_file

    def fake_harden(path: Path) -> None:
        call_log.append(f"harden:{path.name}")
        real_harden(path)

    original_write_bytes = Path.write_bytes

    def fake_write_bytes(self: Path, data: bytes) -> int:
        if data:  # only log the non-empty write (the actual blob write)
            call_log.append(f"write_bytes:{self.name}")
        return original_write_bytes(self, data)

    with (
        patch.object(store, "harden_file", side_effect=fake_harden),
        patch.object(Path, "write_bytes", fake_write_bytes),
    ):
        store.save_secret("ordering_test", b"secret-payload")

    # The tmp ACL harden must appear before the blob write_bytes call
    tmp_harden_idx = next(
        i for i, e in enumerate(call_log) if e.startswith("harden:") and ".tmp" in e
    )
    blob_write_idx = next(i for i, e in enumerate(call_log) if e.startswith("write_bytes:"))
    assert tmp_harden_idx < blob_write_idx, (
        f"harden_file(tmp) must be called before write_bytes(blob); log={call_log}"
    )
