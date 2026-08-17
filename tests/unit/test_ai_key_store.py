"""
tests/unit/test_ai_key_store.py — Encrypted AI provider store.

Covers the three properties the store has to hold in production:
  • the API key is never readable by anyone but the owner (0600),
  • a JWT_SECRET change is reported as exactly that, not as "not configured",
  • AI_* env vars seed the store once and never override a rotated key.
"""
from __future__ import annotations

import json
import stat

import pytest

from manager.manager.ai import key_store


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the store at a temp dir and clear all AI_* env influence."""
    path = tmp_path / "ai_provider.enc"
    monkeypatch.setattr(key_store, "_STORE_PATH", path)
    for var in ("JWT_SECRET", "AI_PROVIDER", "AI_MODEL", "AI_API_KEY", "AI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    return path


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ── Round trip ────────────────────────────────────────────────────────────────

def test_save_then_load_returns_the_same_key(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-master-secret")

    key_store.save_config("openrouter", "sk-or-secret-value", "some/model:free")
    loaded = key_store.load_config()

    assert loaded is not None
    assert loaded.provider == "openrouter"
    assert loaded.model == "some/model:free"
    assert loaded.api_key == "sk-or-secret-value"


def test_plaintext_key_is_never_written_to_disk(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-master-secret")

    key_store.save_config("openrouter", "sk-or-secret-value", "some/model:free")

    assert "sk-or-secret-value" not in store.read_text()


def test_model_falls_back_to_provider_default(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-master-secret")

    saved = key_store.save_config("openrouter", "sk-or-x", "")

    assert saved.model == key_store.DEFAULT_MODELS["openrouter"]


# ── File permissions ──────────────────────────────────────────────────────────

def test_store_is_owner_only(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-master-secret")

    key_store.save_config("openrouter", "sk-or-x", "m")

    assert _mode(store) == 0o600


def test_fallback_master_key_file_is_owner_only(store):
    # No JWT_SECRET — the store falls back to a random key file beside itself.
    key_store.save_config("openrouter", "sk-or-x", "m")

    fallback = store.parent / ".ai_enc_key"
    assert fallback.exists()
    assert _mode(fallback) == 0o600


def test_existing_world_readable_store_is_tightened_on_save(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-master-secret")
    store.write_text("{}")
    store.chmod(0o644)

    key_store.save_config("openrouter", "sk-or-x", "m")

    assert _mode(store) == 0o600


# ── JWT_SECRET rotation ───────────────────────────────────────────────────────

def test_rotating_jwt_secret_is_reported_not_silently_dropped(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "original-secret")
    key_store.save_config("openrouter", "sk-or-x", "m")

    monkeypatch.setenv("JWT_SECRET", "a-different-secret")

    # load_config degrades to None so callers behave, but the reason is explicit.
    assert key_store.load_config() is None
    summary = key_store.config_summary()
    assert summary is not None
    assert summary["key_usable"] is False
    assert summary["key_preview"] == "(unreadable)"


def test_matching_master_reports_key_usable(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "original-secret")
    key_store.save_config("openrouter", "sk-or-abcdefghijkl", "m")

    summary = key_store.config_summary()

    assert summary["key_usable"] is True
    assert summary["key_source"] == "jwt_secret"
    assert "sk-or-" in summary["key_preview"]


def test_check_master_raises_with_actionable_message(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "original-secret")
    key_store.save_config("openrouter", "sk-or-x", "m")
    data = json.loads(store.read_text())

    monkeypatch.setenv("JWT_SECRET", "rotated-secret")

    with pytest.raises(key_store.MasterKeyMismatch, match="Settings -> AI Provider"):
        key_store._check_master(data)


def test_config_written_before_fingerprints_existed_still_loads(store, monkeypatch):
    """Backward compatibility — pre-existing stores have no master_fp."""
    monkeypatch.setenv("JWT_SECRET", "stable-secret")
    key_store.save_config("openrouter", "sk-or-legacy", "m")

    data = json.loads(store.read_text())
    del data["master_fp"]
    store.write_text(json.dumps(data))

    loaded = key_store.load_config()
    assert loaded is not None
    assert loaded.api_key == "sk-or-legacy"


# ── Environment bootstrap ─────────────────────────────────────────────────────

def test_bootstrap_seeds_an_unconfigured_store(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    monkeypatch.setenv("AI_PROVIDER", "openrouter")
    monkeypatch.setenv("AI_API_KEY", "sk-or-from-env")
    monkeypatch.setenv("AI_MODEL", "deepseek/deepseek-chat-v3-0324:free")

    cfg = key_store.bootstrap_from_env()

    assert cfg is not None
    assert cfg.provider == "openrouter"
    assert key_store.load_config().api_key == "sk-or-from-env"
    assert _mode(store) == 0o600


def test_bootstrap_never_overrides_an_existing_config(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    key_store.save_config("openrouter", "sk-or-rotated-via-api", "m")

    monkeypatch.setenv("AI_PROVIDER", "openrouter")
    monkeypatch.setenv("AI_API_KEY", "sk-or-stale-env-value")

    assert key_store.bootstrap_from_env() is None
    assert key_store.load_config().api_key == "sk-or-rotated-via-api"


def test_bootstrap_noops_without_a_key(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    monkeypatch.setenv("AI_PROVIDER", "openrouter")
    monkeypatch.setenv("AI_API_KEY", "")

    assert key_store.bootstrap_from_env() is None
    assert not store.exists()


def test_bootstrap_noops_when_provider_unset(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    monkeypatch.setenv("AI_API_KEY", "sk-or-orphan")

    assert key_store.bootstrap_from_env() is None
    assert not store.exists()


def test_bootstrap_rejects_unknown_provider(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    monkeypatch.setenv("AI_PROVIDER", "not-a-real-provider")
    monkeypatch.setenv("AI_API_KEY", "sk-x")

    assert key_store.bootstrap_from_env() is None
    assert not store.exists()


def test_bootstrap_allows_ollama_without_a_key(store, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "s")
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("AI_API_KEY", "")

    cfg = key_store.bootstrap_from_env()

    assert cfg is not None
    assert cfg.provider == "ollama"
    assert cfg.model == key_store.DEFAULT_MODELS["ollama"]
