"""
tests/unit/test_ai_analyst_unified.py — One credential drives both AI paths.

Before this, ANTHROPIC_API_KEY and the encrypted provider store were disjoint:
setting the env var left validation/investigations unconfigured, and configuring
a provider in the dashboard left the remediation API returning 503. These tests
pin the unified behaviour.
"""
from __future__ import annotations

import pytest

from manager.manager import ai_analyst as analyst_mod
from manager.manager.ai import key_store
from manager.manager.ai.base import AIResponse


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "ai_provider.enc"
    monkeypatch.setattr(key_store, "_STORE_PATH", path)
    monkeypatch.setattr(
        "manager.manager.ai.registry._TASK_MODELS_PATH", tmp_path / "task_models.json"
    )
    for var in ("JWT_SECRET", "ANTHROPIC_API_KEY", "AI_PROVIDER", "AI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("JWT_SECRET", "unit-test-secret")
    return path


class _StubDB:
    async def get_ai_analysis(self, finding_id):
        return None

    async def upsert_ai_analysis(self, finding_id, data):
        self.saved = data


def test_disabled_when_neither_credential_is_present(store):
    a = analyst_mod.AIAnalyst(_StubDB())
    assert a.enabled is False


def test_enabled_once_a_provider_is_configured_in_the_store(store):
    a = analyst_mod.AIAnalyst(_StubDB())
    assert a.enabled is False

    key_store.save_config("openrouter", "sk-or-x", "some/model:free")

    # No restart, no re-instantiation — the property re-reads the store.
    assert a.enabled is True


def test_env_key_still_enables_the_legacy_path(store, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-legacy")
    a = analyst_mod.AIAnalyst(_StubDB())
    # The anthropic SDK may not be installed in CI; enabled is driven by the
    # client when it is, and by the store when it is not.
    if a._client is not None:
        assert a.enabled is True


def test_ai_analyst_enabled_respects_the_global_kill_switch(store, monkeypatch):
    key_store.save_config("openrouter", "sk-or-x", "m")
    monkeypatch.setattr(analyst_mod, "_ENABLED", False)

    a = analyst_mod.AIAnalyst(_StubDB())
    assert a.enabled is False


@pytest.mark.asyncio
async def test_call_routes_through_the_configured_provider(store, monkeypatch):
    key_store.save_config("openrouter", "sk-or-x", "deepseek/deepseek-chat-v3-0324:free")

    class _FakeProvider:
        async def chat(self, prompt, *, max_tokens=1500):
            return AIResponse(
                text='{"analysis": "ok", "confidence": 0.9}',
                model="deepseek/deepseek-chat-v3-0324:free",
                provider="openrouter",
                input_tokens=10,
                output_tokens=5,
            )

    a = analyst_mod.AIAnalyst(_StubDB())
    monkeypatch.setattr(a, "_store_provider", lambda: _FakeProvider())

    result = await a._call_claude("prompt", max_tokens=100)

    assert result["tokens_used"] == 15
    # The model reported back is the one that actually served the call, not the
    # AI_ANALYST_MODEL default.
    assert result["model"] == "deepseek/deepseek-chat-v3-0324:free"


@pytest.mark.asyncio
async def test_call_raises_actionable_error_when_unconfigured(store):
    a = analyst_mod.AIAnalyst(_StubDB())

    with pytest.raises(RuntimeError, match="Settings -> AI Provider"):
        await a._call_claude("prompt")


@pytest.mark.asyncio
async def test_analysis_records_the_model_that_served_it(store, monkeypatch):
    key_store.save_config("openrouter", "sk-or-x", "qwen/qwen-2.5-72b-instruct:free")

    class _FakeProvider:
        async def chat(self, prompt, *, max_tokens=1500):
            return AIResponse(
                text='{"analysis": "a", "threat_context": "t", "confidence": 0.8}',
                model="qwen/qwen-2.5-72b-instruct:free",
                provider="openrouter",
            )

    db = _StubDB()
    a = analyst_mod.AIAnalyst(db)
    monkeypatch.setattr(a, "_store_provider", lambda: _FakeProvider())
    monkeypatch.setattr(a, "_build_context", _noop_context)

    data = await a.analyze_finding(1, {"title": "x"})

    assert data is not None
    assert data["model"] == "qwen/qwen-2.5-72b-instruct:free"


async def _noop_context(finding):
    return {"ioc_matches": [], "news_items": [], "actors": []}
