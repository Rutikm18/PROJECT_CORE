"""
tests/unit/test_openrouter_provider.py

Tests for:
  - OpenRouterProvider: correct headers, base URL, error handling
  - PROVIDER_MODELS / DEFAULT_MODELS include openrouter
  - build_provider resolves openrouter
  - Per-task model API helpers (load/save)
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from manager.manager.ai.base import PROVIDER_MODELS, DEFAULT_MODELS, ProviderConfig
from manager.manager.ai.providers import OpenRouterProvider, build_provider
from manager.manager.integrations.resilience import (
    PermanentError,
    RateLimitedError,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _allow_free_models(monkeypatch):
    """These tests drive a ':free' model to exercise transport mechanics.

    Free tiers train on submitted prompts, so provider calls to one are refused
    unless the operator opts in (see the privacy gate in providers.py). That
    policy is covered by test_ai_catalog_and_safety.py; here it is orthogonal
    noise, so opt in for the whole module.
    """
    monkeypatch.setenv("ATTACKLENS_AI_ALLOW_TRAINING_MODELS", "true")


# ── OpenRouter registered ─────────────────────────────────────────────────────

def test_openrouter_in_provider_models():
    assert "openrouter" in PROVIDER_MODELS
    models = PROVIDER_MODELS["openrouter"]
    assert any(":free" in m for m in models), "Expected at least one free model"


def test_openrouter_has_default_model():
    assert "openrouter" in DEFAULT_MODELS
    default = DEFAULT_MODELS["openrouter"]
    assert default in PROVIDER_MODELS["openrouter"]


def test_openrouter_default_is_free():
    default = DEFAULT_MODELS["openrouter"]
    assert ":free" in default, f"Default openrouter model should be free: {default}"


def test_codex_in_openai_models():
    assert any("codex" in m for m in PROVIDER_MODELS["openai"])


def test_codex_in_openrouter_models():
    assert any("codex" in m for m in PROVIDER_MODELS["openrouter"])


# ── build_provider ────────────────────────────────────────────────────────────

def test_build_provider_openrouter():
    cfg = ProviderConfig(
        provider="openrouter",
        api_key="sk-or-test",
        model="meta-llama/llama-3.3-70b-instruct:free",
    )
    provider = build_provider(cfg)
    assert isinstance(provider, OpenRouterProvider)


def test_build_provider_unknown_raises():
    cfg = ProviderConfig(provider="unknown-provider", api_key="x", model="y")
    with pytest.raises(ValueError, match="Unknown provider"):
        build_provider(cfg)


# ── OpenRouterProvider.chat (mocked HTTP) ────────────────────────────────────

def _make_provider(model: str = "meta-llama/llama-3.3-70b-instruct:free") -> OpenRouterProvider:
    from manager.manager.ai.providers import _openrouter_usage_guard
    _openrouter_usage_guard.reset()
    cfg = ProviderConfig(
        provider="openrouter",
        api_key="sk-or-test-key",
        model=model,
    )
    return OpenRouterProvider(cfg)


def _mock_response(content: str, prompt_tokens: int = 10, completion_tokens: int = 5) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
    }


def test_openrouter_chat_sends_correct_headers():
    provider = _make_provider()
    captured_headers = {}

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        captured_headers.update(headers or {})
        return _mock_response('{"status":"ok"}')

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    _run(provider.chat("test prompt", max_tokens=20))

    assert "Authorization" in captured_headers
    assert captured_headers["Authorization"] == "Bearer sk-or-test-key"
    assert "HTTP-Referer" in captured_headers
    assert captured_headers["X-OpenRouter-Title"] == "AttackLens"
    assert captured_headers["X-OpenRouter-Metadata"] == "true"


def test_openrouter_chat_uses_correct_base_url():
    provider = _make_provider()
    captured_urls = []

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        captured_urls.append(url)
        return _mock_response('{"status":"ok"}')

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    _run(provider.chat("test prompt"))

    assert len(captured_urls) == 1
    assert "openrouter.ai" in captured_urls[0]
    assert "/chat/completions" in captured_urls[0]


def test_openrouter_chat_returns_correct_provider_name():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return _mock_response('{"verdict":"tp"}', prompt_tokens=15, completion_tokens=8)

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    resp = _run(provider.chat("analyze this"))
    assert resp.provider == "openrouter"
    assert resp.text == '{"verdict":"tp"}'
    assert resp.input_tokens == 15
    assert resp.output_tokens == 8
    assert resp.total_tokens == 23


def test_openrouter_structured_chat_enforces_validation_privacy_and_schema():
    # Deliberately a PAID model. data_collection=deny and zdr=true cannot be
    # satisfied by a free tier, so combining them with allow_fallbacks=False
    # leaves OpenRouter zero eligible providers and the call fails outright.
    # The free-model path is covered by the companion test below.
    provider = _make_provider("openai/gpt-4o-mini")
    captured_payload = {}

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        captured_payload.update(json_body or {})
        return _mock_response('{"verdict":"uncertain"}')

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
        "additionalProperties": False,
    }

    _run(provider.chat_structured("validate", schema=schema, max_tokens=30))

    assert captured_payload["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "attacklens_validation",
            "strict": True,
            "schema": schema,
        },
    }
    assert captured_payload["provider"] == {
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
        "allow_fallbacks": False,
    }


def test_openrouter_chat_captures_actual_route_and_generation_metadata():
    provider = _make_provider("requested/model")

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {
            "id": "gen-1",
            "model": "actual/model",
            "provider": "Together",
            "choices": [{
                "message": {"content": '{"verdict":"tp"}'},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": 15,
                "completion_tokens": 8,
                "cost": 0.0012,
            },
        }

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    resp = _run(provider.chat("analyze this"))

    assert resp.model == "actual/model"
    assert resp.generation_id == "gen-1"
    assert resp.upstream_provider == "Together"
    assert resp.finish_reason == "stop"
    assert resp.cost_usd == pytest.approx(0.0012)


def test_openrouter_error_response_raises():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {"error": {"code": 429, "message": "Rate limit exceeded"}}

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    with pytest.raises(RateLimitedError, match="Rate limit exceeded"):
        _run(provider.chat("prompt"))


def test_openrouter_body_rate_limit_is_typed():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {"error": {"code": 429, "message": "Rate limit exceeded"}}

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    with pytest.raises(RateLimitedError):
        _run(provider.chat("prompt"))


def test_openrouter_stable_error_type_is_preserved():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {"error": {
            "code": 503,
            "message": "No providers available",
            "metadata": {"error_type": "no_available_provider"},
        }}

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    from manager.manager.integrations.resilience import TransientError
    with pytest.raises(TransientError) as exc:
        _run(provider.chat("prompt"))
    assert exc.value.error_type == "no_available_provider"


def test_openrouter_kill_switch_blocks_before_transport(monkeypatch):
    provider = _make_provider()
    provider._http = MagicMock()
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_ENABLED", "false")

    with pytest.raises(PermanentError) as exc:
        _run(provider.chat("prompt"))

    assert exc.value.error_type == "kill_switch"
    provider._http.request_json.assert_not_called()


def test_openrouter_local_rate_budget_is_typed(monkeypatch):
    provider = _make_provider()
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "1")

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return _mock_response('{"status":"ok"}')

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json
    _run(provider.chat("first"))
    with pytest.raises(RateLimitedError) as exc:
        _run(provider.chat("second"))
    assert exc.value.error_type == "local_rate_budget"


def test_openrouter_malformed_success_is_permanent_error():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {"id": "gen-empty", "choices": []}

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    with pytest.raises(PermanentError, match="missing a non-empty choice"):
        _run(provider.chat("prompt"))


def test_openrouter_health_check_ok():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return _mock_response('{"status": "ok"}', prompt_tokens=5, completion_tokens=3)

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    ok, msg = _run(provider.health_check())
    assert ok is True
    assert "OpenRouter" in msg


def test_openrouter_health_check_error_returns_false():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        raise ConnectionError("Network unreachable")

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    ok, msg = _run(provider.health_check())
    assert ok is False
    assert "unreachable" in msg.lower() or "Network" in msg


# ── Per-task model config helpers ─────────────────────────────────────────────

def test_task_models_load_save_roundtrip(tmp_path, monkeypatch):
    import manager.manager.api.ai_settings as ai_settings_mod

    task_file = tmp_path / "ai_task_models.json"
    monkeypatch.setattr(ai_settings_mod, "_TASK_MODELS_PATH", task_file)

    # Initially empty
    result = ai_settings_mod._load_task_models()
    assert result == {}

    # Save a task model
    ai_settings_mod._save_task_models({
        "validation": {"provider": "openrouter", "model": "meta-llama/llama-3.3-70b-instruct:free"}
    })

    loaded = ai_settings_mod._load_task_models()
    assert loaded["validation"]["provider"] == "openrouter"
    assert ":free" in loaded["validation"]["model"]


def test_task_models_missing_file_returns_empty(tmp_path, monkeypatch):
    import manager.manager.api.ai_settings as ai_settings_mod

    monkeypatch.setattr(ai_settings_mod, "_TASK_MODELS_PATH", tmp_path / "nonexistent.json")
    result = ai_settings_mod._load_task_models()
    assert result == {}


def test_task_model_rejects_provider_without_matching_saved_credential(
    tmp_path, monkeypatch,
):
    from fastapi import HTTPException
    import manager.manager.api.ai_settings as ai_settings_mod

    monkeypatch.setattr(
        ai_settings_mod,
        "load_config",
        lambda: ProviderConfig(
            provider="openrouter", api_key="sk-or-secret", model="model-a",
        ),
    )
    monkeypatch.setattr(ai_settings_mod, "_TASK_MODELS_PATH", tmp_path / "tasks.json")
    body = ai_settings_mod.TaskModelRequest(
        task="validation",
        provider="anthropic",
        model=PROVIDER_MODELS["anthropic"][0],
    )

    with pytest.raises(HTTPException) as exc:
        _run(ai_settings_mod.set_task_model(body))

    assert exc.value.status_code == 422
    assert "credential" in str(exc.value.detail).lower()
