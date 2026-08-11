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


def _run(coro):
    return asyncio.run(coro)


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
    assert "X-Title" in captured_headers


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


def test_openrouter_error_response_raises():
    provider = _make_provider()

    async def mock_request_json(method, url, *, headers=None, json_body=None):
        return {"error": {"code": 429, "message": "Rate limit exceeded"}}

    provider._http = MagicMock()
    provider._http.request_json = mock_request_json

    with pytest.raises(RuntimeError, match="Rate limit exceeded"):
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
