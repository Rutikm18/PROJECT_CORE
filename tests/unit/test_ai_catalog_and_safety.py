"""
tests/unit/test_ai_catalog_and_safety.py — Live model catalog + free-model gates.

Two failure modes are pinned here:

  • Strict json_schema sent to a model that cannot do structured output. With
    require_parameters=True and allow_fallbacks=False, OpenRouter finds zero
    eligible providers and the call fails outright. Most free models qualify.

  • Endpoint telemetry sent to a free tier that trains on prompts.
"""
from __future__ import annotations

import json

import pytest

from manager.manager.ai import catalog


SAMPLE = {
    "data": [
        {
            "id": "deepseek/deepseek-chat-v3-0324:free",
            "name": "DeepSeek V3 (free)",
            "context_length": 64000,
            "pricing": {"prompt": "0", "completion": "0"},
            "supported_parameters": ["max_tokens", "temperature"],
        },
        {
            "id": "openai/gpt-4o-mini",
            "name": "GPT-4o Mini",
            "context_length": 128000,
            "pricing": {"prompt": "0.00000015", "completion": "0.0000006"},
            "supported_parameters": ["max_tokens", "structured_outputs", "response_format"],
        },
        {
            "id": "anthropic/claude-sonnet-4.5",
            "name": "Claude Sonnet 4.5",
            "context_length": 200000,
            "pricing": {"prompt": "0.000003", "completion": "0.000015"},
            "supported_parameters": ["max_tokens", "structured_outputs"],
        },
    ]
}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    path = tmp_path / "ai_models_cache.json"
    monkeypatch.setattr(catalog, "_CACHE_PATH", path)
    catalog.invalidate_memo()
    yield path
    catalog.invalidate_memo()


def _seed(path):
    payload = dict(SAMPLE)
    payload["fetched_at"] = 9e9   # far future so it never looks stale
    path.write_text(json.dumps(payload))
    catalog.invalidate_memo()


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_free_model_detected_from_zero_pricing(cache):
    _seed(cache)
    assert catalog.is_free_model("deepseek/deepseek-chat-v3-0324:free") is True


def test_paid_model_not_reported_free(cache):
    _seed(cache)
    assert catalog.is_free_model("openai/gpt-4o-mini") is False


def test_structured_output_support_read_from_parameters(cache):
    _seed(cache)
    assert catalog.supports_structured_output("openai/gpt-4o-mini") is True
    assert catalog.supports_structured_output("deepseek/deepseek-chat-v3-0324:free") is False


def test_unknown_model_returns_none_not_false(cache):
    """Unknown must stay distinct from 'known not to support'."""
    _seed(cache)
    assert catalog.supports_structured_output("some/unlisted-model") is None


def test_free_heuristic_used_when_catalog_is_cold(cache):
    # No cache written at all.
    assert catalog.is_free_model("whatever/model:free") is True
    assert catalog.is_free_model("whatever/model") is False


def test_price_note_converts_to_per_million_tokens(cache):
    _seed(cache)
    note = catalog.get("openai/gpt-4o-mini").price_note()
    assert "$0.15/M in" in note
    assert "$0.60/M out" in note


def test_corrupt_cache_degrades_instead_of_raising(cache):
    cache.write_text("{not json")
    catalog.invalidate_memo()
    assert catalog.cached_models() == {}


@pytest.mark.asyncio
async def test_refresh_returns_cached_data_when_fetch_fails(cache, monkeypatch):
    _seed(cache)
    monkeypatch.setattr(catalog, "_CACHE_TTL_S", -1)   # force it to try fetching

    async def _boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(catalog, "_parse", catalog._parse)
    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", _boom)

    models = await catalog.refresh()
    assert "openai/gpt-4o-mini" in models


# ── Free-model privacy + capability gates ─────────────────────────────────────

def _provider(model_id):
    from manager.manager.ai.base import ProviderConfig
    from manager.manager.ai.providers import OpenRouterProvider
    return OpenRouterProvider(
        ProviderConfig(provider="openrouter", api_key="sk-or-x", model=model_id)
    )


@pytest.mark.asyncio
async def test_free_model_refused_without_explicit_optin(cache, monkeypatch):
    from manager.manager.integrations.resilience import PermanentError

    _seed(cache)
    monkeypatch.delenv("ATTACKLENS_AI_ALLOW_TRAINING_MODELS", raising=False)
    monkeypatch.setattr(
        "manager.manager.ai.providers._openrouter_usage_guard.check", lambda: None
    )

    p = _provider("deepseek/deepseek-chat-v3-0324:free")
    with pytest.raises(PermanentError, match="ATTACKLENS_AI_ALLOW_TRAINING_MODELS"):
        await p.chat("hello")


@pytest.mark.asyncio
async def test_paid_model_needs_no_optin(cache, monkeypatch):
    _seed(cache)
    monkeypatch.delenv("ATTACKLENS_AI_ALLOW_TRAINING_MODELS", raising=False)
    captured = await _capture_payload(monkeypatch, "openai/gpt-4o-mini", schema=None)
    assert captured["model"] == "openai/gpt-4o-mini"


@pytest.mark.asyncio
async def test_schema_omitted_for_model_without_structured_output(cache, monkeypatch):
    _seed(cache)
    monkeypatch.setenv("ATTACKLENS_AI_ALLOW_TRAINING_MODELS", "true")

    captured = await _capture_payload(
        monkeypatch, "deepseek/deepseek-chat-v3-0324:free", schema={"type": "object"}
    )
    # Sending response_format here would make OpenRouter route to zero providers.
    assert "response_format" not in captured
    assert "provider" not in captured


@pytest.mark.asyncio
async def test_schema_sent_for_capable_model(cache, monkeypatch):
    _seed(cache)
    captured = await _capture_payload(
        monkeypatch, "openai/gpt-4o-mini", schema={"type": "object"}
    )
    assert captured["response_format"]["type"] == "json_schema"
    assert captured["provider"]["require_parameters"] is True
    # Paid model: the privacy preferences are satisfiable, so they are sent.
    assert captured["provider"]["data_collection"] == "deny"
    assert captured["provider"]["zdr"] is True


@pytest.mark.asyncio
async def test_privacy_prefs_dropped_for_opted_in_free_model(cache, monkeypatch):
    """data_collection=deny excludes free providers — requesting both routes to nothing."""
    _seed(cache)
    monkeypatch.setenv("ATTACKLENS_AI_ALLOW_TRAINING_MODELS", "true")

    # A free model that DOES advertise structured output, so we reach the prefs.
    payload = dict(SAMPLE)
    payload["data"] = payload["data"] + [{
        "id": "free/structured:free",
        "pricing": {"prompt": "0", "completion": "0"},
        "supported_parameters": ["structured_outputs"],
    }]
    payload["fetched_at"] = 9e9
    cache.write_text(json.dumps(payload))
    catalog.invalidate_memo()

    captured = await _capture_payload(
        monkeypatch, "free/structured:free", schema={"type": "object"}
    )
    assert captured["response_format"]["type"] == "json_schema"
    assert "data_collection" not in captured["provider"]
    assert "zdr" not in captured["provider"]


async def _capture_payload(monkeypatch, model_id, schema):
    """Run a chat call, intercepting the HTTP layer, and return the sent payload."""
    monkeypatch.setattr(
        "manager.manager.ai.providers._openrouter_usage_guard.check", lambda: None
    )
    p = _provider(model_id)
    seen = {}

    async def _fake_request_json(method, url, headers=None, json_body=None):
        seen.update(json_body)
        return {
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "cost": 0},
            "model": model_id,
        }

    monkeypatch.setattr(p._http, "request_json", _fake_request_json)
    if schema is None:
        await p.chat("hello")
    else:
        await p.chat_structured("hello", schema=schema)
    return seen


# ── Seed-list hygiene ─────────────────────────────────────────────────────────

def test_default_openrouter_model_is_in_the_seed_list():
    from manager.manager.ai.base import PROVIDER_MODELS, DEFAULT_MODELS

    assert DEFAULT_MODELS["openrouter"] in PROVIDER_MODELS["openrouter"]


def test_seeded_free_models_all_advertise_structured_output(cache):
    """A free default that cannot do structured output silently downgrades
    every validation call to prompt-only JSON. Catch that at the seed level."""
    from manager.manager.ai.base import DEFAULT_MODELS

    _seed(cache)
    default = DEFAULT_MODELS["openrouter"]
    # The default must be either paid, or free-with-structured-output.
    if catalog.is_free_model(default):
        supports = catalog.supports_structured_output(default)
        assert supports is not False, (
            f"default free model {default} cannot do structured output"
        )


# ── Startup warming ───────────────────────────────────────────────────────────
#
# refresh() used to be reachable only from GET /api/v1/ai/models, so on a
# headless deployment the catalog never warmed and every lookup silently fell
# back to a heuristic. server.py now runs a background refresher; these pin the
# refresh contract it depends on.

@pytest.mark.asyncio
async def test_refresh_is_a_noop_while_the_cache_is_fresh(cache, monkeypatch):
    _seed(cache)
    calls = {"n": 0}

    class _Boom:
        def __init__(self, *a, **k):
            calls["n"] += 1
            raise AssertionError("must not fetch while the cache is fresh")

    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", _Boom)

    models = await catalog.refresh()
    assert calls["n"] == 0
    assert "openai/gpt-4o-mini" in models


@pytest.mark.asyncio
async def test_refresh_never_raises_when_the_provider_is_down(cache, monkeypatch):
    """A provider outage must not take down the caller — here, a startup task."""
    monkeypatch.setattr(catalog, "_CACHE_TTL_S", -1)

    class _Boom:
        def __init__(self, *a, **k):
            raise OSError("dns failure")

    import aiohttp
    monkeypatch.setattr(aiohttp, "ClientSession", _Boom)

    assert await catalog.refresh() == {}          # empty, not an exception


@pytest.mark.asyncio
async def test_cold_catalog_lookups_degrade_to_heuristics(cache):
    """What the refresher exists to prevent: no catalog, so nothing is known."""
    assert catalog.cached_models() == {}
    assert catalog.supports_structured_output("anything/at-all") is None
    assert catalog.is_free_model("x/y:free") is True


def test_cache_age_is_reported_for_staleness_checks(cache):
    assert catalog.cache_age_seconds() is None    # never fetched
    _seed(cache)
    age = catalog.cache_age_seconds()
    assert age is not None


def test_refresher_only_runs_for_openrouter_providers():
    """The background task is gated on provider == 'openrouter'.

    Fetching OpenRouter's catalog for an Anthropic or Ollama deployment would
    be a pointless outbound call on a security appliance.
    """
    import inspect
    from manager.manager import server

    src = inspect.getsource(server)
    assert "_ai_catalog_refresher" in src
    idx = src.index("_ai_catalog_refresher")
    body = src[idx:idx + 1400]
    assert 'cfg.provider == "openrouter"' in body
    assert "catalog.refresh()" in body
    # Must be a background task, never awaited inline during startup.
    assert "asyncio.create_task(_ai_catalog_refresher())" in src
