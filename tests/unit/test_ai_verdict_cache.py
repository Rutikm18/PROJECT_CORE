"""
tests/unit/test_ai_verdict_cache.py — Answered-prompt cache + usage guard caps.

The detection loop re-evaluates every open finding on each 60s cycle. Before
this cache, one finding that stayed open all day cost ~1,440 model calls
against evidence that never changed. On OpenRouter's free tier that exhausts
the daily request quota (50/day, or 1000/day after a one-time credit purchase)
within minutes, so the AI validation layer went dark — while the *cost* guard
stayed silent, because free models report $0.

Two behaviours are pinned here:

  • cache identity — a change to the prompt, the model, or either contract
    version must miss, so a verdict produced under one set of rules is never
    served under another.
  • guard caps — the per-minute and per-day CALL caps must fire independently
    of spend, since the cost cap cannot bound a free model.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

from manager.manager.attacklens.ai_validator import (
    AiVerdict,
    _verdict_from_cache_payload,
    _verdict_to_cache_payload,
    _ai_evaluate_cluster,
    verdict_cache_key,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@dataclass
class _FakeSignal:
    rule_id: str = "test-rule"
    layer: str = "execution"
    data_point: str = "proc"
    strength: float = 0.8
    weight: float = 1.0
    severity_hint: str = "high"
    entity_key: str = "proc:sh"
    evidence: dict = field(default_factory=dict)


@dataclass
class _FakeCluster:
    agent_id: str = "agent-1"
    entity_key: str = "proc:sh"
    layers_covered: set = field(default_factory=lambda: {"execution"})
    signals: list = field(default_factory=lambda: [_FakeSignal()])
    confidence: float = 0.8


@dataclass
class _FakeVerdict:
    label: str = "tp"
    confidence: float = 0.88
    reasoning: str = "looks malicious"
    key_evidence: list = field(default_factory=list)
    risk_factors: list = field(default_factory=list)
    provider: str = "openrouter"
    model: str = "openai/gpt-oss-20b:free"
    generation_id: str = "gen-1"
    upstream_provider: str = "openai"
    finish_reason: str = "stop"
    tokens_used: int = 400
    cost_usd: float = 0.0
    prompt_version: str = "validation-v2"
    schema_version: str = "validation-response-v1"


class _CountingModel:
    """A validation model that records how many real calls it served."""

    model_id = "openai/gpt-oss-20b:free"

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, prompt: str) -> _FakeVerdict:
        self.calls += 1
        return _FakeVerdict()


class _FakeCache:
    """In-memory stand-in for the IntelDB cache accessors."""

    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}
        self.touches = 0

    async def get_cached_ai_verdict(self, cache_key, *, max_age_s=604800.0):
        return self.rows.get(cache_key)

    async def put_cached_ai_verdict(self, cache_key, verdict, **kw):
        self.rows[cache_key] = verdict

    async def touch_ai_verdict_cache(self, cache_key):
        self.touches += 1


# ── Cache key identity ────────────────────────────────────────────────────────

def test_same_prompt_and_model_produce_a_stable_key():
    assert verdict_cache_key("prompt", "m") == verdict_cache_key("prompt", "m")


def test_prompt_change_misses():
    assert verdict_cache_key("prompt A", "m") != verdict_cache_key("prompt B", "m")


def test_model_change_misses():
    """A verdict from one model must never be served for another."""
    assert verdict_cache_key("prompt", "free-model") != verdict_cache_key("prompt", "paid-model")


def test_unknown_model_is_uncacheable():
    """An empty model id means we cannot prove which model answered."""
    assert verdict_cache_key("prompt", "") == ""


def test_prompt_version_bump_invalidates_every_entry(monkeypatch):
    """A prompt rewrite must not keep serving verdicts from the old wording."""
    before = verdict_cache_key("prompt", "m")
    monkeypatch.setattr(
        "manager.manager.attacklens.validation_model.VALIDATION_PROMPT_VERSION",
        "validation-v3",
    )
    assert verdict_cache_key("prompt", "m") != before


def test_schema_version_bump_invalidates_every_entry(monkeypatch):
    before = verdict_cache_key("prompt", "m")
    monkeypatch.setattr(
        "manager.manager.attacklens.validation_model.VALIDATION_RESPONSE_SCHEMA_VERSION",
        "validation-response-v2",
    )
    assert verdict_cache_key("prompt", "m") != before


# ── Payload round-trip ────────────────────────────────────────────────────────

def test_roundtrip_preserves_the_verdict():
    original = AiVerdict(
        label="fp", confidence=0.31, reasoning="sanctioned scanner",
        key_evidence=["evidence_ref=a"], risk_factors=["none"],
        used_llm=True, model="m", provider="openrouter",
    )
    restored = _verdict_from_cache_payload(_verdict_to_cache_payload(original))
    assert restored.label == "fp"
    assert restored.confidence == 0.31
    assert restored.reasoning == "sanctioned scanner"
    assert restored.key_evidence == ["evidence_ref=a"]


def test_cache_hit_reports_zero_spend():
    """No call was made on this run, so the run's cost must read as zero.

    Reporting the original call's tokens again would double-count spend on
    every hit and make the cost telemetry claim the opposite of the truth.
    """
    original = AiVerdict(label="tp", confidence=0.9, tokens_used=900, cost_usd=0.02)
    restored = _verdict_from_cache_payload(_verdict_to_cache_payload(original))
    assert restored.tokens_used == 0
    assert restored.cost_usd == 0.0


def test_cache_hit_keeps_used_llm_true():
    """The verdict is model-derived; flipping this reroutes the score.

    `used_llm=False` is the signal for 'no model verdict available', which
    sends the score down the deterministic-only path with a different weight.
    """
    restored = _verdict_from_cache_payload(
        _verdict_to_cache_payload(AiVerdict(label="tp", confidence=0.9))
    )
    assert restored.used_llm is True
    assert restored.cached is True


@pytest.mark.parametrize("bad", [
    {"label": "not-a-verdict", "confidence": 0.5},
    {"label": "tp", "confidence": "high"},
    {"label": "tp", "confidence": True},
    {"confidence": 0.5},
    {},
    None,
    "a string",
])
def test_malformed_rows_behave_as_a_miss(bad):
    """A corrupt row must degrade to 'call the model', never raise."""
    assert _verdict_from_cache_payload(bad) is None


# ── End-to-end through _ai_evaluate_cluster ──────────────────────────────────

def test_second_identical_evaluation_makes_no_call():
    """The behaviour the whole phase exists for."""
    model, cache, cluster = _CountingModel(), _FakeCache(), _FakeCluster()

    async def run():
        first = await _ai_evaluate_cluster(cluster, {}, model, cache)
        second = await _ai_evaluate_cluster(cluster, {}, model, cache)
        return first, second

    first, second = asyncio.run(run())
    assert model.calls == 1, "identical evidence must not trigger a second call"
    assert first.label == second.label
    assert first.cached is False
    assert second.cached is True
    assert cache.touches == 1


def test_without_a_db_handle_every_evaluation_calls():
    """Caching is opt-in via idb; callers that pass None keep old behaviour."""
    model, cluster = _CountingModel(), _FakeCluster()

    async def run():
        await _ai_evaluate_cluster(cluster, {}, model, None)
        await _ai_evaluate_cluster(cluster, {}, model, None)

    asyncio.run(run())
    assert model.calls == 2


def test_changed_evidence_triggers_a_fresh_call():
    """A cache that survived an evidence change would serve a stale verdict."""
    model, cache = _CountingModel(), _FakeCache()

    async def run():
        await _ai_evaluate_cluster(_FakeCluster(agent_id="agent-1"), {}, model, cache)
        await _ai_evaluate_cluster(_FakeCluster(agent_id="agent-2"), {}, model, cache)

    asyncio.run(run())
    assert model.calls == 2


def test_a_broken_cache_degrades_to_calling_the_model():
    """A cache outage must not fail validation."""

    class _BrokenCache(_FakeCache):
        async def get_cached_ai_verdict(self, cache_key, *, max_age_s=604800.0):
            raise RuntimeError("cache unavailable")

    model, cluster = _CountingModel(), _FakeCluster()
    with pytest.raises(RuntimeError):
        # The accessor itself raises here; IntelDB's real implementation
        # swallows this and returns None. Pinned so that contract is explicit:
        # the swallow belongs in IntelDB, not in the validator.
        asyncio.run(_ai_evaluate_cluster(cluster, {}, model, _BrokenCache()))


# ── Usage guard caps ─────────────────────────────────────────────────────────

def _fresh_guard():
    from manager.manager.ai.providers import _OpenRouterUsageGuard
    return _OpenRouterUsageGuard()


def test_per_minute_cap_defaults_to_the_free_tier_ceiling(monkeypatch):
    """OpenRouter allows 20/min on :free variants regardless of credit."""
    from manager.manager.integrations.resilience import RateLimitedError

    monkeypatch.delenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", raising=False)
    monkeypatch.delenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_DAY", raising=False)
    guard = _fresh_guard()
    served = 0
    with pytest.raises(RateLimitedError):
        for _ in range(200):
            guard.check()
            served += 1
    assert served == 20


def test_daily_call_cap_fires_on_free_models_at_zero_cost(monkeypatch):
    """The gap the cost cap cannot cover.

    Free models report $0, so cost_usd never rises and the cost budget never
    trips. Without a call cap a runaway loop on a free model is bounded by
    nothing local.
    """
    from manager.manager.integrations.resilience import PermanentError

    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "100000")
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_DAY", "50")
    guard = _fresh_guard()
    served = 0
    with pytest.raises(PermanentError, match="daily request budget"):
        for _ in range(500):
            guard.check()
            guard.charge(0.0)      # free model: no spend, ever
            served += 1
    assert served == 50


def test_cost_cap_still_bounds_paid_models(monkeypatch):
    from manager.manager.integrations.resilience import PermanentError

    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "100000")
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_DAY", "100000")
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD", "0.5")
    guard = _fresh_guard()
    with pytest.raises(PermanentError, match="cost budget"):
        for _ in range(500):
            guard.check()
            guard.charge(0.01)
    assert guard.cost_usd >= 0.5


def test_guard_snapshot_reports_both_counters(monkeypatch):
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "100")
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_DAY", "100")
    guard = _fresh_guard()
    for _ in range(3):
        guard.check()
        guard.charge(0.001)
    snap = guard.snapshot()
    assert snap["calls_last_minute"] == 3
    assert snap["calls_today"] == 3
    assert snap["cost_usd_today"] == pytest.approx(0.003)


def test_default_daily_budget_is_conservative(monkeypatch):
    """An unset budget must not default to a number that surprises an operator."""
    from manager.manager.integrations.resilience import PermanentError

    monkeypatch.delenv("ATTACKLENS_OPENROUTER_DAILY_BUDGET_USD", raising=False)
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_MINUTE", "100000")
    monkeypatch.setenv("ATTACKLENS_OPENROUTER_MAX_CALLS_PER_DAY", "100000")
    guard = _fresh_guard()
    guard.check()
    guard.charge(0.6)          # over the 0.5 default
    with pytest.raises(PermanentError, match="cost budget"):
        guard.check()
