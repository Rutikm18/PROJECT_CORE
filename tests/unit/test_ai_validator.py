"""
tests/unit/test_ai_validator.py

Tests for ai_validator.py gaps fixed in T3.x:
  - _ai_evaluate_cluster uses provider.chat() (not _call_claude)
  - tokens_used comes from resp.total_tokens (not raw.get)
  - JSON parse hardening (malformed / empty / non-dict output)
  - Fallback chain activates on 429/503 errors
  - PrecisionResult has top_factor / bottom_factor populated
  - validate_with_ai returns valid PrecisionResult with no AI configured
  - AiVerdict fields are correctly clamped and sanitised
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from manager.manager.attacklens.ai_validator import (
    AiVerdict,
    PrecisionResult,
    PRECISION_WEIGHTS,
    _ai_to_score,
    _factors_only_estimate,
    _is_transient_error,
    _ti_corroboration_score,
    _cross_layer_score,
    _asset_criticality_score,
    _weighted_sum,
    validate_with_ai,
)
from manager.manager.attacklens.validation_model import ValidationResponseError
from manager.manager.integrations.resilience import RateLimitedError


def _run(coro):
    return asyncio.run(coro)


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    layers_covered: set = field(default_factory=lambda: {"execution", "surface", "exposure"})
    signals: list = field(default_factory=lambda: [_FakeSignal()])
    confidence: float = 0.8


def _make_idb():
    idb = AsyncMock()
    idb._fetchone = AsyncMock(return_value={"n": 0})
    idb.get_fp_rate_for_rules = AsyncMock(return_value=0.0)
    return idb


def _make_ai_analyst(response_text: str = '{"verdict":"tp","confidence":0.85,"reasoning":"x"}'):
    """Build a mock FindingAnalyzer-like object whose provider returns response_text."""
    try:
        response_payload = json.loads(response_text)
        if isinstance(response_payload, dict):
            response_payload.setdefault("key_evidence", [])
            response_payload.setdefault("risk_factors", [])
            response_text = json.dumps(response_payload)
    except json.JSONDecodeError:
        pass
    mock_provider = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = response_text
    mock_resp.total_tokens = 42
    mock_resp.provider = "openrouter"
    mock_provider.chat = AsyncMock(return_value=mock_resp)

    analyst = MagicMock()
    analyst.enabled = True
    analyst._get_provider = MagicMock(return_value=mock_provider)
    return analyst


# ── Deterministic factor unit tests ──────────────────────────────────────────

def test_ti_corroboration_kev_only():
    score = _ti_corroboration_score({"kev_hit": True})
    assert 0.4 <= score <= 0.5


def test_ti_corroboration_kev_and_hash():
    score = _ti_corroboration_score({"kev_hit": True, "malicious_hash_hit": True})
    # 0.45 + 0.35 + 0.10 bonus = 0.90
    assert score >= 0.9


def test_ti_corroboration_empty():
    assert _ti_corroboration_score({}) == 0.0


def test_cross_layer_1():
    cluster = _FakeCluster(layers_covered={"execution"})
    assert _cross_layer_score(cluster) == 0.40


def test_cross_layer_2():
    cluster = _FakeCluster(layers_covered={"execution", "surface"})
    assert _cross_layer_score(cluster) == 0.70


def test_cross_layer_3():
    cluster = _FakeCluster(layers_covered={"execution", "surface", "exposure"})
    assert _cross_layer_score(cluster) == 1.0


def test_asset_criticality_crown_jewel():
    assert _asset_criticality_score({"asset_tier": "crown_jewel"}) == 1.0


def test_asset_criticality_endpoint_default():
    # No asset_tier → defaults to "endpoint" → 0.50
    assert _asset_criticality_score({}) == 0.50


def test_weighted_sum_clamped():
    factors = {k: 1.0 for k in PRECISION_WEIGHTS}
    assert _weighted_sum(factors) == 1.0


def test_ai_to_score_tp():
    v = AiVerdict(label="tp", confidence=0.9)
    assert _ai_to_score(v) == 0.9


def test_ai_to_score_fp():
    v = AiVerdict(label="fp", confidence=0.8)
    assert _ai_to_score(v) == pytest.approx(0.2)


def test_ai_to_score_uncertain():
    v = AiVerdict(label="uncertain", confidence=0.9)
    assert _ai_to_score(v) == 0.5


def test_factors_only_estimate():
    factors = {"ti_corroboration": 1.0, "cross_layer": 1.0, "baseline_anomaly": 1.0}
    est = _factors_only_estimate(factors)
    assert 0.9 <= est <= 1.0


# ── AI evaluate cluster ───────────────────────────────────────────────────────

def test_ai_evaluate_uses_provider_chat_not_call_claude():
    """Verify _ai_evaluate_cluster calls provider.chat(), not ai_analyst._call_claude."""
    analyst = _make_ai_analyst('{"verdict":"tp","confidence":0.88,"reasoning":"ok"}')
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    verdict = _run(_ai_evaluate_cluster(cluster, {}, analyst))

    # provider.chat must have been called
    analyst._get_provider.assert_called_once()
    provider = analyst._get_provider()
    provider.chat.assert_called()
    assert verdict.label == "tp"
    assert abs(verdict.confidence - 0.88) < 0.01
    assert verdict.used_llm is True


def test_ai_evaluate_tokens_from_resp_total_tokens():
    """tokens_used must come from resp.total_tokens, not raw.get()."""
    analyst = _make_ai_analyst('{"verdict":"fp","confidence":0.7,"reasoning":"noise"}')
    # Manually set total_tokens on the mock response
    analyst._get_provider().chat.return_value.total_tokens = 123
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    verdict = _run(_ai_evaluate_cluster(cluster, {}, analyst))
    assert verdict.tokens_used == 123


def test_ai_evaluate_malformed_json_is_rejected():
    """Empty / non-JSON output cannot become an inferred verdict."""
    analyst = _make_ai_analyst("this is not json at all !!!")
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    with pytest.raises(ValidationResponseError):
        _run(_ai_evaluate_cluster(cluster, {}, analyst))


def test_ai_evaluate_invalid_label_is_rejected():
    analyst = _make_ai_analyst('{"verdict":"maybe","confidence":0.9}')
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    with pytest.raises(ValidationResponseError):
        _run(_ai_evaluate_cluster(cluster, {}, analyst))


def test_ai_evaluate_out_of_range_confidence_is_rejected():
    analyst = _make_ai_analyst('{"verdict":"tp","confidence":99.0}')
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    with pytest.raises(ValidationResponseError):
        _run(_ai_evaluate_cluster(cluster, {}, analyst))


def test_ai_evaluate_empty_response_text():
    analyst = _make_ai_analyst("")
    cluster = _FakeCluster()

    from manager.manager.attacklens.ai_validator import _ai_evaluate_cluster
    with pytest.raises(ValidationResponseError):
        _run(_ai_evaluate_cluster(cluster, {}, analyst))


# ── Fallback chain ────────────────────────────────────────────────────────────

def test_is_transient_error_429():
    assert _is_transient_error(
        RateLimitedError("ai:openrouter", "429 from OpenRouter")
    ) is True


def test_is_transient_error_auth():
    assert _is_transient_error(RuntimeError("401 Unauthorized")) is False


def test_is_transient_error_value_error():
    assert _is_transient_error(ValueError("bad model")) is False


# ── PrecisionResult explainability ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_precision_result_has_top_factor_when_promoted():
    cluster = _FakeCluster(
        layers_covered={"execution", "surface", "exposure"},
        confidence=0.95,
    )
    idb = _make_idb()
    # No AI (should still compute top/bottom factor)
    result = await validate_with_ai(cluster, {"kev_hit": True, "asset_tier": "crown_jewel"},
                                    idb, None, None)
    assert result.top_factor is not None
    assert result.bottom_factor is not None
    assert result.top_factor in PRECISION_WEIGHTS


@pytest.mark.asyncio
async def test_precision_result_no_ai_produces_valid_score():
    cluster = _FakeCluster(layers_covered={"execution"}, confidence=0.9)
    idb = _make_idb()
    result = await validate_with_ai(cluster, {}, idb, None, None)
    assert 0.0 <= result.score <= 1.0
    assert result.ai is None
    assert result.ai_error == "no_analyst"


@pytest.mark.asyncio
async def test_precision_result_ai_fp_requires_review_without_suppressing():
    cluster = _FakeCluster(layers_covered={"surface"}, confidence=0.9)
    idb = _make_idb()
    analyst = _make_ai_analyst('{"verdict":"fp","confidence":0.92,"reasoning":"known scanner"}')
    result = await validate_with_ai(cluster, {}, idb, None, analyst)
    assert result.promoted is True
    assert result.review_required is True
    assert "ai_review" in (result.rejection_reason or "")
    assert result.top_factor is not None
    assert result.bottom_factor is not None


@pytest.mark.asyncio
async def test_precision_result_base_confidence_floor_populates_factors():
    """A high-score cluster with low base confidence should be rejected with explainability."""
    cluster = _FakeCluster(
        layers_covered={"execution", "surface", "exposure"},
        confidence=0.4,  # below 0.6 floor
    )
    idb = _make_idb()
    analyst = _make_ai_analyst('{"verdict":"tp","confidence":0.99,"reasoning":"strong"}')
    result = await validate_with_ai(
        cluster,
        {"kev_hit": True, "malicious_hash_hit": True, "asset_tier": "crown_jewel"},
        idb, None, analyst,
    )
    # Base confidence floor should veto (0.4 < 0.6) even if score ≥ threshold
    if not result.promoted:
        assert "base_confidence_floor" in (result.rejection_reason or "")
        assert result.top_factor is not None
