from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from manager.manager.api.settings import ValidationUpdate
from manager.manager.attacklens.asset_priority import (
    apply_priority_to_enriched,
    apply_priority_to_finding,
    normalize_agent_priorities,
    priority_profile,
)
from manager.manager.attacklens.clustering import SignalCluster
from manager.manager.attacklens.confidence import score_confidence
from manager.manager.attacklens.signals import Signal


def _run(coro):
    return asyncio.run(coro)


class _NoFpHistory:
    async def get_fp_rate_for_rules(self, rule_ids, host_class: str, window_days: int) -> float:
        return 0.0


def _cluster(strength: float = 0.78) -> SignalCluster:
    sig = Signal(
        rule_id="rule:test",
        layer="execution",
        data_point="processes",
        entity_key="process:evil@agent-a",
        agent_id="agent-a",
        severity_hint="high",
        evidence={"process": "evil"},
        weight=0.80,
        strength=strength,
    )
    return SignalCluster(
        agent_id="agent-a",
        entity_key=sig.entity_key,
        signals=[sig],
        layers_covered={"execution"},
    )


def test_overall_confidence_increases_for_top_priority_asset() -> None:
    base = _run(score_confidence(
        _cluster(),
        {"asset_tier": "endpoint", "host_class": "endpoint"},
        _NoFpHistory(),
        "agent-a",
    ))
    top = _run(score_confidence(
        _cluster(),
        apply_priority_to_enriched(
            {"asset_tier": "endpoint", "host_class": "endpoint"},
            priority_profile("top"),
        ),
        _NoFpHistory(),
        "agent-a",
    ))

    assert top > base
    assert top <= 1.0


def test_priority_finding_calibration_is_bounded_and_auditable() -> None:
    finding = {
        "confidence": 0.82,
        "precision_score": 0.76,
        "score": 8.0,
        "evidence": {"path": "/tmp/evil"},
        "precision_factors": {"rule_confidence": 0.82},
    }

    apply_priority_to_finding(finding, priority_profile("top"))

    assert finding["confidence"] == pytest.approx(0.88)
    assert finding["precision_score"] == pytest.approx(0.80)
    assert finding["asset_tier"] == "crown_jewel"
    assert finding["precision_factors"]["asset_priority_level"] == "top"
    assert finding["evidence"]["_confidence_calibration"]["final_confidence"] == pytest.approx(0.88)


def test_priority_does_not_overpromote_weak_evidence() -> None:
    finding = {
        "confidence": 0.58,
        "precision_score": 0.54,
        "score": 7.0,
        "evidence": {"path": "/tmp/helper"},
        "precision_factors": {},
    }

    apply_priority_to_finding(finding, priority_profile("top"))

    assert 0.58 < finding["confidence"] < 0.65
    assert finding["precision_score"] < 0.57
    assert finding["precision_factors"]["asset_priority_confidence_boost"] <= 0.025


def test_validation_settings_accept_agent_priority_map() -> None:
    update = ValidationUpdate(agent_priorities={
        "agent-a": "top",
        "agent-b": "critical",
        "agent-c": "production",
    })

    assert update.agent_priorities == {
        "agent-a": "top",
        "agent-b": "top",
        "agent-c": "high",
    }
    assert normalize_agent_priorities({"agent-d": "standard"}) == {"agent-d": "standard"}


def test_validation_settings_reject_invalid_priority_level() -> None:
    with pytest.raises(ValidationError):
        ValidationUpdate(agent_priorities={"agent-a": "impossible"})
