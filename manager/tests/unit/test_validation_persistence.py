from __future__ import annotations

import pytest

from manager.manager.attacklens.ai_validator import PrecisionResult
from manager.manager.attacklens.clustering import SignalCluster
from manager.manager.attacklens.engine import AttackLensEngine
from manager.manager.attacklens.signals import Signal


class _CaptureFindings:
    def __init__(self) -> None:
        self.finding: dict | None = None

    async def upsert_finding(self, finding: dict, _timestamp: float) -> str:
        self.finding = finding
        return "unchanged"

    async def _fetchall(self, _query: str, _args: tuple) -> list[dict]:
        return []

    async def get_asset_tier(self, _agent_id: str) -> str:
        return "endpoint"


class _NoFeeds:
    @staticmethod
    def is_kev_cve(_cve_id: str) -> bool:
        return False


@pytest.mark.asyncio
async def test_emission_persists_distinct_validation_scores_and_state() -> None:
    signal = Signal(
        rule_id="AL-DEV-009",
        layer="execution",
        data_point="developer_security",
        entity_key="developer_container:container-1",
        agent_id="agent-a",
        severity_hint="critical",
        evidence={"id": "container-1", "privileged": True, "high_risk": True},
        weight=0.95,
        strength=0.95,
    )
    cluster = SignalCluster(
        agent_id="agent-a",
        entity_key=signal.entity_key,
        signals=[signal],
        layers_covered={"execution"},
        confidence=0.97,
    )
    cluster.id = 42
    precision = PrecisionResult(
        score=0.97,
        promoted=True,
        factors={"ai_verdict": 0.95},
        ai=None,
        threshold_used=0.90,
    )
    findings = _CaptureFindings()
    engine = object.__new__(AttackLensEngine)
    engine._idb = findings

    await engine._emit_finding_from_cluster(cluster, {}, 1_700_000_000, precision)

    assert findings.finding is not None
    assert findings.finding["model_precision_score"] == pytest.approx(0.97)
    assert findings.finding["terrain_score"] == pytest.approx(0.80)
    assert findings.finding["validation_score"] == pytest.approx(0.80)
    assert findings.finding["validation_state"] == "needs_review"
    assert findings.finding["validation_policy_version"] == "terrain-v1"
    assert findings.finding["validated_at"] == 0


@pytest.mark.asyncio
async def test_legacy_emission_assigns_explicit_validation_state(monkeypatch) -> None:
    async def threshold(_idb, _agent_id: str, _category: str) -> float:
        return 0.75

    monkeypatch.setattr(
        "manager.manager.attacklens.engine.resolve_threshold",
        threshold,
    )
    engine = object.__new__(AttackLensEngine)
    engine._idb = _CaptureFindings()
    engine._feeds = _NoFeeds()
    finding = {
        "agent_id": "agent-a",
        "category": "developer_security",
        "source": "AL-DEV-009",
        "rule_id": "AL-DEV-009",
        "severity": "critical",
        "score": 9.5,
        "evidence": {
            "id": "container-1",
            "privileged": True,
            "high_risk": True,
        },
    }

    await engine._attach_legacy_precision(finding)

    assert finding["terrain_score"] == pytest.approx(0.80)
    assert finding["validation_score"] == pytest.approx(0.80)
    assert finding["effective_validation_threshold"] == pytest.approx(0.75)
    assert finding["validation_state"] == "validated"
    assert finding["validation_policy_version"] == "terrain-v1"
    assert finding["validated_at"] > 0
