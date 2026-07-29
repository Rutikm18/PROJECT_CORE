from __future__ import annotations

import pytest

from manager.manager.attacklens.ai_validator import validate_with_ai
from manager.manager.attacklens.clustering import SignalCluster
from manager.manager.attacklens.signals import Signal
from manager.manager.attacklens.terrain_validators import evaluate_finding


class _NoHistory:
    async def _fetchone(self, _sql, _args):
        return {"n": 0}

    async def get_fp_rate_for_rules(self, _rule_ids, *, host_class, window_days):
        return 0.0


def _cluster(rule_id: str) -> SignalCluster:
    signal = Signal(
        rule_id=rule_id,
        layer="execution",
        data_point="processes",
        entity_key="process:test@agent-a",
        agent_id="agent-a",
        severity_hint="high",
        evidence={"name": "test"},
        weight=0.95,
        strength=0.95,
    )
    return SignalCluster(
        agent_id="agent-a",
        entity_key=signal.entity_key,
        signals=[signal],
        layers_covered={"execution"},
        confidence=0.95,
    )


@pytest.mark.asyncio
async def test_high_base_confidence_does_not_bypass_precision_threshold():
    result = await validate_with_ai(
        _cluster("rule:generic"),
        {},
        _NoHistory(),
        feeds=None,
        ai_analyst=None,
        threshold=0.90,
    )
    assert result.score < 0.90
    assert result.promoted is False


@pytest.mark.asyncio
async def test_verified_cross_matrix_floor_can_promote_without_ai():
    result = await validate_with_ai(
        _cluster("rule:process_lineage"),
        {},
        _NoHistory(),
        feeds=None,
        ai_analyst=None,
        threshold=0.90,
    )
    assert result.score == 0.90
    assert result.promoted is True


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        ({"dst_ip": "8.8.8.8"}, 1.0),
        ({"remote_address": "1.1.1.1:443"}, 1.0),
        ({"dst_ip": "10.20.30.40"}, 0.0),
        ({"dst_ip": "172.31.10.2"}, 0.0),
        ({"bind_addr": "0.0.0.0"}, 0.5),
    ],
)
def test_vector_external_exposure_uses_ip_semantics(evidence, expected):
    report = evaluate_finding(
        {"category": "connection", "evidence": evidence},
        enriched={},
    )
    criterion = next(
        item for item in report["criteria"] if item["name"] == "external_exposure"
    )
    assert criterion["met"] == expected
