"""
Tests for terrain classification completeness — behavioral anomalies and SCA/
compliance failures must land in a real terrain bucket AND be scored against a
non-empty criteria set, instead of falling through to UNCLASSIFIED with score 0
(which made them invisible on the six-bucket Attack Terrain map).
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens.terrain_validators import (
    terrain_for,
    evaluate_finding,
    GENERIC_CRITERIA,
    ORIGIN_CRITERIA,
)


# ── Routing ──────────────────────────────────────────────────────────────────

def test_compliance_routes_to_posture():
    f = {"category": "compliance", "severity": "high",
         "evidence": {"policy_id": "cis", "result": "failed"}}
    assert terrain_for(f) == "posture"


@pytest.mark.parametrize("metric,expected", [
    ("conn_count", "vector"),
    ("conn_dest_diversity", "vector"),
    ("port_count", "vector"),
    ("proc_count", "citadels"),
    ("service_count", "citadels"),
    ("cpu", "citadels"),
    ("admin_count", "identity"),
    ("pkg_count", "origin"),
])
def test_behavioral_routes_by_metric(metric, expected):
    f = {"category": "behavioral", "item_key": f"{metric}_anomaly",
         "evidence": {"metric": metric, "zscore": 3.5}}
    assert terrain_for(f) == expected


def test_behavioral_unknown_metric_defaults_to_citadels():
    f = {"category": "behavioral", "item_key": "mystery_anomaly",
         "evidence": {"metric": "mystery"}}
    assert terrain_for(f) == "citadels"


def test_explicit_terrain_id_still_wins():
    f = {"category": "behavioral", "terrain_id": "identity",
         "evidence": {"metric": "conn_count"}}
    assert terrain_for(f) == "identity"


# ── Scoring: no more empty criteria / zero score ─────────────────────────────

def test_behavioral_finding_gets_generic_criteria_and_nonzero_score():
    f = {
        "category": "behavioral",
        "severity": "high",
        "source": "behavioral_zscore",
        "mitre_technique": "T1496",
        "evidence": {"metric": "cpu", "zscore": 5.0, "value": 98, "threshold": 20},
    }
    result = evaluate_finding(f, enriched={})
    assert result["total_count"] == len(GENERIC_CRITERIA)
    assert result["percentage"] > 0
    names = {c["name"] for c in result["criteria"]}
    assert "deviation_magnitude" in names
    # A 5σ deviation must register as met.
    dev = next(c for c in result["criteria"] if c["name"] == "deviation_magnitude")
    assert dev["status"] == "met"


def test_critical_behavioral_anchor_floor_validates():
    f = {
        "category": "behavioral",
        "severity": "critical",
        "evidence": {"metric": "admin_count", "zscore": 6.0},
    }
    result = evaluate_finding(f, enriched={})
    # Critical severity is an anchor → score floored at 0.80.
    assert result["score"] >= 0.80
    assert result["anchor_hit"] is True


def test_compliance_failed_high_impact_check_scores_fairly():
    f = {
        "category": "compliance",
        "severity": "high",
        "mitre_technique": "T1003",
        "evidence": {"policy_id": "cis-macos", "result": "failed", "mitre": ["T1003"]},
    }
    result = evaluate_finding(f, enriched={"asset_tier": "server"})
    assert result["total_count"] == len(GENERIC_CRITERIA)
    # high severity + mapped technique + failed-check deviation + server asset
    # should clear a meaningful bar, not sit at 0.
    assert result["percentage"] >= 40


def test_unknown_category_uses_generic_not_empty():
    f = {"category": "some_future_category", "severity": "medium",
         "evidence": {"foo": "bar"}}
    result = evaluate_finding(f, enriched={})
    assert result["total_count"] == len(GENERIC_CRITERIA)
    assert result["terrain"] == "unclassified"


# ── Existing terrains are unaffected ─────────────────────────────────────────

def test_origin_package_finding_still_uses_origin_criteria():
    f = {"category": "package", "severity": "high",
         "cve_ids": ["CVE-2024-1"], "evidence": {"name": "nginx"}}
    result = evaluate_finding(f, enriched={"kev_hit": True})
    assert result["terrain"] == "origin"
    assert result["total_count"] == len(ORIGIN_CRITERIA)
    names = {c["name"] for c in result["criteria"]}
    assert "kev_listed" in names            # origin-specific, not generic
