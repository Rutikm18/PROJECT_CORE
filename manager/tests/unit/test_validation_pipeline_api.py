"""
manager/tests/unit/test_validation_pipeline_api.py — the three endpoints behind
Settings → Validation Pipeline.

  GET /validation/criteria          — per-terrain rubrics
  GET /validation/pipeline          — stages + accuracy + integrations + failures
  GET /validation/debug/{id}        — why is *this* finding not validated?

The behaviour worth pinning is the degradation: an operator opens this page
precisely when something is broken, so one unavailable subsystem must never
blank the others.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from manager.manager.api.settings import make_settings_router


class FakeIntelDB:
    """Minimal intel_db surface the validation endpoints touch."""

    def __init__(self, *, settings=None, finding=None, explode=()):
        self._settings = settings or {}
        self._finding = finding
        self._explode = set(explode)

    async def _fetchall(self, query: str, _args=()):
        if "org_settings" in query:
            return [{"key": k, "value": v} for k, v in self._settings.items()]
        return []

    async def _fetchone(self, _query: str, _args=()):
        return None

    async def get_validation_observability(self, *, hours: int = 24):
        if "observability" in self._explode:
            raise RuntimeError("ledger unavailable")
        return {
            "window_hours": hours,
            "current_states": {"validated": 12, "needs_review": 3},
            "decisions": {"validated": 9, "rejected": 4},
            "abstentions": 1,
            "errors": {"llm_timeout": 2},
            "providers": [{
                "provider": "openrouter", "model": "some/model", "calls": 5,
                "tokens": 400, "cost_usd": 0.02, "latency_ms": 210.0,
            }],
            "false_positive_by_rule": [
                {"rule_id": "R-LOW", "tp": 9, "fp": 1, "false_positive_rate": 0.1},
                {"rule_id": "R-BAD", "tp": 1, "fp": 9, "false_positive_rate": 0.9},
                {"rule_id": "R-NONE", "tp": 0, "fp": 0, "false_positive_rate": None},
            ],
            "analyst_overrides": 10,
            "recompute_jobs": {"running": 1},
            "unknown_terrain": 2,
            "alerts": [{"code": "unknown_terrain", "severity": "high", "count": 2}],
            "observed_at": 1700000000.0,
        }

    async def compute_confidence_metrics(self):
        if "confidence" in self._explode:
            raise RuntimeError("confidence unavailable")
        return {
            "precision_overall": 0.87,
            "precision_by_rule": [{"rule_id": "R-LOW", "precision": 0.9}],
            "rejected_by_gate": [{"gate": "G4_reachability", "n": 5}],
        }

    async def get_finding_by_id(self, finding_id: int):
        if self._finding and self._finding.get("id") == finding_id:
            return dict(self._finding)
        return None

    async def get_validation_runs(self, _finding_id: int, limit: int = 20):
        if "runs" in self._explode:
            raise RuntimeError("runs unavailable")
        return [{"run_uid": "r1", "status": "validated", "threshold_used": 0.8}]


def _client(db: FakeIntelDB) -> TestClient:
    app = FastAPI()
    app.include_router(make_settings_router(db), prefix="/api/v1/settings")
    return TestClient(app)


# ── /validation/criteria ─────────────────────────────────────────────────────

def test_criteria_returns_every_terrain_rubric():
    body = _client(FakeIntelDB()).get("/api/v1/settings/validation/criteria").json()
    ids = {r["id"] for r in body["rubrics"]}
    assert {"origin", "vector", "citadels", "identity", "posture", "mesh", "generic"} <= ids
    assert body["terrain_count"] == len(body["rubrics"])
    assert body["criteria_total"] == sum(r["criteria_count"] for r in body["rubrics"])


def test_criteria_exposes_identity_and_posture_anchors():
    """The two terrains just added to Attack Terrain must be scorable, not empty."""
    body = _client(FakeIntelDB()).get("/api/v1/settings/validation/criteria").json()
    rubrics = {r["id"]: r for r in body["rubrics"]}
    identity_anchor = {c["name"] for c in rubrics["identity"]["criteria"] if c["is_anchor"]}
    posture_anchor = {c["name"] for c in rubrics["posture"]["criteria"] if c["is_anchor"]}
    assert identity_anchor == {"uid_zero_non_root"}
    # Two anchors on purpose: SIP is the macOS kernel baseline, and
    # critical_control_disabled covers the cross-platform catalogue so a
    # Secure Boot / Defender / SELinux failure is not scored as a weak signal.
    assert posture_anchor == {"sip_disabled", "critical_control_disabled"}


# ── /validation/pipeline ─────────────────────────────────────────────────────

def test_pipeline_returns_stages_with_live_settings_values():
    db = FakeIntelDB(settings={"validation_global_threshold": "0.66"})
    body = _client(db).get("/api/v1/settings/validation/pipeline").json()

    assert body["stage_count"] == len(body["stages"]) > 0
    assert body["stages_error"] == ""
    thresholds = next(s for s in body["stages"] if s["id"] == "threshold_resolution")
    values = {c["key"]: c["value"] for c in thresholds["config"]}
    assert values["validation_global_threshold"] == "0.66"


def test_pipeline_reports_accuracy_integrations_and_failures():
    body = _client(FakeIntelDB()).get("/api/v1/settings/validation/pipeline").json()

    accuracy = body["accuracy"]
    assert accuracy["current_states"] == {"validated": 12, "needs_review": 3}
    assert accuracy["precision_overall"] == 0.87
    assert accuracy["unknown_terrain"] == 2
    # worst_rules is ranked and excludes rules with no dispositions at all.
    assert [r["rule_id"] for r in accuracy["worst_rules"]] == ["R-BAD", "R-LOW"]

    assert body["integrations"]["providers"][0]["provider"] == "openrouter"
    assert "registry" in body["integrations"]
    assert body["failures"]["errors"] == {"llm_timeout": 2}
    assert body["failures"]["alerts"][0]["code"] == "unknown_terrain"


def test_pipeline_survives_an_unavailable_subsystem():
    """The page is opened *because* something is broken — it must still render."""
    db = FakeIntelDB(explode={"observability", "confidence"})
    body = _client(db).get("/api/v1/settings/validation/pipeline").json()

    assert body["stage_count"] > 0            # stages still enumerated
    assert body["accuracy"]["error"]           # failure surfaced, not hidden
    assert body["accuracy"]["current_states"] == {}


def test_pipeline_window_is_bounded():
    client = _client(FakeIntelDB())
    assert client.get("/api/v1/settings/validation/pipeline?hours=0").status_code == 422
    assert client.get("/api/v1/settings/validation/pipeline?hours=99999").status_code == 422


# ── /validation/debug/{id} ───────────────────────────────────────────────────

_POSTURE_FINDING = {
    "id": 42,
    "external_id": "AL-F-00000042",
    "title": "SIP disabled",
    "agent_id": "agent-1",
    "category": "security",
    "item_key": "sec:sip",
    "severity": "critical",
    "source": "rule:security_posture",
    "status": "new",
    "is_active": 1,
    "evidence": json.dumps({"sip_enabled": False}),
    "ai_verdict": "{}",
    "precision_score": 0.0,
    "validation_state": "needs_review",
}


def test_debug_traces_a_finding_to_its_terrain_and_criteria():
    db = FakeIntelDB(finding=_POSTURE_FINDING)
    body = _client(db).get("/api/v1/settings/validation/debug/42").json()

    assert body["terrain"] == "posture"
    assert body["eval_error"] == ""
    names = {c["name"] for c in body["evaluation"]["criteria"]}
    assert "sip_disabled" in names
    # SIP off is the posture anchor: the floor must be visible in the trace.
    assert body["evaluation"]["anchor_hit"] is True
    assert body["evaluation"]["score"] >= 0.80


def test_debug_shows_the_threshold_resolution_chain():
    db = FakeIntelDB(
        finding=_POSTURE_FINDING,
        settings={
            "validation_global_threshold": "0.90",
            "validation_terrain_thresholds": json.dumps({"posture": 0.70}),
        },
    )
    body = _client(db).get("/api/v1/settings/validation/debug/42").json()

    chain = body["thresholds"]
    assert chain["global"]["value"] == 0.90
    assert chain["terrain"] == {"terrain_id": "posture", "value": 0.70}
    assert chain["agent"]["value"] is None
    assert chain["source"] == "terrain"
    assert chain["effective"] == 0.70
    assert body["passes_threshold"] is True


def test_debug_agent_override_beats_terrain_override():
    db = FakeIntelDB(
        finding=_POSTURE_FINDING,
        settings={
            "validation_global_threshold": "0.50",
            "validation_terrain_thresholds": json.dumps({"posture": 0.60}),
            "validation_agent_thresholds": json.dumps({"agent-1": 0.99}),
        },
    )
    body = _client(db).get("/api/v1/settings/validation/debug/42").json()

    assert body["thresholds"]["source"] == "agent"
    assert body["thresholds"]["effective"] == 0.99
    assert body["passes_threshold"] is False
    # The actionable half: what is costing this finding the most weight.
    assert body["blocking_criteria"]
    weights = [c["weight"] for c in body["blocking_criteria"]]
    assert weights == sorted(weights, reverse=True)


def test_debug_marks_ai_as_not_run_for_an_empty_verdict():
    """ai_verdict defaults to '{}' — that means abstained, not 'said no'."""
    db = FakeIntelDB(finding=_POSTURE_FINDING)
    body = _client(db).get("/api/v1/settings/validation/debug/42").json()

    assert body["ai_ran"] is False
    ai_criterion = next(
        c for c in body["evaluation"]["criteria"] if c["name"] == "ai_verdict_tp"
    )
    assert ai_criterion["skipped"] is True


def test_debug_returns_404_for_a_missing_finding():
    db = FakeIntelDB(finding=_POSTURE_FINDING)
    assert _client(db).get("/api/v1/settings/validation/debug/999").status_code == 404


def test_debug_survives_an_unreadable_ledger():
    db = FakeIntelDB(finding=_POSTURE_FINDING, explode={"runs"})
    body = _client(db).get("/api/v1/settings/validation/debug/42").json()
    assert body["validation_runs"] == []
    assert body["evaluation"]["criteria"]        # the trace itself still works
