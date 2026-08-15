"""
manager/tests/unit/test_custom_correlations.py

Two sections:
  1. Pure unit tests for condition evaluation (no DB, no network)
  2. API integration tests via httpx AsyncClient + IntelDB on real Postgres

Edge cases covered:
  • All 10 condition operators (eq/neq/contains/not_contains/gt/lt/gte/lte/regex/in)
  • AND / OR logic with mixed results
  • Empty conditions block  → matches every finding
  • Missing 'rules' key    → matches every finding
  • Dot-path evidence field access (evidence.proc_name)
  • Tag field as JSON string  → parsed to list
  • Evidence field as JSON string → parsed before dot-path walk
  • None / missing field  → safe numeric zero, safe string ''
  • regex with invalid pattern → returns False, no exception
  • 'in' op: scalar actual vs list actual
  • required_count gate: not enough matches → no correlation
  • Time-window cutoff: old findings excluded
  • Disabled rules → not loaded / not evaluated
  • CRUD lifecycle (create → read → update → delete)
  • 404 on get/put/delete/toggle for unknown id
  • toggle flips enabled flag
  • Test endpoint dry-run: would_fire / matched_count
  • tags and conditions returned as parsed objects, not raw JSON strings
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.custom_correlations import make_custom_correlations_router
from manager.manager.attacklens.custom_correlator import (
    CustomCorrelator,
    _evaluate_condition,
    _get_field,
    _matches_conditions,
)
from manager.manager.indexer import IntelDB

# ══════════════════════════════════════════════════════════════════════════════
# 1. Pure unit tests — condition evaluation (no DB required)
# ══════════════════════════════════════════════════════════════════════════════

FINDING = {
    "id": 1,
    "agent_id": "mac-01",
    "category": "process",
    "severity": "high",
    "score": 8.5,
    "title": "Reverse shell detected",
    "source": "rule:proc",
    "status": "new",
    "tags": json.dumps(["lateral-movement", "shell"]),
    "evidence": json.dumps({"proc_name": "nc", "remote_addr": "10.0.0.5"}),
    "cvss_score": 7.2,
    "epss_score": 0.04,
}


@pytest.mark.asyncio
async def test_reload_rules_reports_executable_inventory():
    app = _make_app(object())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/custom-correlations/reload-rules")

    assert response.status_code == 200
    body = response.json()
    assert body["total_yaml_rules"] == 118
    assert body["executable_rules"] == 85
    assert body["declarative_only_rules"] == 33
    assert body["by_status"]["stable"]["declarative_only"] == 0


# ── _get_field ────────────────────────────────────────────────────────────────

def test_get_field_flat():
    assert _get_field(FINDING, "category") == "process"

def test_get_field_missing_key():
    assert _get_field(FINDING, "nonexistent") is None

def test_get_field_tag_parses_json():
    tags = _get_field(FINDING, "tag")
    assert isinstance(tags, list)
    assert "shell" in tags

def test_get_field_tag_already_list():
    f = {**FINDING, "tags": ["a", "b"]}
    tags = _get_field(f, "tag")
    assert tags == ["a", "b"]

def test_get_field_tag_missing_field():
    f = {**FINDING, "tags": None}
    assert _get_field(f, "tag") == []

def test_get_field_dot_path_evidence_string():
    val = _get_field(FINDING, "evidence.proc_name")
    assert val == "nc"

def test_get_field_dot_path_evidence_dict():
    f = {**FINDING, "evidence": {"proc_name": "bash", "remote_addr": "1.2.3.4"}}
    assert _get_field(f, "evidence.proc_name") == "bash"

def test_get_field_dot_path_missing_key():
    assert _get_field(FINDING, "evidence.no_such") is None

def test_get_field_dot_path_broken_json():
    f = {**FINDING, "evidence": "NOT_JSON"}
    assert _get_field(f, "evidence.proc_name") is None


# ── _evaluate_condition — all operators ───────────────────────────────────────

def cond(field, op, value):
    return {"field": field, "op": op, "value": value}


def test_eq_match():
    assert _evaluate_condition(cond("category", "eq", "process"), FINDING)

def test_eq_no_match():
    assert not _evaluate_condition(cond("category", "eq", "network"), FINDING)

def test_eq_case_insensitive():
    assert _evaluate_condition(cond("severity", "eq", "HIGH"), FINDING)

def test_neq_match():
    assert _evaluate_condition(cond("category", "neq", "network"), FINDING)

def test_neq_no_match():
    assert not _evaluate_condition(cond("category", "neq", "process"), FINDING)

def test_contains_string():
    assert _evaluate_condition(cond("title", "contains", "shell"), FINDING)

def test_contains_string_no_match():
    assert not _evaluate_condition(cond("title", "contains", "kernel"), FINDING)

def test_contains_list_field():
    assert _evaluate_condition(cond("tag", "contains", "shell"), FINDING)

def test_contains_list_no_match():
    assert not _evaluate_condition(cond("tag", "contains", "exfil"), FINDING)

def test_not_contains_string():
    assert _evaluate_condition(cond("title", "not_contains", "kernel"), FINDING)

def test_not_contains_list_match():
    assert not _evaluate_condition(cond("tag", "not_contains", "shell"), FINDING)

def test_gt_match():
    assert _evaluate_condition(cond("score", "gt", 7.0), FINDING)

def test_gt_no_match():
    assert not _evaluate_condition(cond("score", "gt", 9.0), FINDING)

def test_lt_match():
    assert _evaluate_condition(cond("score", "lt", 9.0), FINDING)

def test_lt_no_match():
    assert not _evaluate_condition(cond("score", "lt", 7.0), FINDING)

def test_gte_exact():
    assert _evaluate_condition(cond("score", "gte", 8.5), FINDING)

def test_lte_exact():
    assert _evaluate_condition(cond("score", "lte", 8.5), FINDING)

def test_numeric_none_field_treated_as_zero():
    f = {**FINDING, "cvss_score": None}
    assert _evaluate_condition(cond("cvss_score", "lt", 1.0), f)

def test_regex_match():
    assert _evaluate_condition(cond("title", "regex", r"reverse\s+shell"), FINDING)

def test_regex_no_match():
    assert not _evaluate_condition(cond("title", "regex", r"dropper"), FINDING)

def test_regex_invalid_pattern_returns_false():
    # A broken pattern must not raise — condition silently fails
    result = _evaluate_condition(cond("title", "regex", "[invalid"), FINDING)
    assert result is False

def test_in_scalar_match():
    assert _evaluate_condition(cond("severity", "in", ["high", "critical"]), FINDING)

def test_in_scalar_no_match():
    assert not _evaluate_condition(cond("severity", "in", ["low", "info"]), FINDING)

def test_in_list_actual():
    # tag field is a list; 'in' checks if any element is in the value list
    assert _evaluate_condition(cond("tag", "in", ["shell", "exfil"]), FINDING)

def test_in_single_string_value():
    assert _evaluate_condition(cond("severity", "in", "high"), FINDING)


# ── _matches_conditions — AND / OR / empty ────────────────────────────────────

def test_and_all_true():
    conditions = {
        "operator": "AND",
        "rules": [
            cond("category", "eq", "process"),
            cond("severity", "eq", "high"),
        ],
    }
    assert _matches_conditions(conditions, FINDING)

def test_and_one_false():
    conditions = {
        "operator": "AND",
        "rules": [
            cond("category", "eq", "process"),
            cond("severity", "eq", "low"),     # false
        ],
    }
    assert not _matches_conditions(conditions, FINDING)

def test_or_one_true():
    conditions = {
        "operator": "OR",
        "rules": [
            cond("category", "eq", "network"),  # false
            cond("severity", "eq", "high"),      # true
        ],
    }
    assert _matches_conditions(conditions, FINDING)

def test_or_all_false():
    conditions = {
        "operator": "OR",
        "rules": [
            cond("category", "eq", "network"),
            cond("severity", "eq", "low"),
        ],
    }
    assert not _matches_conditions(conditions, FINDING)

def test_empty_rules_matches_all():
    conditions = {"operator": "AND", "rules": []}
    assert _matches_conditions(conditions, FINDING)

def test_missing_rules_key_matches_all():
    conditions = {"operator": "AND"}
    assert _matches_conditions(conditions, FINDING)

def test_empty_conditions_dict_matches_all():
    assert _matches_conditions({}, FINDING)

def test_operator_lowercase():
    conditions = {"operator": "and", "rules": [cond("category", "eq", "process")]}
    assert _matches_conditions(conditions, FINDING)


# ══════════════════════════════════════════════════════════════════════════════
# 2. API integration tests — real Postgres via pg_intel_dsn
# ══════════════════════════════════════════════════════════════════════════════

async def _mk_db(dsn: str) -> IntelDB:
    idb = IntelDB(dsn)
    await idb.init()
    return idb


def _make_app(intel_db: IntelDB) -> FastAPI:
    app = FastAPI()
    app.include_router(
        make_custom_correlations_router(intel_db),
        prefix="/api/v1/custom-correlations",
    )
    return app


def _minimal_body(**overrides) -> dict:
    base = {
        "name": "Test rule",
        "action": "alert",
        "severity": "medium",
        "confidence": 70,
        "required_count": 1,
        "time_window_hours": 24,
    }
    base.update(overrides)
    return base


# ── helpers ────────────────────────────────────────────────────────────────────

async def _create_rule(client, **overrides) -> dict:
    body = _minimal_body(**overrides)
    resp = await client.post("/api/v1/custom-correlations", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── GET /  ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_empty(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/v1/custom-correlations")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rules"] == []
        assert data["total"] == 0
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_list_returns_all_rules(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            await _create_rule(c, name="Rule A")
            await _create_rule(c, name="Rule B")
            resp = await c.get("/api/v1/custom-correlations")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        names = {r["name"] for r in data["rules"]}
        assert names == {"Rule A", "Rule B"}
    finally:
        await idb.close()


# ── POST /  ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_minimal_body(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = await _create_rule(c)
        assert rule["name"] == "Test rule"
        assert rule["action"] == "alert"
        assert rule["enabled"] is True
        assert isinstance(rule["id"], str) and len(rule["id"]) > 0
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_create_conditions_returned_as_object(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        body = _minimal_body()
        body["conditions"] = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/custom-correlations", json=body)
        assert resp.status_code == 200
        rule = resp.json()
        # conditions must be an object (parsed), not a raw JSON string
        assert isinstance(rule["conditions"], dict)
        assert rule["conditions"]["operator"] == "AND"
        assert len(rule["conditions"]["rules"]) == 1
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_create_tags_returned_as_list(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        body = _minimal_body()
        body["tags"] = ["fp-reduction", "custom"]
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/custom-correlations", json=body)
        rule = resp.json()
        assert isinstance(rule["tags"], list)
        assert "fp-reduction" in rule["tags"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_create_all_action_types(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            for action in ("alert", "suppress", "elevate", "tag"):
                rule = await _create_rule(c, name=f"rule-{action}", action=action)
                assert rule["action"] == action
    finally:
        await idb.close()


# ── GET /{id}  ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_rule_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            created = await _create_rule(c, name="GetMe")
            resp = await c.get(f"/api/v1/custom-correlations/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "GetMe"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_get_rule_not_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/custom-correlations/{uuid.uuid4()}")
        assert resp.status_code == 404
    finally:
        await idb.close()


# ── PUT /{id}  ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_rule(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = await _create_rule(c, name="Original", severity="medium")
            updated_body = _minimal_body(name="Updated", severity="high")
            resp = await c.put(f"/api/v1/custom-correlations/{rule['id']}", json=updated_body)
        assert resp.status_code == 200
        updated = resp.json()
        assert updated["name"] == "Updated"
        assert updated["severity"] == "high"
        assert updated["id"] == rule["id"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_update_rule_not_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.put(
                f"/api/v1/custom-correlations/{uuid.uuid4()}",
                json=_minimal_body(),
            )
        assert resp.status_code == 404
    finally:
        await idb.close()


# ── DELETE /{id}  ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_rule(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = await _create_rule(c)
            resp = await c.delete(f"/api/v1/custom-correlations/{rule['id']}")
            assert resp.status_code == 200
            assert resp.json()["deleted"] is True
            # Confirm it is actually gone
            get_resp = await c.get(f"/api/v1/custom-correlations/{rule['id']}")
        assert get_resp.status_code == 404
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_delete_rule_not_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.delete(f"/api/v1/custom-correlations/{uuid.uuid4()}")
        assert resp.status_code == 404
    finally:
        await idb.close()


# ── POST /{id}/toggle  ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_toggle_disables_rule(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = await _create_rule(c)
            assert rule["enabled"] is True

            resp = await c.post(f"/api/v1/custom-correlations/{rule['id']}/toggle")
            assert resp.status_code == 200
            assert resp.json()["enabled"] is False

            # Toggle back
            resp2 = await c.post(f"/api/v1/custom-correlations/{rule['id']}/toggle")
            assert resp2.json()["enabled"] is True
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_toggle_not_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(f"/api/v1/custom-correlations/{uuid.uuid4()}/toggle")
        assert resp.status_code == 404
    finally:
        await idb.close()


# ── POST /{id}/test (dry-run)  ─────────────────────────────────────────────────

async def _seed_finding(idb: IntelDB, agent_id: str, category: str = "process",
                        item_key: str | None = None) -> None:
    f = {
        "agent_id": agent_id,
        "category": category,
        "item_key": item_key or f"{category}:{uuid.uuid4().hex[:8]}",
        "severity": "high",
        "score": 8.0,
        "title": f"Test finding {category}",
        "source": "rule:test",
        "rule_id": "rule:test",
        "evidence": {},
    }
    await idb.upsert_finding(f, time.time())


@pytest.mark.asyncio
async def test_test_endpoint_no_findings(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = await _create_rule(c, required_count=1)
            resp = await c.post(f"/api/v1/custom-correlations/{rule['id']}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["would_fire"] is False
        assert data["matched_count"] == 0
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_test_endpoint_would_fire_with_matching_findings(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        body = _minimal_body(required_count=1)
        body["conditions"] = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        await _seed_finding(idb, "agent-01", category="process")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post("/api/v1/custom-correlations", json=body)
            rule = resp.json()
            test_resp = await c.post(f"/api/v1/custom-correlations/{rule['id']}/test")

        assert test_resp.status_code == 200
        data = test_resp.json()
        assert data["would_fire"] is True
        assert data["matched_count"] >= 1
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_test_endpoint_required_count_gate(pg_intel_dsn):
    """Only 1 matching finding but required_count=3 — must not fire."""
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        body = _minimal_body(required_count=3)
        body["conditions"] = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        await _seed_finding(idb, "agent-01", category="process")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = (await c.post("/api/v1/custom-correlations", json=body)).json()
            test_resp = await c.post(f"/api/v1/custom-correlations/{rule['id']}/test")

        data = test_resp.json()
        assert data["would_fire"] is False
        assert data["required_count"] == 3
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_test_endpoint_agent_filter(pg_intel_dsn):
    """agent_id body param limits scan to one agent's findings."""
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        body = _minimal_body(required_count=1)
        body["conditions"] = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        # Finding on agent-X; we will query only agent-Y
        await _seed_finding(idb, "agent-X", category="process")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            rule = (await c.post("/api/v1/custom-correlations", json=body)).json()
            test_resp = await c.post(
                f"/api/v1/custom-correlations/{rule['id']}/test",
                json={"agent_id": "agent-Y"},
            )

        data = test_resp.json()
        assert data["would_fire"] is False
        assert data["matched_count"] == 0
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_test_endpoint_not_found(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(f"/api/v1/custom-correlations/{uuid.uuid4()}/test")
        assert resp.status_code == 404
    finally:
        await idb.close()


# ══════════════════════════════════════════════════════════════════════════════
# 3. CustomCorrelator unit tests (engine-level, real DB)
# ══════════════════════════════════════════════════════════════════════════════

async def _insert_rule(idb: IntelDB, *, name: str = "r", action: str = "alert",
                       enabled: int = 1, conditions: dict | None = None,
                       required_count: int = 1, time_window_hours: int = 24) -> str:
    rule_id = str(uuid.uuid4())
    now = time.time()
    await idb._conn.execute(
        """INSERT INTO custom_correlation_rules
           (id, name, description, enabled, action, severity, confidence,
            conditions, required_count, time_window_hours, tags, attack_chain,
            recommendation, created_by, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rule_id, name, "", enabled, action, "high", 80,
         json.dumps(conditions or {}), required_count, time_window_hours,
         "[]", "[]", "", "test", now, now),
    )
    await idb._conn.commit()
    return rule_id


@pytest.mark.asyncio
async def test_correlator_no_rules(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        assert results == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_disabled_rule_skipped(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        await _insert_rule(idb, name="disabled", enabled=0)
        await _seed_finding(idb, "agent-01")
        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        # Disabled rule must never fire
        assert results == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_no_findings_no_fire(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        await _insert_rule(idb, name="active-rule", enabled=1)
        cc = CustomCorrelator(idb)
        # No findings seeded — should not fire
        results = await cc.correlate("agent-01")
        assert results == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_fires_when_conditions_match(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        conditions = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        await _insert_rule(idb, name="proc-rule", conditions=conditions,
                           action="alert", required_count=1)
        await _seed_finding(idb, "agent-01", category="process")

        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        assert len(results) == 1
        assert results[0]["action"] == "alert"
        assert results[0]["agent_id"] == "agent-01"
        assert results[0]["rule_id"].startswith("custom:")
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_required_count_gate(pg_intel_dsn):
    """2 findings, required_count=3 — must NOT fire."""
    idb = await _mk_db(pg_intel_dsn)
    try:
        conditions = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        await _insert_rule(idb, name="proc-rule", conditions=conditions, required_count=3)
        await _seed_finding(idb, "agent-01", category="process", item_key="k1")
        await _seed_finding(idb, "agent-01", category="process", item_key="k2")

        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        assert results == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_suppress_action(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        conditions = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "process"}],
        }
        await _insert_rule(idb, name="suppress-rule", conditions=conditions, action="suppress")
        await _seed_finding(idb, "agent-01", category="process")

        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        assert len(results) == 1
        assert results[0]["action"] == "suppress"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_custom_actions_use_postgres_safe_updates(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        await _seed_finding(idb, "agent-01", category="process", item_key="action-target")
        row = await idb._fetchone(
            "SELECT id FROM findings WHERE agent_id=? AND item_key=?",
            ("agent-01", "action-target"),
        )
        finding_id = int(row["id"])

        await idb.apply_custom_correlation_action(
            finding_id, "tag", ["reviewed", "custom-rule"],
        )
        await idb.apply_custom_correlation_action(finding_id, "elevate")
        updated = await idb._fetchone(
            "SELECT tags, severity FROM findings WHERE id=?", (finding_id,),
        )
        assert set(json.loads(updated["tags"])) == {"reviewed", "custom-rule"}
        assert updated["severity"] == "critical"

        await idb.apply_custom_correlation_action(finding_id, "suppress")
        suppressed = await idb._fetchone(
            "SELECT status, is_active, closed_at FROM findings WHERE id=?",
            (finding_id,),
        )
        assert suppressed["status"] == "false_positive"
        assert suppressed["is_active"] == 0
        assert suppressed["closed_at"] is not None
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_correlator_condition_no_match_no_fire(pg_intel_dsn):
    """Condition requires 'network' category but only 'process' findings exist."""
    idb = await _mk_db(pg_intel_dsn)
    try:
        conditions = {
            "operator": "AND",
            "rules": [{"field": "category", "op": "eq", "value": "network"}],
        }
        await _insert_rule(idb, name="net-rule", conditions=conditions)
        await _seed_finding(idb, "agent-01", category="process")

        cc = CustomCorrelator(idb)
        results = await cc.correlate("agent-01")
        assert results == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_load_rules_returns_only_enabled(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        await _insert_rule(idb, name="enabled-1", enabled=1)
        await _insert_rule(idb, name="enabled-2", enabled=1)
        await _insert_rule(idb, name="disabled-1", enabled=0)

        cc = CustomCorrelator(idb)
        rules = await cc._load_rules()
        names = {r["name"] for r in rules}
        assert "enabled-1" in names
        assert "enabled-2" in names
        assert "disabled-1" not in names
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_load_rules_conditions_parsed(pg_intel_dsn):
    """Conditions stored as JSON string must come back as a dict."""
    idb = await _mk_db(pg_intel_dsn)
    try:
        conditions = {"operator": "OR", "rules": [{"field": "severity", "op": "eq", "value": "critical"}]}
        await _insert_rule(idb, name="parsed-rule", conditions=conditions)

        cc = CustomCorrelator(idb)
        rules = await cc._load_rules()
        assert len(rules) == 1
        assert isinstance(rules[0]["conditions"], dict)
        assert rules[0]["conditions"]["operator"] == "OR"
    finally:
        await idb.close()


# ── _eval_rule time-window edge cases (pure function, no DB) ──────────────────

def _make_rule(required_count: int = 1, time_window_hours: float = 24,
               conditions: dict | None = None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "name": "test",
        "action": "alert",
        "severity": "high",
        "confidence": 70,
        "required_count": required_count,
        "time_window_hours": time_window_hours,
        "conditions": conditions or {},
        "attack_chain": [],
        "tags": [],
        "recommendation": "",
    }


def _make_finding(agent_id: str = "a1", category: str = "process",
                  last_detected_at: float | None = None) -> dict:
    return {
        "id": 1,
        "agent_id": agent_id,
        "category": category,
        "severity": "high",
        "score": 7.0,
        "title": "test",
        "source": "rule:test",
        "tags": "[]",
        "evidence": "{}",
        "last_detected_at": last_detected_at or time.time(),
    }


def test_eval_rule_finding_in_window():
    cc = CustomCorrelator.__new__(CustomCorrelator)
    rule = _make_rule(required_count=1, time_window_hours=24)
    finding = _make_finding(last_detected_at=time.time() - 3600)  # 1h ago — inside window
    result = cc._eval_rule(rule, [finding], "a1", time.time())
    assert result is not None


def test_eval_rule_finding_outside_window():
    cc = CustomCorrelator.__new__(CustomCorrelator)
    rule = _make_rule(required_count=1, time_window_hours=1)  # only 1h window
    finding = _make_finding(last_detected_at=time.time() - 7200)   # 2h ago — outside
    result = cc._eval_rule(rule, [finding], "a1", time.time())
    assert result is None


def test_eval_rule_mixed_window():
    cc = CustomCorrelator.__new__(CustomCorrelator)
    rule = _make_rule(required_count=2, time_window_hours=1)
    now = time.time()
    findings = [
        _make_finding(last_detected_at=now - 1800),  # 30m ago — inside
        _make_finding(last_detected_at=now - 7200),  # 2h ago — outside
    ]
    # Only 1 in window but required_count=2 → must not fire
    result = cc._eval_rule(rule, findings, "a1", now)
    assert result is None


def test_eval_rule_result_fields():
    cc = CustomCorrelator.__new__(CustomCorrelator)
    rule = _make_rule()
    finding = _make_finding()
    result = cc._eval_rule(rule, [finding], "agent-01", time.time())
    assert result is not None
    assert "rule_id" in result
    assert "action" in result
    assert "agent_id" in result
    assert result["agent_id"] == "agent-01"
    assert result["source"] == "custom_correlator"
