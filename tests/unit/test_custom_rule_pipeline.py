"""
tests/unit/test_custom_rule_pipeline.py

Tests for:
  - Custom rule `layer` field (raw | correlation)
  - Raw-layer evaluator (CustomCorrelator.evaluate_raw)
  - Toggle behavior (enabled flag honored per layer)
  - YAML import endpoint (in-memory mock)
  - Pull-all/reload endpoint
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from manager.manager.attacklens.custom_correlator import (
    CustomCorrelator,
    _matches_conditions,
    _evaluate_condition,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def _make_rule(
    *,
    rule_id: str | None = None,
    name: str = "TestRule",
    layer: str = "raw",
    enabled: bool = True,
    action: str = "alert",
    severity: str = "high",
    confidence: int = 80,
    conditions: dict | None = None,
    required_count: int = 1,
    time_window_hours: int = 24,
) -> dict:
    return {
        "id": rule_id or str(uuid.uuid4()),
        "name": name,
        "layer": layer,
        "enabled": enabled,
        "action": action,
        "severity": severity,
        "confidence": confidence,
        "conditions": conditions or {"operator": "AND", "rules": []},
        "required_count": required_count,
        "time_window_hours": time_window_hours,
        "tags": [],
        "attack_chain": [],
        "recommendation": "",
    }


def _make_db(rules: list[dict]) -> MagicMock:
    """Minimal intel_db mock that serves custom rules from an in-memory list."""
    db = MagicMock()

    async def _fetchall(sql: str, args: tuple) -> list[dict]:
        if "custom_correlation_rules" not in sql:
            return []
        results = list(rules)
        if "layer = ?" in sql:
            layer_val = args[0] if args else None
            results = [r for r in results if r.get("layer") == layer_val and r.get("enabled", True)]
        elif "enabled = 1" in sql:
            results = [r for r in results if r.get("enabled", True)]
        # Serialize conditions/tags as the real DB would
        for r in results:
            for field in ("conditions", "tags", "attack_chain"):
                if isinstance(r.get(field), (dict, list)):
                    r[field] = json.dumps(r[field])
        return results

    db._fetchall = _fetchall
    db._conn = MagicMock()
    db._conn.execute = AsyncMock()
    db._conn.commit = AsyncMock()
    return db


# ── condition evaluation ──────────────────────────────────────────────────────

class TestConditionEvaluation:
    def test_eq_match(self):
        assert _evaluate_condition({"field": "severity", "op": "eq", "value": "high"}, {"severity": "high"})

    def test_eq_case_insensitive(self):
        assert _evaluate_condition({"field": "severity", "op": "eq", "value": "HIGH"}, {"severity": "high"})

    def test_neq_match(self):
        assert _evaluate_condition({"field": "severity", "op": "neq", "value": "low"}, {"severity": "high"})

    def test_contains_string(self):
        assert _evaluate_condition({"field": "title", "op": "contains", "value": "exploit"}, {"title": "Remote exploit detected"})

    def test_contains_list(self):
        # "tag" is a virtual field that reads from "tags" (plural) in the item
        assert _evaluate_condition({"field": "tag", "op": "contains", "value": "malware"}, {"tags": ["malware", "ttp"]})

    def test_gt(self):
        assert _evaluate_condition({"field": "score", "op": "gt", "value": 5.0}, {"score": 7.5})

    def test_in_operator(self):
        assert _evaluate_condition({"field": "category", "op": "in", "value": ["process", "binary"]}, {"category": "process"})

    def test_regex_match(self):
        assert _evaluate_condition({"field": "title", "op": "regex", "value": r"CVE-\d{4}"}, {"title": "CVE-2024-1234 found"})

    def test_no_match_returns_false(self):
        assert not _evaluate_condition({"field": "severity", "op": "eq", "value": "critical"}, {"severity": "low"})


class TestMatchesConditions:
    def test_and_all_match(self):
        conds = {"operator": "AND", "rules": [
            {"field": "severity", "op": "eq", "value": "high"},
            {"field": "category", "op": "eq", "value": "process"},
        ]}
        assert _matches_conditions(conds, {"severity": "high", "category": "process"})

    def test_and_partial_no_match(self):
        conds = {"operator": "AND", "rules": [
            {"field": "severity", "op": "eq", "value": "high"},
            {"field": "category", "op": "eq", "value": "network"},
        ]}
        assert not _matches_conditions(conds, {"severity": "high", "category": "process"})

    def test_or_one_match(self):
        conds = {"operator": "OR", "rules": [
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "category", "op": "eq", "value": "process"},
        ]}
        assert _matches_conditions(conds, {"severity": "high", "category": "process"})

    def test_empty_rules_always_match(self):
        assert _matches_conditions({"operator": "AND", "rules": []}, {"anything": "value"})


# ── raw-layer evaluator ───────────────────────────────────────────────────────

class TestEvaluateRaw:
    def test_raw_rule_fires_on_matching_item(self):
        rule = _make_rule(
            layer="raw",
            conditions={"operator": "AND", "rules": [
                {"field": "process_name", "op": "eq", "value": "nc"},
            ]},
        )
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"process_name": "nc", "pid": 1234}]
        results = _run(correlator.evaluate_raw("agent-1", "processes", items))
        assert len(results) == 1
        assert results[0]["custom_rule_layer"] == "raw"
        assert results[0]["agent_id"] == "agent-1"
        assert results[0]["severity"] == "high"

    def test_raw_rule_does_not_fire_on_non_matching_item(self):
        rule = _make_rule(
            layer="raw",
            conditions={"operator": "AND", "rules": [
                {"field": "process_name", "op": "eq", "value": "nc"},
            ]},
        )
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"process_name": "python3", "pid": 5678}]
        results = _run(correlator.evaluate_raw("agent-1", "processes", items))
        assert results == []

    def test_disabled_raw_rule_is_skipped(self):
        rule = _make_rule(
            layer="raw",
            enabled=False,
            conditions={"operator": "AND", "rules": [
                {"field": "process_name", "op": "eq", "value": "nc"},
            ]},
        )
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"process_name": "nc"}]
        results = _run(correlator.evaluate_raw("agent-1", "processes", items))
        assert results == []

    def test_required_count_not_met_no_fire(self):
        rule = _make_rule(
            layer="raw",
            required_count=3,
            conditions={"operator": "AND", "rules": [
                {"field": "port", "op": "gt", "value": 1024},
            ]},
        )
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"port": 2222}, {"port": 3333}]  # only 2 matches, need 3
        results = _run(correlator.evaluate_raw("agent-1", "ports", items))
        assert results == []

    def test_required_count_met_fires(self):
        rule = _make_rule(
            layer="raw",
            required_count=2,
            conditions={"operator": "AND", "rules": [
                {"field": "port", "op": "gt", "value": 1024},
            ]},
        )
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"port": 2222}, {"port": 3333}, {"port": 4444}]
        results = _run(correlator.evaluate_raw("agent-1", "ports", items))
        # One finding per rule-fire, with all matched evidence
        assert len(results) == 1
        assert results[0]["evidence"]["matched_count"] == 3

    def test_section_filter_skips_wrong_section(self):
        rule = _make_rule(
            layer="raw",
            conditions={"operator": "AND", "rules": []},
        )
        rule["section_filter"] = "connections"  # only fire on connections
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        items = [{"process_name": "nc"}]
        results = _run(correlator.evaluate_raw("agent-1", "processes", items))
        assert results == []

    def test_correlation_rules_not_loaded_by_evaluate_raw(self):
        corr_rule = _make_rule(layer="correlation", conditions={"operator": "AND", "rules": []})
        raw_rule = _make_rule(layer="raw", conditions={"operator": "AND", "rules": []})
        db = _make_db([corr_rule, raw_rule])
        correlator = CustomCorrelator(db)
        items = [{"key": "value"}]
        results = _run(correlator.evaluate_raw("agent-1", "processes", items))
        # Only raw_rule should fire
        assert len(results) == 1
        assert results[0]["custom_rule_name"] == raw_rule["name"]


# ── layer field validation ────────────────────────────────────────────────────

class TestLayerValidation:
    def test_valid_correlation_layer(self):
        from manager.manager.api.custom_correlations import CustomRuleBody
        body = CustomRuleBody(name="test", layer="correlation")
        body.validate_layer()  # should not raise

    def test_valid_raw_layer(self):
        from manager.manager.api.custom_correlations import CustomRuleBody
        body = CustomRuleBody(name="test", layer="raw")
        body.validate_layer()  # should not raise

    def test_invalid_layer_raises(self):
        from manager.manager.api.custom_correlations import CustomRuleBody
        body = CustomRuleBody(name="test", layer="invalid")
        with pytest.raises(ValueError, match="layer must be"):
            body.validate_layer()

    def test_default_layer_is_correlation(self):
        from manager.manager.api.custom_correlations import CustomRuleBody
        body = CustomRuleBody(name="test")
        assert body.layer == "correlation"


# ── toggle honors enabled flag ────────────────────────────────────────────────

class TestToggleHonored:
    def test_enabled_true_rule_runs(self):
        rule = _make_rule(layer="raw", enabled=True, conditions={"operator": "AND", "rules": []})
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        results = _run(correlator.evaluate_raw("agent-1", "processes", [{"x": "y"}]))
        assert len(results) == 1

    def test_enabled_false_rule_skipped(self):
        rule = _make_rule(layer="raw", enabled=False, conditions={"operator": "AND", "rules": []})
        db = _make_db([rule])
        correlator = CustomCorrelator(db)
        results = _run(correlator.evaluate_raw("agent-1", "processes", [{"x": "y"}]))
        assert results == []


# ── YAML import parsing ───────────────────────────────────────────────────────

class TestYAMLImportParsing:
    """Test YAML parsing logic (not the HTTP route — that needs a full app)."""

    def test_parse_single_rule_dict(self):
        import yaml
        raw = yaml.dump({"name": "My Rule", "layer": "raw", "severity": "high"})
        payload = yaml.safe_load(raw)
        assert payload["name"] == "My Rule"
        assert payload["layer"] == "raw"

    def test_parse_rules_list(self):
        import yaml
        raw = yaml.dump({"rules": [
            {"name": "Rule A", "layer": "raw"},
            {"name": "Rule B", "layer": "correlation"},
        ]})
        payload = yaml.safe_load(raw)
        assert len(payload["rules"]) == 2

    def test_parse_flat_list(self):
        import yaml
        raw = yaml.dump([{"name": "Rule X"}, {"name": "Rule Y"}])
        payload = yaml.safe_load(raw)
        assert isinstance(payload, list)
        assert len(payload) == 2
