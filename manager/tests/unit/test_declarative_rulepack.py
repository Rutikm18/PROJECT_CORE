"""Tests for the generic declarative YAML evaluator and new rulepack files.

Covers:
  - _eval_one_condition: all supported operators
  - _generic_yaml_evaluator: logic_mode=all/any/majority, nested any: []
  - RulePackDetector.analyze: falls through to generic evaluator for rules
    with conditions_structured but no Python evaluator
  - developer_security.yml and sca.yml are loaded and executable
  - detection_source_coverage counts both sections as covered
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from manager.manager.attacklens.rulepack import (
    RulePackDetector,
    RulePackRule,
    _eval_one_condition,
    _generic_yaml_evaluator,
)


def _run(coro):
    return asyncio.run(coro)


def _rule(conditions_structured, *, logic_mode="all", section="developer_security"):
    return RulePackRule(
        id="TEST-DECL-001",
        section=section,
        title="Declarative test rule",
        description="",
        severity="high",
        mitre_attack=["T1204.002"],
        detection={"conditions_structured": conditions_structured, "logic_mode": logic_mode},
        false_positives=[],
        enrichment_sources=[],
        response_actions=[],
        status="stable",
        source_file="test",
    )


@pytest.fixture(scope="module")
def det():
    return RulePackDetector.load()


# ── _eval_one_condition ───────────────────────────────────────────────────────

class TestEvalOneCondition:
    def test_truthy(self):
        ok, _ = _eval_one_condition({"x": 1}, {"field": "x", "op": "truthy"})
        assert ok
        ok, _ = _eval_one_condition({"x": 0}, {"field": "x", "op": "truthy"})
        assert not ok

    def test_falsy(self):
        ok, _ = _eval_one_condition({"x": ""}, {"field": "x", "op": "falsy"})
        assert ok
        ok, _ = _eval_one_condition({"x": "val"}, {"field": "x", "op": "falsy"})
        assert not ok

    def test_eq_true(self):
        ok, _ = _eval_one_condition({"v": True}, {"field": "v", "op": "eq_true"})
        assert ok
        ok, _ = _eval_one_condition({"v": "yes"}, {"field": "v", "op": "eq_true"})
        assert ok
        ok, _ = _eval_one_condition({"v": False}, {"field": "v", "op": "eq_true"})
        assert not ok

    def test_eq_false(self):
        ok, _ = _eval_one_condition({"v": False}, {"field": "v", "op": "eq_false"})
        assert ok
        ok, _ = _eval_one_condition({"v": "no"}, {"field": "v", "op": "eq_false"})
        assert ok
        ok, _ = _eval_one_condition({"v": True}, {"field": "v", "op": "eq_false"})
        assert not ok

    def test_eq(self):
        ok, _ = _eval_one_condition({"status": "failed"}, {"field": "status", "op": "eq", "value": "failed"})
        assert ok
        ok, _ = _eval_one_condition({"status": "FAILED"}, {"field": "status", "op": "eq", "value": "failed"})
        assert ok  # case-insensitive
        ok, _ = _eval_one_condition({"status": "ok"}, {"field": "status", "op": "eq", "value": "failed"})
        assert not ok

    def test_neq(self):
        ok, _ = _eval_one_condition({"x": "a"}, {"field": "x", "op": "neq", "value": "b"})
        assert ok

    def test_regex(self):
        ok, _ = _eval_one_condition(
            {"path": "/tmp/evil.sh"},
            {"field": "path", "op": "regex", "pattern": r"^/tmp/"},
        )
        assert ok
        ok, _ = _eval_one_condition(
            {"path": "/usr/bin/ls"},
            {"field": "path", "op": "regex", "pattern": r"^/tmp/"},
        )
        assert not ok

    def test_in(self):
        ok, _ = _eval_one_condition(
            {"bind": "0.0.0.0"},
            {"field": "bind", "op": "in", "values": ["0.0.0.0", "::", "*"]},
        )
        assert ok
        ok, _ = _eval_one_condition(
            {"bind": "127.0.0.1"},
            {"field": "bind", "op": "in", "values": ["0.0.0.0", "::", "*"]},
        )
        assert not ok

    def test_not_in(self):
        ok, _ = _eval_one_condition(
            {"bind": "127.0.0.1"},
            {"field": "bind", "op": "not_in", "values": ["0.0.0.0", "::"]},
        )
        assert ok

    def test_gt_lt_gte_lte(self):
        for op, v, thr, expected in [
            ("gt", 5, 3, True), ("gt", 3, 3, False),
            ("lt", 2, 3, True), ("lt", 3, 3, False),
            ("gte", 3, 3, True), ("lte", 3, 3, True),
        ]:
            ok, _ = _eval_one_condition({"n": v}, {"field": "n", "op": op, "value": thr})
            assert ok is expected, f"op={op} v={v} thr={thr}"

    def test_contains_string(self):
        ok, _ = _eval_one_condition({"cmd": "curl | bash"}, {"field": "cmd", "op": "contains", "value": "bash"})
        assert ok

    def test_contains_list(self):
        ok, _ = _eval_one_condition(
            {"perms": ["read", "write"]},
            {"field": "perms", "op": "contains", "value": "write"},
        )
        assert ok

    def test_nested_any(self):
        cond = {"any": [
            {"field": "a", "op": "eq_true"},
            {"field": "b", "op": "eq_true"},
        ]}
        ok, label = _eval_one_condition({"a": False, "b": True}, cond)
        assert ok
        ok, _ = _eval_one_condition({"a": False, "b": False}, cond)
        assert not ok

    def test_field_alias_resolution(self):
        # exec_path aliases to binary_path etc.
        ok, _ = _eval_one_condition(
            {"binary_path": "/tmp/evil"},
            {"field": "exec_path", "op": "regex", "pattern": r"^/tmp/"},
        )
        assert ok


# ── _generic_yaml_evaluator ───────────────────────────────────────────────────

class TestGenericYamlEvaluator:
    def test_all_mode_all_must_pass(self, det):
        rule = _rule([
            {"field": "privileged", "op": "eq_true"},
            {"field": "host_network", "op": "eq_true"},
        ], logic_mode="all")
        assert _generic_yaml_evaluator(det, "a", {"privileged": True, "host_network": True}, None, rule) is not None
        assert _generic_yaml_evaluator(det, "a", {"privileged": True, "host_network": False}, None, rule) is None
        assert _generic_yaml_evaluator(det, "a", {"privileged": False, "host_network": False}, None, rule) is None

    def test_any_mode_one_suffices(self, det):
        rule = _rule([
            {"field": "privileged", "op": "eq_true"},
            {"field": "host_network", "op": "eq_true"},
        ], logic_mode="any")
        assert _generic_yaml_evaluator(det, "a", {"privileged": True, "host_network": False}, None, rule) is not None
        assert _generic_yaml_evaluator(det, "a", {"privileged": False, "host_network": False}, None, rule) is None

    def test_majority_mode(self, det):
        rule = _rule([
            {"field": "a", "op": "eq_true"},
            {"field": "b", "op": "eq_true"},
            {"field": "c", "op": "eq_true"},
        ], logic_mode="majority")
        # 2/3 pass → majority
        assert _generic_yaml_evaluator(det, "a", {"a": True, "b": True, "c": False}, None, rule) is not None
        # 1/3 pass → not majority
        assert _generic_yaml_evaluator(det, "a", {"a": True, "b": False, "c": False}, None, rule) is None

    def test_matched_conditions_in_result(self, det):
        rule = _rule([
            {"field": "privileged", "op": "eq_true"},
            {"field": "host_network", "op": "eq_true"},
        ], logic_mode="all")
        result = _generic_yaml_evaluator(det, "a", {"privileged": True, "host_network": True}, None, rule)
        assert result is not None
        assert len(result["matched_conditions"]) == 2
        assert "declarative:all:2/2" in result["reason"]

    def test_no_conditions_structured_returns_none(self, det):
        rule = RulePackRule(
            id="TEST-EMPTY", section="developer_security", title="T", description="",
            severity="high", mitre_attack=[],
            detection={},  # no conditions_structured
            false_positives=[], enrichment_sources=[], response_actions=[],
            status="stable", source_file="test",
        )
        assert _generic_yaml_evaluator(det, "a", {"x": True}, None, rule) is None

    def test_empty_conditions_list_returns_none(self, det):
        rule = _rule([], logic_mode="all")
        assert _generic_yaml_evaluator(det, "a", {"x": True}, None, rule) is None


# ── RulePackDetector.analyze falls through to generic evaluator ───────────────

class TestAnalyzeFallsThrough:
    def test_rule_with_conditions_structured_fires_without_python_evaluator(self, det):
        """A rule not in _RULE_EVALUATORS but with conditions_structured should fire."""
        from manager.manager.attacklens import rulepack as rp_mod

        rule = RulePackRule(
            id="DECLARATIVE-TEST-999",
            section="developer_security",
            title="Declarative test",
            description="",
            severity="high",
            mitre_attack=["T1055"],
            detection={"conditions_structured": [
                {"field": "privileged", "op": "eq_true"},
            ]},
            false_positives=[], enrichment_sources=[], response_actions=[],
            status="stable", source_file="test",
        )
        # Build a detector with this rule; it has NO Python evaluator
        detector = RulePackDetector({"developer_security": [rule]})
        assert "DECLARATIVE-TEST-999" not in rp_mod._RULE_EVALUATORS

        findings = _run(detector.analyze("agent-1", "developer_security", [{"privileged": True}]))
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "rulepack:DECLARATIVE-TEST-999"
        assert findings[0]["category"] == "developer_security"

    def test_rule_without_conditions_structured_and_no_evaluator_is_skipped(self, det):
        rule = RulePackRule(
            id="DECLARATIVE-TEST-SKIP",
            section="developer_security",
            title="No conditions_structured",
            description="",
            severity="medium",
            mitre_attack=[],
            detection={"logic": "prose only"},  # no conditions_structured
            false_positives=[], enrichment_sources=[], response_actions=[],
            status="stable", source_file="test",
        )
        detector = RulePackDetector({"developer_security": [rule]})
        findings = _run(detector.analyze("agent-1", "developer_security", [{"anything": True}]))
        assert findings == []

    def test_no_false_positive_on_non_matching_item(self, det):
        rule = RulePackRule(
            id="DECLARATIVE-TEST-FP",
            section="sca",
            title="FP guard",
            description="",
            severity="high",
            mitre_attack=[],
            detection={"conditions_structured": [
                {"field": "status", "op": "in", "values": ["failed", "error"]},
            ]},
            false_positives=[], enrichment_sources=[], response_actions=[],
            status="stable", source_file="test",
        )
        detector = RulePackDetector({"sca": [rule]})
        # passed check must NOT fire
        assert _run(detector.analyze("agent-1", "sca", [{"status": "passed"}])) == []
        # failed check MUST fire
        assert _run(detector.analyze("agent-1", "sca", [{"status": "failed"}])) != []


# ── New YAML rulepack files are loaded and executable ─────────────────────────

class TestNewRulepackFiles:
    def test_developer_security_rules_loaded(self, det):
        rules = det.rules_for("developer_security")
        assert len(rules) >= 16, f"Expected >=16 AL-DEV rules, got {len(rules)}"

    def test_developer_security_is_executable(self, det):
        assert det.has_executable_rules("developer_security"), (
            "developer_security section should have executable rules via declarative evaluator"
        )

    def test_sca_rules_loaded(self, det):
        rules = det.rules_for("sca")
        assert len(rules) >= 3, f"Expected >=3 SCA rules, got {len(rules)}"

    def test_sca_is_executable(self, det):
        assert det.has_executable_rules("sca"), (
            "sca section should have executable rules via declarative evaluator"
        )

    def test_al_dev_rule_ids_present(self, det):
        ids = {r.id for r in det.rules_for("developer_security")}
        for rule_id in ["AL-DEV-001", "AL-DEV-002", "AL-DEV-009", "AL-DEV-010", "AL-DEV-016"]:
            assert rule_id in ids, f"Expected {rule_id} in developer_security rulepack"

    def test_al_dev_rules_have_conditions_structured(self, det):
        for rule in det.rules_for("developer_security"):
            conds = rule.detection.get("conditions_structured")
            assert conds and len(conds) > 0, (
                f"{rule.id} has no conditions_structured — it will never fire"
            )

    def test_execution_inventory_counts_declarative_as_executable(self, det):
        inv = det.execution_inventory()
        assert inv["executable_rules"] >= 100, (
            f"Expected >=100 executable rules (python+declarative), got {inv['executable_rules']}"
        )
        # Confirm declarative-only count dropped from before adding the new files
        assert inv["declarative_only_rules"] < inv["total_yaml_rules"]


# ── developer_security AL-DEV rules fire on matching telemetry ────────────────

class TestDevSecRulesFireCorrectly:
    def _detector_for(self, rule_id: str, det: RulePackDetector) -> tuple[RulePackDetector, RulePackRule]:
        rules = [r for r in det.rules_for("developer_security") if r.id == rule_id]
        assert rules, f"{rule_id} not found"
        return RulePackDetector({"developer_security": rules}), rules[0]

    def test_al_dev_001_fires_on_auto_activating_vsix(self, det):
        d, _ = self._detector_for("AL-DEV-001", det)
        item = {"auto_activates": True, "installed_from_vsix": True}
        findings = _run(d.analyze("agent-1", "developer_security", [item]))
        assert len(findings) == 1

    def test_al_dev_001_silent_without_auto_activate(self, det):
        d, _ = self._detector_for("AL-DEV-001", det)
        item = {"auto_activates": False, "installed_from_vsix": True}
        assert _run(d.analyze("agent-1", "developer_security", [item])) == []

    def test_al_dev_009_fires_on_privileged_container(self, det):
        d, _ = self._detector_for("AL-DEV-009", det)
        # any one of: privileged, host_network, docker_socket_mount, has_sys_admin_cap
        for field in ("privileged", "host_network", "docker_socket_mount", "has_sys_admin_cap"):
            item = {field: True}
            findings = _run(d.analyze("agent-1", "developer_security", [item]))
            assert len(findings) == 1, f"AL-DEV-009 should fire when {field}=True"

    def test_al_dev_009_silent_for_normal_container(self, det):
        d, _ = self._detector_for("AL-DEV-009", det)
        item = {"privileged": False, "host_network": False}
        assert _run(d.analyze("agent-1", "developer_security", [item])) == []

    def test_al_dev_003_fires_on_world_writable_exec_path(self, det):
        d, _ = self._detector_for("AL-DEV-003", det)
        item = {"world_writable": True, "in_exec_path": True}
        assert _run(d.analyze("agent-1", "developer_security", [item])) != []

    def test_al_dev_003_silent_without_exec_path(self, det):
        d, _ = self._detector_for("AL-DEV-003", det)
        item = {"world_writable": True, "in_exec_path": False}
        assert _run(d.analyze("agent-1", "developer_security", [item])) == []

    def test_al_dev_007_fires_on_group_readable_credential(self, det):
        d, _ = self._detector_for("AL-DEV-007", det)
        item = {"is_credential_store": True, "group_readable": True}
        assert _run(d.analyze("agent-1", "developer_security", [item])) != []

    def test_al_dev_010_fires_on_shell_launcher(self, det):
        d, _ = self._detector_for("AL-DEV-010", det)
        # via launcher_is_shell flag
        item = {"launcher_is_shell": True}
        assert _run(d.analyze("agent-1", "developer_security", [item])) != []
        # via command field regex
        item2 = {"command": "bash"}
        assert _run(d.analyze("agent-1", "developer_security", [item2])) != []

    def test_al_dev_012_fires_on_wildcard_inference_server(self, det):
        d, _ = self._detector_for("AL-DEV-012", det)
        item = {"is_inference_server": True, "bind_addr": "0.0.0.0"}
        assert _run(d.analyze("agent-1", "developer_security", [item])) != []

    def test_al_dev_012_silent_on_loopback(self, det):
        d, _ = self._detector_for("AL-DEV-012", det)
        item = {"is_inference_server": True, "bind_addr": "127.0.0.1"}
        assert _run(d.analyze("agent-1", "developer_security", [item])) == []


# ── SCA rules fire on matching telemetry ──────────────────────────────────────

class TestScaRulesFireCorrectly:
    def test_sca_001_fires_on_failed_check(self, det):
        rules = [r for r in det.rules_for("sca") if r.id == "SCA-001"]
        assert rules
        d = RulePackDetector({"sca": rules})
        for status in ("failed", "fail", "error", "non_compliant"):
            findings = _run(d.analyze("agent-1", "sca", [{"status": status}]))
            assert findings, f"SCA-001 should fire on status={status!r}"

    def test_sca_001_silent_on_passed(self, det):
        rules = [r for r in det.rules_for("sca") if r.id == "SCA-001"]
        d = RulePackDetector({"sca": rules})
        assert _run(d.analyze("agent-1", "sca", [{"status": "passed"}])) == []

    def test_sca_003_fires_on_cve_package(self, det):
        rules = [r for r in det.rules_for("sca") if r.id == "SCA-003"]
        assert rules
        d = RulePackDetector({"sca": rules})
        item = {"cve_ids": ["CVE-2024-1234"], "patch_available": True}
        assert _run(d.analyze("agent-1", "sca", [item])) != []


# ── detection_source_coverage includes new sections ──────────────────────────

def test_detection_source_coverage_includes_developer_security_and_sca():
    from manager.manager.attacklens.engine import detection_source_coverage
    coverage = detection_source_coverage(RulePackDetector.load())
    assert "developer_security" in coverage and coverage["developer_security"]
    assert "sca" in coverage and coverage["sca"]
