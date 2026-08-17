"""
manager/tests/unit/test_posture_criteria_emitter_shapes.py — the Posture rubric
must score the findings the engine actually emits.

Regression: POSTURE_CRITERIA was written against an evidence shape
(`{"sip_enabled": False}`) that *neither* posture emitter produces. The routed
detection module emits `{"control_key": ..., "status": "disabled"}` and the
inline analyzer emits `{"sip": "disabled"}` under `item_key="sec:sip"`. Every
control criterion therefore evaluated to 0.0, and a live critical finding
("Security control disabled: Secure Boot") scored 0.0% against a 50% threshold.

Because `ENGINE_CONFIG["use_detection_modules"]` defaults to True and
`_DETECTION_MODULE_ROUTES` maps "security" to `analyze_sbom_posture`, the module
shape is the one that matters in production — so it is tested first.
"""
from __future__ import annotations

import json

import pytest

from manager.manager.attacklens.detections.sbom_posture import (
    CRITICAL_CONTROLS, CRITICAL_DISABLED,
)
from manager.manager.attacklens.terrain_validators import (
    POSTURE_CRITERIA, evaluate_finding, _disabled_control, _posture_key_off,
)


def _module_finding(control_key: str, **over) -> dict:
    """A finding shaped like detections/sbom_posture.detect_posture_issues."""
    base = {
        "category": "security",
        "terrain_id": "posture",
        "severity": "critical",
        "source": "posture_critical_disabled",
        "rule_id": "posture_critical_disabled",
        # The engine rewrites item_key to rule_id:hash on persist, so the
        # control name is recoverable only from evidence.
        "item_key": "posture_critical_disabled:adaf37adae1d11e6",
        "evidence": {
            "control_key": control_key,
            "control_name": CRITICAL_CONTROLS.get(control_key, control_key),
            "status": "disabled",
        },
    }
    base.update(over)
    return base


def _inline_finding(key: str, value="disabled") -> dict:
    """A finding shaped like engine._security (the fallback path)."""
    return {
        "category": "security",
        "terrain_id": "posture",
        "severity": "critical",
        "source": "rule:security_posture",
        "item_key": f"sec:{key}",
        "evidence": {key: value},
    }


# ── Control extraction across every emitter shape ───────────────────────────

@pytest.mark.parametrize("control_key,expected", [
    ("sip_enabled", "sip"),
    ("gatekeeper_enabled", "gatekeeper"),
    ("filevault_enabled", "filevault"),
    ("firewall_enabled", "firewall"),
    ("secure_boot", "secure_boot"),
])
def test_module_shape_is_understood(control_key, expected):
    assert _disabled_control(_module_finding(control_key)) == expected


@pytest.mark.parametrize("key,expected", [
    ("sip", "sip"), ("gatekeeper", "gatekeeper"),
    ("filevault", "filevault"), ("firewall", "firewall"),
])
def test_inline_shape_is_understood(key, expected):
    assert _disabled_control(_inline_finding(key)) == expected


@pytest.mark.parametrize("value", ["disabled", "off", "false", "no", False, "OFF"])
def test_off_is_recognised_as_string_or_bool(value):
    """Collectors report posture as text far more often than as a bool."""
    assert _disabled_control(_inline_finding("sip", value)) == "sip"


@pytest.mark.parametrize("value", ["enabled", "on", True, "active"])
def test_an_enabled_control_is_never_reported_as_disabled(value):
    assert _disabled_control(_inline_finding("sip", value)) == ""


def test_legacy_key_value_shape_still_works():
    finding = {"item_key": "sec:x", "evidence": {"key": "filevault", "value": False}}
    assert _disabled_control(finding) == "filevault"


def test_evidence_stored_as_a_json_string_is_parsed():
    finding = _module_finding("sip_enabled")
    finding["evidence"] = json.dumps(finding["evidence"])
    assert _disabled_control(finding) == "sip"


def test_aliases_collapse_module_and_inline_spellings():
    """sip_enabled and sip are the same control, so they must score alike."""
    for module_key, inline_key in [
        ("sip_enabled", "sip"), ("gatekeeper_enabled", "gatekeeper"),
        ("filevault_enabled", "filevault"), ("firewall_enabled", "firewall"),
    ]:
        assert _posture_key_off(_module_finding(module_key), inline_key)
        assert _posture_key_off(_inline_finding(inline_key), module_key)


def test_a_finding_with_no_control_evidence_matches_nothing():
    assert _disabled_control({"category": "security", "evidence": {}}) == ""
    assert _disabled_control({"category": "agent_health"}) == ""


# ── End-to-end scoring ──────────────────────────────────────────────────────

def test_the_live_regression_secure_boot_disabled_now_scores():
    """The exact finding that scored 0.0% in production (id 1770)."""
    result = evaluate_finding(_module_finding("secure_boot"), {}, None)

    assert result["terrain"] == "posture"
    assert result["anchor_hit"] is True
    assert result["score"] >= 0.80, result["criteria"]


def test_sip_disabled_still_hits_its_own_anchor_from_both_emitters():
    for finding in (_module_finding("sip_enabled"), _inline_finding("sip")):
        result = evaluate_finding(finding, {}, None)
        sip = next(c for c in result["criteria"] if c["name"] == "sip_disabled")
        assert sip["status"] == "met", finding
        assert result["score"] >= 0.80


@pytest.mark.parametrize("control_key", sorted(CRITICAL_DISABLED))
def test_every_critical_control_reaches_the_anchor_floor(control_key):
    """A control the module calls critical must not score as a weak signal."""
    result = evaluate_finding(_module_finding(control_key), {}, None)
    assert result["anchor_hit"] is True, control_key
    assert result["score"] >= 0.80, control_key


@pytest.mark.parametrize("control_key", sorted(set(CRITICAL_CONTROLS) - set(CRITICAL_DISABLED)))
def test_non_critical_controls_score_partial_not_zero(control_key):
    """High-severity controls are real failures, just not definitive ones."""
    result = evaluate_finding(_module_finding(control_key, severity="high"), {}, None)
    criterion = next(
        c for c in result["criteria"] if c["name"] == "critical_control_disabled"
    )
    assert criterion["met"] == pytest.approx(0.5), control_key
    assert result["score"] > 0.0, control_key


def test_an_unrelated_posture_finding_does_not_claim_a_control():
    """agent_health lives in posture too — it must not fake a control failure."""
    finding = {
        "category": "agent_health", "terrain_id": "posture", "severity": "high",
        "item_key": "agent_health:collector:processes",
        "source": "rule:agent_health",
        "evidence": {"collector": "processes", "status": "degraded"},
    }
    result = evaluate_finding(finding, {}, None)
    criterion = next(
        c for c in result["criteria"] if c["name"] == "critical_control_disabled"
    )
    assert criterion["met"] == 0.0
    assert result["anchor_hit"] is False


def test_posture_weights_still_sum_to_one():
    assert sum(c["weight"] for c in POSTURE_CRITERIA) == pytest.approx(1.0, abs=0.001)
