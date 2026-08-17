"""
manager/tests/unit/test_validation_pipeline_inventory.py — the Settings →
Validation Pipeline inventory must stay derived from the engine, not restated.

The whole point of pipeline_inventory.py is that adding a gate, a criterion, or
a precision factor shows up on the page automatically. These tests fail when
that derivation is replaced by a hardcoded list, which is the only way the page
can silently go stale.
"""
from __future__ import annotations

import pytest

from manager.manager.attacklens import pipeline_inventory
from manager.manager.attacklens.ai_validator import PRECISION_WEIGHTS
from manager.manager.attacklens.terrain_validators import (
    GENERIC_CRITERIA,
    TERRAIN_CRITERIA,
)
from manager.manager.attacklens.validation import _GATES
from manager.manager.attacklens.validation_model import VALIDATION_JSON_SCHEMA


def _stage(inventory: list[dict], stage_id: str) -> dict:
    for stage in inventory:
        if stage["id"] == stage_id:
            return stage
    raise AssertionError(f"stage {stage_id!r} missing from inventory")


@pytest.fixture(scope="module")
def inventory() -> list[dict]:
    return pipeline_inventory.build_inventory()


# ── Derivation ───────────────────────────────────────────────────────────────

def test_gate_checks_track_the_engine_gate_list(inventory):
    """Every gate in validation._GATES appears, in execution order."""
    checks = _stage(inventory, "correlation_gates")["checks"]
    assert [c["id"] for c in checks] == [name for name, _fn in _GATES]
    assert [c["order"] for c in checks] == list(range(1, len(_GATES) + 1))
    # Descriptions come from the gate docstrings — an undocumented gate would
    # ship an empty description to the UI.
    assert all(c["description"] for c in checks)


def test_terrain_rubrics_cover_every_terrain_plus_the_generic_fallback(inventory):
    rubrics = _stage(inventory, "terrain_scoring")["checks"]
    assert {r["id"] for r in rubrics} == set(TERRAIN_CRITERIA) | {"generic"}
    for rubric in rubrics:
        source = GENERIC_CRITERIA if rubric["id"] == "generic" else TERRAIN_CRITERIA[rubric["id"]]
        assert rubric["criteria_count"] == len(source)
        assert [c["name"] for c in rubric["criteria"]] == [c["name"] for c in source]


def test_every_rubric_weights_sum_to_one(inventory):
    """A rubric whose weights do not sum to 1.0 silently rescales its scores."""
    for rubric in _stage(inventory, "terrain_scoring")["checks"]:
        assert rubric["weight_total"] == pytest.approx(1.0, abs=0.001), rubric["id"]


def test_every_rubric_has_at_least_one_anchor(inventory):
    """Without an anchor, a smoking-gun finding can never reach the 0.80 floor."""
    for rubric in _stage(inventory, "terrain_scoring")["checks"]:
        assert rubric["anchor_count"] >= 1, rubric["id"]


def test_precision_factors_track_the_weight_table(inventory):
    checks = _stage(inventory, "ai_verdict")["checks"]
    assert [c["id"] for c in checks] == list(PRECISION_WEIGHTS)
    assert sum(c["weight"] for c in checks) == pytest.approx(1.0, abs=0.001)
    assert all(c["description"] for c in checks)


def test_response_contract_lists_every_schema_field(inventory):
    checks = _stage(inventory, "response_contract")["checks"]
    schema_fields = set(VALIDATION_JSON_SCHEMA["properties"])
    listed = {c["id"] for c in checks} - {"versions"}
    assert listed == schema_fields
    assert all(c["required"] for c in checks if c["id"] in schema_fields)


# ── Failure policy ───────────────────────────────────────────────────────────

def test_terrain_and_persistence_stages_fail_closed(inventory):
    """Their output *is* the decision, so a failure must not pass silently."""
    assert _stage(inventory, "terrain_scoring")["error_policy"]["fails_closed"] is True
    assert _stage(inventory, "decision_ledger")["error_policy"]["fails_closed"] is True


def test_model_failure_never_suppresses_authoritative_evidence(inventory):
    """A dead LLM may demand review; it may never bury endpoint evidence."""
    policy = _stage(inventory, "ai_verdict")["error_policy"]
    assert policy["fails_closed"] is False
    assert policy["on_failure_high_severity"]["state"] == "needs_review"
    assert policy["with_authoritative_evidence"]["state"] == "continue"


# ── Shape guarantees the UI depends on ───────────────────────────────────────

def test_stage_ids_are_unique_and_ordered(inventory):
    ids = [stage["id"] for stage in inventory]
    assert len(ids) == len(set(ids))
    assert [stage["order"] for stage in inventory] == list(range(1, len(ids) + 1))
    assert ids == list(pipeline_inventory.stage_ids())


def test_every_stage_is_documented_and_placed(inventory):
    for stage in inventory:
        assert stage["name"] and stage["purpose"], stage["id"]
        assert stage["module"], stage["id"]
        assert stage["covers"], stage["id"]
        # A raising check builder is swallowed into check_error so the page
        # still renders — but it must never happen in a healthy tree.
        assert stage["check_error"] == "", stage["id"]


def test_config_probes_all_resolve(inventory):
    for stage in inventory:
        for entry in stage["config"]:
            assert entry["error"] == "", f"{stage['id']}.{entry['key']}"
            if entry["source"] == "settings":
                # Resolved later by the API against the settings table.
                assert entry["value"] is None
            else:
                assert entry["value"] is not None, f"{stage['id']}.{entry['key']}"


def test_settings_values_are_applied_from_the_settings_table(inventory):
    keys = pipeline_inventory.settings_config_keys()
    assert "validation_global_threshold" in keys
    filled = pipeline_inventory.apply_settings_values(
        pipeline_inventory.build_inventory(),
        {key: "0.83" for key in keys},
    )
    thresholds = _stage(filled, "threshold_resolution")
    values = {c["key"]: c["value"] for c in thresholds["config"]}
    assert values["validation_global_threshold"] == "0.83"
    # Non-settings keys keep their live value rather than being overwritten.
    assert values["TERRAIN_VALIDATION_THRESHOLD"] == 0.75
