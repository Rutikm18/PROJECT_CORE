import pytest

from manager.manager.attacklens.terrain_validators import (
    CATEGORY_TO_TERRAIN,
    evaluate_finding,
    list_criteria_for_terrain,
    terrain_for,
)
from manager.manager.attacklens.terrain_catalog import (
    all_terrains,
    terrain_for_category,
)
from manager.manager.attacklens.ai_validator import _CATEGORY_TO_TERRAIN as AI_CATEGORY_TO_TERRAIN
from manager.manager.api.settings import (
    VALIDATION_TERRAINS,
    VALIDATION_TERRAIN_CATEGORIES,
    VALIDATION_TERRAIN_LABELS,
)


def test_developer_security_maps_to_mesh():
    assert CATEGORY_TO_TERRAIN["developer_security"] == "mesh"
    assert terrain_for({"category": "developer_security"}) == "mesh"


def test_mesh_registered_in_settings_mirror():
    assert "mesh" in VALIDATION_TERRAINS
    assert VALIDATION_TERRAIN_CATEGORIES["mesh"] == ["developer_security"]
    assert "mesh" in VALIDATION_TERRAIN_LABELS


def test_mesh_registered_in_ai_validator_mirror():
    # ai_validator keeps a THIRD copy of the category→terrain map, used to
    # resolve the per-terrain validation threshold. It must agree with the
    # other two mirrors or a mesh threshold would be silently ignored.
    assert AI_CATEGORY_TO_TERRAIN["developer_security"] == "mesh"


def test_backend_terrain_consumers_share_one_catalog():
    definitions = all_terrains()
    expected_ids = [
        "citadels", "vector", "origin", "identity", "posture", "mesh",
    ]

    assert [definition.id for definition in definitions] == expected_ids
    assert VALIDATION_TERRAINS == expected_ids
    assert {
        definition.id: list(definition.categories) for definition in definitions
    } == VALIDATION_TERRAIN_CATEGORIES
    assert terrain_for_category("developer_security") == "mesh"
    assert terrain_for_category("new_detector_category") is None
    assert terrain_for({"category": "new_detector_category"}) == "unclassified"


def test_mesh_exposes_its_own_validation_policy():
    criteria = list_criteria_for_terrain("mesh")

    assert [criterion["name"] for criterion in criteria] == [
        "rule_evidence_complete",
        "execution_capability",
        "mutable_or_untrusted_source",
        "sensitive_access",
        "unsafe_permissions_or_privilege",
        "external_exposure",
        "ai_verdict_tp",
    ]
    assert sum(criterion["weight"] for criterion in criteria) == pytest.approx(1.0)

    report = evaluate_finding({
        "category": "developer_security",
        "rule_id": "AL-DEV-009",
        "evidence": {"id": "container-1", "privileged": True},
        "kev": True,
        "cvss_score": 10.0,
    })

    assert report["terrain"] == "mesh"
    assert {item["name"] for item in report["criteria"]} == {
        criterion["name"] for criterion in criteria
    }
    assert "kev_listed" not in {item["name"] for item in report["criteria"]}
