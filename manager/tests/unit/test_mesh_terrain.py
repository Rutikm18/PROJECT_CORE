from manager.manager.attacklens.terrain_validators import terrain_for, CATEGORY_TO_TERRAIN
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
