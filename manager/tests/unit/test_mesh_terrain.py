from manager.manager.attacklens.terrain_validators import terrain_for, CATEGORY_TO_TERRAIN
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
