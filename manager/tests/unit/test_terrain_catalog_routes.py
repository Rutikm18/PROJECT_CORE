"""
manager/tests/unit/test_terrain_catalog_routes.py — the terrain catalogue is
the single source of truth for Attack Terrain navigation.

The Sidebar routes its live badge counts through ``TerrainDefinition.route``
(see terrainCatalog.ts / Sidebar.tsx). A route here that does not match a real
dashboard page silently sends a terrain's findings to the wrong screen — which
is exactly what happened while posture pointed at the legacy /posture/overview
page instead of its Attack Terrain view.
"""
from __future__ import annotations

import re

from manager.manager.attacklens.terrain_catalog import all_terrains
from manager.manager.attacklens.terrain_validators import TERRAIN_CRITERIA

# Routes the React router actually registers under /terrain (router/index.tsx).
_LIVE_TERRAIN_ROUTES = {
    "/terrain/origin",
    "/terrain/vector",
    "/terrain/citadels",
    "/terrain/mesh",
    "/terrain/identity",
    "/terrain/posture",
}


def test_every_terrain_routes_to_a_live_attack_terrain_page():
    routes = {d.id: d.route for d in all_terrains()}
    assert set(routes.values()) == _LIVE_TERRAIN_ROUTES
    # Each terrain gets its own page — no two share a route.
    assert len(set(routes.values())) == len(routes)


def test_posture_lives_under_terrain_not_the_legacy_posture_page():
    posture = next(d for d in all_terrains() if d.id == "posture")
    assert posture.route == "/terrain/posture"


def test_identity_and_posture_are_scorable_terrains():
    """A terrain in the nav with no rubric would score every finding at zero."""
    for terrain_id in ("identity", "posture"):
        assert terrain_id in TERRAIN_CRITERIA
        assert TERRAIN_CRITERIA[terrain_id]


def test_terrain_colours_are_distinct_hex_values():
    """The map dot colour identifies the terrain — duplicates make it ambiguous."""
    colours = [d.color for d in all_terrains()]
    assert all(re.fullmatch(r"#[0-9a-fA-F]{6}", c) for c in colours)
    assert len(set(colours)) == len(colours)


def test_no_category_is_claimed_by_two_terrains():
    seen: dict[str, str] = {}
    for definition in all_terrains():
        for category in definition.categories:
            assert category not in seen, (
                f"category {category!r} claimed by both "
                f"{seen.get(category)!r} and {definition.id!r}"
            )
            seen[category] = definition.id
