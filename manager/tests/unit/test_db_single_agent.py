"""
manager/tests/unit/test_db_single_agent.py — single-agent section fetch.

Pins the perf-optimisation queries used by the asset/posture *detail* views:
get_latest_section / get_latest_sections return the newest payload for ONE
agent without scanning the whole fleet, and agree with the fleet-wide
get_latest_section_per_agent for that agent.
"""
from __future__ import annotations

import pytest

from manager.manager.db import Database


@pytest.fixture
async def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    await d.init()
    # Two agents, multiple sections, multiple revisions (newest = highest ts).
    await d.upsert_agent("a1", "host-a1", "10.0.0.1")
    await d.upsert_agent("a2", "host-a2", "10.0.0.2")
    await d.insert_payload("a1", "metrics", 10, {"cpu": 1})
    await d.insert_payload("a1", "metrics", 20, {"cpu": 2})   # newest for a1/metrics
    await d.insert_payload("a1", "battery", 15, {"pct": 80})
    await d.insert_payload("a2", "metrics", 99, {"cpu": 9})   # different agent
    try:
        yield d
    finally:
        await d.close()


async def test_get_latest_section_returns_newest(db):
    assert await db.get_latest_section("a1", "metrics") == {"cpu": 2}


async def test_get_latest_section_missing_returns_none(db):
    assert await db.get_latest_section("a1", "nope") is None
    assert await db.get_latest_section("ghost", "metrics") is None


async def test_get_latest_sections_batch(db):
    out = await db.get_latest_sections("a1", ["metrics", "battery", "absent"])
    assert out["metrics"] == {"cpu": 2}     # newest revision
    assert out["battery"] == {"pct": 80}
    assert "absent" not in out              # missing sections simply absent


async def test_single_agent_agrees_with_fleet_query(db):
    fleet = await db.get_latest_section_per_agent("metrics")
    assert await db.get_latest_section("a1", "metrics") == fleet["a1"]
    assert await db.get_latest_section("a2", "metrics") == fleet["a2"]


async def test_does_not_bleed_across_agents(db):
    # a1's batch must not include a2's metrics value.
    out = await db.get_latest_sections("a1", ["metrics"])
    assert out["metrics"] == {"cpu": 2}
    assert out["metrics"] != {"cpu": 9}


async def test_empty_sections_list(db):
    assert await db.get_latest_sections("a1", []) == {}
