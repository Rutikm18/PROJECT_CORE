"""
manager/tests/unit/test_payload_storage.py — raw-payload storage must not
silently lose data to a missing agents-table FK parent.

`payloads.agent_id` is a FOREIGN KEY → agents(agent_id). If insert_payload runs
before/without the agent row (registration race, ON DELETE CASCADE eviction, or
an agent_id mismatch), a raw FK failure would be swallowed by ingest and Deep
Analysis would go empty with no signal. insert_payload now self-heals.

Uses pg_manager_dsn (conftest.py) — a freshly CREATEd, then DROPped, real
Postgres database per test.
"""
from __future__ import annotations

from manager.manager.db import Database


async def test_insert_payload_self_heals_missing_agent(pg_manager_dsn):
    db = Database(pg_manager_dsn); await db.init()
    try:
        # No upsert_agent first — the silent-loss scenario.
        await db.insert_payload("ghost-agent", "metrics", 1_700_000_000, {"cpu": 42})
        rows = await db.query_section("ghost-agent", "metrics", limit=5)
        assert len(rows) == 1, "raw payload must persist even with no agent row"
    finally:
        await db.close()


async def test_insert_payload_normal_path(pg_manager_dsn):
    db = Database(pg_manager_dsn); await db.init()
    try:
        await db.upsert_agent("mac-1", "Test", "127.0.0.1")
        await db.insert_payload("mac-1", "ports", 1_700_000_000, [{"port": 4444}])
        assert len(await db.query_section("mac-1", "ports", limit=5)) == 1
    finally:
        await db.close()
