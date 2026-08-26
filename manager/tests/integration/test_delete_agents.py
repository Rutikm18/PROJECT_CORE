"""
manager/tests/integration/test_delete_agents.py — delete_agent against real
Postgres: an agent's rows are removed across every table (including the
detection_event_chunks cascade and the intel database), a second agent is left
completely untouched, and the CLI orchestration (_run) does the same end to end.
"""
from __future__ import annotations

import argparse

from manager.manager.db import Database
from manager.manager.indexer import INTEL_AGENT_SCOPED_TABLES, IntelDB
from manager.manager.scripts import delete_agents as da

A, B = "agent-A", "agent-B"


async def _count(pool, sql: str, params: tuple) -> int:
    async with pool.read() as conn:
        async with conn.execute(sql, params) as cur:
            row = await cur.fetchone()
    return int(row["c"])


async def _seed_manager(db: Database, agent_id: str) -> None:
    await db.upsert_agent(agent_id, f"host-{agent_id}", "1.2.3.4")
    ev = f"ev-{agent_id}"
    async with db._pool.write() as conn:
        await conn.execute(
            "INSERT INTO agent_keys(agent_id, api_key_hex, enrolled_at) VALUES (?,?,?)",
            (agent_id, "deadbeef", 1),
        )
        await conn.execute(
            "INSERT INTO payloads(event_id, agent_id, section, collected_at, received_at, data) "
            "VALUES (?,?,?,?,?,?)",
            (f"p-{agent_id}", agent_id, "processes", 1, 1, "{}"),
        )
        # NB: upsert_agent() already opened one agent_sessions row for this agent.
        await conn.execute(
            "INSERT INTO detection_events(event_id, agent_id, section, collected_at, received_at, payload_json) "
            "VALUES (?,?,?,?,?,?)",
            (ev, agent_id, "processes", 1, 1, "{}"),
        )
        await conn.execute(
            "INSERT INTO detection_event_chunks(event_id, chunk_index, processed_at) VALUES (?,?,?)",
            (ev, 0, 1.0),
        )
        await conn.commit()


async def test_delete_agent_cascades_and_isolates(pg_manager_dsn):
    db = Database(pg_manager_dsn)
    await db.init()
    try:
        await _seed_manager(db, A)
        await _seed_manager(db, B)

        counts = await db.delete_agent(A)

        # Every table the agent touched reports exactly one row removed.
        assert counts["agents"] == 1
        assert counts["agent_keys"] == 1
        assert counts["payloads"] == 1
        assert counts["agent_sessions"] == 1
        assert counts["detection_events"] == 1
        assert counts["detection_event_chunks"] == 1

        # A is gone everywhere; B is entirely untouched.
        for table in ("agents", "agent_keys", "payloads", "agent_sessions", "detection_events"):
            assert await _count(db._pool, f"SELECT COUNT(*) c FROM {table} WHERE agent_id=?", (A,)) == 0
            assert await _count(db._pool, f"SELECT COUNT(*) c FROM {table} WHERE agent_id=?", (B,)) == 1
        assert await _count(db._pool, "SELECT COUNT(*) c FROM detection_event_chunks WHERE event_id=?", (f"ev-{A}",)) == 0
        assert await _count(db._pool, "SELECT COUNT(*) c FROM detection_event_chunks WHERE event_id=?", (f"ev-{B}",)) == 1
    finally:
        await db.close()


async def test_intel_delete_agent_isolates_and_covers_every_table(pg_intel_dsn):
    intel = IntelDB(pg_intel_dsn)
    await intel.init()
    try:
        async with intel._pool.write() as conn:
            await conn.execute("INSERT INTO asset_registry(agent_id) VALUES (?)", (A,))
            await conn.execute("INSERT INTO asset_registry(agent_id) VALUES (?)", (B,))
            await conn.commit()

        # A ghost delete proves every DELETE targets a table that actually exists
        # (a typo'd table name would raise here, not return 0).
        ghost = await intel.delete_agent("no-such-agent")
        assert set(ghost) == set(INTEL_AGENT_SCOPED_TABLES)
        assert all(v == 0 for v in ghost.values())

        counts = await intel.delete_agent(A)
        assert counts["asset_registry"] == 1
        assert await _count(intel._pool, "SELECT COUNT(*) c FROM asset_registry WHERE agent_id=?", (A,)) == 0
        assert await _count(intel._pool, "SELECT COUNT(*) c FROM asset_registry WHERE agent_id=?", (B,)) == 1
    finally:
        await intel.close()


async def test_list_and_count_are_read_only(pg_manager_dsn, pg_intel_dsn):
    db, intel = Database(pg_manager_dsn), IntelDB(pg_intel_dsn)
    await db.init()
    await intel.init()
    try:
        await _seed_manager(db, A)
        await _seed_manager(db, B)
        async with intel._pool.write() as conn:
            await conn.execute("INSERT INTO asset_registry(agent_id) VALUES (?)", (A,))
            await conn.commit()

        assert {a["agent_id"] for a in await db.list_agents()} >= {A, B}

        counts = {**await db.count_agent_rows(A), **await intel.count_agent_rows(A)}
        assert counts["agents"] == 1
        assert counts["payloads"] == 1
        assert counts["detection_events"] == 1
        assert counts["detection_event_chunks"] == 1
        assert counts["asset_registry"] == 1

        # counting must not delete — the agent and its rows are still there
        assert await db.agent_exists(A) is True
        assert (await db.count_agent_rows(A))["agents"] == 1
    finally:
        await intel.close()
        await db.close()


async def test_cli_all_deletes_every_agent(pg_manager_dsn, pg_intel_dsn, monkeypatch):
    monkeypatch.setenv("MANAGER_DATABASE_URL", pg_manager_dsn)
    monkeypatch.setenv("INTEL_DATABASE_URL", pg_intel_dsn)
    db, intel = Database(pg_manager_dsn), IntelDB(pg_intel_dsn)
    await db.init()
    await intel.init()
    try:
        await _seed_manager(db, A)
        await _seed_manager(db, B)
        assert len(await db.list_agents()) == 2

        args = argparse.Namespace(list=False, all=True, agents=None,
                                  older_than=None, dry_run=False, yes=True)
        assert await da._run(args) == 0

        assert await db.list_agents() == []
        assert await _count(db._pool, "SELECT COUNT(*) c FROM agents WHERE agent_id=?", (A,)) == 0
        assert await _count(db._pool, "SELECT COUNT(*) c FROM agents WHERE agent_id=?", (B,)) == 0
    finally:
        await intel.close()
        await db.close()


async def test_cli_run_deletes_end_to_end(pg_manager_dsn, pg_intel_dsn, monkeypatch):
    monkeypatch.setenv("MANAGER_DATABASE_URL", pg_manager_dsn)
    monkeypatch.setenv("INTEL_DATABASE_URL", pg_intel_dsn)

    db, intel = Database(pg_manager_dsn), IntelDB(pg_intel_dsn)
    await db.init()
    await intel.init()
    try:
        await _seed_manager(db, "agent-C")
        async with intel._pool.write() as conn:
            await conn.execute("INSERT INTO asset_registry(agent_id) VALUES (?)", ("agent-C",))
            await conn.commit()

        def _args(**kw):
            return argparse.Namespace(list=False, all=False, agents=["agent-C"], older_than=None,
                                      dry_run=kw.get("dry_run", False), yes=True)

        # Dry run leaves everything in place.
        assert await da._run(_args(dry_run=True)) == 0
        assert await _count(db._pool, "SELECT COUNT(*) c FROM agents WHERE agent_id=?", ("agent-C",)) == 1
        assert await _count(intel._pool, "SELECT COUNT(*) c FROM asset_registry WHERE agent_id=?", ("agent-C",)) == 1

        # Real run removes it from both databases.
        assert await da._run(_args(dry_run=False)) == 0
        assert await _count(db._pool, "SELECT COUNT(*) c FROM agents WHERE agent_id=?", ("agent-C",)) == 0
        assert await _count(intel._pool, "SELECT COUNT(*) c FROM asset_registry WHERE agent_id=?", ("agent-C",)) == 0
    finally:
        await intel.close()
        await db.close()
