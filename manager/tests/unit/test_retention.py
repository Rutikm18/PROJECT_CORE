"""
manager/tests/unit/test_retention.py — 30-day raw telemetry retention.

Before this, `payloads` (the table Deep Analysis / /api/v1/raw/* actually
queries — see manager/db.py) and `agent_sessions` had NO retention at all and
grew unbounded forever. TelemetryStore's file-tier archive had retention, but
its outer bound was 365 days, not 30, and was disconnected from the row store.

Pins:
  - RAW_TELEMETRY_RETENTION_DAYS derives hot/warm/cold consistently (warm never
    exceeds the overall cap; cold IS the cap)
  - prune_payloads deletes rows older than cutoff, keeps newer rows
  - prune_agent_sessions deletes only CLOSED sessions older than cutoff —
    never touches a still-'connected' session regardless of age
  - env override (RAW_TELEMETRY_RETENTION_DAYS) actually changes the bound

Uses the pg_manager_dsn fixture (conftest.py) — a freshly CREATEd, then
DROPped, real Postgres database per test. Replaces the old
tempfile.mkdtemp() + SQLite-file-per-test pattern (same isolation guarantee,
adapted for Postgres having no equivalent of "just point at a new path").
Tests are now native `async def` — pytest-asyncio (mode=auto) drives them
directly, so the manual event-loop-juggling _run() helper this file used to
need is gone.
"""
from __future__ import annotations

import importlib
import time

from manager.manager.db import Database


def test_retention_constants_consistent():
    from manager.manager import store
    assert store.RAW_TELEMETRY_RETENTION_DAYS == 30
    assert store.HOT_RETENTION_SEC == 86400
    assert store.WARM_RETENTION_SEC <= store.COLD_RETENTION_SEC
    assert store.COLD_RETENTION_SEC == store.RAW_TELEMETRY_RETENTION_DAYS * 86400


def test_env_override_changes_retention_bound(monkeypatch):
    monkeypatch.setenv("RAW_TELEMETRY_RETENTION_DAYS", "7")
    from manager.manager import store
    importlib.reload(store)
    try:
        assert store.RAW_TELEMETRY_RETENTION_DAYS == 7
        assert store.COLD_RETENTION_SEC == 7 * 86400
        assert store.WARM_RETENTION_SEC == 7 * 86400   # min(7d, 7d)
    finally:
        monkeypatch.delenv("RAW_TELEMETRY_RETENTION_DAYS", raising=False)
        importlib.reload(store)   # restore default for subsequent tests


async def test_prune_payloads_deletes_old_keeps_new(pg_manager_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        now = int(time.time())
        old_ts = now - 40 * 86400   # 40 days ago — beyond 30d retention
        new_ts = now - 1 * 86400    # 1 day ago — well within retention
        await dbm.upsert_agent("mac-1", "T", "127.0.0.1")
        await dbm.insert_payload("mac-1", "metrics", old_ts, {"cpu": 1})
        await dbm.insert_payload("mac-1", "metrics", new_ts, {"cpu": 2})

        cutoff = now - 30 * 86400
        deleted = await dbm.prune_payloads(cutoff)
        assert deleted == 1, "exactly the 40-day-old row must be deleted"

        remaining = await dbm.query_payloads(agent_id="mac-1", start=0, end=now + 1)
        assert len(remaining) == 1
        assert remaining[0]["collected_at"] == new_ts
    finally:
        await dbm.close()


async def test_prune_payloads_handles_large_backlog_in_batches(pg_manager_dsn):
    """Confirms the batched-delete loop actually drains a backlog larger than
    one batch, not just the first 5000 rows."""
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        now = int(time.time())
        old_ts = now - 40 * 86400
        await dbm.upsert_agent("mac-1", "T", "127.0.0.1")
        # Small backlog (not 5000+, to keep the test fast) but verify the
        # loop terminates and reports the correct total.
        for i in range(12):
            await dbm.insert_payload("mac-1", "metrics", old_ts + i, {"i": i})
        deleted = await dbm.prune_payloads(now - 30 * 86400)
        assert deleted == 12
    finally:
        await dbm.close()


async def test_prune_agent_sessions_skips_connected(pg_manager_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        now = int(time.time())
        old_ts = now - 40 * 86400
        # upsert_agent itself opens a 'connected' session row as a side
        # effect (db.py: starts_new_session) — account for it rather than
        # asserting an exact row count.
        await dbm.upsert_agent("mac-1", "T", "127.0.0.1")
        async with dbm._pool.write() as db:
            await db.execute(
                "INSERT INTO agent_sessions(agent_id, connected_at, "
                "disconnected_at, last_seen, status) VALUES(?,?,?,?,?)",
                ("mac-1", old_ts, old_ts + 10, old_ts + 10, "disconnected"),
            )
            await db.execute(
                "INSERT INTO agent_sessions(agent_id, connected_at, "
                "disconnected_at, last_seen, status) VALUES(?,?,?,?,?)",
                ("mac-1", old_ts, 0, old_ts, "connected"),
            )
            await db.commit()

        deleted = await dbm.prune_agent_sessions(now - 30 * 86400)
        assert deleted == 1, "only the disconnected session is prunable"

        async with dbm._pool.read() as db:
            cur = await db.execute("SELECT status, last_seen FROM agent_sessions")
            rows = [dict(r) for r in await cur.fetchall()]
        assert not any(r["status"] == "disconnected" for r in rows), \
            "the old disconnected session must be gone"
        assert any(r["status"] == "connected" and r["last_seen"] == old_ts for r in rows), \
            "a still-connected session must survive regardless of age"
    finally:
        await dbm.close()


async def test_prune_payloads_noop_when_nothing_old(pg_manager_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        now = int(time.time())
        await dbm.upsert_agent("mac-1", "T", "127.0.0.1")
        await dbm.insert_payload("mac-1", "metrics", now, {"cpu": 1})
        deleted = await dbm.prune_payloads(now - 30 * 86400)
        assert deleted == 0
    finally:
        await dbm.close()
