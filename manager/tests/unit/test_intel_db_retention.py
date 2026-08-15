"""
manager/tests/unit/test_intel_db_retention.py — bound intel.db to the same
retention window as raw telemetry (Settings → Data Retention), per explicit
user request after the live intel.db was found corrupted at 580MB with a
799-row dead-agent backlog: "store last 30 days at this point only ...
should only [keep] required data only".

Pins:
  - prune_inactive() removes resolved findings / closed correlations /
    timeline events older than cutoff
  - a currently-active finding/correlation is NEVER removed regardless of
    age — this is a historical-backlog bound, not a correctness regression
    that could drop a real, currently-true finding
  - wired into the same hourly _cleanup_store job as payloads/store cleanup

Uses the pg_intel_dsn fixture (conftest.py) — a freshly CREATEd, then DROPped,
real Postgres database per test (replaces tempfile.mkdtemp() + SQLite file).
Tests are native `async def` — pytest-asyncio (mode=auto) drives them
directly, no manual event-loop _run() helper needed.
"""
from __future__ import annotations

import time

from manager.manager.indexer import IntelDB


async def test_prune_inactive_removes_old_resolved_findings(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        old, new = now - 40 * 86400, now - 1 * 86400
        await idb.upsert_finding({
            "agent_id": "a1", "category": "process", "item_key": "old",
            "severity": "high", "score": 7.0, "title": "old resolved",
            "source": "rule:x", "rule_id": "rule:x", "evidence": {},
        }, old)
        await idb.mark_resolved("a1", 1)
        # mark_resolved stamps resolved_at=now; backdate last_detected_at
        # directly so the test controls "how old" independent of wall clock.
        await idb._conn.execute("UPDATE findings SET last_detected_at=? WHERE id=1", (old,))
        await idb._conn.commit()

        await idb.upsert_finding({
            "agent_id": "a1", "category": "process", "item_key": "new",
            "severity": "high", "score": 7.0, "title": "new resolved",
            "source": "rule:x", "rule_id": "rule:x", "evidence": {},
        }, new)
        await idb.mark_resolved("a1", 2)
        await idb._conn.execute("UPDATE findings SET last_detected_at=? WHERE id=2", (new,))
        await idb._conn.commit()

        deleted = await idb.prune_inactive(now - 30 * 86400)
        assert deleted["findings"] == 1

        remaining = await idb.get_soc_findings(active_only=False, limit=10)
        assert len(remaining) == 1
        assert remaining[0]["item_key"] == "new"
    finally:
        await idb.close()


async def test_prune_inactive_never_removes_active_finding_regardless_of_age(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        very_old = now - 400 * 86400
        await idb.upsert_finding({
            "agent_id": "a1", "category": "process", "item_key": "still-active",
            "severity": "high", "score": 7.0, "title": "ancient but still true",
            "source": "rule:x", "rule_id": "rule:x", "evidence": {},
        }, very_old)
        await idb._conn.execute(
            "UPDATE findings SET last_detected_at=? WHERE item_key='still-active'",
            (very_old,),
        )
        await idb._conn.commit()

        deleted = await idb.prune_inactive(now - 30 * 86400)
        assert deleted["findings"] == 0

        remaining = await idb.get_soc_findings(active_only=True, limit=10)
        assert len(remaining) == 1
    finally:
        await idb.close()


async def test_prune_inactive_removes_old_closed_correlations(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        old = now - 40 * 86400
        await idb._conn.execute(
            "INSERT INTO correlations(agent_id, rule_id, severity, score, title, "
            "description, first_detected, last_detected, is_active) "
            "VALUES('a1','rule:c','high',8.0,'t','d',?,?,0)",
            (old, old),
        )
        await idb._conn.commit()
        deleted = await idb.prune_inactive(now - 30 * 86400)
        assert deleted["correlations"] == 1
    finally:
        await idb.close()


async def test_prune_inactive_never_removes_active_correlation(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        old = now - 400 * 86400
        await idb._conn.execute(
            "INSERT INTO correlations(agent_id, rule_id, severity, score, title, "
            "description, first_detected, last_detected, is_active) "
            "VALUES('a1','rule:c','high',8.0,'t','d',?,?,1)",
            (old, old),
        )
        await idb._conn.commit()
        deleted = await idb.prune_inactive(now - 30 * 86400)
        assert deleted["correlations"] == 0
    finally:
        await idb.close()


async def test_prune_inactive_removes_old_timeline_events_unconditionally(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        old, new = now - 40 * 86400, now - 1 * 86400
        await idb._conn.execute(
            "INSERT INTO change_timeline(agent_id, category, change_type, "
            "item_key, title, detected_at) VALUES('a1','process','new','k','t',?)",
            (old,),
        )
        await idb._conn.execute(
            "INSERT INTO change_timeline(agent_id, category, change_type, "
            "item_key, title, detected_at) VALUES('a1','process','new','k2','t2',?)",
            (new,),
        )
        await idb._conn.commit()
        deleted = await idb.prune_inactive(now - 30 * 86400)
        assert deleted["change_timeline"] == 1
    finally:
        await idb.close()


async def test_prune_inactive_noop_on_empty_db(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        deleted = await idb.prune_inactive(time.time() - 30 * 86400)
        assert deleted == {
            "findings": 0,
            "correlations": 0,
            "change_timeline": 0,
            "notification_deliveries": 0,
        }
    finally:
        await idb.close()
