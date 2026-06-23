"""
manager/tests/unit/test_auto_resolve.py — stale-incident auto-resolution.

Point-in-time detections become persistent findings; without reconciliation a
port that closed, a package that was removed, or a process that exited lingers
as an "active incident" (a false positive — the data is no longer present).

These tests pin the fix:
  • auto_resolve_absent() resolves ONLY active findings in the given categories
    whose evidence wasn't re-confirmed by a fresh snapshot (last_detected_at <
    cutoff), and leaves fresh findings, other categories, and other agents alone.
  • _is_live_snapshot() refuses to treat an empty/errored section as a snapshot,
    so "data missed" never mass-resolves real incidents.

Uses pg_intel_dsn (conftest.py) — a freshly CREATEd, then DROPped, real
Postgres database per test.
"""
from __future__ import annotations

import time

from manager.manager.attacklens.engine import _is_live_snapshot
from manager.manager.indexer import IntelDB


async def _seed(idb, agent, category, item_key, last_seen):
    await idb.upsert_finding(
        {"agent_id": agent, "category": category, "item_key": item_key,
         "title": f"{category} {item_key}", "severity": "high", "score": 5.0},
        last_seen,
    )


async def _state(idb, agent):
    rows = await idb._fetchall(
        "SELECT item_key, is_active, status FROM findings WHERE agent_id=?",
        (agent,),
    )
    return {r["item_key"]: (r["is_active"], r["status"]) for r in rows}


async def test_auto_resolve_resolves_only_absent_in_category(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        now = time.time()
        await _seed(idb, "a1", "port", "port:9999", now - 3600)   # stale → resolve
        await _seed(idb, "a1", "port", "port:443",  now)          # fresh → keep
        await _seed(idb, "a1", "process", "proc:x",  now - 3600)  # other cat → keep
        await _seed(idb, "a2", "port", "port:9999", now - 3600)   # other agent → keep

        n = await idb.auto_resolve_absent("a1", ["port"], cutoff_ts=now - 1.0)
        assert n == 1, f"expected exactly one resolution, got {n}"

        s1 = await _state(idb, "a1")
        assert s1["port:9999"] == (0, "auto_resolved")   # closed port → resolved
        assert s1["port:443"][0] == 1                     # still-open port kept
        assert s1["proc:x"][0] == 1                        # different category untouched

        s2 = await _state(idb, "a2")
        assert s2["port:9999"][0] == 1                     # different agent untouched

        # Idempotent: nothing left to resolve.
        assert await idb.auto_resolve_absent("a1", ["port"], cutoff_ts=now - 1.0) == 0
    finally:
        await idb.close()


async def test_empty_categories_is_noop(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "a1", "port", "p", time.time() - 3600)
        assert await idb.auto_resolve_absent("a1", [], cutoff_ts=time.time()) == 0
    finally:
        await idb.close()


def test_is_live_snapshot_guards_against_missed_data():
    # Real snapshots
    assert _is_live_snapshot({"port:443": {"pid": 1}}) is True
    assert _is_live_snapshot([{"port": 443}]) is True
    # "Missed"/broken — must NOT count as a snapshot (would mass-resolve)
    assert _is_live_snapshot({}) is False
    assert _is_live_snapshot([]) is False
    assert _is_live_snapshot(None) is False
    assert _is_live_snapshot({"error": "collector timed out"}) is False
