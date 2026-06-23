"""
manager/tests/unit/test_dashboard_stats_perf.py — get_dashboard_stats()
correctness with live_agent_ids, plus the index/plan pins for the queries
this depends on.

Found while continuing the "opening new tabs is slow" investigation: this is
literally the first page most users see, and it ran 16 separate SQL queries
with zero agent-liveness filtering. Two of those queries dominated cost on
the real 18.4k-row findings table (confirmed via EXPLAIN QUERY PLAN + direct
timing): top_agents' GROUP BY agent_id forced a temp B-TREE scan (136ms), and
the 7-day trend loop ran 7 unindexed full-table scans on first_detected_at
(~157ms combined) — together ~290ms of this page's ~305ms total.

Also: zero agent-liveness filtering meant a 16-day-silent agent's 794
findings were baked directly into total_active/critical/top_agents.

Uses the pg_intel_dsn fixture (conftest.py) — a freshly CREATEd, then DROPped,
real Postgres database per test. The two index-plan pin tests now run
Postgres's EXPLAIN (was SQLite's EXPLAIN QUERY PLAN, parsed differently) and
check for "Index ... Scan using <name>" / absence of "Seq Scan" — Postgres's
equivalent of SQLite's SEARCH/SCAN distinction.
"""
from __future__ import annotations

import time

import asyncpg

from manager.manager.indexer import IntelDB


async def _seed(idb, agent_id, severity="critical", **overrides):
    f = {
        "agent_id": agent_id, "category": "process", "item_key": f"k:{agent_id}:{severity}:{overrides.get('item_key','')}",
        "severity": severity, "score": 7.0, "title": "t", "source": "rule:x",
        "rule_id": "rule:x", "evidence": {}, **{k: v for k, v in overrides.items() if k != "item_key"},
    }
    await idb.upsert_finding(f, time.time())


async def test_dashboard_stats_excludes_stale_agent(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "live-host", severity="critical", item_key="1")
        await _seed(idb, "stale-host", severity="critical", item_key="2")

        unfiltered = await idb.get_dashboard_stats()
        assert unfiltered["kpi"]["total_active"] == 2

        filtered = await idb.get_dashboard_stats(live_agent_ids=["live-host"])
        assert filtered["kpi"]["total_active"] == 1
        assert {a["agent_id"] for a in filtered["top_agents"]} == {"live-host"}
    finally:
        await idb.close()


async def test_dashboard_stats_none_is_unfiltered(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "host-a", item_key="1")
        await _seed(idb, "host-b", item_key="2")
        stats = await idb.get_dashboard_stats()
        assert stats["kpi"]["total_active"] == 2
    finally:
        await idb.close()


async def test_dashboard_stats_empty_live_ids_returns_empty_shape(pg_intel_dsn):
    """No live agents at all — must short-circuit cleanly, not crash on an
    empty IN () or error out."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "host-a", item_key="1")
        stats = await idb.get_dashboard_stats(live_agent_ids=[])
        assert stats["kpi"] == {}
        assert stats["top_agents"] == []
        assert stats["daily_trend"] == []
    finally:
        await idb.close()


async def test_dashboard_stats_daily_trend_still_works_with_filter(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "live-host", item_key="1")
        stats = await idb.get_dashboard_stats(live_agent_ids=["live-host"])
        assert len(stats["daily_trend"]) == 7
        assert sum(d["critical"] for d in stats["daily_trend"]) >= 1
    finally:
        await idb.close()


async def test_dashboard_stats_sla_compliance_respects_filter(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "live-host", severity="critical", item_key="1")
        await _seed(idb, "stale-host", severity="critical", item_key="2")
        stats = await idb.get_dashboard_stats(live_agent_ids=["live-host"])
        assert stats["sla_compliance"]["critical"]["total"] == 1
    finally:
        await idb.close()


# ── Index plan pins — confirm the query shapes this method depends on use an
#    index scan, not a sequential scan, so this can't silently regress back
#    to the slow path.

async def test_top_agents_query_uses_index_not_scan(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "host-a", item_key="1")
    finally:
        await idb.close()

    conn = await asyncpg.connect(pg_intel_dsn)
    try:
        plan = await conn.fetch(
            "EXPLAIN SELECT agent_id, COUNT(*) FROM findings "
            "WHERE is_active=1 GROUP BY agent_id ORDER BY 2 DESC LIMIT 5"
        )
    finally:
        await conn.close()
    detail = " ".join(row[0] for row in plan)
    assert "idx_find_active_agent" in detail, detail
    assert "Seq Scan" not in detail, detail


async def test_daily_trend_query_uses_first_detected_index(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed(idb, "host-a", item_key="1")
    finally:
        await idb.close()

    conn = await asyncpg.connect(pg_intel_dsn)
    try:
        plan = await conn.fetch(
            "EXPLAIN SELECT COUNT(*) FROM findings "
            "WHERE first_detected_at >= $1 AND first_detected_at < $2",
            0.0, time.time(),
        )
    finally:
        await conn.close()
    detail = " ".join(row[0] for row in plan)
    assert "idx_find_first_detected" in detail, detail
    assert "Seq Scan" not in detail, detail
