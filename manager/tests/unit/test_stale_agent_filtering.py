"""
manager/tests/unit/test_stale_agent_filtering.py — exclude stale-agent
findings from fleet-wide views, and the FTS5 search crash fix.

Root cause this addresses (confirmed live against the real deployment data):
an agent that stopped reporting 16 days ago still had 794 findings marked
is_active=1 — auto_resolve_absent (engine.py) can't catch this because it
only fires when a FRESH payload arrives; a silent agent never sends one.
Incidents / Attack Terrain pages showed this data as if it were current,
and cross-checking against the live agent list found nothing — i.e. exactly
"data that isn't actually coming from agents".

Fix: get_soc_findings/get_active_findings_global accept live_agent_ids and
exclude anything else — but ONLY for fleet-wide (no explicit agent_id) reads
of active data; an analyst explicitly viewing one (possibly offline) agent's
findings is never filtered.

Also pins the FTS5 search fix: get_soc_findings(search=...) used to LEFT JOIN
a subquery selecting `agents` — a table that only exists in manager.db, a
different SQLite file from intel.db. Every search request threw
"no such table: agents". Reproduced directly against the live database before
fixing; pinned here so it can't regress silently.

Uses pg_intel_dsn/pg_manager_dsn (conftest.py) — freshly CREATEd, then
DROPped, real Postgres databases.
"""
from __future__ import annotations

import time

from manager.manager.indexer import IntelDB, FLEET_AGENT_ID
from manager.manager.db import Database


async def _seed_finding(idb, agent_id, category="process", **overrides):
    f = {
        "agent_id": agent_id, "category": category,
        "item_key": f"{category}:{agent_id}", "severity": "high", "score": 7.0,
        "title": f"finding for {agent_id}", "source": "rule:test", "rule_id": "rule:test",
        "evidence": {}, **overrides,
    }
    await idb.upsert_finding(f, time.time())


async def test_get_soc_findings_excludes_stale_agent_when_no_agent_filter(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "live-host")
        await _seed_finding(idb, "stale-host")

        rows = await idb.get_soc_findings(live_agent_ids=["live-host"])
        assert {r["agent_id"] for r in rows} == {"live-host"}
    finally:
        await idb.close()


async def test_get_soc_findings_explicit_agent_id_ignores_staleness(pg_intel_dsn):
    """An analyst explicitly investigating a (possibly offline) agent must
    still see its findings — staleness filtering only applies to fleet-wide,
    no-agent-filter reads."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "stale-host")

        rows = await idb.get_soc_findings(agent_id="stale-host", live_agent_ids=["live-host"])
        assert len(rows) == 1
        assert rows[0]["agent_id"] == "stale-host"
    finally:
        await idb.close()


async def test_get_soc_findings_historical_view_ignores_staleness(pg_intel_dsn):
    """active_only=False (closed/all views) is browsing history, not 'current
    fleet state' — staleness filtering must not hide it."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "stale-host")
        await idb.mark_resolved("stale-host", 1)

        rows = await idb.get_soc_findings(active_only=False, live_agent_ids=["live-host"])
        assert len(rows) == 1
    finally:
        await idb.close()


async def test_get_soc_findings_none_live_ids_is_unfiltered(pg_intel_dsn):
    """live_agent_ids=None (the default) must behave exactly as before this
    change — callers that haven't computed agent liveness aren't affected."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "host-a")
        await _seed_finding(idb, "host-b")
        rows = await idb.get_soc_findings()
        assert {r["agent_id"] for r in rows} == {"host-a", "host-b"}
    finally:
        await idb.close()


async def test_get_soc_findings_empty_live_ids_returns_nothing(pg_intel_dsn):
    """No live agents at all (e.g. fresh manager, nothing has reported yet) —
    must short-circuit to empty, not emit invalid SQL like 'IN ()'."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "host-a")
        rows = await idb.get_soc_findings(live_agent_ids=[])
        assert rows == []
    finally:
        await idb.close()


async def test_search_path_does_not_crash(pg_intel_dsn):
    """Regression pin for the 'no such table: agents' crash — confirmed live
    against the real deployment database before this fix existed."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "host-a", title="Suspicious process spawned")
        rows = await idb.get_soc_findings(search="suspicious")
        assert len(rows) == 1
    finally:
        await idb.close()


async def test_search_path_respects_live_agent_filter_too(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "live-host", title="Suspicious process spawned")
        await _seed_finding(idb, "stale-host", title="Suspicious process spawned")
        rows = await idb.get_soc_findings(search="suspicious", live_agent_ids=["live-host"])
        assert {r["agent_id"] for r in rows} == {"live-host"}
    finally:
        await idb.close()


async def test_get_active_findings_global_excludes_stale_agent(pg_intel_dsn):
    """Fleet correlation: a stale agent's lingering finding must not count
    toward a cross-host campaign's min_hosts threshold."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "live-1", category="connection")
        await _seed_finding(idb, "live-2", category="connection")
        await _seed_finding(idb, "stale-3", category="connection")

        rows = await idb.get_active_findings_global(
            categories=["connection"], live_agent_ids=["live-1", "live-2"],
        )
        assert {r["agent_id"] for r in rows} == {"live-1", "live-2"}
    finally:
        await idb.close()


async def test_get_active_findings_global_none_is_unfiltered(pg_intel_dsn):
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "host-a", category="connection")
        rows = await idb.get_active_findings_global(categories=["connection"])
        assert len(rows) == 1
    finally:
        await idb.close()


async def test_get_active_findings_global_still_excludes_fleet_pseudo_agent(pg_intel_dsn):
    """Regression guard: the live_agent_ids addition must not break the
    pre-existing __fleet__ self-recursion exclusion."""
    idb = IntelDB(pg_intel_dsn); await idb.init()
    try:
        await _seed_finding(idb, "live-1", category="connection")
        await idb.upsert_correlation({
            "rule_id": "fleet:test", "category": "connection",
            "agent_id": FLEET_AGENT_ID, "item_key": "fleet:test",
            "severity": "high", "score": 8.0, "title": "t", "description": "",
            "evidence": {}, "affected_assets": ["live-1"],
        }, time.time())
        rows = await idb.get_active_findings_global(
            categories=["connection"], live_agent_ids=["live-1"],
        )
        assert all(r["agent_id"] != FLEET_AGENT_ID for r in rows)
    finally:
        await idb.close()


# ── Database.get_live_agent_ids ──────────────────────────────────────────────

async def test_get_live_agent_ids_excludes_stale(pg_manager_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        now = int(time.time())
        await dbm.upsert_agent("live-host", "Live", "127.0.0.1")
        async with dbm._pool.write() as db:
            await db.execute(
                "UPDATE agents SET last_seen=? WHERE agent_id='live-host'",
                (now,),
            )
            await db.execute(
                "INSERT INTO agents(agent_id, name, last_seen, last_ip, created_at) "
                "VALUES('stale-host','Stale',?,?,?)",
                (now - 20 * 86400, "127.0.0.1", now - 20 * 86400),
            )
            await db.commit()

        live = await dbm.get_live_agent_ids(stale_after_sec=86400)
        assert live == ["live-host"]
    finally:
        await dbm.close()


async def test_get_live_agent_ids_empty_when_nothing_reported(pg_manager_dsn):
    dbm = Database(pg_manager_dsn); await dbm.init()
    try:
        live = await dbm.get_live_agent_ids(stale_after_sec=86400)
        assert live == []
    finally:
        await dbm.close()
