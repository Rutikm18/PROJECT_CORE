"""
Backend integrity checks for the SOC detection workflow:

* exploitability is computed at the finding write chokepoint
* direct ID lookup respects selected agent filters
* case timelines include SOC analyst actions and case notes
* validated-finding stats are scoped to the selected agent
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.cases import make_cases_router
from manager.manager.api.findings import make_findings_router
from manager.manager.indexer import IntelDB


async def _mk_db(dsn: str) -> IntelDB:
    idb = IntelDB(dsn)
    await idb.init()
    return idb


def _make_app(idb: IntelDB) -> FastAPI:
    app = FastAPI()
    app.include_router(make_findings_router(idb), prefix="/api/v1/soc")
    app.include_router(make_cases_router(idb), prefix="/api/v1/cases")
    return app


async def _seed_finding(idb: IntelDB, *, agent_id: str, item_key: str, **overrides) -> dict:
    await idb.upsert_finding({
        "agent_id": agent_id,
        "category": "package",
        "item_key": item_key,
        "severity": "critical",
        "score": 9.0,
        "title": item_key,
        "source": "nvd",
        "rule_id": "nvd",
        "precision_score": 0.95,
        "cvss_score": 9.8,
        "epss_score": 0.72,
        "kev": True,
        "exploit_available": True,
        "exploit_sources": ["metasploit", "exploitdb:verified"],
        "asset_tier": "server",
        **overrides,
    }, time.time())
    rows = await idb.get_soc_findings(agent_id=agent_id, active_only=True, limit=10)
    return next(r for r in rows if r["item_key"] == item_key)


@pytest.mark.asyncio
async def test_upsert_computes_exploitability_and_id_search_respects_agent(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        a1 = await _seed_finding(idb, agent_id="agent-a", item_key="openssl-cve")
        await _seed_finding(idb, agent_id="agent-b", item_key="curl-cve")

        assert a1["exploitability_score"] >= 90
        assert a1["exploitability_band"] == "critical"

        visible = await idb.search_by_external_id(
            a1["external_id"], active_only=True, agent_id="agent-a",
        )
        hidden = await idb.search_by_external_id(
            a1["external_id"], active_only=True, agent_id="agent-b",
        )
        assert [r["id"] for r in visible] == [a1["id"]]
        assert hidden == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_case_timeline_merges_soc_activity_without_case_duplicates(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        finding = await _seed_finding(idb, agent_id="agent-a", item_key="timeline-cve")
        fid = finding["id"]
        app = _make_app(idb)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(f"/api/v1/cases/{fid}")
            assert r.status_code == 200, r.text
            assert r.json() == {}

            r = await c.get("/api/v1/cases/999999")
            assert r.status_code == 404, r.text

            r = await c.put(
                "/api/v1/cases/999999",
                json={"status": "triaging", "actor": "alice"},
            )
            assert r.status_code == 404, r.text

            r = await c.post(
                f"/api/v1/cases/{fid}/notes",
                json={"actor": "alice", "note": "   "},
            )
            assert r.status_code == 422, r.text

            r = await c.patch(
                f"/api/v1/soc/findings/{fid}",
                json={"status": "triaging", "actor": "alice"},
            )
            assert r.status_code == 200, r.text

            r = await c.put(
                f"/api/v1/cases/{fid}",
                json={
                    "status": "investigating",
                    "assignee": "bob",
                    "priority": 2,
                    "notes": "opened for review",
                    "actor": "bob",
                },
            )
            assert r.status_code == 200, r.text

            r = await c.put(
                f"/api/v1/cases/{fid}",
                json={
                    "status": "investigating",
                    "assignee": "carol",
                    "priority": 2,
                    "notes": "owner changed",
                    "actor": "bob",
                },
            )
            assert r.status_code == 200, r.text

            r = await c.post(
                f"/api/v1/cases/{fid}/notes",
                json={"actor": "carol", "note": "confirmed exploitable service"},
            )
            assert r.status_code == 201, r.text

            case_timeline = (await c.get(f"/api/v1/cases/{fid}/timeline")).json()["timeline"]
            soc_timeline = (await c.get(f"/api/v1/soc/findings/{fid}/timeline")).json()["timeline"]

            r = await c.post(
                "/api/v1/cases/999999/notes",
                json={"actor": "alice", "note": "should not create orphan timeline"},
            )
            assert r.status_code == 404, r.text

            r = await c.get("/api/v1/cases/999999/timeline")
            assert r.status_code == 404, r.text

        def stable(events: list[dict]) -> list[tuple]:
            return [
                (e["source"], e["actor"], e["action"], e.get("from_status"),
                 e.get("to_status"), e.get("note"))
                for e in events
            ]

        assert stable(case_timeline) == stable(soc_timeline)
        actions = [e["action"] for e in soc_timeline]
        assert "status change" in actions
        assert "opened" in actions
        assert "case assigned" in actions
        assert "case updated" in actions
        assert "note" in actions

        status_events = [e for e in soc_timeline if e.get("raw_action") == "status_change"]
        assert status_events[0]["actor"] == "alice"
        assert status_events[0]["from_status"] == "new"
        assert status_events[0]["to_status"] == "triaging"

        note_events = [e for e in soc_timeline if e.get("note") == "confirmed exploitable service"]
        assert len(note_events) == 1

        opened_events = [e for e in soc_timeline if e["action"] == "opened"]
        assert opened_events[0]["source"] == "case"
        assignment_events = [e for e in soc_timeline if e.get("raw_action") == "case_assigned"]
        assert assignment_events[0]["source"] == "soc_activity"
        assert assignment_events[0]["note"] == "bob -> carol"
        assert soc_timeline == sorted(
            soc_timeline,
            key=lambda e: (e.get("created_at") or 0, e.get("id") or 0),
        )
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_validated_findings_stats_are_scoped_to_agent_filter(pg_intel_dsn):
    idb = await _mk_db(pg_intel_dsn)
    try:
        await _seed_finding(idb, agent_id="agent-a", item_key="a-high", precision_score=0.95)
        await _seed_finding(idb, agent_id="agent-a", item_key="a-low", precision_score=0.50)
        await _seed_finding(idb, agent_id="agent-b", item_key="b-high", precision_score=0.95)

        app = _make_app(idb)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/soc/findings?validated_only=true&agent_id=agent-a&limit=500")
        assert r.status_code == 200, r.text
        body = r.json()

        assert [f["agent_id"] for f in body["findings"]] == ["agent-a"]
        assert body["stats"]["active_total"] == 2
        assert body["stats"]["validated_count"] == 1
        assert body["stats"]["below_threshold"] == 1
    finally:
        await idb.close()
