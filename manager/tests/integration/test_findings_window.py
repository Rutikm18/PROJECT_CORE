"""
Integration tests for the findings-list time-window filter.

Requires a live Postgres: docker compose up -d postgres
Run: python3 -m pytest manager/tests/integration/test_findings_window.py -v
"""
import time
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from manager.manager.api.findings import make_findings_router
from manager.manager.indexer import IntelDB


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def intel_db(pg_intel_dsn):
    db = IntelDB(pg_intel_dsn)
    await db.init()
    yield db
    await db.close()


@pytest.fixture
async def seed_findings(intel_db):
    """Insert three findings at known first_detected_at times and return their IDs."""
    now = int(time.time())
    # recent: now - 10 (within 1h window)
    # mid: now - 4000 (within 6h window but not 1h)
    # old: now - 800000 (only within 30d window)
    async def _insert(offset, title):
        ts = float(now - offset)
        # Use the indexer's upsert path with a unique fingerprint
        row = await intel_db._fetchone(
            """
            INSERT INTO findings
              (external_id, fingerprint, agent_id, category, item_key, title, severity, score,
               first_detected_at, last_detected_at, is_active, status, terrain_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1,'new','origin')
            RETURNING id
            """,
            (f"test-{title}", f"fp-{title}", "agent-test", "test", title, title, "medium", 0.5, ts),
        )
        return row["id"]

    async def _insert_split(first_offset, last_offset, title):
        """A finding first seen long ago but last re-detected recently."""
        first_ts = float(now - first_offset)
        last_ts = float(now - last_offset)
        row = await intel_db._fetchone(
            """
            INSERT INTO findings
              (external_id, fingerprint, agent_id, category, item_key, title, severity, score,
               first_detected_at, last_detected_at, is_active, status, terrain_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,'new','origin')
            RETURNING id
            """,
            (f"test-{title}", f"fp-{title}", "agent-test", "test", title, title, "medium", 0.5, first_ts, last_ts),
        )
        return row["id"]

    recent_id = await _insert(10, "recent")
    mid_id    = await _insert(4000, "mid")
    old_id    = await _insert(800000, "old")
    # First seen 800000s ago, still active (last seen 5s ago) — must appear in
    # even a 1h window under interval-overlap semantics.
    old_active_id = await _insert_split(800000, 5, "old-active")
    return {"now": now, "recent_id": recent_id, "mid_id": mid_id,
            "old_id": old_id, "old_active_id": old_active_id}


@pytest.fixture
async def client(intel_db):
    app = FastAPI()
    app.include_router(make_findings_router(intel_db), prefix="/api/v1/soc")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as value:
        yield value


async def test_findings_list_filters_by_window(client, seed_findings):
    now = seed_findings["now"]
    r = await client.get("/api/v1/soc/findings", params={"window": "1h"})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["recent_id"] in ids
    assert seed_findings["old_id"] not in ids


async def test_old_but_active_finding_shows_in_short_window(client, seed_findings):
    """Interval-overlap: a finding first seen long ago but re-detected seconds
    ago is a live threat and MUST appear in a 1h window (regression: the old
    first_detected_at-only filter hid it, emptying short windows)."""
    r = await client.get("/api/v1/soc/findings", params={"window": "1h"})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["old_active_id"] in ids


async def test_findings_list_absolute_range(client, seed_findings):
    now = seed_findings["now"]
    r = await client.get("/api/v1/soc/findings",
                         params={"start": now - 5000, "end": now - 3000})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["mid_id"] in ids
    assert seed_findings["recent_id"] not in ids


async def test_findings_list_bad_range_422(client):
    r = await client.get("/api/v1/soc/findings", params={"start": 100, "end": 50})
    assert r.status_code == 422
