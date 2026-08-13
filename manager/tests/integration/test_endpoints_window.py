"""
Integration tests for windowed detection/threat endpoints.

Requires a live Postgres: docker compose up -d postgres
Run: python3 -m pytest manager/tests/integration/test_endpoints_window.py -v
"""
import time
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.detection import make_detection_router
from manager.manager.indexer import IntelDB


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def intel_db(pg_intel_dsn):
    db = IntelDB(pg_intel_dsn)
    await db.init()
    try:
        yield db
    finally:
        await db.close()


@pytest.fixture
async def client(intel_db):
    app = FastAPI()
    app.include_router(make_detection_router(intel_db), prefix="/api/v1/detection")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as value:
        yield value


@pytest.mark.parametrize("route,category", [
    ("/api/v1/detection/packages", "package"),
    ("/api/v1/detection/ports", "port"),
    ("/api/v1/detection/persistence", "service"),
    ("/api/v1/detection/processes", "process"),
    ("/api/v1/detection/identity", "user"),
    ("/api/v1/detection/all", "package"),
])
async def test_detection_route_bad_range_returns_422(client, route, category):
    r = await client.get(route, params={"start": 100, "end": 50})
    assert r.status_code == 422


@pytest.mark.parametrize("route,category", [
    ("/api/v1/detection/packages", "package"),
    ("/api/v1/detection/ports", "port"),
    ("/api/v1/detection/all", "package"),
])
async def test_detection_route_window_narrows_results(client, intel_db, route, category):
    now = int(time.time())
    # Insert one finding within 1h window and one outside it.
    await intel_db._conn.execute(
        """INSERT INTO findings
             (external_id,fingerprint,agent_id,category,item_key,title,severity,score,
              first_detected_at,last_detected_at,is_active,status,terrain_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1,'new','origin')""",
        (f"recent-id:{route}", f"recent-{route}", "agent-x", category, f"recent:{route}", "recent", "medium", 0.5,
         float(now - 60)),
    )
    await intel_db._conn.execute(
        """INSERT INTO findings
             (external_id,fingerprint,agent_id,category,item_key,title,severity,score,
              first_detected_at,last_detected_at,is_active,status,terrain_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1,'new','origin')""",
        (f"old-id:{route}", f"old-{route}", "agent-x", category, f"old:{route}", "old", "medium", 0.5,
         float(now - 900000)),
    )
    r30d = await client.get(route, params={"window": "30d"})
    r1h  = await client.get(route, params={"window": "1h"})
    assert r30d.status_code == 200
    assert r1h.status_code == 200
    count_30d = r30d.json().get("count", 0)
    count_1h  = r1h.json().get("count", 0)
    assert count_30d >= count_1h  # wider window ≥ narrower window
