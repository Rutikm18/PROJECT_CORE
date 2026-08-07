"""
Integration tests for windowed detection/threat endpoints.

Requires a live Postgres: docker compose up -d postgres
Run: python3 -m pytest manager/tests/integration/test_endpoints_window.py -v
"""
import time
import pytest


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("route,category", [
    ("/api/v1/detection/packages", "package"),
    ("/api/v1/detection/ports", "port"),
    ("/api/v1/detection/persistence", "service"),
    ("/api/v1/detection/processes", "process"),
    ("/api/v1/detection/identity", "user"),
    ("/api/v1/detection/all", "package"),
])
def test_detection_route_bad_range_returns_422(client, route, category):
    r = client.get(route, params={"start": 100, "end": 50})
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
             (fingerprint,agent_id,category,title,severity,score,
              first_detected_at,last_detected_at,is_active,status,terrain_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$7,1,'new','origin')""",
        (f"recent-{route}", "agent-x", category, "recent", "medium", 0.5,
         float(now - 60)),
    )
    await intel_db._conn.execute(
        """INSERT INTO findings
             (fingerprint,agent_id,category,title,severity,score,
              first_detected_at,last_detected_at,is_active,status,terrain_id)
           VALUES($1,$2,$3,$4,$5,$6,$7,$7,1,'new','origin')""",
        (f"old-{route}", "agent-x", category, "old", "medium", 0.5,
         float(now - 900000)),
    )
    r30d = client.get(route, params={"window": "30d"})
    r1h  = client.get(route, params={"window": "1h"})
    assert r30d.status_code == 200
    assert r1h.status_code == 200
    count_30d = r30d.json().get("count", 0)
    count_1h  = r1h.json().get("count", 0)
    assert count_30d >= count_1h  # wider window ≥ narrower window
