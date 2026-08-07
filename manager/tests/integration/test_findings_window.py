"""
Integration tests for the findings-list time-window filter.

Requires a live Postgres: docker compose up -d postgres
Run: python3 -m pytest manager/tests/integration/test_findings_window.py -v
"""
import time
import pytest
from fastapi.testclient import TestClient
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
              (fingerprint, agent_id, category, title, severity, score,
               first_detected_at, last_detected_at, is_active, status, terrain_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$7,1,'new','origin')
            RETURNING id
            """,
            (f"fp-{title}", "agent-test", "test", title, "medium", 0.5, ts),
        )
        return row["id"]

    recent_id = await _insert(10, "recent")
    mid_id    = await _insert(4000, "mid")
    old_id    = await _insert(800000, "old")
    return {"now": now, "recent_id": recent_id, "mid_id": mid_id, "old_id": old_id}


@pytest.fixture
def client(intel_db):
    from manager.manager.server import create_app
    from manager.manager.db import Database
    # Create a minimal app with just the findings router wired to our test intel_db.
    # We reuse the app-factory pattern and override the intel_db dependency.
    app = create_app.__wrapped__(intel_db=intel_db)  # best-effort; adjust if create_app signature differs
    return TestClient(app)


def test_findings_list_filters_by_window(client, seed_findings):
    now = seed_findings["now"]
    r = client.get("/api/v1/soc/findings", params={"window": "1h"})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["recent_id"] in ids
    assert seed_findings["old_id"] not in ids


def test_findings_list_absolute_range(client, seed_findings):
    now = seed_findings["now"]
    r = client.get("/api/v1/soc/findings",
                   params={"start": now - 5000, "end": now - 3000})
    assert r.status_code == 200
    ids = {f["id"] for f in r.json()["findings"]}
    assert seed_findings["mid_id"] in ids
    assert seed_findings["recent_id"] not in ids


def test_findings_list_bad_range_422(client):
    r = client.get("/api/v1/soc/findings", params={"start": 100, "end": 50})
    assert r.status_code == 422
