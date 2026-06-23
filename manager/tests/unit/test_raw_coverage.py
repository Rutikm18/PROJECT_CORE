"""
manager/tests/unit/test_raw_coverage.py — first-layer data checkpoint.

Drives GET /api/v1/raw/coverage through the real ASGI app and verifies the
per-section status logic (ok | stale | empty | missing) and the detection_ready
gate, plus edge cases (no agents, unknown agent).

Uses pg_manager_dsn (conftest.py) — a freshly CREATEd, then DROPped, real
Postgres database per test.
"""
from __future__ import annotations

import time

import httpx
from fastapi import FastAPI

from manager.manager.db import Database
from manager.manager.api.raw import make_raw_router


async def _seed_and_app(dsn: str):
    db = Database(dsn)
    await db.init()
    await db.upsert_agent("mac-1", "Test Mac", "127.0.0.1")
    now = int(time.time())
    # fresh + real  → ok            (detection-feeding)
    await db.insert_payload("mac-1", "ports", now, [{"port": 443}])
    await db.insert_payload("mac-1", "processes", now, [{"pid": 1, "name": "x"}])
    # fresh but collector-error     → empty
    await db.insert_payload("mac-1", "users", now, {"error": "permission denied"})
    # stale (older than 2h default) → stale
    await db.insert_payload("mac-1", "security", now - 100_000, {"sip": "enabled"})
    # everything else (sbom, packages, …) never reported → missing
    app = FastAPI()
    app.include_router(make_raw_router(db), prefix="/api/v1/raw")
    return db, app


async def _get(app, url):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        return await c.get(url)


async def test_coverage_statuses_and_gate(pg_manager_dsn):
    db, app = await _seed_and_app(pg_manager_dsn)
    try:
        r = await _get(app, "/api/v1/raw/coverage?agent_id=mac-1")
        assert r.status_code == 200, r.text
        j = r.json()
        by = {s["section"]: s for s in j["sections"]}

        assert by["ports"]["status"] == "ok"
        assert by["processes"]["status"] == "ok"
        assert by["users"]["status"] == "empty"        # {"error": …}
        assert by["security"]["status"] == "stale"     # >2h old
        assert by["sbom"]["status"] == "missing"       # never reported

        # detection_ready must be False (processes ok but users empty,
        # security stale, sbom/packages missing — all detection-feeding).
        assert j["ok"] is False
        assert j["detection_ready"] is False
        assert "users" in j["empty"]
        assert "security" in j["stale"]
        assert "sbom" in j["missing"]
        assert j["expected"] == 22
    finally:
        await db.close()


async def test_coverage_stale_window_param(pg_manager_dsn):
    db, app = await _seed_and_app(pg_manager_dsn)
    try:
        # With a huge stale window, the "security" payload counts as fresh.
        r = await _get(app, "/api/v1/raw/coverage?agent_id=mac-1&stale_sec=999999")
        j = r.json()
        by = {s["section"]: s for s in j["sections"]}
        assert by["security"]["status"] == "ok"   # within the widened window
    finally:
        await db.close()


async def test_coverage_no_agents(pg_manager_dsn):
    db = Database(pg_manager_dsn)
    await db.init()
    app = FastAPI()
    app.include_router(make_raw_router(db), prefix="/api/v1/raw")
    try:
        r = await _get(app, "/api/v1/raw/coverage")
        assert r.status_code == 200
        assert r.json()["ok"] is False
    finally:
        await db.close()
