from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.detection import make_detection_router
from manager.manager.indexer import IntelDB


TERRAINS = ("citadels", "vector", "origin", "identity", "posture", "mesh")


def _app(idb: IntelDB) -> FastAPI:
    app = FastAPI()
    app.include_router(make_detection_router(idb), prefix="/api/v1/detection")
    return app


async def _seed_many(idb: IntelDB, total: int) -> list[dict]:
    now = time.time()
    rows = []
    expected = []
    for index in range(total):
        terrain = TERRAINS[index % len(TERRAINS)]
        severity = ("critical", "high", "medium", "low")[index % 4]
        validation_state = "validated" if index % 2 == 1 else "needs_review"
        row = (
            f"AL-F-{index + 1:08d}", "scale-agent", "developer_security" if terrain == "mesh" else f"cat-{terrain}",
            f"item-{index:05d}", f"fp-{index:05d}", severity, float(index % 10),
            f"Finding {index}", now - 120, now - index / 1000,
            1 if index % 5 == 0 else 0, terrain, validation_state,
            0.95 if validation_state == "validated" else 0.55,
        )
        rows.append(row)
        expected.append({
            "external_id": row[0], "terrain": terrain, "severity": severity,
            "kev": bool(row[10]), "validation_state": validation_state,
            "last_detected_at": row[9],
        })
    await idb._conn.executemany(
        """INSERT INTO findings
           (external_id,agent_id,category,item_key,fingerprint,severity,score,title,
            first_detected_at,last_detected_at,kev,terrain_id,validation_state,
            validation_score)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    await idb._conn.commit()
    return expected


@pytest.mark.asyncio
async def test_attack_terrain_is_exact_all_incidents_projection(pg_intel_dsn) -> None:
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        await _seed_many(idb, 24)
        async with AsyncClient(
            transport=ASGITransport(app=_app(idb)), base_url="http://test",
        ) as client:
            all_rows = (await client.get(
                "/api/v1/detection/all?window=1d&limit=1000",
            )).json()["findings"]
            for terrain in TERRAINS:
                response = await client.get(
                    f"/api/v1/detection/all?window=1d&limit=1000&terrain_id={terrain}",
                )
                assert response.status_code == 200, response.text
                projected = {
                    row["external_id"] for row in all_rows if row["terrain_id"] == terrain
                }
                assert {row["external_id"] for row in response.json()["findings"]} == projected
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_large_query_has_complete_facets_and_cursor_pagination(pg_intel_dsn) -> None:
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        expected = await _seed_many(idb, 1205)
        matching = [
            row for row in expected
            if row["terrain"] == "mesh" and row["validation_state"] == "validated"
        ]
        async with AsyncClient(
            transport=ASGITransport(app=_app(idb)), base_url="http://test",
        ) as client:
            cursor = ""
            seen: list[str] = []
            first_body = None
            while True:
                params = {
                    "window": "1d", "limit": "37", "terrain_id": "mesh",
                    "validated_only": "true", "sort_by": "last_detected_at",
                    "sort_dir": "desc",
                }
                if cursor:
                    params["cursor"] = cursor
                response = await client.get("/api/v1/detection/all", params=params)
                assert response.status_code == 200, response.text
                body = response.json()
                first_body = first_body or body
                seen.extend(row["external_id"] for row in body["findings"])
                cursor = body.get("next_cursor") or ""
                if not cursor:
                    break

        assert len(seen) == len(set(seen)) == len(matching)
        assert set(seen) == {row["external_id"] for row in matching}
        assert first_body["total"] == len(matching)
        assert first_body["facets"]["terrain"] == {"mesh": len(matching)}
        assert sum(first_body["facets"]["severity"].values()) == len(matching)
        assert first_body["facets"]["validation_state"] == {"validated": len(matching)}
    finally:
        await idb.close()
