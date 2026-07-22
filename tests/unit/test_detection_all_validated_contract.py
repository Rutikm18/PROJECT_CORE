from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.detection import make_detection_router
from manager.manager.attacklens.ai_validator import invalidate_validation_settings_cache


def _finding(
    fid: int,
    item_key: str,
    *,
    terrain_id: str,
    category: str,
    precision_score: float,
    composite_score: float,
) -> dict:
    return {
        "id": fid,
        "external_id": f"AL-F-{fid:08d}",
        "agent_id": "agent-a",
        "terrain_id": terrain_id,
        "category": category,
        "item_key": item_key,
        "title": item_key,
        "description": item_key,
        "severity": "high",
        "status": "new",
        "source": "rule:test",
        "rule_id": "rule:test",
        "precision_score": precision_score,
        "score": composite_score,
        "composite_score": composite_score,
        "is_active": 1,
        "first_detected_at": 1000,
        "last_detected_at": 1000,
        "sla_due": 0,
        "evidence": {},
        "action_plan": [],
        "cve_ids": [],
        "exploit_sources": [],
        "tags": [],
        "precision_factors": {},
        "ai_verdict": {},
        "layers_involved": [],
        "validation_gates_passed": [],
        "terrain_validation": {},
    }


class FakeIntelDB:
    def __init__(self, rows: list[dict], threshold: float = 0.90) -> None:
        self.rows = rows
        self.threshold = threshold
        self.calls: list[dict] = []

    async def _fetchall(self, sql: str, args=()) -> list[dict]:
        if "org_settings" not in sql:
            return []
        return [
            {"key": "validation_global_threshold", "value": str(self.threshold)},
            {"key": "validation_terrain_thresholds", "value": "{}"},
            {"key": "validation_agent_thresholds", "value": "{}"},
            {"key": "validation_agent_priorities", "value": "{}"},
        ]

    async def search_by_external_id(self, prefix: str, **kwargs) -> list[dict]:
        return [
            dict(r)
            for r in self.rows
            if str(r.get("external_id", "")).startswith(prefix)
        ][: kwargs.get("limit", 100)]

    async def get_soc_findings(self, **kwargs) -> list[dict]:
        self.calls.append(dict(kwargs))
        rows = list(self.rows)

        if kwargs.get("active_only", True):
            rows = [r for r in rows if r.get("is_active", 1)]
        if kwargs.get("agent_id"):
            rows = [r for r in rows if r.get("agent_id") == kwargs["agent_id"]]
        if kwargs.get("terrain_id"):
            rows = [r for r in rows if r.get("terrain_id") == kwargs["terrain_id"]]
        if kwargs.get("category"):
            rows = [r for r in rows if r.get("category") == kwargs["category"]]
        if kwargs.get("severity"):
            rows = [r for r in rows if r.get("severity") == kwargs["severity"]]
        if kwargs.get("status"):
            rows = [r for r in rows if r.get("status") == kwargs["status"]]
        if kwargs.get("min_precision") is not None:
            floor = float(kwargs["min_precision"])
            rows = [r for r in rows if float(r.get("precision_score") or 0.0) >= floor]

        rows.sort(key=lambda r: r.get("composite_score") or r.get("score") or 0, reverse=True)
        offset = int(kwargs.get("offset") or 0)
        limit = int(kwargs.get("limit") or 200)
        return [dict(r) for r in rows[offset : offset + limit]]


@pytest.fixture(autouse=True)
def _clear_validation_cache():
    invalidate_validation_settings_cache()
    yield
    invalidate_validation_settings_cache()


def _app(idb: FakeIntelDB) -> FastAPI:
    app = FastAPI()
    app.include_router(make_detection_router(idb), prefix="/api/v1/detection")
    return app


@pytest.mark.asyncio
async def test_all_findings_default_returns_low_and_high_confidence() -> None:
    idb = FakeIntelDB([
        _finding(1, "origin-high", terrain_id="origin", category="package", precision_score=0.96, composite_score=90),
        _finding(2, "origin-low", terrain_id="origin", category="storage", precision_score=0.40, composite_score=80),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get("/api/v1/detection/all?limit=10")

    assert response.status_code == 200, response.text
    body = response.json()
    assert {f["item_key"] for f in body["findings"]} == {"origin-high", "origin-low"}
    assert idb.calls[-1]["min_precision"] is None


@pytest.mark.asyncio
async def test_validated_only_prefilters_before_pagination() -> None:
    idb = FakeIntelDB([
        _finding(1, "low-score-first", terrain_id="origin", category="package", precision_score=0.20, composite_score=100),
        _finding(2, "validated-behind-low", terrain_id="origin", category="package", precision_score=0.95, composite_score=90),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get("/api/v1/detection/all?validated_only=true&limit=1")

    assert response.status_code == 200, response.text
    body = response.json()
    assert [f["item_key"] for f in body["findings"]] == ["validated-behind-low"]
    assert body["validated_only"] is True
    assert idb.calls[-1]["min_precision"] == pytest.approx(0.90)


@pytest.mark.asyncio
async def test_attack_terrain_filters_use_canonical_terrain_id() -> None:
    idb = FakeIntelDB([
        _finding(1, "origin-package", terrain_id="origin", category="package", precision_score=0.96, composite_score=90),
        _finding(2, "origin-storage", terrain_id="origin", category="storage", precision_score=0.50, composite_score=80),
        _finding(3, "vector-port", terrain_id="vector", category="port", precision_score=0.94, composite_score=88),
        _finding(4, "vector-lateral", terrain_id="vector", category="lateral", precision_score=0.55, composite_score=82),
        _finding(5, "citadels-process", terrain_id="citadels", category="process", precision_score=0.97, composite_score=91),
        _finding(6, "citadels-service", terrain_id="citadels", category="service", precision_score=0.45, composite_score=84),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        origin = await client.get("/api/v1/detection/all?terrain_id=origin&limit=10")
        vector = await client.get("/api/v1/detection/all?terrain_id=vector&limit=10")
        citadels = await client.get("/api/v1/detection/all?terrain_id=citadels&limit=10")

    assert origin.status_code == 200, origin.text
    assert vector.status_code == 200, vector.text
    assert citadels.status_code == 200, citadels.text
    assert {f["item_key"] for f in origin.json()["findings"]} == {"origin-package", "origin-storage"}
    assert {f["item_key"] for f in vector.json()["findings"]} == {"vector-port", "vector-lateral"}
    assert {f["item_key"] for f in citadels.json()["findings"]} == {"citadels-process", "citadels-service"}


@pytest.mark.asyncio
async def test_validated_terrain_view_keeps_only_threshold_passing_findings() -> None:
    idb = FakeIntelDB([
        _finding(1, "origin-high", terrain_id="origin", category="package", precision_score=0.96, composite_score=90),
        _finding(2, "origin-low", terrain_id="origin", category="storage", precision_score=0.40, composite_score=80),
        _finding(3, "vector-high", terrain_id="vector", category="connection", precision_score=0.97, composite_score=89),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get("/api/v1/detection/all?terrain_id=origin&validated_only=true&limit=10")

    assert response.status_code == 200, response.text
    body = response.json()
    assert {f["item_key"] for f in body["findings"]} == {"origin-high"}
    assert all(f["is_validated"] for f in body["findings"])
