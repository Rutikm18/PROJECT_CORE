from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager.api.detection import make_detection_router
from manager.manager.attacklens.ai_validator import invalidate_validation_settings_cache
from manager.manager.indexer import FindingPage


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
        "kev": False,
        "exploit_available": False,
        "mitre_technique": "",
        "mitre_tactic": "",
        "precision_score": precision_score,
        "validation_score": precision_score,
        "validation_state": "validated" if precision_score >= 0.90 else "needs_review",
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
        if kwargs.get("kev_only"):
            rows = [r for r in rows if r.get("kev")]
        if kwargs.get("exploit_only"):
            rows = [r for r in rows if r.get("exploit_available")]
        if kwargs.get("mitre"):
            term = str(kwargs["mitre"]).lower()
            rows = [
                r for r in rows
                if term in str(r.get("mitre_technique") or "").lower()
                or term == str(r.get("mitre_tactic") or "").lower()
            ]
        for condition in kwargs.get("advanced_filters") or []:
            field = condition["field"]
            needle = str(condition.get("value") or "").lower()
            if condition["op"] == "contains":
                rows = [r for r in rows if needle in str(r.get(field) or "").lower()]
            elif condition["op"] == "is":
                rows = [r for r in rows if str(r.get(field) or "").lower() == needle]
        if kwargs.get("external_id_prefix"):
            prefix = str(kwargs["external_id_prefix"]).rstrip("%")
            rows = [r for r in rows if str(r.get("external_id", "")).startswith(prefix)]
        if kwargs.get("min_precision") is not None:
            floor = float(kwargs["min_precision"])
            rows = [r for r in rows if float(r.get("precision_score") or 0.0) >= floor]
        if kwargs.get("validation_state"):
            rows = [r for r in rows if r.get("validation_state") == kwargs["validation_state"]]

        rows.sort(key=lambda r: r.get("composite_score") or r.get("score") or 0, reverse=True)
        filtered_total = len(rows)
        filtered_critical = sum(r.get("severity") == "critical" for r in rows)
        filtered_high = sum(r.get("severity") == "high" for r in rows)
        filtered_kev = sum(bool(r.get("kev")) for r in rows)
        offset = int(kwargs.get("offset") or 0)
        limit = int(kwargs.get("limit") or 200)
        page = [dict(r) for r in rows[offset : offset + limit]]
        for row in page:
            row["filtered_total"] = filtered_total
            row["filtered_critical"] = filtered_critical
            row["filtered_high"] = filtered_high
            row["filtered_kev"] = filtered_kev
        return page

    async def query_soc_findings(self, query) -> FindingPage:
        rows = await self.get_soc_findings(
            agent_id=query.agent_id,
            terrain_id=query.terrain_id,
            severity=query.severity,
            status=query.status,
            category=query.category,
            assignee=query.assignee,
            sla_breached=query.sla_breached,
            kev_only=query.kev_only,
            exploit_only=query.exploit_only,
            mitre=query.mitre,
            advanced_filters=list(query.advanced_filters),
            active_only=query.active_only,
            search=query.search,
            external_id_prefix=query.external_id_prefix,
            limit=100_000,
            offset=0,
            sort_by=query.sort_by,
            sort_dir=query.sort_dir,
            min_precision=query.min_precision,
            validation_state=query.validation_state,
            live_agent_ids=query.live_agent_ids,
            window_start=query.window_start,
            window_end=query.window_end,
        )
        facets = {
            name: {} for name in (
                "severity", "terrain", "status", "category", "validation_state",
                "assignee", "kev", "exploit_available",
            )
        }
        for row in rows:
            values = {
                "severity": row.get("severity") or "",
                "terrain": row.get("terrain_id") or "",
                "status": row.get("status") or "",
                "category": row.get("category") or "",
                "validation_state": row.get("validation_state") or "",
                "assignee": row.get("assignee") or "",
                "kev": "true" if row.get("kev") else "false",
                "exploit_available": "true" if row.get("exploit_available") else "false",
            }
            for name, value in values.items():
                facets[name][value] = facets[name].get(value, 0) + 1
        start = query.offset
        page_rows = rows[start : start + query.limit]
        return FindingPage(
            findings=page_rows,
            total=len(rows),
            facets=facets,
            next_cursor=None,
        )


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
    assert idb.calls[-1]["min_precision"] is None
    assert idb.calls[-1]["validation_state"] == "validated"


@pytest.mark.asyncio
async def test_attack_terrain_filters_use_canonical_terrain_id() -> None:
    idb = FakeIntelDB([
        _finding(1, "origin-package", terrain_id="origin", category="package", precision_score=0.96, composite_score=90),
        _finding(2, "origin-storage", terrain_id="origin", category="storage", precision_score=0.50, composite_score=80),
        _finding(3, "vector-port", terrain_id="vector", category="port", precision_score=0.94, composite_score=88),
        _finding(4, "vector-lateral", terrain_id="vector", category="lateral", precision_score=0.55, composite_score=82),
        _finding(5, "citadels-process", terrain_id="citadels", category="process", precision_score=0.97, composite_score=91),
        _finding(6, "citadels-service", terrain_id="citadels", category="service", precision_score=0.45, composite_score=84),
        _finding(7, "mesh-extension", terrain_id="mesh", category="developer_security", precision_score=0.92, composite_score=87),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        origin = await client.get("/api/v1/detection/all?terrain_id=origin&limit=10")
        vector = await client.get("/api/v1/detection/all?terrain_id=vector&limit=10")
        citadels = await client.get("/api/v1/detection/all?terrain_id=citadels&limit=10")
        mesh = await client.get("/api/v1/detection/all?terrain_id=mesh&limit=10")

    assert origin.status_code == 200, origin.text
    assert vector.status_code == 200, vector.text
    assert citadels.status_code == 200, citadels.text
    assert mesh.status_code == 200, mesh.text
    assert {f["item_key"] for f in origin.json()["findings"]} == {"origin-package", "origin-storage"}
    assert {f["item_key"] for f in vector.json()["findings"]} == {"vector-port", "vector-lateral"}
    assert {f["item_key"] for f in citadels.json()["findings"]} == {"citadels-process", "citadels-service"}
    assert {f["item_key"] for f in mesh.json()["findings"]} == {"mesh-extension"}


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


@pytest.mark.asyncio
async def test_external_id_search_keeps_validated_filter_contract() -> None:
    idb = FakeIntelDB([
        _finding(1, "below-threshold", terrain_id="mesh", category="developer_security", precision_score=0.20, composite_score=100),
        _finding(2, "validated-match", terrain_id="mesh", category="developer_security", precision_score=0.95, composite_score=90),
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/detection/all",
            params={"id_search": "AL-F-", "terrain_id": "mesh", "validated_only": "true"},
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert [finding["item_key"] for finding in body["findings"]] == ["validated-match"]
    assert body["validated_only"] is True


@pytest.mark.asyncio
async def test_standard_filters_are_applied_before_pagination() -> None:
    matching = _finding(
        2, "matching-mesh", terrain_id="mesh", category="developer_security",
        precision_score=0.95, composite_score=90,
    )
    matching.update({
        "kev": True,
        "exploit_available": True,
        "mitre_technique": "T1195.002",
        "mitre_tactic": "Initial Access",
    })
    idb = FakeIntelDB([
        _finding(1, "higher-but-not-matching", terrain_id="mesh", category="developer_security", precision_score=0.95, composite_score=100),
        matching,
    ])

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/detection/all",
            params={
                "kev_only": "true",
                "exploit_only": "true",
                "mitre": "T1195",
                "sort_by": "epss_score",
                "sort_dir": "asc",
                "limit": "1",
            },
        )

    assert response.status_code == 200, response.text
    assert [finding["item_key"] for finding in response.json()["findings"]] == ["matching-mesh"]
    assert response.json()["total"] == 1
    assert response.json()["stats"] == {
        "total": 1,
        "critical": 0,
        "high": 1,
        "kev": 1,
    }
    assert idb.calls[-1]["kev_only"] is True
    assert idb.calls[-1]["exploit_only"] is True
    assert idb.calls[-1]["mitre"] == "T1195"
    assert idb.calls[-1]["sort_by"] == "epss_score"
    assert idb.calls[-1]["sort_dir"] == "asc"


@pytest.mark.asyncio
async def test_advanced_filters_are_allowlisted_and_run_before_pagination() -> None:
    matching = _finding(
        2, "mcp-match", terrain_id="mesh", category="developer_security",
        precision_score=0.95, composite_score=90,
    )
    matching["title"] = "Unpinned MCP server"
    idb = FakeIntelDB([
        _finding(1, "higher-nonmatch", terrain_id="mesh", category="developer_security", precision_score=0.95, composite_score=100),
        matching,
    ])
    conditions = [
        {"field": "title", "op": "contains", "value": "MCP"},
        {"field": "category", "op": "is", "value": "developer_security"},
    ]

    async with AsyncClient(transport=ASGITransport(app=_app(idb)), base_url="http://test") as client:
        response = await client.get(
            "/api/v1/detection/all",
            params={"advanced": json.dumps(conditions), "limit": "1"},
        )
        unsafe = await client.get(
            "/api/v1/detection/all",
            params={"advanced": json.dumps([{
                "field": "title) OR 1=1 --", "op": "contains", "value": "x",
            }])},
        )

    assert response.status_code == 200, response.text
    assert [finding["item_key"] for finding in response.json()["findings"]] == ["mcp-match"]
    assert idb.calls[-1]["advanced_filters"] == conditions
    assert unsafe.status_code == 422
