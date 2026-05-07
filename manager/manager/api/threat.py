"""
manager/manager/api/threat.py — Threat intelligence REST API.

Endpoints:
  GET /api/v1/threat/{agent_id}/summary        — counts by severity
  GET /api/v1/threat/{agent_id}/findings       — paginated findings list
  GET /api/v1/threat/{agent_id}/findings/{id}  — single finding detail
  GET /api/v1/threat/{agent_id}/timeline       — change events log
  GET /api/v1/threat/{agent_id}/search         — FTS search
  POST /api/v1/threat/{agent_id}/resolve/{id}  — mark finding resolved
  GET /api/v1/threat/stats                     — global intel DB stats
"""
from __future__ import annotations

import time
from typing import Optional

import aiohttp
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse


def make_threat_router(intel_db, central_url: str = "") -> APIRouter:
    router = APIRouter()

    async def _central_get(path: str) -> dict | None:
        if not central_url:
            return None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(f"{central_url}{path}") as response:
                    if response.status != 200:
                        return None
                    return await response.json()
        except Exception:
            return None

    # ── Threat Intel module overview ─────────────────────────────────────────
    @router.get("/intel/summary")
    async def intel_summary():
        central = await _central_get("/api/v1/intel/summary")
        if central is not None:
            central["source"] = "central"
            return central
        return await intel_db.get_threat_intel_overview()

    @router.get("/intel/cves")
    async def intel_cves(
        severity: Optional[str] = Query(None, description="Filter by severity"),
        limit:    int           = Query(100, ge=1, le=1000),
        offset:   int           = Query(0, ge=0),
    ):
        q = f"?limit={limit}&offset={offset}"
        if severity:
            q += f"&severity={severity}"
        central = await _central_get(f"/api/v1/intel/cves{q}")
        if central is not None:
            central["source"] = "central"
            return central
        rows = await intel_db.list_cves(
            severity=severity, limit=limit, offset=offset,
        )
        return {"cves": rows, "count": len(rows), "offset": offset}

    @router.get("/intel/architecture")
    async def intel_architecture():
        central = await _central_get("/api/v1/intel/architecture")
        if central is not None:
            central["source"] = "central"
            return central
        return {
            "stores": [
                {
                    "name": "manager.db",
                    "purpose": "agent registry, live status sessions, raw telemetry payload index",
                    "failure_mode": "WAL SQLite keeps dashboard reads available during writes",
                },
                {
                    "name": "intel.db",
                    "purpose": "NVD CVEs, IOC cache, feed health, findings, scoring, correlations",
                    "failure_mode": "threat-intel failures degrade to cached data and do not block ingest",
                },
            ],
            "request_handling": {
                "fast_path": "ingest verifies crypto, updates agent heartbeat, publishes telemetry to RabbitMQ when configured",
                "fallback": "when RabbitMQ is unavailable, ingest writes synchronously and schedules Jarvis analysis in-process",
                "scale": "RabbitMQ prefetch, bounded worker concurrency, chunked large payloads, and DLQ isolation",
            },
            "correlation": [
                "package telemetry maps to cached NVD CVEs",
                "connection telemetry maps to IOC feed cache",
                "rules and behavioral baselines emit findings",
                "correlation engine combines findings into attack chains",
            ],
        }

    # ── Global stats ──────────────────────────────────────────────────────────
    @router.get("/stats")
    async def stats():
        return await intel_db.stats()

    # ── NVD local mirror stats ────────────────────────────────────────────────
    @router.get("/nvd/stats")
    async def nvd_stats():
        """NVD local mirror: total CVE count, coverage by severity, last sync timestamps."""
        return await intel_db.get_nvd_stats()

    @router.get("/nvd/search")
    async def nvd_search(
        q:     str = Query(..., description="Package name or keyword to search"),
        limit: int = Query(20, ge=1, le=200),
    ):
        """FTS5 search against local NVD mirror — returns CVEs matching the keyword."""
        results = await intel_db.search_nvd_local(q.lower(), limit=limit)
        return {"results": results, "count": len(results), "query": q}

    # ── Feed health ───────────────────────────────────────────────────────────
    @router.get("/feeds")
    async def feed_health():
        """Return health status for every configured threat intel feed."""
        rows = await intel_db.get_all_feed_health()
        return {"feeds": rows, "count": len(rows)}

    # ── IOC browse ────────────────────────────────────────────────────────────
    @router.get("/iocs")
    async def iocs(
        ioc_type: str           = Query("ip",  description="IOC type: ip | domain"),
        source:   Optional[str] = Query(None,  description="Filter by feed source"),
        limit:    int           = Query(100,   ge=1, le=1000),
        offset:   int           = Query(0,     ge=0),
    ):
        """Browse the IOC cache with optional type and source filters."""
        all_rows = await intel_db.get_all_iocs(ioc_type)
        if source:
            all_rows = [r for r in all_rows if r.get("source") == source]
        total = len(all_rows)
        page  = all_rows[offset : offset + limit]
        return {"iocs": page, "total": total, "offset": offset, "limit": limit}

    # ── Summary ───────────────────────────────────────────────────────────────
    @router.get("/{agent_id}/summary")
    async def summary(agent_id: str):
        data = await intel_db.get_summary(agent_id)
        if not data:
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                    "total": 0, "active": 0, "max_score": 0}
        return data

    # ── Findings list ─────────────────────────────────────────────────────────
    @router.get("/{agent_id}/findings")
    async def findings(
        agent_id:    str,
        severity:    Optional[str] = Query(None, description="Filter severity"),
        category:    Optional[str] = Query(None, description="Filter category"),
        active_only: bool          = Query(True),
        limit:       int           = Query(100, ge=1, le=1000),
        offset:      int           = Query(0, ge=0),
    ):
        rows = await intel_db.get_findings(
            agent_id,
            severity=severity,
            category=category,
            active_only=active_only,
            limit=limit,
            offset=offset,
        )
        return {"findings": rows, "count": len(rows), "offset": offset}

    # ── Single finding ────────────────────────────────────────────────────────
    @router.get("/{agent_id}/findings/{finding_id}")
    async def finding_detail(agent_id: str, finding_id: int):
        rows = await intel_db.get_findings(agent_id, active_only=False, limit=1000)
        match = next((r for r in rows if r["id"] == finding_id), None)
        if not match:
            raise HTTPException(404, "Finding not found")
        return match

    # ── Timeline ──────────────────────────────────────────────────────────────
    @router.get("/{agent_id}/timeline")
    async def timeline(
        agent_id: str,
        category: Optional[str] = Query(None),
        since:    float         = Query(0.0, description="Unix timestamp"),
        limit:    int           = Query(200, ge=1, le=1000),
    ):
        rows = await intel_db.get_timeline(
            agent_id, category=category, since=since, limit=limit)
        return {"events": rows, "count": len(rows)}

    # ── FTS Search ────────────────────────────────────────────────────────────
    @router.get("/{agent_id}/search")
    async def search(
        agent_id: str,
        q:        str = Query(..., description="Full-text search query"),
        limit:    int = Query(50, ge=1, le=500),
    ):
        try:
            rows = await intel_db.search_findings(agent_id, q, limit=limit)
        except Exception as exc:
            # FTS5 syntax errors should not crash the endpoint
            raise HTTPException(400, f"Invalid search query: {exc}")
        return {"results": rows, "count": len(rows), "query": q}

    # ── Resolve ───────────────────────────────────────────────────────────────
    @router.post("/{agent_id}/resolve/{finding_id}")
    async def resolve(agent_id: str, finding_id: int):
        await intel_db.mark_resolved(agent_id, finding_id)
        return {"status": "resolved", "finding_id": finding_id}

    return router
