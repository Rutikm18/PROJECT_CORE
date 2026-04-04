"""
manager/manager/api/jarvis.py — Jarvis verified findings REST API.

Endpoints (mounted at /api/v1/jarvis):
  GET  /stats                          — global IntelDB stats
  GET  /{agent_id}/summary             — severity counts + max_score
  GET  /{agent_id}/findings            — paginated findings list
  GET  /{agent_id}/findings/{id}       — single finding detail
  GET  /{agent_id}/timeline            — change events log
  GET  /{agent_id}/search?q=...        — FTS5 full-text search
  POST /{agent_id}/resolve/{id}        — mark finding resolved
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query


def make_jarvis_router(intel_db) -> APIRouter:
    router = APIRouter()

    # ── Global stats ──────────────────────────────────────────────────────────
    @router.get("/stats")
    async def stats():
        return await intel_db.stats()

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
        severity:    Optional[str] = Query(None, description="Filter by severity"),
        category:    Optional[str] = Query(None, description="Filter by category"),
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
            raise HTTPException(400, f"Invalid search query: {exc}")
        return {"results": rows, "count": len(rows), "query": q}

    # ── Resolve ───────────────────────────────────────────────────────────────
    @router.post("/{agent_id}/resolve/{finding_id}")
    async def resolve(agent_id: str, finding_id: int):
        await intel_db.mark_resolved(agent_id, finding_id)
        return {"status": "resolved", "finding_id": finding_id}

    return router
