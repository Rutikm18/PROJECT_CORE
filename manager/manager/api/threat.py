"""
manager/manager/api/threat.py — Threat intelligence REST API.

Dashboard endpoints (new):
  GET /api/v1/threat/intel/dashboard   — single call: feeds + CVEs + actors + news + KEV
  GET /api/v1/threat/intel/actors      — active threat actors
  GET /api/v1/threat/intel/news        — recent security news
  GET /api/v1/threat/intel/kev         — CISA KEV list
  GET /api/v1/threat/intel/epss/top    — top EPSS exploitability scores

Existing endpoints:
  GET /api/v1/threat/{agent_id}/summary        — counts by severity
  GET /api/v1/threat/{agent_id}/findings       — paginated findings list
  GET /api/v1/threat/{agent_id}/findings/{id}  — single finding detail
  GET /api/v1/threat/{agent_id}/timeline       — change events log
  GET /api/v1/threat/{agent_id}/search         — FTS search
  POST /api/v1/threat/{agent_id}/resolve/{id}  — mark finding resolved
  GET /api/v1/threat/stats                     — global intel DB stats
"""
from __future__ import annotations

import asyncio
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

    # ── Comprehensive dashboard (single call for the UI) ─────────────────────
    @router.get("/intel/dashboard")
    async def intel_dashboard(
        cve_limit:  int = Query(20, ge=1, le=100),
        news_hours: int = Query(48, ge=1, le=168),
        news_limit: int = Query(10, ge=1, le=50),
        kev_limit:  int = Query(15, ge=1, le=100),
        actor_limit:int = Query(10, ge=1, le=50),
        epss_limit: int = Query(10, ge=1, le=50),
    ):
        """
        Single endpoint that powers the Threat Intelligence dashboard.
        All sub-queries run concurrently via asyncio.gather.
        Returns feeds, top CVEs, KEV, threat actors, news, EPSS top scores.
        """
        (
            feeds,
            nvd_stats,
            kev_count,
            actor_count,
            top_cves,
            kev_recent,
            actors,
            news,
            ip_iocs,
        ) = await asyncio.gather(
            intel_db.get_all_feed_health(),
            intel_db.get_nvd_stats(),
            intel_db.kev_count(),
            intel_db.actor_count(),
            intel_db.list_cves(limit=cve_limit),
            intel_db.list_kev(limit=kev_limit),
            intel_db.get_threat_actors(active_only=True, limit=actor_limit),
            intel_db.get_recent_news(hours=news_hours, limit=news_limit),
            intel_db.get_all_iocs("ip"),
        )

        # Top EPSS scores from epss_scores table
        try:
            epss_rows = await intel_db._fetchall(
                "SELECT cve_id, epss, percentile, model_date FROM epss_scores "
                "ORDER BY epss DESC LIMIT ?",
                (epss_limit,),
            )
            top_epss = [dict(r) for r in epss_rows]
        except Exception:
            top_epss = []

        # Enrich CVE list with KEV and EPSS data for display
        kev_ids = {k["cve_id"] for k in kev_recent}
        epss_map = {r["cve_id"]: r["epss"] for r in top_epss}

        enriched_cves = []
        for cve in top_cves:
            cid = cve.get("cve_id", "")
            enriched_cves.append({
                **cve,
                "is_kev":    cid in kev_ids,
                "epss":      epss_map.get(cid),
                "priority":  _priority_label(cve, cid in kev_ids, epss_map.get(cid)),
            })

        # Feed active count
        active_feeds = sum(1 for f in feeds if f.get("status") in ("ok", "live"))

        return {
            "stats": {
                "kev_count":     kev_count,
                "actor_count":   actor_count,
                "nvd_total":     nvd_stats.get("total", 0),
                "nvd_critical":  nvd_stats.get("by_severity", {}).get("critical", 0),
                "nvd_high":      nvd_stats.get("by_severity", {}).get("high", 0),
                "ioc_count":     len(ip_iocs),
                "active_feeds":  active_feeds,
                "total_feeds":   len(feeds),
                "last_nvd_sync": nvd_stats.get("last_delta_sync", 0),
            },
            "feeds":      feeds,
            "top_cves":   enriched_cves,
            "kev_recent": kev_recent,
            "actors":     actors,
            "news":       news,
            "top_epss":   top_epss,
        }

    # ── Threat actors ─────────────────────────────────────────────────────────
    @router.get("/intel/actors")
    async def intel_actors(
        active_only: bool = Query(True),
        limit:       int  = Query(50, ge=1, le=200),
    ):
        rows = await intel_db.get_threat_actors(active_only=active_only, limit=limit)
        return {"actors": rows, "count": len(rows)}

    # ── Security news ─────────────────────────────────────────────────────────
    @router.get("/intel/news")
    async def intel_news(
        hours: int = Query(48, ge=1, le=168),
        limit: int = Query(30, ge=1, le=100),
    ):
        rows = await intel_db.get_recent_news(hours=hours, limit=limit)
        return {"news": rows, "count": len(rows)}

    # ── CISA KEV ──────────────────────────────────────────────────────────────
    @router.get("/intel/kev")
    async def intel_kev(limit: int = Query(100, ge=1, le=500)):
        rows = await intel_db.list_kev(limit=limit)
        count = await intel_db.kev_count()
        return {"kev": rows, "count": count}

    # ── Top EPSS scores ───────────────────────────────────────────────────────
    @router.get("/intel/epss/top")
    async def intel_epss_top(limit: int = Query(20, ge=1, le=100)):
        try:
            rows = await intel_db._fetchall(
                "SELECT cve_id, epss, percentile, model_date FROM epss_scores "
                "ORDER BY epss DESC LIMIT ?",
                (limit,),
            )
            return {"scores": [dict(r) for r in rows], "count": len(rows)}
        except Exception as exc:
            raise HTTPException(500, str(exc))

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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _priority_label(cve: dict, is_kev: bool, epss: float | None) -> str:
    """Human-readable priority label for a CVE combining CVSS + KEV + EPSS."""
    if is_kev:
        return "CRITICAL – Actively Exploited"
    cvss = cve.get("cvss_score") or 0
    ep   = epss or 0
    if cvss >= 9.0 and ep >= 0.5:
        return "CRITICAL – High Exploit Probability"
    if cvss >= 9.0 or ep >= 0.7:
        return "HIGH – Patch Immediately"
    if cvss >= 7.0 or ep >= 0.3:
        return "HIGH – Patch This Week"
    if cvss >= 4.0:
        return "MEDIUM – Schedule Patch"
    return "LOW – Monitor"
