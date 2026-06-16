"""
manager/manager/api/intel.py — Multi-source vulnerability intelligence REST API.

Endpoints:
  GET  /api/v1/intel/status              — pipeline health + circuit breaker states
  GET  /api/v1/intel/cve/{cve_id}        — full multi-source CVE enrichment
  POST /api/v1/intel/enrich              — batch enrich up to 50 CVE IDs
  GET  /api/v1/intel/kev                 — CISA KEV catalog (paginated, searchable)
  GET  /api/v1/intel/epss/{cve_id}       — EPSS score for a single CVE
  GET  /api/v1/intel/exploits/{cve_id}   — exploit presence across all exploit sources

All endpoints handle missing pipeline gracefully (503) to allow staged rollouts.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

log = logging.getLogger("manager.api.intel")

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])

_CVE_RE        = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_PROXY_TIMEOUT = aiohttp.ClientTimeout(total=10)

# Read at import time (same pattern as remediation.py) so central mode works
# even if app.state.threat_intel_url is not set yet at first request.
_CENTRAL_URL: str = os.environ.get("THREAT_INTEL_URL", "").strip().rstrip("/")


# ── Dependency helpers ────────────────────────────────────────────────────────

def _pipeline(req: Request):
    p = getattr(req.app.state, "intel_pipeline", None)
    if p is None:
        raise HTTPException(503, detail="IntelPipeline not initialized")
    return p


def _feeds(req: Request):
    f = getattr(req.app.state, "feeds", None)
    if f is None:
        raise HTTPException(503, detail="FeedManager not initialized")
    return f


def _intel_db(req: Request):
    d = getattr(req.app.state, "intel_db", None)
    if d is None:
        raise HTTPException(503, detail="IntelDB not initialized")
    return d


def _central_url(req: Request) -> str:
    """Return the threat-intel central URL, or empty string in embedded mode."""
    return (
        getattr(req.app.state, "threat_intel_url", "") or _CENTRAL_URL
    )


def _require_cve(cve_id: str) -> str:
    cid = cve_id.strip().upper()
    if not _CVE_RE.match(cid):
        raise HTTPException(400, detail=f"Invalid CVE ID format: {cve_id!r} (expected CVE-YYYY-NNNNN)")
    return cid


async def _proxy_get(base_url: str, path: str, params: dict | None = None):
    """Fetch from central threat-intel service. Returns parsed JSON or None."""
    if not base_url:
        return None
    try:
        async with aiohttp.ClientSession(timeout=_PROXY_TIMEOUT) as s:
            async with s.get(f"{base_url}{path}", params=params) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
    except Exception as exc:
        log.warning("Central intel proxy %s: %s", path, exc)
    return None


# ── Request models ────────────────────────────────────────────────────────────

class BulkEnrichRequest(BaseModel):
    cve_ids:     list[str] = Field(..., min_length=1, max_length=50,
                                    description="List of CVE IDs to enrich (max 50)")
    concurrency: int       = Field(default=5, ge=1, le=10,
                                   description="Max parallel source queries")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def intel_status(pipeline=Depends(_pipeline)) -> dict:
    """
    Return health status of all intel sources including circuit breaker states.
    Use this to diagnose which external sources are reachable.
    """
    health = pipeline.get_source_health()
    # Classify overall health
    open_circuits = [
        k for k, v in health.items()
        if isinstance(v, dict) and v.get("circuit", {}).get("state") == "open"
    ]
    return {
        "ok":             True,
        "timestamp":      time.time(),
        "sources":        health,
        "open_circuits":  open_circuits,
        "degraded":       len(open_circuits) > 0,
    }


@router.get("/cve/{cve_id}")
async def get_cve_enrichment(
    cve_id:   str,
    pipeline=Depends(_pipeline),
) -> dict:
    """
    Return fully enriched CVE data from all available sources:
    NVD, CISA KEV, EPSS, ExploitDB, Metasploit, GitHub PoC, GHSA, OSV, CIRCL.

    The `composite_score` field (0-10) incorporates all signals.
    The `intel_confidence` field (0-1) reflects how many sources agreed.
    The `_source_errors` field lists any sources that failed during this request.
    """
    cid = _require_cve(cve_id)
    enriched = await pipeline.enrich_cve(cid)
    if "error" in enriched:
        raise HTTPException(400, detail=enriched["error"])
    return enriched


@router.post("/enrich")
async def bulk_enrich(
    body:     BulkEnrichRequest,
    pipeline=Depends(_pipeline),
) -> dict:
    """
    Enrich up to 50 CVE IDs in one request.
    Invalid IDs are skipped and reported in `invalid_ids`.
    Concurrency parameter controls parallelism to avoid overwhelming sources.
    """
    valid:   list[str] = []
    invalid: list[str] = []
    for cid in body.cve_ids:
        cid = cid.strip().upper()
        if _CVE_RE.match(cid):
            valid.append(cid)
        else:
            invalid.append(cid)

    if not valid:
        raise HTTPException(400, detail="No valid CVE IDs in request")

    results = await pipeline.bulk_enrich(valid, concurrency=body.concurrency)
    return {
        "enriched":    results,
        "count":       len(results),
        "invalid_ids": invalid,
        "timestamp":   time.time(),
    }


@router.get("/kev")
async def get_kev_catalog(
    req:     Request,
    intel_db=Depends(_intel_db),
    feeds=Depends(_feeds),
    limit:   int           = Query(default=100, ge=1, le=1000),
    offset:  int           = Query(default=0, ge=0),
    search:  Optional[str] = Query(default=None, description="Filter by CVE ID, vendor, or product"),
) -> dict:
    """
    Return the CISA Known Exploited Vulnerabilities catalog.
    In central mode, proxies to the threat-intel service and normalises the
    response.  In embedded mode, reads directly from the local DB.
    Supports full-text search across CVE ID, vendor name, and product name.
    """
    central = _central_url(req)
    if central:
        # Proxy to threat-intel; fetch a large page so we can search/paginate here
        proxied = await _proxy_get(central, "/api/v1/intel/kev", {"limit": 5000})
        if proxied is not None:
            # Normalise: central uses "vulnerabilities" key, we use "kev_entries"
            rows = proxied.get("kev_entries") or proxied.get("vulnerabilities") or []
            if search:
                q = search.lower()
                rows = [
                    r for r in rows
                    if q in (
                        (r.get("cve_id") or "") + " "
                        + (r.get("vendor_project") or r.get("vendor") or "") + " "
                        + (r.get("product") or "") + " "
                        + (r.get("vulnerability_name") or "")
                    ).lower()
                ]
            total   = len(rows)
            results = rows[offset: offset + limit]
            return {
                "kev_entries":     results,
                "total":           total,
                "limit":           limit,
                "offset":          offset,
                "in_memory_count": len(feeds._kev_set),
                "timestamp":       time.time(),
                "source":          "central",
            }

    # Embedded mode — read from local DB
    try:
        rows = await intel_db.list_kev(limit=5000)
    except Exception as exc:
        log.error("KEV catalog query failed: %s", exc)
        raise HTTPException(500, detail="KEV catalog unavailable")

    if search:
        q = search.lower()
        rows = [
            r for r in rows
            if q in (
                (r.get("cve_id") or "") + " "
                + (r.get("vendor_project") or r.get("vendor") or "") + " "
                + (r.get("product") or "") + " "
                + (r.get("vulnerability_name") or "")
            ).lower()
        ]

    total   = len(rows)
    results = rows[offset: offset + limit]
    return {
        "kev_entries":     results,
        "total":           total,
        "limit":           limit,
        "offset":          offset,
        "in_memory_count": len(feeds._kev_set),
        "timestamp":       time.time(),
        "source":          "local",
    }


@router.get("/epss/{cve_id}")
async def get_epss(
    cve_id: str,
    req:    Request,
    feeds=Depends(_feeds),
) -> dict:
    """
    Return the EPSS (Exploit Prediction Scoring System) score for a single CVE.
    In central mode, proxies to the threat-intel service.
    EPSS is updated daily by FIRST.org and reflects exploit probability.
    """
    cid     = _require_cve(cve_id)
    central = _central_url(req)
    if central:
        proxied = await _proxy_get(central, f"/api/v1/intel/epss/{cid}")
        if proxied is not None:
            return proxied

    result = await feeds.get_epss(cid)
    if result is None:
        raise HTTPException(404, detail=f"EPSS score not available for {cid}. "
                            "The CVE may not be in the EPSS dataset yet.")
    return result


@router.get("/exploits/{cve_id}")
async def get_exploit_info(
    cve_id:   str,
    pipeline=Depends(_pipeline),
) -> dict:
    """
    Return exploit availability for a CVE from ExploitDB, Metasploit, and GitHub PoC.
    Sources are queried in parallel.  Unavailable sources return null for their field.
    """
    cid = _require_cve(cve_id)
    import asyncio

    edb_task = asyncio.create_task(pipeline._src_exploitdb(cid))
    msf_task = asyncio.create_task(pipeline._src_metasploit(cid))
    poc_task = asyncio.create_task(pipeline._src_poc_github(cid))

    edb, msf, poc = await asyncio.gather(edb_task, msf_task, poc_task, return_exceptions=True)

    def _safe(v):
        return None if isinstance(v, Exception) else v

    edb, msf, poc = _safe(edb), _safe(msf), _safe(poc)

    return {
        "cve_id":           cid,
        "exploit_available": bool(edb or msf or poc),
        "exploitdb":        edb,
        "metasploit":       bool(msf),
        "poc_github":       poc,
        "sources_queried":  ["exploitdb", "metasploit", "poc_github"],
        "timestamp":        time.time(),
    }
