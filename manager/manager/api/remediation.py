"""
manager/manager/api/remediation.py — AI-powered remediation API.

Endpoints:
  GET  /api/v1/remediation/{finding_id}                  Get cached plan
  POST /api/v1/remediation/{finding_id}/generate          Generate AI plan
  GET  /api/v1/remediation/{finding_id}/analysis          Get AI analysis
  POST /api/v1/remediation/{finding_id}/analysis/generate Generate AI analysis
  GET  /api/v1/remediation/assets                         List asset registry
  PUT  /api/v1/remediation/assets/{agent_id}              Update asset tier/group
  GET  /api/v1/remediation/assets/{agent_id}              Get asset info
  GET  /api/v1/remediation/org-groups                     List org groups
  POST /api/v1/remediation/org-groups                     Create/update org group
  GET  /api/v1/intel/kev                                  CISA KEV list
  GET  /api/v1/intel/actors                               Threat actors
  GET  /api/v1/intel/news                                 Recent security news
  GET  /api/v1/intel/epss/{cve_id}                       EPSS score
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("manager.api.remediation")

router = APIRouter(tags=["remediation"])

_CENTRAL_URL = os.environ.get("THREAT_INTEL_URL", "").strip().rstrip("/")
_PROXY_TIMEOUT = aiohttp.ClientTimeout(total=10)


async def _proxy_get(path: str, params: dict | None = None) -> Optional[Any]:
    """Fetch from central threat-intel service. Returns parsed JSON or None."""
    if not _CENTRAL_URL:
        return None
    try:
        async with aiohttp.ClientSession(timeout=_PROXY_TIMEOUT) as s:
            async with s.get(f"{_CENTRAL_URL}{path}", params=params) as r:
                if r.status == 200:
                    return await r.json()
    except Exception as exc:
        log.debug("Central intel proxy error %s: %s", path, exc)
    return None


def _idb(request: Request):
    return request.app.state.intel_db


def _analyst(request: Request):
    return getattr(request.app.state, "ai_analyst", None)


def _feeds(request: Request):
    return getattr(request.app.state, "feeds", None)


def _notifier(request: Request):
    return getattr(request.app.state, "email_notifier", None)


# ── Remediation plans ─────────────────────────────────────────────────────────

@router.get("/api/v1/remediation/{finding_id}")
async def get_remediation_plan(
    finding_id: int,
    os_type: str = Query("macos", regex="^(macos|windows|linux)$"),
    idb=Depends(_idb),
):
    plan = await idb.get_remediation_plan(finding_id, os_type)
    if not plan:
        raise HTTPException(404, "No remediation plan found. POST /generate to create one.")
    return plan


@router.post("/api/v1/remediation/{finding_id}/generate")
async def generate_remediation_plan(
    finding_id: int,
    request: Request,
    os_type: str = Query("macos", regex="^(macos|windows|linux)$"),
    force: bool = Query(False),
    notify: bool = Query(False),
    idb=Depends(_idb),
    analyst=Depends(_analyst),
    notifier=Depends(_notifier),
):
    if not analyst or not analyst.enabled:
        raise HTTPException(503, "AI analyst not available. Set ANTHROPIC_API_KEY.")

    # Fetch finding
    rows = await idb.get_soc_findings(active_only=False, limit=1)
    finding = None
    async with idb._conn.execute(
        "SELECT * FROM findings WHERE id=?", (finding_id,)
    ) as cur:
        row = await cur.fetchone()
        if row:
            finding = dict(row)

    if not finding:
        raise HTTPException(404, f"Finding {finding_id} not found.")

    plan = await analyst.generate_remediation(finding_id, finding, os_type=os_type, force=force)
    if not plan:
        raise HTTPException(500, "Remediation generation failed.")

    if notify and notifier and notifier.enabled:
        await notifier.send_remediation_ready(finding, os_type)

    return plan


# ── AI analysis ───────────────────────────────────────────────────────────────

@router.get("/api/v1/remediation/{finding_id}/analysis")
async def get_ai_analysis(finding_id: int, idb=Depends(_idb)):
    analysis = await idb.get_ai_analysis(finding_id)
    if not analysis:
        raise HTTPException(404, "No AI analysis found. POST /analysis/generate to create one.")
    return analysis


@router.post("/api/v1/remediation/{finding_id}/analysis/generate")
async def generate_ai_analysis(
    finding_id: int,
    force: bool = Query(False),
    idb=Depends(_idb),
    analyst=Depends(_analyst),
):
    if not analyst or not analyst.enabled:
        raise HTTPException(503, "AI analyst not available. Set ANTHROPIC_API_KEY.")

    async with idb._conn.execute(
        "SELECT * FROM findings WHERE id=?", (finding_id,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, f"Finding {finding_id} not found.")
    finding = dict(row)

    result = await analyst.analyze_finding(finding_id, finding, force=force)
    if not result:
        raise HTTPException(500, "AI analysis failed.")
    return result


@router.post("/api/v1/remediation/prioritize")
async def ai_prioritize(
    request: Request,
    agent_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    idb=Depends(_idb),
    analyst=Depends(_analyst),
):
    """AI-assisted prioritization of active findings."""
    if not analyst or not analyst.enabled:
        raise HTTPException(503, "AI analyst not available. Set ANTHROPIC_API_KEY.")
    findings = await idb.get_soc_findings(agent_id=agent_id, active_only=True, limit=limit)
    prioritized = await analyst.prioritize_findings(findings)
    return {"findings": prioritized, "count": len(prioritized),
            "ai_powered": True, "model": "claude-sonnet-4-6"}


# ── Asset registry ────────────────────────────────────────────────────────────

@router.get("/api/v1/assets")
async def list_assets(
    limit: int = Query(500, ge=1, le=2000),
    idb=Depends(_idb),
):
    assets = await idb.list_assets(limit=limit)
    return {"assets": assets, "count": len(assets)}


@router.get("/api/v1/assets/{agent_id}")
async def get_asset(agent_id: str, idb=Depends(_idb)):
    asset = await idb.get_asset(agent_id)
    if not asset:
        raise HTTPException(404, f"Asset {agent_id} not found.")
    return asset


@router.put("/api/v1/assets/{agent_id}")
async def update_asset(agent_id: str, request: Request, idb=Depends(_idb)):
    body = await request.json()
    tier  = str(body.get("asset_tier", "standard"))
    imp   = float(body.get("importance", 0.3))
    group = str(body.get("asset_group", ""))
    owner = str(body.get("owner", ""))
    dept  = str(body.get("department", ""))
    tags  = body.get("tags", [])
    valid_tiers = {"server", "workstation", "laptop", "critical", "crown_jewel", "standard"}
    if tier not in valid_tiers:
        raise HTTPException(422, f"Invalid tier. Must be one of: {valid_tiers}")
    await idb.upsert_asset(agent_id, {
        "asset_tier": tier, "importance": imp, "asset_group": group,
        "owner": owner, "department": dept, "tags": tags,
    })
    return {"status": "ok", "agent_id": agent_id}


# ── Org groups ────────────────────────────────────────────────────────────────

@router.get("/api/v1/org-groups")
async def list_org_groups(idb=Depends(_idb)):
    groups = await idb.list_org_groups()
    return {"groups": groups, "count": len(groups)}


@router.post("/api/v1/org-groups")
async def upsert_org_group(request: Request, idb=Depends(_idb)):
    body = await request.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(422, "name is required")
    await idb.upsert_org_group(name, body)
    return {"status": "ok", "name": name}


# ── Threat intel extended endpoints ──────────────────────────────────────────

@router.get("/api/v1/intel/kev")
async def list_kev(
    limit: int = Query(200, ge=1, le=2000),
    idb=Depends(_idb),
):
    """CISA Known Exploited Vulnerabilities catalog."""
    # Try central service first; fall back to local DB
    proxied = await _proxy_get("/api/v1/intel/kev", {"limit": limit})
    if proxied:
        return proxied
    rows  = await idb.list_kev(limit=limit)
    count = await idb.kev_count()
    return {"vulnerabilities": rows, "total": count, "returned": len(rows)}


@router.get("/api/v1/intel/actors")
async def list_actors(
    active_only: bool = Query(True),
    limit: int = Query(100, ge=1, le=500),
    idb=Depends(_idb),
):
    """Known threat actors (ransomware groups, APTs)."""
    proxied = await _proxy_get("/api/v1/intel/actors",
                               {"active_only": str(active_only).lower(), "limit": limit})
    if proxied:
        return proxied
    actors = await idb.get_threat_actors(active_only=active_only, limit=limit)
    total  = await idb.actor_count()
    return {"actors": actors, "total_active": total, "returned": len(actors)}


@router.get("/api/v1/intel/news")
async def list_news(
    hours: int = Query(48, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    idb=Depends(_idb),
):
    """Recent security news from HackerNews and other feeds."""
    proxied = await _proxy_get("/api/v1/intel/news", {"hours": hours, "limit": limit})
    if proxied:
        return proxied
    news = await idb.get_recent_news(hours=hours, limit=limit)
    return {"news": news, "count": len(news), "window_hours": hours}


@router.get("/api/v1/intel/epss/{cve_id}")
async def get_epss(cve_id: str, idb=Depends(_idb), feeds=Depends(_feeds)):
    """EPSS exploit probability score for a CVE."""
    if feeds and hasattr(feeds, "get_epss"):
        result = await feeds.get_epss(cve_id.upper())
    else:
        result = await idb.get_epss(cve_id.upper())
    if not result:
        raise HTTPException(404, f"EPSS score not available for {cve_id}")
    return result


@router.get("/api/v1/intel/overview")
async def intel_overview(idb=Depends(_idb)):
    """Extended threat intel overview including new data sources."""
    base = await idb.get_threat_intel_overview()
    kev_count   = await idb.kev_count()
    actor_count = await idb.actor_count()
    news_count  = await idb.news_count()
    base.update({
        "cisa_kev":      kev_count,
        "threat_actors": actor_count,
        "security_news": news_count,
        "sources": [
            "Feodo Tracker (C2 IPs)",
            "Emerging Threats (compromised hosts)",
            "URLhaus (malware URLs)",
            "ThreatFox (IOCs)",
            "Spamhaus DROP+EDROP (bad CIDRs)",
            "CISA KEV (known exploited CVEs)",
            "ransomware.live (active groups)",
            "HackerNews (security news)",
            "NVD (CVE database)",
            "AbuseIPDB (IP reputation — optional)",
            "OTX AlienVault (optional)",
            "GreyNoise (scanner detection — optional)",
            "Shodan InternetDB (on-demand)",
            "EPSS (exploit prediction)",
        ],
    })
    return base
