"""
manager/manager/api/integrations.py — Integration reliability observability.

  GET /api/v1/integrations/health   — per-integration health, metrics, breakers
  GET /api/v1/integrations/dedup    — ingest dedup cache stats (hit rate, savings)

Surfaces the IntegrationRegistry snapshot so operators (and the dashboard) can
see, at a glance, which external dependencies are healthy / degraded / down,
their error rates, latency percentiles, retry counts, and circuit-breaker state.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..integrations.resilience import registry

log = logging.getLogger("manager.api.integrations")

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/health")
async def integrations_health(request: Request) -> JSONResponse:
    """
    Return the reliability snapshot for every external integration that has
    been exercised this process lifetime. `overall` is 'healthy' unless any
    breaker is open ('down') or error rate is elevated ('degraded').
    """
    snap = registry.snapshot()
    services: dict[str, dict] = {}
    notifier = getattr(request.app.state, "email_notifier", None)
    if notifier and hasattr(notifier, "health_status"):
        services["email"] = notifier.health_status()
    dispatcher = getattr(request.app.state, "finding_notification_dispatcher", None)
    if dispatcher and hasattr(dispatcher, "health_status"):
        services["finding_notifications"] = await dispatcher.health_status()

    if services:
        counts = {"healthy": 0, "degraded": 0, "down": 0, "disabled": 0}
        for svc in services.values():
            status = str(svc.get("status") or "healthy")
            if status == "down":
                counts["down"] += 1
            elif status == "degraded" or (status == "not_configured" and svc.get("enabled")):
                counts["degraded"] += 1
            elif status == "not_configured":
                counts["disabled"] += 1
            elif status == "disabled":
                counts["disabled"] += 1
            else:
                counts["healthy"] += 1
        snap["platform_services"] = services
        snap["service_counts"] = counts
        if counts["down"]:
            snap["overall"] = "down"
        elif counts["degraded"] and snap["overall"] == "healthy":
            snap["overall"] = "degraded"
    # Map overall status to an HTTP code so uptime probes can alert on it.
    code = 200 if snap["overall"] == "healthy" else 207 if snap["overall"] == "degraded" else 503
    return JSONResponse(status_code=code, content=snap)


@router.get("/dedup")
async def dedup_stats(request: Request) -> JSONResponse:
    """
    Return ingest dedup cache statistics.

    hit_rate approaching 1.0 means the agent is sending mostly stable data —
    the cache is working. A persistently low hit_rate means frequent content
    changes (or a fresh restart with a cold cache).

    Fields:
      cache_size     — findings currently tracked in memory
      hits           — submissions served from cache (no DB read/write)
      misses         — cache misses that fell through to DB SELECT
      changes        — findings whose content changed (triggered DB UPDATE)
      hit_rate       — hits / (hits + misses + changes)
      pending_flush  — heartbeats accumulated, waiting for the 30s batch flush
    """
    idb = request.app.state.intel_db
    return JSONResponse(content=idb.dedup_stats())
