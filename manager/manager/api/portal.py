"""
manager/manager/api/portal.py — the customer-facing data API.

This is the **only** surface a customer principal can reach. Every operator
router refuses an ``aud=portal`` token (see ``authz.require_session``), so
confining the customer here is what makes tenant isolation tractable: instead
of twenty routers that must each remember to scope, there is one router where
no query runs without a scope.

Three rules hold for everything below.

  **Scope is not optional.** Every query takes ``scope.agent_ids`` as its first
  argument. An org with no agents assigned resolves to ``AND FALSE`` and sees
  nothing — never everything.

  **Out of scope is 404, not 403.** A 403 confirms the row exists. A customer
  probing finding ids must not be able to learn how many findings the platform
  holds, or that a particular id belongs to someone else.

  **Projection is by allowlist.** ``PORTAL_FINDING_FIELDS`` names what a
  customer may see. A column added to ``findings`` tomorrow is hidden by
  default and stays hidden until somebody deliberately adds it here. A denylist
  would leak every new column until someone remembered to exclude it.

Read-only. The single write is the customer's own dashboard preferences, which
touch nothing but their own display settings.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .authz import PortalScope, make_require_portal_user

log = logging.getLogger("manager.portal")

# ── Projection allowlist ─────────────────────────────────────────────────────
# What a customer sees of a finding. Anything not named here is withheld.
#
# Deliberately excluded, and why:
#   precision_factors, ai_verdict, model_precision_score, terrain_validation,
#   validation_policy_version, effective_validation_threshold, confidence,
#   signal_cluster_id, validation_gates_passed
#       — scoring internals. Exposing them would publish how detections are
#         weighted, which is both proprietary and a tuning guide for anyone
#         wanting to stay under a threshold.
#   assignee, actions_log, notes, host_class
#       — operator workflow state. Not the customer's business, and it names
#         internal staff.
#   fingerprint, item_key
#       — internal identity, useful only for correlating across tenants.
PORTAL_FINDING_FIELDS: tuple[str, ...] = (
    "id", "external_id", "finding_uid",
    "agent_id", "category", "terrain_id",
    "severity", "score", "composite_score", "confidence_pct",
    "title", "description",
    "cve_ids", "cvss_score", "epss_score", "kev", "exploit_available",
    "mitre_technique", "mitre_tactic",
    "status", "first_detected_at", "last_detected_at", "scan_count",
    "validation_state", "precision_score",
)

# Evidence is endpoint telemetry from the customer's own machines, so it is
# theirs to see — but the raw blob also carries collector internals. Only these
# keys pass through.
PORTAL_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "name", "version", "package", "path", "process", "port", "proto",
    "control_key", "control_name", "status", "shell", "uid", "username",
    "cve", "installed", "fixed",
})


def _json_field(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default
    return value if value is not None else default


def project_finding(row: dict) -> dict:
    """Reduce an operator findings row to the customer-visible projection."""
    out: dict[str, Any] = {}
    for field in PORTAL_FINDING_FIELDS:
        if field in row:
            out[field] = row[field]
    out["cve_ids"] = _json_field(out.get("cve_ids"), [])
    out["kev"] = bool(out.get("kev"))
    out["exploit_available"] = bool(out.get("exploit_available"))

    evidence = _json_field(row.get("evidence"), {})
    out["evidence"] = (
        {k: v for k, v in evidence.items() if k in PORTAL_EVIDENCE_KEYS}
        if isinstance(evidence, dict) else {}
    )
    return out


class PortalPreferences(BaseModel):
    """The customer's own dashboard configuration — the one write in the portal.

    Nothing here changes infrastructure, detection behaviour, or anything
    outside this org's display.
    """

    display_name: Optional[str] = Field(default=None, max_length=120)
    timezone: Optional[str] = Field(default=None, max_length=64)
    notification_email: Optional[str] = Field(default=None, max_length=320)
    default_severity_filter: Optional[str] = Field(default=None, max_length=16)


def make_portal_router(intel_db) -> APIRouter:
    require_portal_user = make_require_portal_user(intel_db)

    # Router-level dependency: a portal endpoint cannot be added without a
    # resolved scope, because the scope is how the router authenticates at all.
    router = APIRouter(
        prefix="/api/v1/portal",
        tags=["portal"],
        dependencies=[Depends(require_portal_user)],
    )

    @router.get("/summary")
    async def portal_summary(scope: PortalScope = Depends(require_portal_user)):
        """Headline counts for the customer dashboard."""
        summary = await intel_db.portal_summary(list(scope.agent_ids))
        summary["org"] = {"slug": scope.org_slug, "org_id": scope.org_id}
        return summary

    @router.get("/findings")
    async def portal_findings(
        severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
        terrain_id: Optional[str] = Query(None, max_length=32),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        scope: PortalScope = Depends(require_portal_user),
    ):
        page = await intel_db.portal_findings(
            list(scope.agent_ids),
            severity=severity, terrain_id=terrain_id,
            limit=limit, offset=offset,
        )
        return {
            "findings": [project_finding(f) for f in page["findings"]],
            "total": page["total"],
            "limit": page["limit"],
            "offset": page["offset"],
        }

    @router.get("/findings/{finding_id}")
    async def portal_finding_detail(
        finding_id: int, scope: PortalScope = Depends(require_portal_user),
    ):
        row = await intel_db.portal_finding_detail(list(scope.agent_ids), finding_id)
        if row is None:
            # 404 for both "no such finding" and "not yours". A 403 here would
            # confirm the id exists and belongs to another customer.
            raise HTTPException(status_code=404, detail="Finding not found.")
        return project_finding(row)

    @router.get("/terrains")
    async def portal_terrains(scope: PortalScope = Depends(require_portal_user)):
        """Terrain catalogue with this customer's counts."""
        from ..attacklens.terrain_catalog import all_terrains

        summary = await intel_db.portal_summary(list(scope.agent_ids))
        counts = summary.get("by_terrain", {})
        return {
            "terrains": [
                {
                    "id": d.id, "label": d.label, "description": d.description,
                    "color": d.color, "route": d.route,
                    "count": int(counts.get(d.id, 0)),
                }
                for d in all_terrains()
            ],
            "unclassified": int(counts.get("unclassified", 0)),
        }

    @router.get("/trends")
    async def portal_trends(
        days: int = Query(30, ge=1, le=365),
        scope: PortalScope = Depends(require_portal_user),
    ):
        return {"days": days, "series": await intel_db.portal_trend(
            list(scope.agent_ids), days=days,
        )}

    @router.get("/agents")
    async def portal_agents(scope: PortalScope = Depends(require_portal_user)):
        """The customer's own endpoints. Never the fleet."""
        return {"agents": await intel_db.portal_agents(list(scope.agent_ids))}

    @router.get("/preferences")
    async def get_preferences(scope: PortalScope = Depends(require_portal_user)):
        org = await intel_db.get_org(scope.org_id) or {}
        stored = _json_field(org.get("preferences"), {})
        return {
            "display_name": stored.get("display_name") or org.get("name") or scope.org_slug,
            "timezone": stored.get("timezone") or "UTC",
            "notification_email": stored.get("notification_email") or "",
            "default_severity_filter": stored.get("default_severity_filter") or "",
        }

    @router.put("/preferences")
    async def put_preferences(
        body: PortalPreferences, scope: PortalScope = Depends(require_portal_user),
    ):
        """The only write in the portal, and it touches only this org's display."""
        patch = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
        if not patch:
            raise HTTPException(status_code=400, detail="No preferences supplied.")
        await intel_db.set_org_preferences(scope.org_id, patch)
        await intel_db.record_portal_audit(
            org_id=scope.org_id, actor=scope.email,
            action="portal.preferences.updated", detail={"fields": sorted(patch)},
        )
        return await get_preferences(scope)

    return router
