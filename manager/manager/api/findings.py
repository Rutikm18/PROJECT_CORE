"""
manager/manager/api/findings.py — SOC Finding Lifecycle API.

Full finding management: status workflow, assignment, SLA tracking,
analyst comments, activity log, bulk operations, and dashboard stats.

Endpoints (mounted at /api/v1/soc):
  GET  /findings                  — global findings list (all agents, full filters)
  GET  /findings/{id}             — single finding detail with comments + activity
  PATCH /findings/{id}            — update status / assignee / notes / priority
  POST /findings/{id}/comments    — add analyst comment
  GET  /findings/{id}/comments    — list comments
  GET  /findings/{id}/activity    — activity log
  POST /bulk                      — bulk status/assignee update
  GET  /dashboard                 — KPIs, charts, SLA data for dashboard
  GET  /sla                       — SLA breach report (urgent findings)

SOC Workflow States:
  new → triaging → investigating → in_remediation → remediated → verified → closed
  Any state → false_positive | accepted_risk | duplicate
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


# ── Request models ────────────────────────────────────────────────────────────

class FindingUpdate(BaseModel):
    status:        Optional[str] = None
    assignee:      Optional[str] = None
    analyst_notes: Optional[str] = None
    priority:      Optional[int] = None
    actor:         Optional[str] = "analyst"


class CommentCreate(BaseModel):
    analyst: str = "analyst"
    comment: str


class BulkAction(BaseModel):
    finding_ids: list[int]
    action:      str          # "assign" | "status" | "escalate" | "close"
    value:       Optional[str] = None   # assignee name or status value
    actor:       Optional[str] = "analyst"


# ── Router factory ────────────────────────────────────────────────────────────

def make_findings_router(intel_db) -> APIRouter:
    router = APIRouter()

    # ── Dashboard stats ───────────────────────────────────────────────────────
    @router.get("/dashboard")
    async def dashboard_stats():
        """
        Return all analytics data for the SOC dashboard in one call:
          kpi, severity_dist, status_dist, category_dist, top_agents,
          daily_trend (7 days), sla_compliance.
        """
        return await intel_db.get_dashboard_stats()

    # ── SLA breach report ─────────────────────────────────────────────────────
    @router.get("/sla")
    async def sla_report():
        """Return active findings that are breaching or at risk of breaching SLA."""
        findings = await intel_db.get_sla_report()
        breached = [f for f in findings if f.get("sla_status") == "breached"]
        warning  = [f for f in findings if f.get("sla_status") == "warning"]
        return {
            "breached": breached,
            "warning":  warning,
            "total_at_risk": len(findings),
        }

    # ── Findings list (global, all agents) ───────────────────────────────────
    @router.get("/findings")
    async def list_findings(
        agent_id:     Optional[str]  = Query(None, description="Filter by agent"),
        severity:     Optional[str]  = Query(None, description="critical|high|medium|low|info"),
        status:       Optional[str]  = Query(None, description="SOC workflow status"),
        category:     Optional[str]  = Query(None, description="Finding category"),
        assignee:     Optional[str]  = Query(None, description="Assigned analyst"),
        sla_breached: bool           = Query(False, description="Only SLA-breached findings"),
        active_only:  bool           = Query(True,  description="Only active findings"),
        search:       Optional[str]  = Query(None,  description="Full-text search"),
        sort_by:      str            = Query("score", description="score|last_detected_at|severity|sla_due"),
        limit:        int            = Query(200, ge=1, le=1000),
        offset:       int            = Query(0, ge=0),
    ):
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            severity=severity,
            status=status,
            category=category,
            assignee=assignee,
            sla_breached=sla_breached,
            active_only=active_only,
            search=search,
            sort_by=sort_by,
            limit=limit,
            offset=offset,
        )
        return {"findings": rows, "count": len(rows), "offset": offset}

    # ── Single finding ────────────────────────────────────────────────────────
    @router.get("/findings/{finding_id}")
    async def get_finding(finding_id: int):
        """Full finding detail including comments and activity log."""
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, f"Finding {finding_id} not found")
        comments = await intel_db.get_comments(finding_id)
        activity = await intel_db.get_activity(finding_id)
        return {
            **finding,
            "comments": comments,
            "activity": activity,
        }

    # ── Update finding ────────────────────────────────────────────────────────
    @router.patch("/findings/{finding_id}")
    async def update_finding(finding_id: int, body: FindingUpdate):
        """
        Update SOC workflow fields. Automatically logs all changes to activity.

        Status transitions:
          new → triaging → investigating → in_remediation → remediated → verified → closed
          Any → false_positive | accepted_risk | duplicate
        """
        updated = await intel_db.update_finding(
            finding_id,
            status=body.status,
            assignee=body.assignee,
            analyst_notes=body.analyst_notes,
            priority=body.priority,
            actor=body.actor or "analyst",
        )
        if not updated:
            raise HTTPException(404, f"Finding {finding_id} not found")
        return updated

    # ── Comments ──────────────────────────────────────────────────────────────
    @router.get("/findings/{finding_id}/comments")
    async def get_comments(finding_id: int):
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        comments = await intel_db.get_comments(finding_id)
        return {"comments": comments, "count": len(comments)}

    @router.post("/findings/{finding_id}/comments")
    async def add_comment(finding_id: int, body: CommentCreate):
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        if not body.comment.strip():
            raise HTTPException(400, "Comment cannot be empty")
        result = await intel_db.add_comment(
            finding_id, finding["agent_id"], body.analyst, body.comment.strip(),
        )
        return result

    # ── Activity log ──────────────────────────────────────────────────────────
    @router.get("/findings/{finding_id}/activity")
    async def get_activity(finding_id: int):
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        activity = await intel_db.get_activity(finding_id)
        return {"activity": activity, "count": len(activity)}

    # ── Bulk actions ──────────────────────────────────────────────────────────
    @router.post("/bulk")
    async def bulk_action(body: BulkAction):
        """
        Bulk update findings. Supported actions:
          - assign      → set assignee to body.value
          - status      → set status to body.value
          - escalate    → set priority=1
          - close       → set status=closed
          - false_positive → set status=false_positive
          - accepted_risk  → set status=accepted_risk
        """
        if not body.finding_ids:
            raise HTTPException(400, "finding_ids cannot be empty")
        if len(body.finding_ids) > 200:
            raise HTTPException(400, "Maximum 200 findings per bulk action")

        kwargs: dict = {"actor": body.actor or "analyst"}

        if body.action == "assign":
            if not body.value:
                raise HTTPException(400, "value (assignee name) required for assign action")
            kwargs["assignee"] = body.value

        elif body.action == "status":
            if not body.value:
                raise HTTPException(400, "value (status) required for status action")
            kwargs["status"] = body.value

        elif body.action == "escalate":
            kwargs["priority"] = 1

        elif body.action == "close":
            kwargs["status"] = "closed"

        elif body.action == "false_positive":
            kwargs["status"] = "false_positive"

        elif body.action == "accepted_risk":
            kwargs["status"] = "accepted_risk"

        else:
            raise HTTPException(400, f"Unknown action: {body.action}. "
                                "Valid: assign, status, escalate, close, false_positive, accepted_risk")

        updated = await intel_db.bulk_update_findings(body.finding_ids, **kwargs)
        return {
            "updated": updated,
            "requested": len(body.finding_ids),
            "action": body.action,
        }

    return router
