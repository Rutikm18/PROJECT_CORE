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

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger("manager.findings")


# ── Request models ────────────────────────────────────────────────────────────

class FindingUpdate(BaseModel):
    status:        Optional[str] = None
    assignee:      Optional[str] = None
    analyst_notes: Optional[str] = None
    priority:      Optional[int] = None
    actor:         Optional[str] = "analyst"
    resolution_note: Optional[str] = None  # close/accept justification


class QuickAction(BaseModel):
    actor:  str = "analyst"
    reason: Optional[str] = None   # optional justification for close/accept/FP


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
        try:
            return await intel_db.get_dashboard_stats()
        except Exception as exc:
            log.exception("dashboard_stats failed")
            raise HTTPException(500, f"Failed to load dashboard stats: {exc}")

    # ── SLA breach report ─────────────────────────────────────────────────────
    @router.get("/sla")
    async def sla_report():
        """Return active findings that are breaching or at risk of breaching SLA."""
        try:
            findings = await intel_db.get_sla_report()
        except Exception as exc:
            log.exception("sla_report failed")
            raise HTTPException(500, f"Failed to load SLA report: {exc}")
        breached = [f for f in findings if f.get("sla_status") == "breached"]
        warning  = [f for f in findings if f.get("sla_status") == "warning"]
        return {
            "breached": breached,
            "warning":  warning,
            "total_at_risk": len(findings),
        }

    # ── Findings list (global, all agents) ───────────────────────────────────
    _TERMINAL_STATUSES = {"closed","false_positive","accepted_risk","duplicate","verified","remediated"}

    @router.get("/findings")
    async def list_findings(
        agent_id:     Optional[str]  = Query(None,  description="Filter by agent"),
        severity:     Optional[str]  = Query(None,  description="critical|high|medium|low|info"),
        status:       Optional[str]  = Query(None,  description="SOC workflow status"),
        category:     Optional[str]  = Query(None,  description="Finding category"),
        assignee:     Optional[str]  = Query(None,  description="Assigned analyst"),
        sla_breached: bool           = Query(False,  description="Only SLA-breached findings"),
        active_only:  bool           = Query(True,   description="Only active (open) findings"),
        view:         Optional[str]  = Query(None,   description="active|closed|all — shorthand for active_only"),
        search:       Optional[str]  = Query(None,   description="Full-text search"),
        sort_by:      str            = Query("score", description="score|last_detected_at|severity|sla_due"),
        limit:        int            = Query(500, ge=1, le=1000),
        offset:       int            = Query(0, ge=0),
    ):
        """
        List findings with full SOC filters.

        `view` overrides `active_only`:
          active  → only open/active findings (default)
          closed  → only closed/resolved/accepted/fp findings
          all     → every finding regardless of state
        """
        # view param takes precedence
        if view == "active":
            active_only = True
        elif view == "closed":
            active_only = False
            # If no status filter, restrict to terminal states
            if not status:
                status = "__closed__"   # sentinel handled in DB layer
        elif view == "all":
            active_only = False

        try:
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
        except Exception as exc:
            log.exception("list_findings failed")
            raise HTTPException(500, f"Failed to load findings: {exc}")
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
        actions = await intel_db.get_actions(finding_id)
        return {
            **finding,
            "comments": comments,
            "activity": activity,
            "actions": actions,
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

    # ── Improvement metrics ───────────────────────────────────────────────────
    @router.get("/metrics")
    async def improvement_metrics():
        """
        Computed improvement metrics for the dashboard:
          - MTTR (mean time to resolve) in hours
          - Closure rate (% closed vs total this week)
          - False positive rate
          - Week-over-week improvement
          - Actions taken counts (status changes by type)
        """
        import time as _time
        now = _time.time()
        week_ago   = now - 7  * 86400
        week_2_ago = now - 14 * 86400

        try:
            # MTTR: avg resolution time for findings closed in last 30 days
            mttr_rows = await intel_db._fetchall(
                "SELECT first_detected_at, resolved_at FROM findings "
                "WHERE resolved_at IS NOT NULL AND resolved_at > ? AND is_active=0 "
                "AND status IN ('closed','verified','remediated') LIMIT 500",
                (now - 30 * 86400,),
            )
            if mttr_rows:
                times = [r["resolved_at"] - r["first_detected_at"] for r in mttr_rows
                         if r["resolved_at"] and r["first_detected_at"]]
                mttr_hours = round(sum(times) / len(times) / 3600, 1) if times else 0
            else:
                mttr_hours = 0

            # This week vs last week closed count
            this_week_closed = (await intel_db._fetchone(
                "SELECT COUNT(*) AS n FROM findings WHERE resolved_at > ? AND is_active=0",
                (week_ago,),
            ) or {}).get("n", 0)
            last_week_closed = (await intel_db._fetchone(
                "SELECT COUNT(*) AS n FROM findings WHERE resolved_at > ? AND resolved_at <= ? AND is_active=0",
                (week_2_ago, week_ago),
            ) or {}).get("n", 0)

            wow_improvement = 0
            if last_week_closed and last_week_closed > 0:
                wow_improvement = round(((this_week_closed - last_week_closed) / last_week_closed) * 100)

            # False positive rate (last 30 days)
            total_30d = (await intel_db._fetchone(
                "SELECT COUNT(*) AS n FROM findings WHERE first_detected_at > ?",
                (now - 30 * 86400,),
            ) or {}).get("n", 0)
            fp_30d = (await intel_db._fetchone(
                "SELECT COUNT(*) AS n FROM findings WHERE first_detected_at > ? AND status='false_positive'",
                (now - 30 * 86400,),
            ) or {}).get("n", 0)
            fp_rate = round((fp_30d / total_30d) * 100, 1) if total_30d else 0

            # Actions breakdown (soc_activity this week)
            action_rows = await intel_db._fetchall(
                "SELECT action, COUNT(*) AS cnt FROM soc_activity WHERE created_at > ? GROUP BY action",
                (week_ago,),
            )
            actions = {r["action"]: r["cnt"] for r in action_rows}

            # Accepted risk count
            accepted = (await intel_db._fetchone(
                "SELECT COUNT(*) AS n FROM findings WHERE status='accepted_risk' AND is_active=0",
                (),
            ) or {}).get("n", 0)

            return {
                "mttr_hours":         mttr_hours,
                "closed_this_week":   this_week_closed,
                "closed_last_week":   last_week_closed,
                "wow_improvement_pct": wow_improvement,
                "fp_rate_pct":        fp_rate,
                "fp_count_30d":       fp_30d,
                "accepted_risk":      accepted,
                "actions_this_week":  actions,
                "note": "MTTR calculated over findings closed in last 30 days. WoW = week-over-week closure count change.",
            }
        except Exception as exc:
            log.exception("improvement_metrics failed")
            raise HTTPException(500, f"Failed to compute metrics: {exc}")

    # ── Quick-action convenience endpoints ───────────────────────────────────
    # These wrap PATCH so the frontend can call a single intent endpoint
    # instead of encoding state-machine knowledge on the client.

    @router.post("/findings/{finding_id}/close")
    async def close_finding(finding_id: int, body: QuickAction):
        """Close a finding. Marks is_active=0, records closed_at."""
        updated = await intel_db.update_finding(
            finding_id, status="closed", actor=body.actor,
            analyst_notes=body.reason,
        )
        if not updated:
            raise HTTPException(404, f"Finding {finding_id} not found")
        return {"status": "closed", **updated}

    @router.post("/findings/{finding_id}/accept-risk")
    async def accept_risk(finding_id: int, body: QuickAction):
        """Accept the risk. Marks is_active=0, status=accepted_risk."""
        updated = await intel_db.update_finding(
            finding_id, status="accepted_risk", actor=body.actor,
            analyst_notes=body.reason,
        )
        if not updated:
            raise HTTPException(404, f"Finding {finding_id} not found")
        return {"status": "accepted_risk", **updated}

    @router.post("/findings/{finding_id}/false-positive")
    async def mark_false_positive(finding_id: int, body: QuickAction):
        """Mark as false positive. Marks is_active=0, status=false_positive."""
        updated = await intel_db.update_finding(
            finding_id, status="false_positive", actor=body.actor,
            analyst_notes=body.reason,
        )
        if not updated:
            raise HTTPException(404, f"Finding {finding_id} not found")
        return {"status": "false_positive", **updated}

    @router.post("/findings/{finding_id}/reopen")
    async def reopen_finding(finding_id: int, body: QuickAction):
        """
        Reopen a closed/accepted/FP finding.
        Sets status=triaging, is_active=1, clears closed_at.
        """
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, f"Finding {finding_id} not found")
        updated = await intel_db.update_finding(
            finding_id, status="triaging", actor=body.actor,
            analyst_notes=body.reason,
        )
        return {"status": "triaging", "reopened": True, **updated}

    @router.post("/findings/{finding_id}/open")
    async def open_finding(finding_id: int, body: QuickAction):
        """Move finding to triaging (open). Alias for reopen."""
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, f"Finding {finding_id} not found")
        updated = await intel_db.update_finding(
            finding_id, status="triaging", actor=body.actor,
        )
        return {"status": "triaging", **updated}

    # ── 6-month historical trend ──────────────────────────────────────────────
    @router.get("/historical")
    async def historical_trend(months: int = Query(6, ge=1, le=24)):
        """Monthly finding counts for the last N months (dashboard 6-month chart)."""
        try:
            return {"monthly_trend": await intel_db.get_historical_trend(months), "months": months}
        except Exception as exc:
            log.exception("historical_trend failed")
            raise HTTPException(500, f"Failed to load historical trend: {exc}")

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

        try:
            updated = await intel_db.bulk_update_findings(body.finding_ids, **kwargs)
        except Exception as exc:
            log.exception("bulk_action failed")
            raise HTTPException(500, f"Bulk action failed: {exc}")
        return {
            "updated": updated,
            "requested": len(body.finding_ids),
            "action": body.action,
        }

    return router
