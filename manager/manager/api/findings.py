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

import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
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
        agent_id:     Optional[str]   = Query(None,  description="Filter by agent"),
        severity:     Optional[str]   = Query(None,  description="critical|high|medium|low|info"),
        status:       Optional[str]   = Query(None,  description="SOC workflow status"),
        category:     Optional[str]   = Query(None,  description="Finding category"),
        assignee:     Optional[str]   = Query(None,  description="Assigned analyst"),
        sla_breached: bool            = Query(False,  description="Only SLA-breached findings"),
        active_only:  bool            = Query(True,   description="Only active (open) findings"),
        view:         Optional[str]   = Query(None,   description="active|closed|all — shorthand for active_only"),
        search:       Optional[str]   = Query(None,   description="Full-text search"),
        sort_by:      str             = Query("score", description="score|last_detected_at|severity|sla_due"),
        limit:        int             = Query(500, ge=1, le=1000),
        offset:       int             = Query(0, ge=0),
        min_precision: Optional[float] = Query(
            None, ge=0.0, le=1.0,
            description="Static precision floor. Findings with precision_score < this value are dropped. "
                        "For the Validated Findings page, prefer `validated_only=true` which applies the "
                        "configured per-agent / per-terrain / global threshold instead."
        ),
        validated_only: bool          = Query(
            False,
            description="When true, apply the configured Validation Settings thresholds "
                        "(per-agent → per-terrain → global) on a row-by-row basis. "
                        "Used by the Validated Findings page so user-configured thresholds take effect.",
        ),
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

        # If validated_only is set we apply the user-configured threshold
        # resolution per row.  Pull the configured global as a coarse SQL
        # pre-filter to keep the result set small; the precise per-agent /
        # per-terrain threshold is enforced in Python below.
        effective_global: Optional[float] = None
        effective_thresholds: dict = {}
        if validated_only:
            try:
                from ..attacklens.ai_validator import (
                    _load_validation_settings, resolve_threshold,
                )
                vsettings = await _load_validation_settings(intel_db)
                effective_global = float(vsettings.get("global", 0.90))
                effective_thresholds = {
                    "global":  effective_global,
                    "terrain": dict(vsettings.get("terrain") or {}),
                    "agent":   dict(vsettings.get("agent") or {}),
                }
                # SQL pre-filter at the lowest possible threshold so per-agent
                # overrides set BELOW the global still see their findings.
                floor_candidates = [effective_global]
                floor_candidates.extend(vsettings.get("terrain", {}).values())
                floor_candidates.extend(vsettings.get("agent", {}).values())
                pre_filter = min(floor_candidates) if floor_candidates else effective_global
                # Combine with any explicit min_precision the caller passed
                if min_precision is not None:
                    pre_filter = min(pre_filter, float(min_precision))
                min_precision_sql: Optional[float] = pre_filter
            except Exception as exc:
                log.warning("validated_only: failed to load settings: %s — falling back to 0.9 floor", exc)
                min_precision_sql = 0.9
                effective_thresholds = {"global": 0.9, "terrain": {}, "agent": {}}
                effective_global = 0.9
        else:
            min_precision_sql = min_precision

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
                min_precision=min_precision_sql,
            )
        except Exception as exc:
            log.exception("list_findings failed")
            raise HTTPException(500, f"Failed to load findings: {exc}")

        # Apply per-row resolution when validated_only=true.
        precision_meta: list[dict] = []
        if validated_only and rows:
            from ..attacklens.ai_validator import resolve_threshold
            keep: list[dict] = []
            for r in rows:
                # Re-use the same resolution the engine uses (per-agent →
                # per-terrain → global), so analysts see exactly the same
                # bar that promoted the finding in the first place.
                thr = await resolve_threshold(
                    intel_db, r.get("agent_id", ""), r.get("category", ""),
                )
                row_score = float(r.get("precision_score") or 0.0)
                r["effective_threshold"] = round(thr, 3)
                if row_score >= thr:
                    keep.append(r)
            rows = keep

        body: dict = {
            "findings": rows,
            "count":    len(rows),
            "offset":   offset,
        }
        if validated_only:
            body["validated_only"]       = True
            body["effective_thresholds"] = effective_thresholds
            body["global_threshold"]     = effective_global

            # When the filter drops everything, the analyst should not be left
            # guessing why.  Surface the total active-finding count and the top
            # below-threshold scores so the UI can render a helpful banner.
            try:
                stats_row = await intel_db._fetchone(
                    "SELECT COUNT(*) AS n FROM findings WHERE is_active=1", (),
                )
                active_total = int(stats_row["n"] if stats_row else 0)
            except Exception:
                active_total = 0

            # Show top 5 below-threshold scores so analyst knows where the
            # bar lands relative to existing findings.
            try:
                near_rows = await intel_db._fetchall(
                    "SELECT id, agent_id, category, title, precision_score "
                    "FROM findings "
                    "WHERE is_active=1 AND precision_score > 0 "
                    "ORDER BY precision_score DESC LIMIT 5",
                    (),
                )
                top5 = [
                    {
                        "id":              r["id"],
                        "title":           r["title"],
                        "agent_id":        r["agent_id"],
                        "category":        r["category"],
                        "precision_score": float(r["precision_score"]),
                    }
                    for r in near_rows
                ]
            except Exception:
                top5 = []

            # Per-terrain counts so the UI can show a breakdown bar
            from ..attacklens.terrain_validators import terrain_for
            terrain_counts: dict[str, dict[str, int]] = {
                t: {"validated": 0, "below": 0}
                for t in ("citadels","vector","origin","identity","posture")
            }
            try:
                all_rows = await intel_db._fetchall(
                    "SELECT agent_id, category, precision_score, terrain_validation "
                    "FROM findings WHERE is_active=1 LIMIT 100000",
                    (),
                )
                for r in all_rows:
                    f_lite = {"agent_id": r["agent_id"], "category": r["category"]}
                    terrain = terrain_for(f_lite)
                    score   = float(r["precision_score"] or 0)
                    # Re-resolve threshold per row (uses the same hierarchy)
                    if validated_only:
                        try:
                            thr = await resolve_threshold(intel_db, r["agent_id"] or "", r["category"] or "")
                        except Exception:
                            thr = effective_global or 0.90
                    else:
                        thr = effective_global or 0.90
                    bucket = terrain_counts.setdefault(terrain, {"validated":0,"below":0})
                    if score >= thr:
                        bucket["validated"] += 1
                    else:
                        bucket["below"] += 1
            except Exception as exc:
                log.debug("terrain_counts probe error: %s", exc)

            body["stats"] = {
                "active_total":     active_total,
                "validated_count":  len(rows),
                "below_threshold":  max(0, active_total - len(rows)),
                "top_scores":       top5,
                "highest_score":    top5[0]["precision_score"] if top5 else None,
                "by_terrain":       terrain_counts,
            }
        return body

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
        # Capture old status before update (for feedback loop)
        old = await intel_db.get_finding_by_id(finding_id)
        if not old:
            raise HTTPException(404, f"Finding {finding_id} not found")

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

        # ── Feedback loop: record FP/TP/accepted for confidence engine ─────────
        new_status = body.status
        if new_status and new_status != old.get("status"):
            try:
                from ..attacklens import feedback
                if new_status == "false_positive":
                    await feedback.record_fp(intel_db, finding_id)
                elif new_status in ("closed", "verified", "remediated"):
                    await feedback.record_tp(intel_db, finding_id)
                elif new_status == "accepted_risk":
                    await feedback.record_accepted(intel_db, finding_id)
            except Exception as exc:
                log.debug("feedback record failed for finding %s: %s", finding_id, exc)

        return updated

    # ── Signals (confidence engine) ───────────────────────────────────────────
    @router.get("/findings/{finding_id}/signals")
    async def get_finding_signals(finding_id: int):
        """
        Return the signal cluster that produced this finding.
        Only populated for findings emitted by the confidence pipeline
        (signal_cluster_id is non-null). Legacy findings return an empty list.
        """
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        cluster_id = finding.get("signal_cluster_id")
        if not cluster_id:
            return {"cluster_id": None, "signals": [], "confidence": finding.get("confidence")}
        signals = await intel_db.get_signals_for_cluster(cluster_id)
        return {
            "cluster_id":  cluster_id,
            "confidence":  finding.get("confidence"),
            "layers":      json.loads(finding.get("layers_involved") or "[]"),
            "signals":     signals,
            "signal_count": len(signals),
        }

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

    # ── Exploitability assessment ──────────────────────────────────────────────
    @router.get("/findings/{finding_id}/exploitability")
    async def get_exploitability(finding_id: int, req: Request):
        """
        Return a structured exploitability + prioritization assessment.

        Synthesizes signals from stored finding data (instant) and, when
        IntelPipeline is available on app.state, calls live CVE enrichment
        for up to 3 CVE IDs to incorporate fresh ExploitDB / EPSS / KEV data.

        Priority grades (SSVC-inspired):
          P0 Immediate   — KEV + weaponized exploit or EPSS > 50%
          P1 Urgent      — KEV alone, OR critical CVSS + any exploit, OR EPSS > 50%
          P2 High        — exploit available + CVSS ≥ 7, OR CVSS ≥ 9, OR EPSS > 20%
          P3 Scheduled   — exploit present OR CVSS ≥ 7 OR EPSS > 5%
          P4 Defer       — low CVSS / no signals
        """
        finding = await intel_db.get_finding_by_id(finding_id)
        if not finding:
            raise HTTPException(404, f"Finding {finding_id} not found")

        pipeline = getattr(req.app.state, "intel_pipeline", None)

        # Extract CVE IDs (stored as JSON string or list)
        raw_cves = finding.get("cve_ids") or []
        if isinstance(raw_cves, str):
            try:
                raw_cves = json.loads(raw_cves)
            except Exception:
                raw_cves = [raw_cves] if raw_cves.upper().startswith("CVE-") else []
        cve_ids = [c for c in (raw_cves if isinstance(raw_cves, list) else []) if c]

        # Live CVE enrichment (up to 3 CVEs to keep latency bounded)
        cve_intel: list[dict] = []
        cve_errors: dict = {}
        if pipeline and cve_ids:
            import asyncio
            tasks = {cid: asyncio.create_task(pipeline.enrich_cve(cid)) for cid in cve_ids[:3]}
            for cid, task in tasks.items():
                try:
                    result = await task
                    if "error" not in result:
                        cve_intel.append(result)
                except Exception as exc:
                    cve_errors[cid] = str(exc)
                    log.debug("exploitability: CVE %s enrichment failed: %s", cid, exc)

        report = _build_exploitability(finding_id, finding, cve_intel)
        report["cve_intel"]          = cve_intel
        report["cve_errors"]         = cve_errors
        report["pipeline_available"] = pipeline is not None
        return report

    return router


# ── Exploitability synthesis (pure function, no I/O) ─────────────────────────

def _build_exploitability(finding_id: int, finding: dict, cve_intel: list[dict]) -> dict:
    """
    Synthesize exploitability report.  Works with stored data alone (no live
    enrichment) and is upgraded when cve_intel list is populated.
    """
    # ── Aggregate base signals ────────────────────────────────────────────────
    cvss        = float(finding.get("cvss_score") or 0.0)
    epss        = float(finding.get("epss_score") or 0.0)
    is_kev      = bool(finding.get("kev"))
    has_exploit = bool(finding.get("exploit_available"))

    srcs_raw = finding.get("exploit_sources") or []
    if isinstance(srcs_raw, str):
        try:
            srcs_raw = json.loads(srcs_raw)
        except Exception:
            srcs_raw = [srcs_raw] if srcs_raw else []
    stored_srcs = srcs_raw if isinstance(srcs_raw, list) else []

    # ── Upgrade signals from live CVE intel ───────────────────────────────────
    for c in cve_intel:
        cvss        = max(cvss,  float(c.get("cvss_score")  or 0.0))
        epss        = max(epss,  float(c.get("epss_score")  or 0.0))
        is_kev      = is_kev or bool(c.get("kev"))
        has_exploit = has_exploit or bool(c.get("exploit_available"))

    # ── Collect per-source exploit signals ────────────────────────────────────
    exploit_signals: list[dict] = []
    for c in cve_intel:
        edb = c.get("exploitdb")
        if isinstance(edb, dict) and int(edb.get("total", 0) or 0) > 0:
            verified = int(edb.get("verified", 0) or 0)
            exploit_signals.append({
                "source":   "exploitdb",
                "total":    edb["total"],
                "verified": verified,
                "label":    f"ExploitDB ({edb['total']} exploit{'s' if edb['total']!=1 else ''}"
                            + (f", {verified} verified" if verified else "") + ")",
            })
        if c.get("metasploit"):
            exploit_signals.append({"source": "metasploit", "label": "Metasploit module (weaponized)"})
        poc = c.get("poc_github")
        if isinstance(poc, dict) and int(poc.get("count", 0) or 0) > 0:
            exploit_signals.append({
                "source":    "poc_github",
                "count":     poc["count"],
                "max_stars": poc.get("max_stars", 0),
                "label":     f"GitHub PoC ({poc['count']} repo{'s' if poc['count']!=1 else ''},"
                             f" {poc.get('max_stars',0)} ★ max)",
            })

    # Fallback to stored sources when no live data
    if not exploit_signals and has_exploit:
        for s in stored_srcs:
            exploit_signals.append({"source": str(s), "label": str(s)})

    has_verified_edb = any(
        s["source"] == "exploitdb" and s.get("verified", 0) > 0 for s in exploit_signals
    )
    has_msf = any(s["source"] == "metasploit" for s in exploit_signals)

    # ── Priority grade (SSVC-inspired) ────────────────────────────────────────
    if is_kev and (has_verified_edb or has_msf) and epss > 0.5 and cvss >= 9.0:
        grade, label = "P0", "Immediate — patch now (KEV + weaponized + EPSS > 50%)"
    elif is_kev and has_exploit:
        grade, label = "P0", "Immediate — actively exploited (KEV + public exploit)"
    elif is_kev:
        grade, label = "P1", "Urgent — CISA KEV listed (remediate within 3 weeks)"
    elif cvss >= 9.0 and has_exploit:
        grade, label = "P1", "Urgent — critical CVSS + exploit available"
    elif epss > 0.5 and cvss >= 8.0:
        grade, label = "P1", "Urgent — high exploitation probability (EPSS > 50%)"
    elif has_exploit and cvss >= 7.0:
        grade, label = "P2", "High — exploit + high CVSS (schedule within 30 days)"
    elif cvss >= 9.0:
        grade, label = "P2", "High — critical CVSS, no known exploit yet"
    elif epss > 0.2:
        grade, label = "P2", "High — elevated EPSS exploitation probability"
    elif has_exploit or cvss >= 7.0 or epss > 0.05:
        grade, label = "P3", "Scheduled — include in next patch cycle"
    elif cvss >= 4.0:
        grade, label = "P3", "Scheduled — moderate severity, routine patching"
    else:
        grade, label = "P4", "Defer — low risk, no active exploitation signals"

    # ── Rationale ─────────────────────────────────────────────────────────────
    rationale: list[str] = []
    if is_kev:
        rationale.append("Listed in CISA KEV — confirmed active exploitation in the wild")
    if has_verified_edb:
        verified_count = next(
            (s["verified"] for s in exploit_signals if s["source"] == "exploitdb"), 0
        )
        rationale.append(f"Verified exploit in ExploitDB ({verified_count} confirmed PoC)")
    elif any(s["source"] == "exploitdb" for s in exploit_signals):
        rationale.append("Unverified exploit code in ExploitDB (weaponization risk)")
    if has_msf:
        rationale.append("Metasploit module available — trivially weaponized")
    poc_sig = next((s for s in exploit_signals if s["source"] == "poc_github"), None)
    if poc_sig:
        rationale.append(f"GitHub PoC repos present ({poc_sig.get('count',0)} repos, "
                         f"{poc_sig.get('max_stars',0)} ★ max)")
    if epss > 0.5:
        rationale.append(f"EPSS {epss*100:.0f}% — high probability of exploitation in the wild")
    elif epss > 0.2:
        rationale.append(f"EPSS {epss*100:.0f}% — elevated exploitation probability")
    elif epss > 0.05:
        rationale.append(f"EPSS {epss*100:.0f}% — moderate exploitation probability")
    if cvss >= 9.0:
        rationale.append(f"CVSS {cvss:.1f} — critical base severity")
    elif cvss >= 7.0:
        rationale.append(f"CVSS {cvss:.1f} — high base severity")
    if not rationale:
        rationale.append("No active exploitation signals detected — low operational risk")

    # ── Confidence from intel sources ─────────────────────────────────────────
    intel_conf = max(
        (float(c.get("intel_confidence", 0.5) or 0.5) for c in cve_intel),
        default=None,
    )
    sources_used = list({
        src for c in cve_intel for src in (c.get("sources_used") or [])
    })

    return {
        "finding_id":        finding_id,
        "priority_grade":    grade,
        "priority_label":    label,
        "is_kev":            is_kev,
        "exploit_available": bool(exploit_signals) or has_exploit,
        "exploit_signals":   exploit_signals,
        "cvss_score":        cvss if cvss > 0 else None,
        "epss_score":        epss if epss > 0 else None,
        "intel_confidence":  intel_conf,
        "sources_used":      sources_used,
        "rationale":         rationale,
        "assessment_ts":     time.time(),
    }
