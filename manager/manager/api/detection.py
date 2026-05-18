"""
manager/api/detection.py — Category-scoped detection endpoints.

The Jarvis engine writes findings into intel.db as it processes telemetry.
These endpoints read those findings, apply the correct category filters,
and enrich each finding with KEV status, EPSS, impact, and remediation.

Endpoints:
  GET /api/v1/detection/summary            global counts per category
  GET /api/v1/detection/packages           CVE-matched installed packages
  GET /api/v1/detection/ports              open-port threat findings
  GET /api/v1/detection/persistence        service + task + config + binary
  GET /api/v1/detection/network            connection / IOC findings
  GET /api/v1/detection/processes          process / execution findings
  GET /api/v1/detection/all               all active findings, sortable

Design for large data:
  All queries use existing indexes on (agent_id, category, severity, is_active).
  FTS5 is available for search. Pagination with LIMIT/OFFSET.
  Per-CVE KEV enrichment is a dict-lookup (O(1)) from a preloaded KEV set.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, Query

if TYPE_CHECKING:
    from ..indexer import IntelDB

log = logging.getLogger("manager.api.detection")

# Source string → confidence level (0–1)
_SOURCE_CONFIDENCE: dict[str, float] = {
    "feed:feodo":              0.97,
    "feed:emerging":           0.90,
    "feed:threatfox":          0.95,
    "abuseipdb":               0.78,
    "nvd":                     0.88,
    "rule:malicious_port":     0.92,
    "rule:process_lineage":    0.88,
    "rule:process_pattern":    0.75,
    "rule:obfuscation":        0.82,
    "rule:suspicious_service": 0.80,
    "rule:risky_package":      0.72,
    "rule:suspicious_path":    0.78,
    "rule:suid_binary":        0.85,
    "rule:world_writable":     0.75,
    "rule:uid0":               0.98,
    "rule:config_pattern":     0.80,
    "rule:task_pattern":       0.82,
    "rule:security_posture":   0.95,
    "behavioral":              0.70,
}

# Category → human label + icon hint
_CAT_META: dict[str, dict] = {
    "package":    {"label": "Vulnerable Package",    "icon": "package",    "group": "vulnerability"},
    "port":       {"label": "Risky Open Port",       "icon": "port",       "group": "network"},
    "connection": {"label": "Network Threat",        "icon": "network",    "group": "network"},
    "service":    {"label": "Persistence Service",   "icon": "service",    "group": "persistence"},
    "task":       {"label": "Persistence Task",      "icon": "task",       "group": "persistence"},
    "config":     {"label": "Config Anomaly",        "icon": "config",     "group": "persistence"},
    "binary":     {"label": "Suspicious Binary",     "icon": "binary",     "group": "persistence"},
    "process":    {"label": "Execution Threat",      "icon": "process",    "group": "execution"},
    "app":        {"label": "Suspicious App",        "icon": "app",        "group": "execution"},
    "user":       {"label": "Account Anomaly",       "icon": "user",       "group": "identity"},
    "security":   {"label": "Posture Finding",       "icon": "shield",     "group": "posture"},
}

# Impact descriptions by category
_IMPACT: dict[str, str] = {
    "package":    "Exploiting this vulnerability can lead to remote code execution, data exfiltration, or privilege escalation depending on the service exposure.",
    "port":       "An attacker discovering this open port could use it as a command-and-control channel, lateral movement pivot, or exploitation gateway.",
    "connection": "Active connections to known-malicious infrastructure indicate potential C2 communication, data exfiltration, or active compromise.",
    "service":    "Persistence mechanisms survive reboots. An attacker who establishes persistence can maintain access even after credential rotation.",
    "task":       "Scheduled tasks can execute attacker code at system startup or intervals, maintaining stealth persistence.",
    "config":     "Malicious patterns in shell configs are a common persistence technique, injecting backdoors into every interactive shell session.",
    "binary":     "SUID/world-writable binaries are a direct privilege escalation path — any user can exploit them to gain elevated access.",
    "process":    "Offensive tools running in memory indicate active attacker presence. Immediate containment required to prevent lateral movement.",
    "app":        "Unsigned or quarantined applications bypass macOS security controls and may execute malicious payloads.",
    "user":       "Account anomalies such as UID 0 non-root accounts represent direct privilege escalation or attacker-created backdoor accounts.",
    "security":   "Security control misconfigurations directly expand the attack surface, enabling attacks that would otherwise be blocked.",
}


def make_detection_router(intel_db: "IntelDB") -> APIRouter:
    router = APIRouter()

    # ── Summary counts ─────────────────────────────────────────────────────────
    @router.get("/summary")
    async def summary(agent_id: Optional[str] = Query(None)):
        """
        Active finding counts per category and severity.
        Used for sidebar badges and dashboard KPIs.
        """
        try:
            rows = await intel_db._fetchall(
                "SELECT category, severity, COUNT(*) AS cnt "
                "FROM findings "
                "WHERE is_active=1 "
                + ("AND agent_id=? " if agent_id else "")
                + "GROUP BY category, severity",
                ((agent_id,) if agent_id else ()),
            )
        except Exception:
            rows = []

        cats: dict[str, dict] = {}
        totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            cat, sev, cnt = r["category"], r["severity"], r["cnt"]
            if cat not in cats:
                cats[cat] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            cats[cat][sev]    = (cats[cat].get(sev, 0) + cnt)
            cats[cat]["total"] += cnt
            totals[sev]       = totals.get(sev, 0) + cnt

        return {
            "by_category": cats,
            "totals":       totals,
            "grand_total":  sum(totals.values()),
        }

    # ── Package CVE findings ───────────────────────────────────────────────────
    @router.get("/packages")
    async def packages(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        search:   Optional[str] = Query(None),
        sort_by:  str           = Query("composite_score"),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
    ):
        """
        Package CVE findings — installed packages matched against NVD.
        Each finding includes: CVE IDs, CVSS, EPSS, KEV status, risk score,
        exploitation evidence, impact statement, and step-by-step remediation.
        """
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            category="package",
            severity=severity,
            search=search,
            active_only=True,
            sort_by=sort_by,
            limit=limit,
            offset=offset,
        )
        return {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}

    # ── Open port findings ─────────────────────────────────────────────────────
    @router.get("/ports")
    async def ports(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
    ):
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            category="port",
            severity=severity,
            active_only=True,
            sort_by="composite_score",
            limit=limit,
            offset=offset,
        )
        return {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}

    # ── Persistence findings (service + task + config + binary) ───────────────
    @router.get("/persistence")
    async def persistence(
        agent_id:  Optional[str] = Query(None),
        severity:  Optional[str] = Query(None),
        sub_type:  Optional[str] = Query(None, description="service|task|config|binary"),
        limit:     int           = Query(150, ge=1, le=500),
        offset:    int           = Query(0, ge=0),
    ):
        """
        All persistence-related findings: launchd services, cron/launchd tasks,
        malicious config patterns, SUID/world-writable binaries.
        """
        persistence_cats = [sub_type] if sub_type else ["service", "task", "config", "binary"]
        all_rows = []
        # Fetch each category concurrently
        results = await asyncio.gather(*[
            intel_db.get_soc_findings(
                agent_id=agent_id,
                category=cat,
                severity=severity,
                active_only=True,
                sort_by="composite_score",
                limit=limit,
                offset=0,
            )
            for cat in persistence_cats
        ])
        for batch in results:
            all_rows.extend(batch)

        # Sort merged result by composite_score DESC
        all_rows.sort(key=lambda r: r.get("composite_score") or r.get("score") or 0, reverse=True)
        paged = all_rows[offset: offset + limit]
        return {
            "findings": [_enrich(r) for r in paged],
            "count":    len(paged),
            "total":    len(all_rows),
            "offset":   offset,
        }

    # ── Network threat findings ────────────────────────────────────────────────
    @router.get("/network")
    async def network(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
    ):
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            category="connection",
            severity=severity,
            active_only=True,
            sort_by="composite_score",
            limit=limit,
            offset=offset,
        )
        return {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}

    # ── Execution / process findings ───────────────────────────────────────────
    @router.get("/processes")
    async def processes(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
    ):
        results = await asyncio.gather(
            intel_db.get_soc_findings(
                agent_id=agent_id, category="process",
                severity=severity, active_only=True,
                sort_by="composite_score", limit=limit, offset=0,
            ),
            intel_db.get_soc_findings(
                agent_id=agent_id, category="app",
                severity=severity, active_only=True,
                sort_by="composite_score", limit=limit, offset=0,
            ),
        )
        all_rows = sorted(
            results[0] + results[1],
            key=lambda r: r.get("composite_score") or r.get("score") or 0,
            reverse=True,
        )
        paged = all_rows[offset: offset + limit]
        return {"findings": [_enrich(r) for r in paged], "count": len(paged), "offset": offset}

    # ── All active findings ────────────────────────────────────────────────────
    @router.get("/all")
    async def all_findings(
        agent_id:  Optional[str] = Query(None),
        category:  Optional[str] = Query(None),
        severity:  Optional[str] = Query(None),
        status:    Optional[str] = Query(None),
        sla_only:  bool          = Query(False),
        search:    Optional[str] = Query(None),
        sort_by:   str           = Query("composite_score"),
        limit:     int           = Query(200, ge=1, le=1000),
        offset:    int           = Query(0, ge=0),
    ):
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            category=category,
            severity=severity,
            status=status,
            sla_breached=sla_only,
            search=search,
            active_only=True,
            sort_by=sort_by,
            limit=limit,
            offset=offset,
        )
        return {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}

    return router


# ── Enrichment ────────────────────────────────────────────────────────────────

def _enrich(f: dict) -> dict:
    """
    Add computed fields to a raw finding dict:
      confidence_pct  — rule confidence → percentage
      impact          — category-specific impact statement
      cat_meta        — label + icon hint for the category
      sla_status      — ok | warning | breached | closed
      evidence        — always a parsed dict (never raw JSON string)
      action_plan     — always a parsed list
      cve_ids         — always a parsed list
    """
    # Parse JSON fields that come back as strings from SQLite
    for field, default in [("evidence", {}), ("action_plan", []), ("cve_ids", []),
                            ("exploit_sources", []), ("tags", [])]:
        v = f.get(field)
        if isinstance(v, str):
            try:
                f[field] = json.loads(v)
            except Exception:
                f[field] = default

    cat = f.get("category", "")
    source = f.get("source", "") or f.get("rule_id", "")

    f["confidence_pct"] = round(
        _SOURCE_CONFIDENCE.get(source, _source_confidence_guess(source)) * 100
    )
    f["impact"]    = _IMPACT.get(cat, "This finding may indicate a security risk. Review evidence and apply remediation.")
    f["cat_meta"]  = _CAT_META.get(cat, {"label": cat.title(), "icon": "alert", "group": "other"})

    # SLA status
    sla_due = f.get("sla_due") or 0
    status  = f.get("status", "new")
    if status in ("closed", "false_positive", "accepted_risk", "verified", "duplicate"):
        f["sla_status"] = "closed"
    elif not sla_due:
        f["sla_status"] = "ok"
    else:
        now = time.time()
        remaining = sla_due - now
        f["sla_status"] = "breached" if remaining < 0 else "warning" if remaining < 7200 else "ok"

    return f


def _source_confidence_guess(source: str) -> float:
    if source.startswith("feed:"):   return 0.92
    if source.startswith("rule:"):   return 0.75
    if source == "nvd":              return 0.85
    if source == "behavioral":       return 0.68
    return 0.70
