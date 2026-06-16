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
    # Threat feeds
    "feed:feodo":              0.97,
    "feed:emerging":           0.90,
    "feed:threatfox":          0.95,
    "feed:urlhaus":            0.93,
    "feed:spamhaus":           0.94,
    "abuseipdb":               0.78,
    "greynoise":               0.82,
    "shodan":                  0.80,
    # Vulnerability databases
    "nvd":                     0.88,
    # Network / Vector rules
    "rule:malicious_port":     0.92,
    "rule:wildcard_bind":      0.88,
    "rule:arp_spoofing":       0.90,
    "rule:covert_channel":     0.86,
    # Execution / process rules
    "rule:process_lineage":    0.88,
    "rule:process_pattern":    0.75,
    "rule:obfuscation":        0.82,
    "rule:suid_process":       0.85,
    # Persistence rules
    "rule:suspicious_service": 0.80,
    "rule:task_pattern":       0.82,
    "rule:config_pattern":     0.80,
    "rule:suspicious_path":    0.78,
    # Posture / package / identity
    "rule:risky_package":      0.72,
    "rule:suid_binary":        0.85,
    "rule:world_writable":     0.75,
    "rule:uid0":               0.98,
    "rule:security_posture":   0.95,
    "rule:not_notarized":      0.78,
    "rule:unsigned_app":       0.80,
    "rule:quarantine":         0.75,
    # Behavioural analyser
    "behavioral":              0.70,
    "behavioral_new_entity":   0.72,
    "behavioral_change":       0.78,
    "behavioral_threshold":    0.75,
    "behavioral_velocity":     0.74,
    "behavioral_zscore":       0.80,
    "behavioral_entropy":      0.82,
    # Correlator
    "correlation_engine":      0.92,
}

# Category → human label + icon hint
_CAT_META: dict[str, dict] = {
    "package":    {"label": "Vulnerable Package",    "icon": "package",    "group": "vulnerability"},
    "port":       {"label": "Risky Open Port",       "icon": "port",       "group": "network"},
    "connection": {"label": "Network Threat",        "icon": "network",    "group": "network"},
    "network":    {"label": "Network Anomaly",       "icon": "network",    "group": "network"},
    "service":    {"label": "Persistence Service",   "icon": "service",    "group": "persistence"},
    "task":       {"label": "Persistence Task",      "icon": "task",       "group": "persistence"},
    "config":     {"label": "Config Anomaly",        "icon": "config",     "group": "persistence"},
    "binary":     {"label": "Suspicious Binary",     "icon": "binary",     "group": "persistence"},
    "process":    {"label": "Execution Threat",      "icon": "process",    "group": "execution"},
    "app":        {"label": "Suspicious App",        "icon": "app",        "group": "execution"},
    "container":  {"label": "Container Threat",      "icon": "container",  "group": "execution"},
    "user":       {"label": "Account Anomaly",       "icon": "user",       "group": "identity"},
    "security":   {"label": "Posture Finding",       "icon": "shield",     "group": "posture"},
    "sysctl":     {"label": "Kernel Parameter",      "icon": "shield",     "group": "posture"},
}

# Categories that belong to the "Vector" (network) panel in the dashboard.
# Connection IOCs, behavioural/ARP/covert-channel events, and risky open ports
# all surface here because the sidebar has no separate Ports page.
_VECTOR_CATEGORIES: list[str] = ["connection", "network", "port"]

# Impact descriptions by category
_IMPACT: dict[str, str] = {
    "package":    "Exploiting this vulnerability can lead to remote code execution, data exfiltration, or privilege escalation depending on the service exposure.",
    "port":       "An attacker discovering this open port could use it as a command-and-control channel, lateral movement pivot, or exploitation gateway.",
    "connection": "Active connections to known-malicious infrastructure indicate potential C2 communication, data exfiltration, or active compromise.",
    "network":    "Unexpected interface/route changes, ARP anomalies, or covert tunnels indicate either active attacker manipulation of the host network stack or a compromised network neighbour.",
    "container":  "Containerised workloads with privileged or unconfined capabilities allow container-escape and host compromise.",
    "sysctl":     "Kernel parameter tampering disables runtime protections (ASLR, ptrace_scope, kptr_restrict) and enables exploitation primitives.",
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

    # ── Network threat findings (the "Vector" panel) ───────────────────────────
    @router.get("/network")
    async def network(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        sub_type: Optional[str] = Query(
            None,
            description="Restrict to one category: connection | network | port",
        ),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
    ):
        """
        Aggregate every category that belongs to the dashboard's Vector panel:
          • connection — outbound/inbound IOC matches (Feodo, URLhaus, AbuseIPDB)
          • network    — behavioural interface changes, ARP-spoofing, covert
                         channels, DNS tunnelling
          • port       — risky open ports (no dedicated sidebar entry)

        Each category is fetched concurrently and merged sorted by
        composite_score so the Vector page sees one unified stream.
        """
        wanted_cats = (
            [sub_type] if sub_type in _VECTOR_CATEGORIES else _VECTOR_CATEGORIES
        )

        results = await asyncio.gather(*[
            intel_db.get_soc_findings(
                agent_id=agent_id,
                category=cat,
                severity=severity,
                active_only=True,
                sort_by="composite_score",
                # Pull enough per category to give the merge headroom before paging.
                limit=limit + offset,
                offset=0,
            )
            for cat in wanted_cats
        ], return_exceptions=True)

        all_rows: list[dict] = []
        for batch in results:
            if isinstance(batch, Exception):
                log.warning("Vector fetch failed for one sub-category: %s", batch)
                continue
            all_rows.extend(batch)

        # De-duplicate by id (a finding could only be in one category, but be safe).
        seen: set = set()
        unique: list[dict] = []
        for r in all_rows:
            fid = r.get("id")
            if fid is not None and fid in seen:
                continue
            if fid is not None:
                seen.add(fid)
            unique.append(r)

        unique.sort(
            key=lambda r: (r.get("composite_score") or r.get("score") or 0),
            reverse=True,
        )
        paged = unique[offset: offset + limit]
        return {
            "findings":   [_enrich(r) for r in paged],
            "count":      len(paged),
            "total":      len(unique),
            "offset":     offset,
            "categories": wanted_cats,
        }

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
        validated_only: bool     = Query(
            True,
            description="Apply the configured Settings → Validation thresholds "
                        "(per-agent → per-terrain → global) so the All Incidents "
                        "queue shows only findings whose precision ≥ threshold. "
                        "Pass false to see every active finding.",
        ),
    ):
        # When validated_only is on, resolve the per-agent → per-terrain → global
        # threshold from Settings → Validation and keep only findings whose
        # precision_score clears it — the SAME bar the engine used to promote
        # them, so the page stays consistent with the Validated Findings queue.
        min_precision_sql: Optional[float] = None
        global_threshold:  Optional[float] = None
        if validated_only:
            try:
                from ..attacklens.ai_validator import _load_validation_settings
                vs = await _load_validation_settings(intel_db)
                global_threshold = float(vs.get("global", 0.90))
                # SQL pre-filter at the LOWEST configured threshold so per-agent
                # overrides set below the global aren't pre-dropped; the exact
                # per-row bar is enforced in Python after fetch.
                floors = [global_threshold]
                floors.extend((vs.get("terrain") or {}).values())
                floors.extend((vs.get("agent") or {}).values())
                min_precision_sql = min(floors) if floors else global_threshold
            except Exception as exc:
                log.warning("detection/all validated_only settings load failed: %s "
                            "— defaulting to 0.90 floor", exc)
                min_precision_sql = 0.90
                global_threshold = 0.90

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
            min_precision=min_precision_sql,
        )

        below = 0
        if validated_only and rows:
            from ..attacklens.ai_validator import resolve_threshold
            kept: list[dict] = []
            for r in rows:
                try:
                    thr = await resolve_threshold(
                        intel_db, r.get("agent_id", ""), r.get("category", ""),
                    )
                except Exception:
                    thr = global_threshold or 0.90
                r["effective_threshold"] = round(thr, 3)
                if float(r.get("precision_score") or 0.0) >= thr:
                    kept.append(r)
                else:
                    below += 1
            rows = kept

        body = {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}
        if validated_only:
            body["validated_only"]   = True
            body["global_threshold"] = global_threshold
            body["below_threshold"]  = below
        return body

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
    for field, default in [
        ("evidence", {}), ("action_plan", []), ("cve_ids", []),
        ("exploit_sources", []), ("tags", []),
        # AI Precision Validation outputs
        ("precision_factors", {}), ("ai_verdict", {}),
        ("layers_involved", []), ("validation_gates_passed", []),
        # Terrain-aware validation
        ("terrain_validation", {}),
    ]:
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
    if not source:
        return 0.70
    if source.startswith("feed:"):       return 0.92
    if source.startswith("rule:"):       return 0.75
    if source.startswith("behavioral"):  return 0.72
    if source.startswith("corr"):        return 0.90
    if source.startswith("C-"):          return 0.90    # correlator signal rule_id
    if source.startswith(("S-", "E-", "X-")):  return 0.85  # confidence-engine rule IDs
    if source == "nvd":                  return 0.85
    if source == "abuseipdb":            return 0.78
    return 0.70
