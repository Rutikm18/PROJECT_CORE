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


def make_detection_router(intel_db: "IntelDB", db=None) -> APIRouter:
    router = APIRouter()

    async def _live_agent_ids() -> Optional[list[str]]:
        """agent_ids that haven't gone stale (config.py: stale_agent_sec).
        None when db wasn't provided — callers degrade to unfiltered (old
        behavior) rather than break. See get_soc_findings's live_agent_ids
        docstring for why this never affects an explicit single-agent query."""
        if db is None:
            return None
        try:
            from ..attacklens.config import ENGINE_CONFIG
            return await db.get_live_agent_ids(ENGINE_CONFIG.get("stale_agent_sec", 86400))
        except Exception as exc:
            log.warning("Live-agent lookup failed, showing unfiltered: %s", exc)
            return None

    # ── Summary counts ─────────────────────────────────────────────────────────
    @router.get("/summary")
    async def summary(agent_id: Optional[str] = Query(None)):
        """
        Active finding counts per category and severity.
        Used for sidebar badges and dashboard KPIs.
        """
        live_ids = None if agent_id else await _live_agent_ids()
        try:
            if live_ids is not None:
                if not live_ids:
                    rows = []
                else:
                    placeholders = ",".join("?" * len(live_ids))
                    rows = await intel_db._fetchall(
                        "SELECT category, severity, COUNT(*) AS cnt "
                        "FROM findings "
                        f"WHERE is_active=1 AND agent_id IN ({placeholders}) "
                        "GROUP BY category, severity",
                        tuple(live_ids),
                    )
            else:
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

    # ── Fleet-wide / global-threat campaigns ───────────────────────────────────
    @router.get("/fleet")
    async def fleet_campaigns():
        """Cross-host campaigns (distributed C2, malware propagation, supply-chain
        outbreak, mass posture collapse, coordinated recon …). These are emitted
        by the FleetCorrelator and stored under the reserved __fleet__ pseudo-agent
        — they represent threats that span multiple hosts and are invisible to the
        per-agent correlation view."""
        try:
            from ..indexer import FLEET_AGENT_ID
            from ..attacklens.fleet_correlator import build_fleet_summary
            campaigns = await intel_db.get_correlations(FLEET_AGENT_ID)
        except Exception:
            campaigns = []
        return {
            "summary":   build_fleet_summary(campaigns),
            "campaigns": campaigns,
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
        validated_only: bool    = Query(False, description="Only findings with precision_score ≥ configured threshold"),
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
            live_agent_ids=await _live_agent_ids(),
        )
        rows, thr, below = await _apply_validated_filter(intel_db, rows, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}, validated_only, thr, below)

    # ── Open port findings ─────────────────────────────────────────────────────
    @router.get("/ports")
    async def ports(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
        validated_only: bool    = Query(False, description="Only findings with precision_score ≥ configured threshold"),
    ):
        rows = await intel_db.get_soc_findings(
            agent_id=agent_id,
            category="port",
            severity=severity,
            active_only=True,
            sort_by="composite_score",
            limit=limit,
            offset=offset,
            live_agent_ids=await _live_agent_ids(),
        )
        rows, thr, below = await _apply_validated_filter(intel_db, rows, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}, validated_only, thr, below)

    # ── Persistence findings (service + task + config + binary) ───────────────
    @router.get("/persistence")
    async def persistence(
        agent_id:  Optional[str] = Query(None),
        severity:  Optional[str] = Query(None),
        sub_type:  Optional[str] = Query(None, description="service|task|config|binary"),
        limit:     int           = Query(150, ge=1, le=500),
        offset:    int           = Query(0, ge=0),
        validated_only: bool     = Query(False, description="Only findings with precision_score ≥ configured threshold"),
    ):
        """
        All persistence-related findings: launchd services, cron/launchd tasks,
        malicious config patterns, SUID/world-writable binaries.
        """
        persistence_cats = [sub_type] if sub_type else ["service", "task", "config", "binary"]
        all_rows = []
        live_ids = await _live_agent_ids()
        results = await asyncio.gather(*[
            intel_db.get_soc_findings(
                agent_id=agent_id,
                category=cat,
                severity=severity,
                active_only=True,
                sort_by="composite_score",
                limit=limit,
                offset=0,
                live_agent_ids=live_ids,
            )
            for cat in persistence_cats
        ])
        for batch in results:
            all_rows.extend(batch)
        all_rows.sort(key=lambda r: r.get("composite_score") or r.get("score") or 0, reverse=True)
        paged = all_rows[offset: offset + limit]
        paged, thr, below = await _apply_validated_filter(intel_db, paged, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in paged], "count": len(paged), "total": len(all_rows), "offset": offset}, validated_only, thr, below)

    # ── Network threat findings (the "Vector" panel) ───────────────────────────
    @router.get("/network")
    async def network(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        sub_type: Optional[str] = Query(None, description="Restrict to one category: connection | network | port"),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
        validated_only: bool    = Query(False, description="Only findings with precision_score ≥ configured threshold"),
    ):
        """Aggregate every category that belongs to the dashboard's Vector panel."""
        wanted_cats = [sub_type] if sub_type in _VECTOR_CATEGORIES else _VECTOR_CATEGORIES
        live_ids = await _live_agent_ids()
        results = await asyncio.gather(*[
            intel_db.get_soc_findings(
                agent_id=agent_id, category=cat, severity=severity,
                active_only=True, sort_by="composite_score",
                limit=limit + offset, offset=0, live_agent_ids=live_ids,
            ) for cat in wanted_cats
        ], return_exceptions=True)
        all_rows: list[dict] = []
        for batch in results:
            if isinstance(batch, Exception):
                log.warning("Vector fetch failed: %s", batch)
                continue
            all_rows.extend(batch)
        seen: set = set()
        unique: list[dict] = []
        for r in all_rows:
            fid = r.get("id")
            if fid is not None and fid in seen:
                continue
            if fid is not None:
                seen.add(fid)
            unique.append(r)
        unique.sort(key=lambda r: (r.get("composite_score") or r.get("score") or 0), reverse=True)
        paged = unique[offset: offset + limit]
        paged, thr, below = await _apply_validated_filter(intel_db, paged, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in paged], "count": len(paged), "total": len(unique), "offset": offset, "categories": wanted_cats}, validated_only, thr, below)

    # ── Execution / process findings ───────────────────────────────────────────
    @router.get("/processes")
    async def processes(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
        validated_only: bool    = Query(False, description="Only findings with precision_score ≥ configured threshold"),
    ):
        live_ids = await _live_agent_ids()
        results = await asyncio.gather(
            intel_db.get_soc_findings(
                agent_id=agent_id, category="process",
                severity=severity, active_only=True,
                sort_by="composite_score", limit=limit, offset=0,
                live_agent_ids=live_ids,
            ),
            intel_db.get_soc_findings(
                agent_id=agent_id, category="app",
                severity=severity, active_only=True,
                sort_by="composite_score", limit=limit, offset=0,
                live_agent_ids=live_ids,
            ),
        )
        all_rows = sorted(
            results[0] + results[1],
            key=lambda r: r.get("composite_score") or r.get("score") or 0,
            reverse=True,
        )
        paged = all_rows[offset: offset + limit]
        paged, thr, below = await _apply_validated_filter(intel_db, paged, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in paged], "count": len(paged), "offset": offset}, validated_only, thr, below)

    # ── Identity & access findings ────────────────────────────────────────────
    @router.get("/identity")
    async def identity(
        agent_id: Optional[str] = Query(None),
        severity: Optional[str] = Query(None),
        limit:    int           = Query(100, ge=1, le=500),
        offset:   int           = Query(0, ge=0),
        validated_only: bool    = Query(False),
    ):
        """Identity & access terrain — user, account, identity, and auth categories."""
        live_ids = await _live_agent_ids()
        cats = ["user", "identity", "account", "auth", "privilege", "credential"]
        results = await asyncio.gather(*[
            intel_db.get_soc_findings(
                agent_id=agent_id, category=cat, severity=severity,
                active_only=True, sort_by="composite_score",
                limit=limit, offset=0, live_agent_ids=live_ids,
            )
            for cat in cats
        ])
        seen: set[int] = set()
        all_rows: list[dict] = []
        for batch in results:
            for r in batch:
                if r.get("id") not in seen:
                    seen.add(r["id"])
                    all_rows.append(r)
        all_rows.sort(key=lambda r: r.get("composite_score") or r.get("score") or 0, reverse=True)
        paged = all_rows[offset: offset + limit]
        paged, thr, below = await _apply_validated_filter(intel_db, paged, validated_only)
        return _validated_body(
            {"findings": [_enrich(r) for r in paged], "count": len(paged), "total": len(all_rows), "offset": offset},
            validated_only, thr, below,
        )

    # ── All active findings ────────────────────────────────────────────────────
    @router.get("/all")
    async def all_findings(
        agent_id:  Optional[str] = Query(None),
        terrain_id: Optional[str] = Query(None, description="citadels|vector|origin|identity|posture"),
        category:  Optional[str] = Query(None),
        severity:  Optional[str] = Query(None),
        status:    Optional[str] = Query(None),
        sla_only:  bool          = Query(False),
        search:    Optional[str] = Query(None),
        id_search: Optional[str] = Query(
            None, description="Direct ID lookup — prefix match on external_id "
                              "(AL-F-NNNNNNNN). Uses UNIQUE index, O(log n). "
                              "Overrides `search` when both are present."
        ),
        sort_by:   str           = Query("composite_score"),
        limit:     int           = Query(200, ge=1, le=1000),
        offset:    int           = Query(0, ge=0),
        validated_only: bool     = Query(
            False,
            description="Opt-in: apply the configured Settings → Validation "
                        "thresholds (per-agent → per-terrain → global) to show only "
                        "findings whose precision ≥ threshold. Default False — "
                        "All Incidents shows EVERY active incident; the threshold-"
                        "filtered subset is the separate Validated Findings view. "
                        "Defaulting True hid everything in shadow mode (precision "
                        "scores below the bar), which read as 'no data'.",
        ),
    ):
        # ── ID Search fast-path: direct indexed lookup ─────────────────────────
        if id_search:
            term = id_search.strip().upper()
            if not term.startswith("AL-F-"):
                term = "AL-F-" + term
            rows = await intel_db.search_by_external_id(term, active_only=True, limit=limit)
            return {"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": 0, "id_search": id_search}

        rows = await intel_db.get_soc_findings(
            agent_id=agent_id, terrain_id=terrain_id, category=category,
            severity=severity, status=status, sla_breached=sla_only, search=search,
            active_only=True, sort_by=sort_by, limit=limit, offset=offset,
            live_agent_ids=await _live_agent_ids(),
        )
        rows, thr, below = await _apply_validated_filter(intel_db, rows, validated_only)
        return _validated_body({"findings": [_enrich(r) for r in rows], "count": len(rows), "offset": offset}, validated_only, thr, below)

    return router


# ── Validated-only helper ──────────────────────────────────────────────────────

async def _apply_validated_filter(intel_db, rows: list[dict], validated_only: bool) -> tuple[list[dict], float | None, int]:
    """
    When `validated_only` is True, load the configured thresholds from
    Settings → Validation and keep only findings whose precision_score ≥
    the per-agent → per-terrain → global threshold.

    Returns (filtered_rows, global_threshold, below_count).
    """
    global_threshold: float | None = None
    below = 0
    if not validated_only or not rows:
        return rows, global_threshold, below

    try:
        from ..attacklens.ai_validator import _load_validation_settings, resolve_threshold
        vs = await _load_validation_settings(intel_db)
        global_threshold = float(vs.get("global", 0.90))
    except Exception as exc:
        log.warning("validated_only settings load failed — defaulting to 0.90: %s", exc)
        global_threshold = 0.90

    kept: list[dict] = []
    for r in rows:
        try:
            thr = await resolve_threshold(intel_db, r.get("agent_id", ""), r.get("category", ""))
        except Exception:
            thr = global_threshold or 0.90
        r["effective_threshold"] = round(thr, 3)
        row_score = float(r.get("precision_score") or 0.0)
        r["is_validated"] = row_score >= thr
        if row_score >= thr:
            kept.append(r)
        else:
            below += 1
    return kept, global_threshold, below


def _validated_body(body: dict, validated_only: bool, global_threshold: float | None, below: int) -> dict:
    """Attach validated-only metadata to the response body."""
    if validated_only:
        body["validated_only"] = True
        body["global_threshold"] = global_threshold
        body["below_threshold"] = below
    return body


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

    # Lift raw-payload provenance to top-level fields so the UI/analyst can
    # verify the incident against Deep Analysis:
    #   GET /api/v1/raw/query?agent_id=<source_agent_id>&section=<source_section>
    # and locate the payload at <source_collected_at>.
    _src = f.get("evidence", {}).get("_source") if isinstance(f.get("evidence"), dict) else None
    if isinstance(_src, dict):
        f["source_section"]      = _src.get("section")
        f["source_collected_at"] = _src.get("collected_at")
        f["source_agent_id"]     = _src.get("agent_id") or f.get("agent_id")

    cat = f.get("category", "")
    source = f.get("source", "") or f.get("rule_id", "")

    f["confidence_pct"] = round(
        _SOURCE_CONFIDENCE.get(source, _source_confidence_guess(source)) * 100
    )
    f["impact"]    = _IMPACT.get(cat, "This finding may indicate a security risk. Review evidence and apply remediation.")
    f["cat_meta"]  = _CAT_META.get(cat, {"label": cat.title(), "icon": "alert", "group": "other"})

    # SLA status — driven by the canonical terminal-status set.
    from .. import finding_lifecycle as lc
    sla_due = f.get("sla_due") or 0
    status  = lc.normalize(f.get("status"))
    f["status"] = status
    if lc.is_terminal(status):
        f["sla_status"] = "closed"
    elif not sla_due:
        f["sla_status"] = "ok"
    else:
        now = time.time()
        remaining = sla_due - now
        f["sla_status"] = "breached" if remaining < 0 else "warning" if remaining < 7200 else "ok"

    # Stable identifiers + lifecycle, so every page (All Incidents, Attack
    # Terrain Origin/Vector/Citadels) can show the unique id and render the
    # correct triage action buttons for THIS finding's current state.
    if not f.get("external_id") and f.get("id") is not None:
        # Defensive: surface a deterministic display id even if the backfill
        # hasn't stamped this row yet (the DB UNIQUE id is the source of truth).
        f["external_id"] = f"AL-F-{int(f['id']):08d}"
    f["is_terminal"]       = lc.is_terminal(status)
    f["available_actions"] = lc.available_actions(status)

    # Canonical attack-terrain bucket (origin/vector/citadels/identity/posture),
    # the SINGLE source of truth so the same finding lands in the same terrain
    # everywhere — All Incidents and the Attack Terrain sub-views agree, and the
    # external_id is identical across them. Frontends must use this, not their
    # own category→terrain guesses.
    # Prefer the stored terrain_id (set by upsert_finding), fall back to
    # runtime inference for legacy rows not yet backfilled.
    terrain = f.get("terrain_id") or ""
    if not terrain:
        from ..attacklens.terrain_validators import terrain_for
        terrain = terrain_for(f)
    f["terrain"] = terrain
    f["terrain_id"] = terrain

    # Terrain source provenance — the detection source (rule|feed|nvd) that
    # drove the terrain classification, surfaced in the UI as "via <source>".
    f["terrain_source"] = f.get("terrain_source") or f.get("category", "")

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
