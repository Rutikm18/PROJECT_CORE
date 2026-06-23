"""
manager/manager/attacklens/config.py — Tunables for the Detection Confidence Engine.

All values are overridable via environment variables or the
GET/PUT /api/v1/settings/detection_engine endpoint (hot-reload, no restart needed).
Default: shadow mode OFF — pipeline scores and logs but emits findings unconditionally.
Set ATTACKLENS_VALIDATION=true to enable precision gating.
"""
from __future__ import annotations

import os

ENGINE_CONFIG: dict = {
    # Gate: only promote cluster → finding when confidence ≥ this threshold.
    "confidence_threshold": 0.95,

    # Route detection through the rich detections/ modules (verified ones in
    # engine._DETECTION_MODULE_ROUTES) instead of the engine's inline analyzers.
    # Per-section: a routed section uses its module(s); unrouted sections keep
    # the inline analyzer. Default on — only verified-safe sections are routed.
    "use_detection_modules": (
        os.getenv("ATTACKLENS_USE_MODULES", "true").lower() == "true"
    ),

    # How far back to look when pulling existing signals for clustering (seconds).
    "correlation_window_sec":              3600,      # 1 h (default rules)
    "correlation_window_sec_persistence": 86400,      # 24 h (persistence-class rules)
    "correlation_window_sec_supply_chain": 604800,    # 7 d  (supply-chain rules)

    # When False (default), scoring/validation runs but findings are emitted
    # unconditionally (shadow mode).  Set True to enable precision gating.
    "validation_pipeline_enabled": (
        os.getenv("ATTACKLENS_VALIDATION", "false").lower() == "true"
    ),

    # Confidence multipliers applied on top of the weighted-average base score.
    "multipliers": {
        # Number of layers covered by the cluster: 1 = no boost, 2 = +30%, 3 = +60%
        "layer": {1: 1.00, 2: 1.30, 3: 1.60},
        # KEV-listed CVE present in cluster evidence
        "kev": 1.50,
        # Highest EPSS score across CVEs in cluster
        "epss": {0.7: 1.30, 0.5: 1.15, 0.2: 1.05, 0.0: 1.00},
        # How many independent threat-intel sources confirm an IOC/CVE
        "threat_intel": {3: 1.40, 2: 1.20, 1: 1.10, 0: 1.00},
        # Asset tier (1=crown_jewel, 5=endpoint)
        "asset_criticality": {1: 1.20, 2: 1.10, 3: 1.00, 4: 0.95, 5: 0.90},
    },

    "penalties": {
        "fp_rate_high":           2.00,   # rule FP rate > 50%
        "fp_rate_medium":         1.30,   # rule FP rate > 20%
        "compensating_control":   0.10,   # subtract per compensating control
    },

    # Minimum signal strength to count as quality evidence
    "quality_floor_strength": 0.6,

    # Rolling window used to compute per-rule FP rates for the penalty term
    "recent_fp_window_days": 7,

    # How long to suppress duplicate findings for the same cluster (dedup gate G3)
    "active_finding_dedup_hours": 24,

    # ── Auto-resolution of stale findings ─────────────────────────────────
    # Resolve a finding when its evidence stops being observed, so old incidents
    # (e.g. a removed package in Origin) don't linger forever.
    #
    # CRITICAL invariant: `auto_resolve_stale_sec` MUST exceed the longest
    # per-rule alert-dedup window. Detection rules suppress re-emission within
    # their dedup window (Origin = 24 h for packages/apps/SBOM), so a STILL
    # PRESENT entity only refreshes its last_detected_at when that window
    # expires. A cutoff below the dedup window would wrongly resolve live
    # findings (the data-loss regression). Default 48 h is safely above the 24 h
    # max dedup → live findings survive, genuinely-gone ones clear within ~2 days.
    #
    # To clear faster, the right move is to SHRINK the dedup windows (the
    # finding UPDATE is idempotent and doesn't spam the timeline, so frequent
    # re-confirmation is cheap) and then lower this cutoff — that decouples
    # "presence" from "alert dedup", which is the proper long-term design.
    "auto_resolve_enabled": (
        os.getenv("ATTACKLENS_AUTO_RESOLVE", "true").lower() == "true"
    ),
    "auto_resolve_stale_sec": int(
        os.getenv("ATTACKLENS_AUTO_RESOLVE_STALE_SEC", str(2 * 86400))
    ),

    # ── Stale-agent filtering ──────────────────────────────────────────────
    # auto_resolve_stale_sec (above) only fires when the agent sends a FRESH
    # payload that no longer contains a previously-seen item — it requires a
    # live ingest event to trigger. If the agent stops reporting entirely
    # (uninstalled, offline, dev/test identity abandoned), nothing ever
    # triggers it and the finding stays is_active=1 forever — confirmed live:
    # an agent silent for 16 days still had 794 "active" findings showing
    # fleet-wide in Incidents / Attack Terrain pages.
    #
    # This is a DIFFERENT, complementary mechanism: a read-time exclusion
    # (get_soc_findings/get_active_findings_global), not a write-time resolve.
    # Deliberately not touching is_active/status — we don't know the
    # underlying condition is gone, only that the agent stopped talking, and
    # the moment it reports again the finding reappears with zero data loss.
    # Only applied to fleet-wide queries (no explicit agent_id) — an analyst
    # explicitly investigating one agent still sees its findings regardless
    # of how stale that agent is.
    "stale_agent_sec": int(
        os.getenv("ATTACKLENS_STALE_AGENT_SEC", str(86400))
    ),

    # ── AI precision layer (ai_validator.py) ──────────────────────────────
    # When True, after the 8 deterministic gates pass we run an LLM-backed
    # senior-SOC-analyst verdict + multi-source precision score (target ≥ 0.90)
    # before promoting a cluster to a finding.  Set ATTACKLENS_AI_VALIDATION=true
    # to enable; default False so the deterministic pipeline stays in charge.
    "ai_validation_enabled": (
        os.getenv("ATTACKLENS_AI_VALIDATION", "false").lower() == "true"
    ),
    # Minimum aggregate precision score to promote a finding (0–1).
    "ai_precision_threshold": float(
        os.getenv("ATTACKLENS_AI_PRECISION_THRESHOLD", "0.90")
    ),
}
