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
