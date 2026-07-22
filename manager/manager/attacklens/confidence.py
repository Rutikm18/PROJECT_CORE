"""
manager/manager/attacklens/confidence.py — Cluster confidence scoring.

Answers the question: "How likely is this cluster to represent a real attack?"
This is SEPARATE from composite_score (which answers "if real, how bad is it?").

Formula:
  base  = weighted-average of (signal.weight × signal.strength)
  raw   = base × layer_mult × kev_mult × epss_mult × ti_mult × crit_mult
          × agent_priority_mult / fp_pen
  final = max(raw, cross_layer_floor)   clamped to [0, 1]
"""
from __future__ import annotations

from .cross_matrix import matched_floor
from .config import ENGINE_CONFIG
from .asset_priority import priority_profile


async def score_confidence(
    cluster,
    enriched: dict,
    idb,
    agent_id: str,
) -> float:
    """
    Score a SignalCluster and return confidence in [0, 1].
    `enriched` is the dict from engine._enrich_cluster().
    """
    sigs = cluster.signals

    # 1. Base: weighted average of (weight × strength) across all signals
    contributions = [s.weight * s.strength for s in sigs]
    base = sum(contributions) / len(contributions) if contributions else 0.0

    # 2. Multipliers
    n_layers    = len(cluster.layers_covered)
    layer_mult  = ENGINE_CONFIG["multipliers"]["layer"].get(min(n_layers, 3), 1.0)
    kev_mult    = ENGINE_CONFIG["multipliers"]["kev"] if enriched.get("kev_hit") else 1.0

    max_epss = max(
        (e for e in (enriched.get("epss_scores") or []) if e is not None),
        default=0.0,
    )
    epss_mult = _step_mult(max_epss, ENGINE_CONFIG["multipliers"]["epss"])

    ti_count  = int(enriched.get("threat_intel_source_count", 0))
    ti_mult   = _step_mult(ti_count, ENGINE_CONFIG["multipliers"]["threat_intel"])

    asset_num = _asset_tier_number(enriched.get("asset_tier", "endpoint"))
    crit_mult = ENGINE_CONFIG["multipliers"]["asset_criticality"].get(asset_num, 1.0)
    priority_level = enriched.get("asset_priority_level", "standard")
    try:
        priority_mult = float(enriched.get("asset_priority_confidence_multiplier") or 0.0)
    except (TypeError, ValueError):
        priority_mult = 0.0
    if priority_mult <= 0:
        priority_mult = priority_profile(priority_level).confidence_multiplier

    # 3. FP penalty from recent history
    rule_ids = [s.rule_id for s in sigs]
    fp_rate  = await idb.get_fp_rate_for_rules(
        rule_ids,
        host_class=enriched.get("host_class", "unknown"),
        window_days=ENGINE_CONFIG["recent_fp_window_days"],
    )
    if fp_rate > 0.5:
        fp_pen = ENGINE_CONFIG["penalties"]["fp_rate_high"]
    elif fp_rate > 0.2:
        fp_pen = ENGINE_CONFIG["penalties"]["fp_rate_medium"]
    else:
        fp_pen = 1.0

    raw = (
        base
        * layer_mult
        * kev_mult
        * epss_mult
        * ti_mult
        * crit_mult
        * priority_mult
    ) / fp_pen

    # 4. Cross-layer floor (never lower than the floor for this pattern combination)
    floor = matched_floor(cluster)
    if floor is not None:
        raw = max(raw, floor)

    return min(1.0, raw)


def _step_mult(value: float, table: dict) -> float:
    """Pick the multiplier for the highest threshold ≤ value."""
    applicable = [m for thr, m in table.items() if value >= thr]
    return max(applicable) if applicable else 1.0


def _asset_tier_number(tier: str) -> int:
    return {
        "crown_jewel": 1,
        "server":      2,
        "workstation": 3,
        "endpoint":    4,
        "unknown":     5,
    }.get(tier, 5)
