"""
manager/manager/attacklens/validation.py — Eight validation gates.

Gates run sequentially; the first failure short-circuits.  Each gate returns a
ValidationResult.  A passed=False result carries the gate name and a detail
string for observability.

Gate summary:
  G1  entity_exists       — agent online or source is authoritative
  G2  not_allowlisted     — no table-backed or static allowlist match
  G3  not_duplicate       — no active finding for same cluster in last 24 h
  G4  reachability        — pure-Surface clusters require KEV hit to promote
  G5  compensating        — compensating controls reduce confidence; re-check threshold
  G6  recent_fp           — FP-prone rules require at least one corroborating signal
  G7  quality_floor       — at least one signal must meet the strength floor
  G8  time_consistent     — signal timestamps must fit within the window
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .config import ENGINE_CONFIG


@dataclass
class ValidationResult:
    passed:      bool
    failed_gate: str | None = None
    detail:      str | None = None


async def validate_cluster(cluster, enriched: dict, idb, feeds) -> ValidationResult:
    """
    Run all 8 gates.  Returns the first failure or a final passed=True result.
    Side-effect: G5 may mutate cluster.confidence.
    """
    for gate_name, gate_fn in _GATES:
        result = await gate_fn(cluster, enriched, idb, feeds)
        if not result.passed:
            result.failed_gate = gate_name
            return result
    return ValidationResult(passed=True)


# ── Individual gate implementations ──────────────────────────────────────────

async def _g1_entity_exists(cluster, enriched: dict, idb, _feeds) -> ValidationResult:
    """Agent must be reachable, OR the source is an authoritative external intel hit."""
    if (enriched.get("kev_hit")
            or enriched.get("malicious_hash_hit")
            or enriched.get("malicious_ip_hit")):
        return ValidationResult(True)
    try:
        last_seen = await idb.get_agent_last_seen(cluster.agent_id)
    except Exception:
        last_seen = None
    if not last_seen or time.time() - last_seen > 600:
        return ValidationResult(
            False,
            detail=f"agent {cluster.agent_id} offline >10 min and no authoritative intel hit",
        )
    return ValidationResult(True)


async def _g2_not_allowlisted(cluster, _enriched: dict, idb, _feeds) -> ValidationResult:
    """Check both the static FP suppression lists and the table-backed allowlist."""
    for sig in cluster.signals:
        try:
            if await idb.is_allowlisted(sig.rule_id, sig.entity_key, cluster.agent_id):
                return ValidationResult(False, detail=f"allowlisted: rule={sig.rule_id} entity={sig.entity_key}")
        except Exception:
            pass
    return ValidationResult(True)


async def _g3_not_duplicate(cluster, _enriched: dict, idb, _feeds) -> ValidationResult:
    """No active finding already exists for the same cluster entity within 24 h."""
    window = ENGINE_CONFIG["active_finding_dedup_hours"] * 3600
    try:
        is_dup = await idb.has_active_finding_for_cluster(cluster, since=time.time() - window)
    except Exception:
        is_dup = False
    if is_dup:
        return ValidationResult(False, detail="active finding already exists within dedup window")
    return ValidationResult(True)


async def _g4_reachability(cluster, enriched: dict, _idb, _feeds) -> ValidationResult:
    """
    Surface-only clusters need authoritative external confirmation. Cross-layer
    clusters always pass — exposure or execution evidence implies reachability.

    Accept any of:
      • KEV hit
      • Malicious hash hit
      • EPSS ≥ 0.7 (high probability of exploitation)
    """
    if cluster.layers_covered != {"surface"}:
        return ValidationResult(True)

    if enriched.get("kev_hit") or enriched.get("malicious_hash_hit"):
        return ValidationResult(True)

    epss_scores = enriched.get("epss_scores") or []
    if epss_scores and max(epss_scores) >= 0.7:
        return ValidationResult(True)

    return ValidationResult(
        False,
        detail="surface-only cluster without KEV/malicious-hash/high-EPSS confirmation",
    )


async def _g5_compensating_controls(cluster, enriched: dict, _idb, _feeds) -> ValidationResult:
    """
    Reduce confidence by the compensating-controls penalty then re-check threshold.
    Mutates cluster.confidence — must run after scoring.

    KEV / malicious-hash hits bypass this gate: a known-exploited CVE or known-bad
    binary still warrants a finding regardless of EDR/firewall posture.
    """
    if enriched.get("kev_hit") or enriched.get("malicious_hash_hit"):
        return ValidationResult(True)

    controls = enriched.get("compensating_controls") or []
    n = len(controls)
    if n > 0 and cluster.confidence is not None:
        penalty = ENGINE_CONFIG["penalties"]["compensating_control"] * n
        cluster.confidence = max(0.0, cluster.confidence - penalty)
        if cluster.confidence < ENGINE_CONFIG["confidence_threshold"]:
            return ValidationResult(
                False,
                detail=(
                    f"compensating controls (n={n}) reduced confidence to "
                    f"{cluster.confidence:.3f} (< {ENGINE_CONFIG['confidence_threshold']})"
                ),
            )
    return ValidationResult(True)


async def _g6_recent_fp(cluster, enriched: dict, idb, _feeds) -> ValidationResult:
    """
    FP-prone rules need at least one *independent* corroborating signal
    (a second signal from a different rule_id).  KEV / malicious-hash hits
    bypass this gate — they are themselves authoritative corroboration.
    """
    if enriched.get("kev_hit") or enriched.get("malicious_hash_hit"):
        return ValidationResult(True)

    try:
        fp_prone = await idb.rules_with_recent_fp(
            [s.rule_id for s in cluster.signals],
            host_class=enriched.get("host_class", "unknown"),
            window_days=ENGINE_CONFIG["recent_fp_window_days"],
            threshold=0.5,
        )
    except Exception:
        fp_prone = []

    if fp_prone:
        distinct_rules = {s.rule_id for s in cluster.signals}
        if len(distinct_rules) < 2:
            return ValidationResult(
                False,
                detail=f"FP-prone rules need ≥1 corroborating signal: {fp_prone}",
            )
    return ValidationResult(True)


async def _g7_quality_floor(cluster, _enriched: dict, _idb, _feeds) -> ValidationResult:
    """At least one signal must meet the minimum strength floor."""
    floor = ENGINE_CONFIG["quality_floor_strength"]
    strong = [s for s in cluster.signals if s.strength >= floor]
    if not strong:
        return ValidationResult(
            False,
            detail=f"all signals below quality floor ({floor})",
        )
    return ValidationResult(True)


async def _g8_time_consistent(cluster, _enriched: dict, _idb, _feeds) -> ValidationResult:
    """Signal timestamps must fit within the appropriate correlation window."""
    if not cluster.signals:
        return ValidationResult(False, detail="empty cluster")

    timestamps = [s.detected_at for s in cluster.signals]
    spread = max(timestamps) - min(timestamps)

    has_supply_chain = any(
        s.rule_id.startswith(("S-PKG-", "S-APP-")) for s in cluster.signals
    )
    has_persistence = any(
        s.rule_id.startswith(("X-AR-", "X-LA-", "X-SCH-", "X-SVCX-",
                              "rule:suspicious_service", "rule:task_pattern"))
        for s in cluster.signals
    )
    if has_supply_chain:
        limit = ENGINE_CONFIG["correlation_window_sec_supply_chain"]
    elif has_persistence:
        limit = ENGINE_CONFIG["correlation_window_sec_persistence"]
    else:
        limit = ENGINE_CONFIG["correlation_window_sec"]

    if spread > limit:
        return ValidationResult(
            False,
            detail=f"signal time spread {int(spread)}s exceeds window {limit}s",
        )
    return ValidationResult(True)


_GATES: list[tuple[str, object]] = [
    ("G1_entity_exists",   _g1_entity_exists),
    ("G2_not_allowlisted", _g2_not_allowlisted),
    ("G3_not_duplicate",   _g3_not_duplicate),
    ("G4_reachability",    _g4_reachability),
    ("G5_compensating",    _g5_compensating_controls),
    ("G6_recent_fp",       _g6_recent_fp),
    ("G7_quality_floor",   _g7_quality_floor),
    ("G8_time_consistent", _g8_time_consistent),
]
