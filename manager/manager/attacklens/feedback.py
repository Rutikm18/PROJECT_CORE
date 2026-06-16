"""
manager/manager/attacklens/feedback.py — FP/TP feedback recorder.

Called by the SOC findings PATCH handler whenever an analyst transitions a
finding to a terminal state (false_positive, closed / resolved, accepted_risk).
Updates rule_fp_stats so the confidence engine's FP penalty stays calibrated.
Auto-suggests allowlist entries when a (rule, entity) pair accumulates ≥5 FPs
in 30 days.
"""
from __future__ import annotations

import datetime
import logging
import time

log = logging.getLogger("manager.attacklens.feedback")


async def record_fp(idb, finding_id: int) -> None:
    """Analyst marked finding as false positive."""
    await _record(idb, finding_id, fp=1)


async def record_tp(idb, finding_id: int) -> None:
    """Analyst closed/resolved finding as genuine."""
    await _record(idb, finding_id, tp=1)


async def record_accepted(idb, finding_id: int) -> None:
    """Analyst accepted risk (treated as TP for precision purposes)."""
    await _record(idb, finding_id, accepted=1)


async def _record(idb, finding_id: int, *, tp: int = 0, fp: int = 0, accepted: int = 0) -> None:
    try:
        finding = await idb.get_finding_by_id(finding_id)
    except Exception as exc:
        log.warning("feedback._record: get_finding_by_id(%s) failed: %s", finding_id, exc)
        return

    if not finding:
        return

    host_class = finding.get("host_class") or finding.get("asset_tier") or "unknown"
    week = datetime.date.today().strftime("%G-%V")
    cluster_id = finding.get("signal_cluster_id")

    if not cluster_id:
        rule_id = finding.get("rule_id") or finding.get("source") or "unknown"
        await _bump(idb, rule_id, host_class, week, tp=tp, fp=fp, accepted=accepted)
        if fp:
            await _maybe_suggest_allowlist(idb, rule_id, finding.get("item_key", ""), fp_count=1)
        return

    try:
        sigs = await idb.get_signals_for_cluster(cluster_id)
    except Exception as exc:
        log.warning("feedback._record: get_signals_for_cluster(%s) failed: %s", cluster_id, exc)
        sigs = []

    for sig in sigs:
        await _bump(idb, sig["rule_id"], host_class, week, tp=tp, fp=fp, accepted=accepted)
        if fp:
            await _maybe_suggest_allowlist(idb, sig["rule_id"], sig.get("entity_key", ""), fp_count=1)


async def _bump(
    idb,
    rule_id: str,
    host_class: str,
    week: str,
    *,
    tp: int = 0,
    fp: int = 0,
    accepted: int = 0,
) -> None:
    try:
        await idb.execute(
            "INSERT INTO rule_fp_stats "
            "(rule_id, host_class, window_start, tp_count, fp_count, accepted_risk, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(rule_id, host_class, window_start) DO UPDATE SET "
            "tp_count     = tp_count     + excluded.tp_count, "
            "fp_count     = fp_count     + excluded.fp_count, "
            "accepted_risk= accepted_risk+ excluded.accepted_risk, "
            "updated_at   = excluded.updated_at",
            (rule_id, host_class, week, tp, fp, accepted, time.time()),
        )
    except Exception as exc:
        log.warning("feedback._bump rule=%s: %s", rule_id, exc)


async def _maybe_suggest_allowlist(idb, rule_id: str, entity_key: str, fp_count: int) -> None:
    """After each FP, check total recent FPs for this (rule, entity) pair."""
    try:
        total = await idb.recent_fp_count(rule_id=rule_id, entity_key=entity_key, days=30)
        if total >= 5:
            await idb.upsert_allowlist_suggestion(
                rule_id=rule_id,
                entity_key=entity_key,
                fp_count=total,
            )
            log.info("Allowlist suggestion: rule=%s entity=%s fp_count=%d", rule_id, entity_key, total)
    except Exception as exc:
        log.debug("_maybe_suggest_allowlist: %s", exc)
