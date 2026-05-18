"""
manager/api/accuracy.py — Detection accuracy and calibration endpoints.

Task 6.1: Validate and measure the accuracy of Jarvis detection and
correlation logic. Provides:

  GET /api/v1/accuracy/report       full accuracy report (per rule, per category)
  GET /api/v1/accuracy/fp_risk      findings with high false-positive risk
  GET /api/v1/accuracy/calibration  rule confidence vs observed finding distribution
  GET /api/v1/accuracy/correlation  correlation chain integrity check

Accuracy methodology:
  True Positive proxy  — high-confidence source (feed, KEV, NVD) AND CVSS ≥ 7 or feed-confirmed
  False Positive proxy — dual-use source AND no supporting KEV/EPSS AND low CVSS
  Precision estimate   — TP_proxy / (TP_proxy + FP_proxy) per rule/category
  Recall note          — cannot compute without ground truth labels; report explains this

Correlation integrity:
  A correlation is "well-supported" if all signals in the attack_chain
  exist as individual active findings. Orphaned signal IDs → FP risk.
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

log = logging.getLogger("manager.api.accuracy")

# Per-source confidence priors (same as detection.py)
_SOURCE_CONF: dict[str, float] = {
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

# Sources that represent confirmed external validation
_VALIDATED_SOURCES = frozenset({"feed:feodo", "feed:emerging", "feed:threatfox",
                                  "abuseipdb", "nvd"})

# Dual-use / noisy sources (higher FP risk)
_DUAL_USE_SOURCES = frozenset({"rule:risky_package", "rule:wildcard_bind",
                                "rule:suspicious_path", "behavioral"})

# Severity weights for score calculation
_SEV_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


def make_accuracy_router(intel_db: "IntelDB") -> APIRouter:
    router = APIRouter()

    # ── Full accuracy report ───────────────────────────────────────────────────
    @router.get("/report")
    async def accuracy_report(agent_id: Optional[str] = Query(None)):
        """
        Comprehensive accuracy report covering:
          - Per-source finding counts and confidence
          - Per-category precision estimates
          - Validation coverage (KEV, EPSS)
          - FP risk summary
          - Correlation integrity
        """
        findings, correlations = await asyncio.gather(
            _get_all_findings(intel_db, agent_id),
            _get_all_correlations(intel_db, agent_id),
        )

        source_stats   = _compute_source_stats(findings)
        category_stats = _compute_category_stats(findings)
        validation     = _compute_validation_coverage(findings)
        fp_risk_items  = _identify_fp_risk(findings)
        corr_integrity = _check_correlation_integrity(correlations, findings)
        calibration    = _compute_calibration(findings)

        total = len(findings)
        validated = sum(1 for f in findings if f.get("source", "") in _VALIDATED_SOURCES or f.get("kev") or (f.get("epss_score") or 0) > 0.5)
        estimated_precision = round((validated / total) * 100) if total else 0

        return {
            "meta": {
                "generated_at": time.time(),
                "agent_id":     agent_id,
                "total_findings": total,
                "total_correlations": len(correlations),
                "methodology": (
                    "Precision is estimated using external validation signals (threat feeds, NVD CVEs, CISA KEV, EPSS ≥ 50%) "
                    "as True Positive proxies. Recall cannot be computed without ground-truth labels. "
                    "FP risk is flagged for dual-use sources with no external corroboration. "
                    "Treat these as probabilistic estimates, not exact measurements."
                ),
            },
            "overall": {
                "estimated_precision_pct":  estimated_precision,
                "validated_findings":       validated,
                "unvalidated_findings":     total - validated,
                "fp_risk_count":            len(fp_risk_items),
                "high_confidence_count":    sum(1 for f in findings if _conf(f) >= 0.85),
                "correlation_integrity_pct": corr_integrity["integrity_pct"],
            },
            "by_source":       source_stats,
            "by_category":     category_stats,
            "validation":      validation,
            "calibration":     calibration,
            "fp_risk_items":   fp_risk_items[:50],
            "correlation_integrity": corr_integrity,
        }

    # ── FP risk candidates ─────────────────────────────────────────────────────
    @router.get("/fp_risk")
    async def fp_risk(
        agent_id: Optional[str] = Query(None),
        limit:    int           = Query(50, ge=1, le=200),
    ):
        """
        Findings with the highest false-positive risk.
        Criteria: dual-use source + no KEV + no EPSS ≥ 30% + severity ≥ high.
        """
        findings = await _get_all_findings(intel_db, agent_id)
        risky = _identify_fp_risk(findings)
        return {"findings": risky[:limit], "count": len(risky)}

    # ── Rule calibration ───────────────────────────────────────────────────────
    @router.get("/calibration")
    async def calibration(agent_id: Optional[str] = Query(None)):
        """
        Shows the gap between rule confidence priors and observed validation rate.
        A large gap = rule needs tuning (too many FPs or FNs).
        """
        findings = await _get_all_findings(intel_db, agent_id)
        return {"calibration": _compute_calibration(findings)}

    # ── Correlation integrity ──────────────────────────────────────────────────
    @router.get("/correlation")
    async def correlation_integrity(agent_id: Optional[str] = Query(None)):
        """
        Validates that each correlation chain has supporting individual findings.
        Orphaned signal IDs (no matching active finding) indicate stale correlations.
        """
        findings, correlations = await asyncio.gather(
            _get_all_findings(intel_db, agent_id),
            _get_all_correlations(intel_db, agent_id),
        )
        return _check_correlation_integrity(correlations, findings)

    return router


# ── Internal query helpers ─────────────────────────────────────────────────────

async def _get_all_findings(intel_db: "IntelDB", agent_id: Optional[str]) -> list[dict]:
    try:
        rows = await intel_db._fetchall(
            "SELECT id, agent_id, category, severity, score, composite_score, "
            "source, rule_id, kev, epss_score, exploit_available, "
            "cve_ids, cvss_score, title, is_active, first_detected_at, last_detected_at, "
            "scan_count, status, fingerprint "
            "FROM findings WHERE is_active=1 "
            + ("AND agent_id=? " if agent_id else "")
            + "ORDER BY composite_score DESC LIMIT 5000",
            ((agent_id,) if agent_id else ()),
        )
        return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("accuracy: findings fetch failed: %s", exc)
        return []


async def _get_all_correlations(intel_db: "IntelDB", agent_id: Optional[str]) -> list[dict]:
    try:
        rows = await intel_db._fetchall(
            "SELECT id, agent_id, rule_id, severity, score, confidence, title, "
            "signals, signal_count, attack_chain, first_detected, last_detected, is_active "
            "FROM correlations WHERE is_active=1 "
            + ("AND agent_id=? " if agent_id else "")
            + "LIMIT 500",
            ((agent_id,) if agent_id else ()),
        )
        return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("accuracy: correlations fetch failed: %s", exc)
        return []


# ── Analysis functions ────────────────────────────────────────────────────────

def _conf(f: dict) -> float:
    src = f.get("source") or f.get("rule_id") or ""
    return _SOURCE_CONF.get(src, 0.70 if src.startswith("rule:") else 0.65)


def _is_validated(f: dict) -> bool:
    """True if there is external corroboration for this finding."""
    src = f.get("source") or f.get("rule_id") or ""
    if src in _VALIDATED_SOURCES:
        return True
    if f.get("kev"):
        return True
    epss = f.get("epss_score") or 0
    if float(epss) >= 0.5:
        return True
    cvss = f.get("cvss_score") or 0
    if float(cvss) >= 9.0 and src == "nvd":
        return True
    return False


def _is_fp_risk(f: dict) -> bool:
    """True if this finding has meaningful false-positive risk."""
    src  = f.get("source") or f.get("rule_id") or ""
    sev  = f.get("severity", "low")
    if src in _DUAL_USE_SOURCES and not _is_validated(f):
        return True
    conf = _conf(f)
    if conf < 0.70 and sev in ("high", "critical"):
        return True
    if not src or src == "behavioral":
        return sev in ("high", "critical")
    return False


def _compute_source_stats(findings: list[dict]) -> list[dict]:
    stats: dict[str, dict] = {}
    for f in findings:
        src = f.get("source") or f.get("rule_id") or "unknown"
        if src not in stats:
            stats[src] = {
                "source": src,
                "count": 0,
                "confidence_prior": round(_SOURCE_CONF.get(src, 0.70) * 100),
                "validated": 0,
                "fp_risk": 0,
                "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
        s = stats[src]
        s["count"] += 1
        sev = f.get("severity", "info")
        s["severities"][sev] = s["severities"].get(sev, 0) + 1
        if _is_validated(f):
            s["validated"] += 1
        if _is_fp_risk(f):
            s["fp_risk"] += 1

    result = []
    for s in sorted(stats.values(), key=lambda x: -x["count"]):
        cnt = s["count"]
        s["observed_precision_pct"] = round((s["validated"] / cnt) * 100) if cnt else 0
        s["fp_risk_pct"] = round((s["fp_risk"] / cnt) * 100) if cnt else 0
        s["calibration_gap"] = s["confidence_prior"] - s["observed_precision_pct"]
        result.append(s)
    return result


def _compute_category_stats(findings: list[dict]) -> list[dict]:
    cats: dict[str, dict] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        if cat not in cats:
            cats[cat] = {
                "category": cat,
                "count": 0,
                "validated": 0,
                "fp_risk": 0,
                "avg_score": 0.0,
                "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }
        c = cats[cat]
        c["count"] += 1
        sev = f.get("severity", "info")
        c["severities"][sev] = c["severities"].get(sev, 0) + 1
        c["avg_score"] += float(f.get("composite_score") or f.get("score") or 0)
        if _is_validated(f):  c["validated"] += 1
        if _is_fp_risk(f):    c["fp_risk"] += 1

    result = []
    for c in sorted(cats.values(), key=lambda x: -x["count"]):
        cnt = c["count"]
        c["avg_score"] = round(c["avg_score"] / cnt, 2) if cnt else 0
        c["precision_pct"] = round((c["validated"] / cnt) * 100) if cnt else 0
        c["fp_risk_pct"]   = round((c["fp_risk"]   / cnt) * 100) if cnt else 0
        result.append(c)
    return result


def _compute_validation_coverage(findings: list[dict]) -> dict:
    total    = len(findings)
    kev      = sum(1 for f in findings if f.get("kev"))
    epss_hi  = sum(1 for f in findings if float(f.get("epss_score") or 0) >= 0.5)
    epss_any = sum(1 for f in findings if float(f.get("epss_score") or 0) > 0)
    nvd      = sum(1 for f in findings if (f.get("source") or "").startswith("nvd") or (f.get("cve_ids") and f.get("cve_ids") != "[]"))
    feed     = sum(1 for f in findings if (f.get("source") or "").startswith("feed:"))
    exploit  = sum(1 for f in findings if f.get("exploit_available"))

    return {
        "total_findings":         total,
        "kev_validated":          kev,
        "kev_pct":                round((kev / total) * 100) if total else 0,
        "epss_high":              epss_hi,
        "epss_any":               epss_any,
        "epss_coverage_pct":      round((epss_any / total) * 100) if total else 0,
        "nvd_cve_findings":       nvd,
        "feed_confirmed":         feed,
        "exploit_available":      exploit,
        "unvalidated":            total - sum(1 for f in findings if _is_validated(f)),
        "note": (
            "KEV-validated findings are confirmed exploited in the wild. "
            "EPSS ≥ 50% means >50% probability of exploitation within 30 days. "
            "Unvalidated findings rely on rule/behavioral detection — review periodically."
        ),
    }


def _identify_fp_risk(findings: list[dict]) -> list[dict]:
    risky = []
    for f in findings:
        if not _is_fp_risk(f):
            continue
        src  = f.get("source") or ""
        conf = _conf(f)
        reason = []
        if src in _DUAL_USE_SOURCES:
            reason.append(f"dual-use source ({src})")
        if not _is_validated(f):
            reason.append("no external validation (no KEV, EPSS < 50%, no feed confirmation)")
        if conf < 0.70:
            reason.append(f"low rule confidence ({int(conf*100)}%)")
        risky.append({
            "id":          f.get("id"),
            "agent_id":    f.get("agent_id"),
            "category":    f.get("category"),
            "severity":    f.get("severity"),
            "title":       f.get("title"),
            "source":      src,
            "confidence":  int(conf * 100),
            "fp_reasons":  reason,
            "recommendation": _fp_recommendation(f),
        })
    risky.sort(key=lambda x: _SEV_SCORE.get(x["severity"], 0), reverse=True)
    return risky


def _fp_recommendation(f: dict) -> str:
    cat = f.get("category", "")
    src = f.get("source") or ""
    if cat == "process" and "dual-use" in str(src):
        return "Verify the process is not being used for legitimate admin/security testing. Check parent process and network connections."
    if cat == "package":
        return "Verify the installed version against NVD CVE affected ranges. Package names can match multiple different software."
    if cat == "port":
        return "Confirm the owning process. Development tools (Jupyter, webpack, etc.) often bind to non-standard ports."
    if cat == "connection":
        return "Verify the destination IP against current threat intel. CDN/cloud IPs may have been recycled."
    if src == "behavioral":
        return "Behavioral alerts have higher FP rates. Establish a baseline over 7+ days before acting on this finding."
    return "Review evidence context and compare against asset baseline before closing or escalating."


def _compute_calibration(findings: list[dict]) -> list[dict]:
    """
    Per-source: confidence prior vs observed validation rate.
    A calibration_gap > 20 means the rule generates too many unvalidated findings.
    """
    seen: dict[str, list] = {}
    for f in findings:
        src = f.get("source") or f.get("rule_id") or "unknown"
        seen.setdefault(src, []).append(_is_validated(f))

    result = []
    for src, validated_list in sorted(seen.items(), key=lambda x: -len(x[1])):
        prior   = round(_SOURCE_CONF.get(src, 0.70) * 100)
        n       = len(validated_list)
        obs     = round((sum(validated_list) / n) * 100) if n else 0
        gap     = prior - obs
        result.append({
            "source":           src,
            "count":            n,
            "confidence_prior": prior,
            "observed_rate":    obs,
            "calibration_gap":  gap,
            "status": (
                "well_calibrated" if abs(gap) <= 15 else
                "over_confident"  if gap > 15 else
                "under_confident"
            ),
            "action": (
                "No action needed" if abs(gap) <= 15 else
                f"Rule may be generating false positives — raise confidence threshold or add allowlist entries" if gap > 15 else
                f"Rule may be missing true positives — review detection coverage"
            ),
        })
    return result


def _check_correlation_integrity(
    correlations: list[dict],
    findings: list[dict],
) -> dict:
    """
    For each correlation, verify its signals exist as active individual findings.
    Orphaned signals = stale or incorrectly generated correlation.
    """
    finding_ids = {f.get("id") for f in findings if f.get("id")}
    # Also index by item_key (signals may reference item_key strings)
    finding_keys: set[str] = set()
    for f in findings:
        for kfield in ("item_key", "title", "category"):
            v = f.get(kfield)
            if v:
                finding_keys.add(str(v).lower())

    details = []
    well_supported = 0
    for corr in correlations:
        signals_raw = corr.get("signals") or "[]"
        if isinstance(signals_raw, str):
            try:
                signals = json.loads(signals_raw)
            except Exception:
                signals = []
        else:
            signals = signals_raw if isinstance(signals_raw, list) else []

        orphaned = []
        supported = []
        for sig in signals:
            sig_id  = sig.get("id") or sig.get("finding_id") if isinstance(sig, dict) else None
            sig_key = str(sig.get("item_key", "") or sig.get("key", "") or sig).lower() if isinstance(sig, dict) else str(sig).lower()

            if sig_id and sig_id in finding_ids:
                supported.append(sig)
            elif sig_key and any(sig_key in k for k in finding_keys):
                supported.append(sig)
            else:
                orphaned.append(sig)

        total_sig = len(signals)
        is_supported = len(orphaned) == 0 or total_sig == 0
        if is_supported:
            well_supported += 1

        details.append({
            "correlation_id":    corr.get("id"),
            "agent_id":          corr.get("agent_id"),
            "rule_id":           corr.get("rule_id"),
            "title":             corr.get("title"),
            "severity":          corr.get("severity"),
            "signal_count":      total_sig,
            "supported":         len(supported),
            "orphaned":          len(orphaned),
            "integrity":         "ok" if is_supported else "orphaned_signals",
            "orphaned_signals":  orphaned[:5],
        })

    total_corr = len(correlations)
    return {
        "total":           total_corr,
        "well_supported":  well_supported,
        "has_orphans":     total_corr - well_supported,
        "integrity_pct":   round((well_supported / total_corr) * 100) if total_corr else 100,
        "details":         details,
        "note": (
            "Correlations with orphaned signals reference findings that no longer exist (closed/expired). "
            "These do not represent false positives — they may be stale. "
            "Re-run correlation after clearing closed findings."
        ),
    }
