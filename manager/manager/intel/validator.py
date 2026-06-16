"""
manager/manager/intel/validator.py — Cross-source validation and confidence scoring.

Validates each source's data independently, then cross-validates for inter-source
consistency.  Returns a structured report with:
  - field-level validation errors (schema violations)
  - cross-source discrepancies (e.g. CVSS differs by >2 between NVD and GHSA)
  - confidence score 0.0-1.0 based on source agreement + active source count

The confidence score feeds directly into the composite risk scorer as an
additional signal — high confidence = more sources agree = more trustworthy.
"""
from __future__ import annotations

import re
from typing import Any, Optional

CVE_RE    = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EPSS_RANGE = (0.0, 1.0)
CVSS_RANGE = (0.0, 10.0)

# CVSS discrepancy threshold that triggers a cross-source warning
_CVSS_DISCORD_THRESHOLD = 2.0
# Per-source trust weights for confidence calculation
_SOURCE_TRUST = {
    "nvd":       1.0,
    "ghsa":      0.95,
    "circl":     0.85,
    "osv":       0.80,
    "epss":      0.90,
    "kev":       1.0,
    "exploitdb": 0.85,
    "metasploit": 0.90,
    "poc_github": 0.75,
}


def _safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class IntelValidator:
    """
    Validates source data and computes cross-source confidence.
    All methods are pure — no network, no state.
    """

    # ── Per-field validators ──────────────────────────────────────────────────

    def validate_cve_id(self, cve_id: str) -> Optional[str]:
        """Return error message or None."""
        if not cve_id or not isinstance(cve_id, str):
            return "CVE ID is empty or non-string"
        if not CVE_RE.match(cve_id.strip()):
            return f"Invalid CVE ID format: {cve_id!r} (expected CVE-YYYY-NNNNN)"
        return None

    def validate_cvss(self, score: Any, source: str) -> Optional[dict]:
        v = _safe_float(score)
        if v is None:
            return None  # absent is valid
        if not (CVSS_RANGE[0] <= v <= CVSS_RANGE[1]):
            return {"field": "cvss_score", "source": source,
                    "error": f"out of range {CVSS_RANGE}: {v}"}
        return None

    def validate_epss(self, score: Any, source: str) -> Optional[dict]:
        v = _safe_float(score)
        if v is None:
            return None
        if not (EPSS_RANGE[0] <= v <= EPSS_RANGE[1]):
            return {"field": "epss_score", "source": source,
                    "error": f"out of range {EPSS_RANGE}: {v}"}
        return None

    # ── Cross-source validation ───────────────────────────────────────────────

    def cross_validate(self, cve_id: str, sources: dict[str, Any]) -> dict:
        """
        Validate all source data together.
        Returns:
          {
            "errors":        [...],   # field-level schema errors
            "discrepancies": [...],   # cross-source disagreements
            "sources_used":  [...],   # source names that had non-null data
            "source_count":  int,
            "confidence":    float,   # 0.0 - 1.0
          }
        """
        errors:        list[dict] = []
        discrepancies: list[dict] = []

        # CVE ID format
        fmt_err = self.validate_cve_id(cve_id)
        if fmt_err:
            errors.append({"field": "cve_id", "source": "input", "error": fmt_err})

        # Collect CVSS from each source
        cvss_by_source: dict[str, float] = {}

        nvd = sources.get("nvd")
        if isinstance(nvd, dict):
            err = self.validate_cvss(nvd.get("cvss_score"), "nvd")
            if err:
                errors.append(err)
            elif nvd.get("cvss_score") is not None:
                cvss_by_source["nvd"] = float(nvd["cvss_score"])

        for ghsa in (sources.get("ghsa") or []):
            if not isinstance(ghsa, dict):
                continue
            err = self.validate_cvss(ghsa.get("cvss_score"), "ghsa")
            if err:
                errors.append(err)
            elif ghsa.get("cvss_score") is not None:
                cvss_by_source["ghsa"] = float(ghsa["cvss_score"])
            break   # only check first advisory

        circl = sources.get("circl")
        if isinstance(circl, dict):
            err = self.validate_cvss(circl.get("cvss_score"), "circl")
            if err:
                errors.append(err)
            elif circl.get("cvss_score") is not None:
                cvss_by_source["circl"] = float(circl["cvss_score"])

        osv = sources.get("osv")
        if isinstance(osv, dict) and osv.get("cvss_score") is not None:
            err = self.validate_cvss(osv.get("cvss_score"), "osv")
            if err:
                errors.append(err)
            else:
                cvss_by_source["osv"] = float(osv["cvss_score"])

        # Cross-source CVSS discrepancy
        if len(cvss_by_source) >= 2:
            vals = list(cvss_by_source.values())
            spread = max(vals) - min(vals)
            if spread > _CVSS_DISCORD_THRESHOLD:
                discrepancies.append({
                    "field":   "cvss_score",
                    "type":    "large_discrepancy",
                    "spread":  round(spread, 2),
                    "by_source": {k: round(v, 2) for k, v in cvss_by_source.items()},
                    "note":    f"CVSS scores differ by {spread:.1f} across sources",
                })

        # EPSS validation
        epss = sources.get("epss")
        if isinstance(epss, dict):
            err = self.validate_epss(epss.get("epss"), "epss")
            if err:
                errors.append(err)

        # KEV cross-check: if GHSA says kev=True but FeedManager says not KEV, flag it
        kev_from_feed  = sources.get("kev") is not None
        kev_from_ghsa  = any(
            g.get("kev") for g in (sources.get("ghsa") or []) if isinstance(g, dict)
        )
        if kev_from_ghsa and not kev_from_feed:
            discrepancies.append({
                "field": "kev",
                "type":  "source_disagreement",
                "note":  "GHSA reports KEV but CISA feed does not; CISA is authoritative",
            })

        # Compute confidence
        active = [k for k, v in sources.items() if v is not None]
        confidence = self._confidence(active, cvss_by_source, discrepancies)

        return {
            "errors":        errors,
            "discrepancies": discrepancies,
            "sources_used":  active,
            "source_count":  len(active),
            "confidence":    confidence,
        }

    # ── Confidence calculation ────────────────────────────────────────────────

    def _confidence(
        self,
        active_sources: list[str],
        cvss_by_source: dict[str, float],
        discrepancies:  list[dict],
    ) -> float:
        if not active_sources:
            return 0.1

        # Weighted sum of trust scores
        total_trust = sum(_SOURCE_TRUST.get(s, 0.5) for s in active_sources)
        max_trust   = sum(sorted(_SOURCE_TRUST.values(), reverse=True)[:len(active_sources)])
        base        = min(0.90, total_trust / max(1.0, max_trust) * 0.90 + 0.20)

        # Bonus if ≥2 sources agree on CVSS within 1 point
        if len(cvss_by_source) >= 2:
            vals   = list(cvss_by_source.values())
            spread = max(vals) - min(vals)
            if spread <= 1.0:
                base = min(0.95, base + 0.08)

        # Penalty per discrepancy
        base -= len(discrepancies) * 0.05

        return round(max(0.10, min(0.95, base)), 2)
