"""
manager/manager/intel/scorer.py — Enhanced composite risk scorer.

Extends the existing RiskScoreMatrix by incorporating:
  • ExploitDB presence (verified > unverified)
  • Metasploit module availability
  • GitHub PoC count and recency
  • Multi-source intelligence confidence
  • KEV remediation urgency (days until CISA due date)
  • EPSS model date freshness

Scoring formula (all components normalized 0-1 before weighting):

  base = (
    cvss_norm   × 0.22
    epss        × 0.20
    exploit     × 0.18   ← multi-source exploit signal
    recency     × 0.10
    behavioral  × 0.08
    confidence  × 0.05
  ) × scale_to_10

  + kev_bonus    (flat +2.0 if CISA KEV listed)
  + urgency_add  (0–0.5 based on CISA due date proximity)

  final = clamp(base, 0.0, 10.0)

Severity thresholds (0-10 scale):
  ≥ 8.5  → critical
  ≥ 6.5  → high
  ≥ 4.0  → medium
  ≥ 1.5  → low
  <  1.5 → info
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional


def _f(v: Any, default: float = 0.0) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return default


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


_BUCKETS = ((8.5, "critical"), (6.5, "high"), (4.0, "medium"), (1.5, "low"))

# Weighted sum divisor (sum of all weights = 0.83 → scale factor ≈ 12.05)
_W_SUM    = 0.22 + 0.20 + 0.18 + 0.10 + 0.08 + 0.05
_SCALE    = 10.0 / _W_SUM


class EnhancedScorer:
    """
    Compute a 0-10 composite risk score from enriched CVE/finding data.
    Input dict keys (all optional — missing = 0):
      cvss_score, epss_score, kev, kev_due_date,
      exploitdb, metasploit, poc_github, poc_count,
      edb_verified, msf_module, exploit_available, exploit_sources,
      behavioral_deviation, intel_confidence,
      collected_at / first_detected_at
    """

    def compute(self, data: dict) -> float:
        cvss       = _clamp(_f(data.get("cvss_score")) / 10.0)
        epss       = _clamp(_f(data.get("epss_score")))
        exploit    = _clamp(self._exploit_signal(data))
        recency    = _clamp(self._recency(_f(data.get("collected_at") or data.get("first_detected_at"), time.time())))
        behavioral = _clamp(_f(data.get("behavioral_deviation", 0.0)))
        confidence = _clamp(_f(data.get("intel_confidence", 0.5)))

        weighted = (
            cvss       * 0.22
            + epss     * 0.20
            + exploit  * 0.18
            + recency  * 0.10
            + behavioral * 0.08
            + confidence * 0.05
        )
        base = weighted * _SCALE

        # KEV flat bonus (+2.0 = decisive signal)
        if data.get("kev"):
            base += 2.0
            # Urgency bonus: up to +0.5 if due date is near
            base += self._kev_urgency(data.get("kev_due_date", "")) * 0.5

        return round(max(0.0, min(10.0, base)), 2)

    def compute_bulk(self, findings: list[dict]) -> list[dict]:
        for f in findings:
            f["composite_score"] = self.compute(f)
        return findings

    @staticmethod
    def severity_from_score(score: float) -> str:
        for threshold, label in _BUCKETS:
            if score >= threshold:
                return label
        return "info"

    # ── Sub-signals ───────────────────────────────────────────────────────────

    @staticmethod
    def _exploit_signal(data: dict) -> float:
        """
        Multi-source exploit presence → 0-1.
        Priority: verified EDB > Metasploit > unverified EDB > PoC GitHub
        """
        score = 0.0

        # ExploitDB (rich dict from IntelPipeline or simple flags)
        edb = data.get("exploitdb")
        if isinstance(edb, dict):
            verified   = int(edb.get("verified", 0) or 0)
            total      = int(edb.get("total", 0) or 0)
            unverified = max(0, total - verified)
            if verified > 0:
                score = max(score, min(1.0, 0.85 + verified * 0.05))
            elif unverified > 0:
                score = max(score, 0.65)
        elif data.get("edb_verified"):
            score = max(score, 0.90)

        # Metasploit
        if data.get("msf_module") or data.get("metasploit") is True:
            score = max(score, 0.85)

        # GitHub PoC
        poc = data.get("poc_github")
        poc_count = 0
        if isinstance(poc, dict):
            poc_count = int(poc.get("count", 0) or 0)
        else:
            poc_count = int(data.get("poc_count", 0) or 0)
        if poc_count > 0:
            score = max(score, _clamp(0.55 + poc_count * 0.04, 0.55, 0.80))

        # Generic fallback
        if score == 0.0 and data.get("exploit_available"):
            score = 0.40

        return score

    @staticmethod
    def _recency(ts: float) -> float:
        age_h = max(0.0, (time.time() - ts) / 3600.0)
        if age_h < 24:   return 1.0
        if age_h < 168:  return 0.6   # ≤ 7 days
        if age_h < 720:  return 0.25  # ≤ 30 days
        return 0.0

    @staticmethod
    def _kev_urgency(due_date: Any) -> float:
        """
        0-1 urgency based on days until CISA remediation deadline.
        1.0 = overdue or ≤3 days, 0.0 = no date or >30 days.
        """
        if not due_date:
            return 0.0
        try:
            due = datetime.strptime(str(due_date), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days = (due - datetime.now(timezone.utc)).days
            if days <= 0:  return 1.0
            if days <= 3:  return 0.90
            if days <= 7:  return 0.70
            if days <= 14: return 0.40
            if days <= 30: return 0.20
            return 0.05
        except (ValueError, TypeError):
            return 0.0


# Module-level singleton for import convenience
enhanced_scorer = EnhancedScorer()
