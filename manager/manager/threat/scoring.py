"""manager/manager/threat/scoring.py — Multi-factor composite risk scoring."""
from __future__ import annotations

import time
from typing import Any

# Weights — sum is intentionally 1.0 so the weighted dot-product lives in [0,1]
# before being scaled to [0,10].
_W_CVSS       = 0.30
_W_EPSS       = 0.25
_W_KEV        = 0.20
_W_RECENCY    = 0.10
_W_BEHAVIORAL = 0.10
_W_ASSET      = 0.05

# Each input dimension is normalised to [0,1] before weighting.
# CVSS arrives on [0,10] so divide by 10. EPSS, KEV, recency, behavioral and
# asset scores are already in [0,1]. The weighted sum max is therefore 1.0.
_MAX_WEIGHT_SUM = (
    _W_CVSS + _W_EPSS + _W_KEV + _W_RECENCY + _W_BEHAVIORAL + _W_ASSET
)
_SCALE = 10.0 / _MAX_WEIGHT_SUM   # → 10.0 (kept explicit for clarity)

_ASSET_TIER: dict[str, float] = {
    "server":      1.0,
    "workstation": 0.5,
    "laptop":      0.5,
}
_ASSET_DEFAULT = 0.3

# Severity bucketing for the final composite (0-10 scale).
_BUCKETS = (
    (8.5, "critical"),
    (6.5, "high"),
    (4.0, "medium"),
    (1.5, "low"),
)


def _recency_score(collected_ts: float, now: float | None = None) -> float:
    """Decay function over age in hours."""
    if not collected_ts or collected_ts <= 0:
        return 0.0
    now = now if now is not None else time.time()
    age_hours = max(0.0, (now - collected_ts) / 3600.0)
    if age_hours < 24:
        return 1.0
    if age_hours < 24 * 7:
        return 0.5
    if age_hours < 24 * 30:
        return 0.2
    return 0.0


def _clamp01(x: Any) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _cvss_norm(x: Any) -> float:
    """CVSS arrives on [0,10]. Clamp and scale to [0,1]."""
    try:
        v = float(x or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 10.0:
        return 1.0
    return v / 10.0


class RiskScoreMatrix:
    """Composite risk score combining CVSS, EPSS, KEV, recency, behavioral, asset."""

    def __init__(self) -> None:
        self._asset_tier = dict(_ASSET_TIER)

    # ── Public API ────────────────────────────────────────────────────────────

    def compute(
        self,
        finding: dict,
        agent_id: str = "",
        collected_ts: float | None = None,
    ) -> float:
        if collected_ts is None:
            collected_ts = float(finding.get("collected_at") or time.time())

        cvss       = _cvss_norm(finding.get("cvss_score") or 0.0)
        epss       = _clamp01(finding.get("epss_score", 0.0))
        kev        = 1.0 if bool(finding.get("kev", False)) else 0.0
        recency    = _recency_score(collected_ts)
        behavioral = _clamp01(finding.get("behavioral_deviation", 0.0))
        asset      = self._asset_score(finding)

        weighted = (
            cvss       * _W_CVSS
            + epss     * _W_EPSS
            + kev      * _W_KEV
            + recency  * _W_RECENCY
            + behavioral * _W_BEHAVIORAL
            + asset    * _W_ASSET
        )
        composite = weighted * _SCALE
        if composite < 0.0:
            composite = 0.0
        elif composite > 10.0:
            composite = 10.0
        return round(composite, 2)

    def compute_bulk(
        self,
        findings: list[dict],
        agent_id: str = "",
        collected_ts: float | None = None,
    ) -> list[dict]:
        out: list[dict] = []
        for f in findings:
            score = self.compute(f, agent_id=agent_id, collected_ts=collected_ts)
            f["composite_score"] = score
            out.append(f)
        return out

    @staticmethod
    def severity_from_composite(score: float) -> str:
        try:
            s = float(score)
        except (TypeError, ValueError):
            s = 0.0
        for threshold, label in _BUCKETS:
            if s >= threshold:
                return label
        return "info"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _asset_score(self, finding: dict) -> float:
        tier = finding.get("asset_tier")
        if not tier:
            return _ASSET_DEFAULT
        return self._asset_tier.get(str(tier).lower(), _ASSET_DEFAULT)


# Module-level singleton — import as: from .scoring import score_matrix
score_matrix = RiskScoreMatrix()
