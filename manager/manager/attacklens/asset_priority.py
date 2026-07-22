"""
Settings-driven asset priority calibration for detection confidence.

Priority does not replace evidence quality. It gives analyst-marked important
assets a bounded lift, and records the lift so confidence remains auditable.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True)
class AssetPriorityProfile:
    level: str
    label: str
    confidence_multiplier: float
    confidence_delta: float
    precision_delta: float
    asset_tier_floor: str
    asset_importance_floor: float


ASSET_PRIORITY_PROFILES: dict[str, AssetPriorityProfile] = {
    "top": AssetPriorityProfile(
        level="top",
        label="Top priority",
        confidence_multiplier=1.10,
        confidence_delta=0.06,
        precision_delta=0.04,
        asset_tier_floor="crown_jewel",
        asset_importance_floor=1.0,
    ),
    "high": AssetPriorityProfile(
        level="high",
        label="High priority",
        confidence_multiplier=1.05,
        confidence_delta=0.03,
        precision_delta=0.025,
        asset_tier_floor="server",
        asset_importance_floor=0.85,
    ),
    "standard": AssetPriorityProfile(
        level="standard",
        label="Standard priority",
        confidence_multiplier=1.00,
        confidence_delta=0.00,
        precision_delta=0.00,
        asset_tier_floor="endpoint",
        asset_importance_floor=0.40,
    ),
    "low": AssetPriorityProfile(
        level="low",
        label="Low priority",
        confidence_multiplier=1.00,
        confidence_delta=0.00,
        precision_delta=0.00,
        asset_tier_floor="unknown",
        asset_importance_floor=0.30,
    ),
}

ASSET_PRIORITY_LEVELS: tuple[str, ...] = tuple(ASSET_PRIORITY_PROFILES.keys())

_LEVEL_ALIASES = {
    "critical": "top",
    "crown": "top",
    "crown_jewel": "top",
    "crown-jewel": "top",
    "tier1": "top",
    "tier_1": "top",
    "p0": "top",
    "p1": "top",
    "important": "high",
    "server": "high",
    "prod": "high",
    "production": "high",
    "normal": "standard",
    "default": "standard",
    "medium": "standard",
    "endpoint": "standard",
    "sandbox": "low",
    "dev": "low",
    "test": "low",
}

_TIER_RANK = {
    "unknown": 0,
    "standard": 1,
    "endpoint": 1,
    "workstation": 2,
    "server": 3,
    "crown_jewel": 4,
}


def normalize_priority_level(value: Any) -> str:
    level = str(value or "standard").strip().lower().replace(" ", "_")
    level = _LEVEL_ALIASES.get(level, level)
    if level not in ASSET_PRIORITY_PROFILES:
        raise ValueError(
            f"asset priority must be one of {ASSET_PRIORITY_LEVELS}, got {value!r}"
        )
    return level


def priority_profile(level: Any) -> AssetPriorityProfile:
    return ASSET_PRIORITY_PROFILES[normalize_priority_level(level)]


def priority_options() -> list[dict[str, Any]]:
    return [
        {
            "level": profile.level,
            "label": profile.label,
            "confidence_multiplier": profile.confidence_multiplier,
            "confidence_delta": profile.confidence_delta,
            "precision_delta": profile.precision_delta,
            "asset_tier_floor": profile.asset_tier_floor,
        }
        for profile in ASSET_PRIORITY_PROFILES.values()
    ]


def normalize_agent_priorities(value: Any) -> dict[str, str]:
    if value in (None, "", {}):
        return {}
    raw = value
    if isinstance(value, str):
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"agent priority map must be valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("agent priority map must be an object keyed by agent_id")
    out: dict[str, str] = {}
    for agent_id, level in raw.items():
        aid = str(agent_id or "").strip()
        if not aid:
            continue
        out[aid] = normalize_priority_level(level)
    return out


def priority_for_agent(agent_id: str, priorities: dict[str, Any] | None) -> AssetPriorityProfile:
    level = "standard"
    if agent_id and priorities:
        level = priorities.get(agent_id) or priorities.get(str(agent_id)) or "standard"
    return priority_profile(level)


def _tier_floor(current: str, floor: str) -> str:
    current = str(current or "unknown").lower()
    floor = str(floor or "unknown").lower()
    return floor if _TIER_RANK.get(floor, 0) > _TIER_RANK.get(current, 0) else current


def apply_priority_to_enriched(enriched: dict[str, Any], profile: AssetPriorityProfile) -> dict[str, Any]:
    out = dict(enriched or {})
    tier = _tier_floor(str(out.get("asset_tier") or "endpoint"), profile.asset_tier_floor)
    try:
        importance = float(out.get("asset_importance") or 0.0)
    except (TypeError, ValueError):
        importance = 0.0
    out.update({
        "asset_tier": tier,
        "asset_importance": max(importance, profile.asset_importance_floor),
        "asset_priority_level": profile.level,
        "asset_priority_label": profile.label,
        "asset_priority_confidence_multiplier": profile.confidence_multiplier,
        "asset_priority_confidence_delta": profile.confidence_delta,
        "asset_priority_precision_delta": profile.precision_delta,
    })
    return out


def _base_confidence(finding: dict[str, Any]) -> float:
    for key in ("confidence", "precision_score"):
        if finding.get(key) is not None:
            try:
                return max(0.0, min(1.0, float(finding[key])))
            except (TypeError, ValueError):
                pass
    try:
        return max(0.0, min(0.85, float(finding.get("score") or 5.0) / 10.0 * 0.85))
    except (TypeError, ValueError):
        return 0.50


def apply_priority_to_finding(
    finding: dict[str, Any],
    profile: AssetPriorityProfile,
) -> dict[str, Any]:
    """Apply a bounded priority lift to a finding in-place and return it."""
    if profile.level in {"standard", "low"}:
        return finding

    base_conf = _base_confidence(finding)
    raw_delta = profile.confidence_delta

    # Weak single-source evidence should not become a strong finding only
    # because the host is important. Priority helps once the signal is plausible.
    if base_conf < 0.65:
        conf_delta = min(raw_delta * 0.50, 0.025)
        conf_cap = 0.69
    elif base_conf < 0.80:
        conf_delta = raw_delta * 0.75
        conf_cap = 0.86
    else:
        conf_delta = raw_delta
        conf_cap = 0.99

    final_conf = min(conf_cap, base_conf + conf_delta)
    finding["confidence"] = round(final_conf, 3)

    precision_delta = 0.0
    if finding.get("precision_score") is not None:
        try:
            base_precision = max(0.0, min(1.0, float(finding.get("precision_score") or 0.0)))
        except (TypeError, ValueError):
            base_precision = 0.0
        precision_delta = profile.precision_delta
        if base_conf < 0.65:
            precision_delta = min(precision_delta * 0.50, 0.02)
        finding["precision_score"] = round(min(0.99, base_precision + precision_delta), 3)

    factors = finding.get("precision_factors")
    if not isinstance(factors, dict):
        factors = {}
    factors.update({
        "asset_priority_level": profile.level,
        "asset_priority_confidence_boost": round(final_conf - base_conf, 3),
        "asset_priority_precision_boost": round(precision_delta, 3),
    })
    finding["precision_factors"] = factors

    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        evidence["_confidence_calibration"] = {
            "asset_priority_level": profile.level,
            "asset_priority_label": profile.label,
            "base_confidence": round(base_conf, 3),
            "final_confidence": round(final_conf, 3),
            "confidence_delta": round(final_conf - base_conf, 3),
            "precision_delta": round(precision_delta, 3),
        }
        finding["evidence"] = evidence

    if profile.asset_tier_floor:
        finding["asset_tier"] = _tier_floor(
            str(finding.get("asset_tier") or "endpoint"),
            profile.asset_tier_floor,
        )
    try:
        importance = float(finding.get("asset_importance") or 0.0)
    except (TypeError, ValueError):
        importance = 0.0
    finding["asset_importance"] = max(importance, profile.asset_importance_floor)

    return finding
