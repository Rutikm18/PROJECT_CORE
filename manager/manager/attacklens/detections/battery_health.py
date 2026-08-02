"""Battery integrity and health detections.

The battery collector is a snapshot, not an event stream. This detector only
alerts on facts the payload can prove: an explicit service/failure condition,
severe loss of design capacity, or a cycle counter moving backwards after a
DB-backed baseline has been established. The latter can indicate battery or
controller replacement and is therefore an asset-change signal that should be
verified, not treated as proof of compromise.
"""
from __future__ import annotations

import time
from typing import Any


_SECTION = "battery"
_STATE_CATEGORY = "battery_health"
_CYCLE_KEY = "battery:cycle_count"
_BAD_CONDITION_TERMS = ("service", "replace", "failed", "failure", "critical", "poor")


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    evidence: dict[str, Any],
    *,
    item_key: str,
    technique: str = "",
    tactic: str = "",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": 0.82,
        "title": title,
        "description": description,
        "evidence": evidence,
        "item_key": item_key,
        "category": "battery",
        "source": "rule:battery_health",
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "recommended_action": (
            "Verify the battery/controller identity and service history, then compare "
            "the change with the approved hardware inventory."
        ),
        "false_positive_notes": (
            "Legitimate battery replacement, repair, calibration, or vendor telemetry "
            "changes can produce this signal."
        ),
        "tags": ["battery", "hardware_integrity"],
    }


async def analyze(
    agent_id: str,
    section: str,
    data: Any,
    db,
    hostname: str = "",
) -> list[dict[str, Any]]:
    if section != _SECTION or not isinstance(data, dict):
        return []
    if data.get("present") is False:
        return []

    findings: list[dict[str, Any]] = []
    asset = hostname or agent_id

    condition = str(data.get("condition") or "").strip()
    if condition and any(term in condition.lower() for term in _BAD_CONDITION_TERMS):
        findings.append(_finding(
            "BATTERY-HEALTH-001",
            "medium",
            f"Battery reports a service condition on {asset}",
            f"The battery explicitly reported condition {condition!r}.",
            {"condition": condition, "charge_pct": data.get("charge_pct")},
            item_key="battery:condition",
        ))

    capacity = _number(data.get("capacity_mah"))
    design = _number(data.get("design_mah"))
    if capacity is not None and design is not None and design > 0:
        ratio = capacity / design
        if ratio < 0.60:
            findings.append(_finding(
                "BATTERY-HEALTH-002",
                "low",
                f"Battery capacity is severely degraded on {asset}",
                f"Reported full capacity is {ratio:.0%} of design capacity.",
                {
                    "capacity_mah": capacity,
                    "design_mah": design,
                    "capacity_ratio": round(ratio, 3),
                },
                item_key="battery:capacity",
            ))

    cycle = _number(data.get("cycle_count"))
    if cycle is not None and cycle >= 0:
        cycle_int = int(cycle)
        try:
            previous = await db.get_entity_state(agent_id, _STATE_CATEGORY, _CYCLE_KEY)
            previous_cycle = int(previous["fingerprint"]) if previous else None
            if previous_cycle is not None and cycle_int < previous_cycle:
                findings.append(_finding(
                    "BATTERY-002",
                    "medium",
                    f"Battery cycle counter decreased on {asset}",
                    "The battery cycle counter moved backwards relative to its durable baseline, "
                    "which can indicate a battery or controller replacement.",
                    {"previous_cycle_count": previous_cycle, "cycle_count": cycle_int},
                    item_key="battery:cycle_count",
                    technique="T1200",
                    tactic="Initial Access",
                ))
            await db.set_entity_state(
                agent_id, _STATE_CATEGORY, _CYCLE_KEY, str(cycle_int), time.time(),
            )
        except (KeyError, TypeError, ValueError):
            # A malformed historic baseline must not suppress the current health checks.
            await db.set_entity_state(
                agent_id, _STATE_CATEGORY, _CYCLE_KEY, str(cycle_int), time.time(),
            )

    return findings
