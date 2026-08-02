"""Detect hardware inventory changes against a durable per-agent baseline."""
from __future__ import annotations

import json
import time
from typing import Any


_CATEGORY = "hardware_integrity"
_BASELINE_KEY = "known_devices"


def _identity(item: dict) -> str:
    fields = (
        str(item.get("bus") or "unknown").lower(),
        str(item.get("vendor_id") or item.get("vendor") or "unknown").lower(),
        str(item.get("product_id") or item.get("name") or "unknown").lower(),
    )
    return ":".join(fields)


def _fingerprint(item: dict) -> str:
    return json.dumps({
        "serial": item.get("serial"),
        "revision": item.get("revision"),
        "name": item.get("name"),
    }, sort_keys=True, default=str, separators=(",", ":"))


async def analyze(
    agent_id: str,
    section: str,
    data: Any,
    db,
    hostname: str = "",
) -> list[dict]:
    if section != "hardware" or not isinstance(data, list):
        return []

    raw = await db.get_entity_state(agent_id, _CATEGORY, _BASELINE_KEY)
    blob = raw.get("fingerprint") if isinstance(raw, dict) else raw
    try:
        known = json.loads(blob) if isinstance(blob, str) else dict(blob or {})
    except (TypeError, ValueError, json.JSONDecodeError):
        known = {}

    current = {
        _identity(item): _fingerprint(item)
        for item in data if isinstance(item, dict) and item.get("name")
    }
    if not known:
        await db.set_entity_state(
            agent_id, _CATEGORY, _BASELINE_KEY,
            json.dumps(current, sort_keys=True), time.time(),
        )
        return []

    findings: list[dict] = []
    asset = hostname or agent_id
    updated = dict(known)
    for identity, fingerprint in current.items():
        previous = known.get(identity)
        if previous is None:
            findings.append({
                "rule_id": "HARDWARE-NEW-DEVICE",
                "severity": "low",
                "confidence": 0.90,
                "title": f"New hardware device observed on {asset}",
                "description": "A device absent from the durable hardware baseline appeared.",
                "evidence": {"device": identity, "fingerprint": fingerprint},
                "item_key": f"hardware:new:{identity}",
                "category": "hardware",
                "source": "rule:hardware_integrity",
                "mitre_technique": "T1200",
                "mitre_tactic": "Initial Access",
                "recommended_action": "Verify the device against asset and service records.",
                "false_positive_notes": "Normal peripheral attachment or approved repair.",
                "tags": ["hardware", "baseline_change"],
            })
        elif previous != fingerprint:
            findings.append({
                "rule_id": "HARDWARE-COMPONENT-CHANGED",
                "severity": "medium",
                "confidence": 0.90,
                "title": f"Hardware identity changed on {asset}",
                "description": "A known hardware component changed serial, revision, or name.",
                "evidence": {
                    "device": identity, "previous_fingerprint": previous,
                    "current_fingerprint": fingerprint,
                },
                "item_key": f"hardware:changed:{identity}",
                "category": "hardware",
                "source": "rule:hardware_integrity",
                "mitre_technique": "T1200",
                "mitre_tactic": "Initial Access",
                "recommended_action": (
                    "Confirm an approved repair or physically inspect the endpoint."
                ),
                "false_positive_notes": (
                    "Approved repair, firmware update, or unstable vendor metadata."
                ),
                "tags": ["hardware", "baseline_change"],
            })
        updated[identity] = fingerprint

    await db.set_entity_state(
        agent_id, _CATEGORY, _BASELINE_KEY,
        json.dumps(updated, sort_keys=True), time.time(),
    )
    return findings
