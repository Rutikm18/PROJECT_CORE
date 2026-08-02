"""Detect collection blind spots from the agent's real health heartbeat."""
from __future__ import annotations

from typing import Any


def _finding(rule_id: str, severity: str, title: str, evidence: dict, item_key: str) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": 0.98,
        "title": title,
        "description": "The endpoint reported degradation in its own telemetry pipeline.",
        "evidence": evidence,
        "item_key": item_key,
        "category": "agent_health",
        "source": "rule:agent_health",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "Defense Evasion",
        "recommended_action": (
            "Inspect the agent service and affected collector, verify manager connectivity, "
            "and confirm that queued telemetry is draining without loss."
        ),
        "false_positive_notes": (
            "Resource pressure, a sleeping laptop, or a temporary manager outage can cause "
            "the same health state; correlate with the durable ingest ledger."
        ),
        "tags": ["agent_health", "telemetry_coverage"],
    }


async def analyze(
    agent_id: str,
    section: str,
    data: Any,
    db,
    hostname: str = "",
) -> list[dict]:
    del db
    if section != "agent_health" or not isinstance(data, dict):
        return []

    findings: list[dict] = []
    asset = hostname or agent_id
    sections = data.get("sections")
    if isinstance(sections, dict):
        for source, status in sections.items():
            if not isinstance(status, dict):
                continue
            state = str(status.get("state") or "").upper()
            failures = int(status.get("failures") or 0)
            if state in {"OPEN", "HALF_OPEN"} or failures >= 3:
                findings.append(_finding(
                    "AGENT-HEALTH-COLLECTOR-OPEN",
                    "high",
                    f"Telemetry collector {source} is degraded on {asset}",
                    {
                        "collector": str(source),
                        "state": state,
                        "failures": failures,
                        "last_result": status.get("last_result"),
                    },
                    f"agent_health:collector:{source}",
                ))

    link = data.get("link")
    if isinstance(link, dict):
        loss = {
            name: int(link.get(name) or 0)
            for name in ("spool_dropped_trim", "spool_dropped_corrupt", "spool_dropped_auth")
        }
        if any(loss.values()):
            findings.append(_finding(
                "AGENT-HEALTH-SPOOL-LOSS",
                "high",
                f"Agent spool reports dropped telemetry on {asset}",
                {**loss, "spool_bytes": int(link.get("spool_bytes") or 0)},
                "agent_health:spool_loss",
            ))
        auth_failures = int(link.get("auth_failures") or 0)
        if auth_failures >= 3:
            findings.append(_finding(
                "AGENT-HEALTH-AUTH-FAILURES",
                "high",
                f"Repeated manager authentication failures on {asset}",
                {
                    "auth_failures": auth_failures,
                    "delivery_rejected_4xx": int(link.get("delivery_rejected_4xx") or 0),
                },
                "agent_health:auth_failures",
            ))

    return findings
