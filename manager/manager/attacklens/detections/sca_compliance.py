"""Turn failed Security Configuration Assessment checks into findings."""
from __future__ import annotations

from typing import Any


_SECTION = "sca"
_HIGH_IMPACT_TECHNIQUES = {
    "T1003", "T1021", "T1053", "T1068", "T1543", "T1547", "T1552", "T1553",
}


def _techniques(check: dict[str, Any]) -> list[str]:
    value = check.get("mitre") or check.get("mitre_attack") or []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


async def analyze(
    agent_id: str,
    section: str,
    data: Any,
    db,
    hostname: str = "",
) -> list[dict[str, Any]]:
    del db  # SCA results are complete snapshots and need no local detector state.
    if section != _SECTION or not isinstance(data, dict):
        return []

    policies = data.get("policies")
    if not isinstance(policies, list):
        return []

    findings: list[dict[str, Any]] = []
    for policy_result in policies:
        if not isinstance(policy_result, dict) or policy_result.get("applicable") is False:
            continue
        policy = policy_result.get("policy")
        policy = policy if isinstance(policy, dict) else {}
        policy_id = str(policy.get("id") or policy.get("name") or "unknown-policy")
        policy_name = str(policy.get("name") or policy_id)
        checks = policy_result.get("checks")
        if not isinstance(checks, list):
            continue

        for check in checks:
            if not isinstance(check, dict) or str(check.get("result") or "").lower() != "failed":
                continue
            check_id = str(check.get("id") or check.get("title") or "unknown-check")
            title = str(check.get("title") or check_id)
            techniques = _techniques(check)
            severity = "high" if any(
                technique.split(".", 1)[0] in _HIGH_IMPACT_TECHNIQUES
                for technique in techniques
            ) else "medium"
            evidence = {
                "policy_id": policy_id,
                "policy_name": policy_name,
                "check_id": check_id,
                "check_title": title,
                "result": "failed",
                "reason": check.get("reason"),
                "rationale": check.get("rationale"),
                "remediation": check.get("remediation"),
                "cis": check.get("cis"),
                "mitre": techniques,
                "host": hostname or agent_id,
            }
            findings.append({
                "rule_id": "SCA-CHECK-FAILED",
                "severity": severity,
                "confidence": 0.95,
                "title": f"SCA control failed: {title}",
                "description": (
                    f"{hostname or agent_id} failed check {check_id} in {policy_name}."
                ),
                "evidence": evidence,
                "item_key": f"sca:{policy_id}:{check_id}",
                "category": "compliance",
                "source": "rule:sca_compliance",
                "mitre_technique": techniques[0] if techniques else "",
                "mitre_tactic": "Defense Evasion" if techniques else "",
                "recommended_action": str(
                    check.get("remediation")
                    or "Apply the benchmark remediation after validating operational impact."
                ),
                "false_positive_notes": (
                    "Confirm that the control applies to this host role and that the SCA "
                    "probe had sufficient privileges. Not-applicable checks are not alerted."
                ),
                "tags": ["sca", "compliance", policy_id],
            })
    return findings
