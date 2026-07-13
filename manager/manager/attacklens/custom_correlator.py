"""
manager/manager/attacklens/custom_correlator.py — Analyst-defined custom correlation rules.

Custom rules let analysts reduce false positives and enhance detection for their specific
environment without waiting for a code change. Each rule is stored in the DB, evaluated
during every correlation pass, and produces correlation findings identical to built-in rules.

Rule schema (stored as JSON in DB):
  {
    "id":          UUID,
    "name":        "Human-readable rule name",
    "description": "Why this rule exists",
    "enabled":     true,
    "action":      "alert" | "suppress" | "elevate" | "tag",
    "severity":    "critical" | "high" | "medium" | "low" | "info",
    "conditions":  {
      "operator": "AND" | "OR",
      "rules": [
        {
          "field":    "category" | "source" | "severity" | "title" | "tag" | "score" | "cvss_score" | "agent_id",
          "op":       "eq" | "neq" | "contains" | "not_contains" | "gt" | "lt" | "gte" | "lte" | "regex" | "in",
          "value":    <string | number | list>
        },
        ...
      ]
    },
    "required_count": 1,       # min number of matching findings to fire
    "time_window_hours": 24,   # look back window
    "tags":        ["custom", "fp-reduction"],
    "attack_chain": [],        # optional MITRE chain for alert-type rules
    "created_by":  "analyst",
    "created_at":  <unix ts>,
    "updated_at":  <unix ts>,
    "hit_count":   0,          # incremented each time this rule fires
    "last_hit_at": null,
  }
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

log = logging.getLogger("manager.attacklens.custom_correlator")

# ── Condition evaluation ──────────────────────────────────────────────────────

def _get_field(finding: dict, field: str) -> Any:
    """Extract a value from a finding for comparison.  Supports dot-path for nested evidence."""
    if "." in field:
        parts = field.split(".", 1)
        ev = finding.get("evidence") or {}
        if isinstance(ev, str):
            try:
                ev = json.loads(ev) or {}
            except Exception:
                ev = {}
        return ev.get(parts[1])
    # Special: "tag" checks the tags JSON array
    if field == "tag":
        tags = finding.get("tags")
        if isinstance(tags, str):
            try:
                return json.loads(tags)
            except Exception:
                return []
        return tags or []
    return finding.get(field)


def _evaluate_condition(condition: dict, finding: dict) -> bool:
    """Return True if a single condition rule matches a finding."""
    field = condition.get("field", "")
    op    = condition.get("op", "eq")
    value = condition.get("value")
    actual = _get_field(finding, field)

    try:
        if op == "eq":
            return str(actual).lower() == str(value).lower()
        if op == "neq":
            return str(actual).lower() != str(value).lower()
        if op == "contains":
            if isinstance(actual, list):
                return any(str(value).lower() in str(v).lower() for v in actual)
            return str(value).lower() in str(actual or "").lower()
        if op == "not_contains":
            if isinstance(actual, list):
                return not any(str(value).lower() in str(v).lower() for v in actual)
            return str(value).lower() not in str(actual or "").lower()
        if op == "gt":
            return float(actual or 0) > float(value)
        if op == "lt":
            return float(actual or 0) < float(value)
        if op == "gte":
            return float(actual or 0) >= float(value)
        if op == "lte":
            return float(actual or 0) <= float(value)
        if op == "regex":
            return bool(re.search(str(value), str(actual or ""), re.IGNORECASE))
        if op == "in":
            vals = value if isinstance(value, list) else [value]
            if isinstance(actual, list):
                return any(str(v).lower() in [str(x).lower() for x in vals] for v in actual)
            return str(actual or "").lower() in [str(v).lower() for v in vals]
    except Exception as exc:
        log.debug("condition eval error field=%s op=%s: %s", field, op, exc)
    return False


def _matches_conditions(conditions: dict, finding: dict) -> bool:
    """Evaluate a conditions block (AND/OR of condition rules) against one finding."""
    operator = conditions.get("operator", "AND").upper()
    rules    = conditions.get("rules") or []
    if not rules:
        return True
    results = [_evaluate_condition(r, finding) for r in rules]
    return all(results) if operator == "AND" else any(results)


# ── Custom correlator ─────────────────────────────────────────────────────────

class CustomCorrelator:
    """Evaluates analyst-defined correlation/suppression rules against active findings."""

    def __init__(self, intel_db) -> None:
        self._idb = intel_db

    async def correlate(self, agent_id: str) -> list[dict]:
        """Evaluate all enabled custom rules for an agent. Returns correlation dicts."""
        rules = await self._load_rules()
        if not rules:
            return []

        try:
            findings = await self._idb.get_findings(agent_id, active_only=True, limit=500)
        except Exception as exc:
            log.warning("CustomCorrelator: DB read error agent=%s: %s", agent_id, exc)
            return []

        now = time.time()
        results: list[dict] = []

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            try:
                result = self._eval_rule(rule, findings, agent_id, now)
                if result:
                    results.append(result)
                    # Increment hit counter async (best-effort — do not block)
                    try:
                        await self._idb._conn.execute(
                            "UPDATE custom_correlation_rules "
                            "SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                            (now, rule["id"]),
                        )
                        await self._idb._conn.commit()
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("CustomCorrelator: rule %s eval error: %s", rule.get("id"), exc)

        return results

    def _eval_rule(self, rule: dict, findings: list[dict], agent_id: str, now: float) -> dict | None:
        window_secs = float(rule.get("time_window_hours", 24)) * 3600.0
        cutoff      = now - window_secs

        conditions   = rule.get("conditions") or {}
        required_cnt = int(rule.get("required_count", 1))

        # Filter findings to the time window and match conditions
        matched = [
            f for f in findings
            if (f.get("last_detected_at") or f.get("first_detected_at") or 0) >= cutoff
            and _matches_conditions(conditions, f)
        ]

        if len(matched) < required_cnt:
            return None

        action   = rule.get("action", "alert")
        severity = rule.get("severity", "medium")
        score    = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}.get(severity, 5.0)

        return {
            "rule_id":          f"custom:{rule['id']}",
            "agent_id":         agent_id,
            "category":         "correlation",
            "item_key":         f"custom:{rule['id']}",
            "severity":         severity,
            "score":            score,
            "confidence":       int(rule.get("confidence", 70)),
            "title":            rule.get("name", "Custom correlation rule"),
            "description":      rule.get("description", ""),
            "recommendation":   rule.get("recommendation", ""),
            "attack_chain":     rule.get("attack_chain") or [],
            "attack_path":      [],
            "blast_radius":     {"primary_asset": agent_id, "estimated_scope": "single-host"},
            "entry_points":     [],
            "likely_next_steps":[],
            "signals":          matched[:10],
            "signal_count":     len(matched),
            "source":           "custom_correlator",
            "action":           action,  # extra field: alert | suppress | elevate | tag
            "custom_tags":      rule.get("tags") or [],
            "custom_rule_id":   rule["id"],
            "custom_rule_name": rule.get("name", ""),
            "detected_at":      now,
        }

    async def _load_rules(self) -> list[dict]:
        try:
            rows = await self._idb._fetchall(
                "SELECT * FROM custom_correlation_rules WHERE enabled = 1 ORDER BY created_at DESC",
                (),
            )
            result = []
            for row in rows:
                r = dict(row)
                for field in ("conditions", "attack_chain", "tags"):
                    if isinstance(r.get(field), str):
                        try:
                            r[field] = json.loads(r[field]) or {}
                        except Exception:
                            r[field] = {} if field == "conditions" else []
                result.append(r)
            return result
        except Exception as exc:
            log.warning("CustomCorrelator: failed to load rules: %s", exc)
            return []
