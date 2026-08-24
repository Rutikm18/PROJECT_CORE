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
    "layer":       "raw" | "correlation",   ← NEW
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
    "required_count": 1,       # min number of matching items to fire (raw layer: items in the section)
    "time_window_hours": 24,   # look back window (correlation layer only)
    "tags":        ["custom", "fp-reduction"],
    "attack_chain": [],        # optional MITRE chain for alert-type rules
    "created_by":  "analyst",
    "created_at":  <unix ts>,
    "updated_at":  <unix ts>,
    "hit_count":   0,          # incremented each time this rule fires
    "last_hit_at": null,
  }

Layers
------
  correlation (default) — evaluates conditions over *existing findings* stored in DB.
                          Runs during the correlation pass (CustomCorrelator.correlate).

  raw                   — evaluates conditions directly against *incoming telemetry items*
                          before findings are stored.  Conditions reference fields in the
                          raw section payload (e.g. "process_name", "dest_port").
                          Runs during the detection pass (CustomCorrelator.evaluate_raw).
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

    async def evaluate_raw(
        self,
        agent_id: str,
        section: str,
        items: list[dict],
    ) -> list[dict]:
        """Evaluate raw-layer rules against incoming telemetry items.

        Called once per payload section during the detection pass, before findings
        are stored.  Conditions reference fields in the raw telemetry item dict.
        Returns a list of finding dicts (same schema as rulepack findings).
        """
        rules = await self._load_rules(layer="raw")
        if not rules:
            return []

        now = time.time()
        results: list[dict] = []

        for rule in rules:
            conditions = rule.get("conditions") or {}
            required_cnt = int(rule.get("required_count", 1))
            section_filter = rule.get("section_filter", "")  # optional: restrict to specific sections
            if section_filter and section.lower() != section_filter.lower():
                continue

            matched = [item for item in items if _matches_conditions(conditions, item)]
            if len(matched) < required_cnt:
                continue

            severity = rule.get("severity", "medium")
            score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}.get(severity, 5.0)
            action = rule.get("action", "alert")

            results.append({
                "rule_id":          f"custom-raw:{rule['id']}",
                "agent_id":         agent_id,
                "category":         section,
                "item_key":         f"custom-raw:{rule['id']}",
                "severity":         severity,
                "score":            score,
                "confidence":       int(rule.get("confidence", 70)),
                "title":            rule.get("name", "Custom raw detection rule"),
                "description":      rule.get("description", ""),
                "recommendation":   rule.get("recommendation", ""),
                "attack_chain":     rule.get("attack_chain") or [],
                "tags":             rule.get("tags") or [],
                "evidence":         {"matched_items": matched[:10], "matched_count": len(matched)},
                "source":           "custom_raw_rule",
                "action":           action,
                "custom_rule_id":   rule["id"],
                "custom_rule_name": rule.get("name", ""),
                "custom_rule_layer": "raw",
                "detected_at":      now,
            })

            # Increment hit counter (best-effort)
            try:
                # Best-effort, but it shares the one write connection: without
                # a rollback a failed counter update poisons that connection
                # and silently breaks settings, cases and validation.
                async with self._idb.write_txn() as conn:
                    await conn.execute(
                        "UPDATE custom_correlation_rules "
                        "SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                        (now, rule["id"]),
                    )
            except Exception:
                pass

        return results

    async def correlate(self, agent_id: str) -> list[dict]:
        """Evaluate all enabled correlation-layer custom rules for an agent."""
        rules = await self._load_rules(layer="correlation")
        if not rules:
            return []

        findings = await self._idb.get_findings(agent_id, active_only=True, limit=500)

        now = time.time()
        results: list[dict] = []

        errors: list[tuple[str, Exception]] = []
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            try:
                result = self._eval_rule(rule, findings, agent_id, now)
                if result:
                    results.append(result)
                    # Increment hit counter async (best-effort — do not block)
                    try:
                        # Best-effort, but it shares the one write connection: without
                        # a rollback a failed counter update poisons that connection
                        # and silently breaks settings, cases and validation.
                        async with self._idb.write_txn() as conn:
                            await conn.execute(
                                "UPDATE custom_correlation_rules "
                                "SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                                (now, rule["id"]),
                            )
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("CustomCorrelator: rule %s eval error: %s", rule.get("id"), exc)
                errors.append((str(rule.get("id") or "unknown"), exc))

        if errors:
            rule_id, first = errors[0]
            raise RuntimeError(
                f"{len(errors)} custom correlation rule(s) failed; "
                f"first={rule_id}:{type(first).__name__}:{first}"
            ) from first

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

    async def _load_rules(self, layer: str | None = None) -> list[dict]:
        if layer:
            rows = await self._idb._fetchall(
                "SELECT * FROM custom_correlation_rules WHERE enabled = 1 AND layer = ? ORDER BY created_at DESC",
                (layer,),
            )
        else:
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
