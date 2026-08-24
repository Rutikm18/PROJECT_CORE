"""
manager/manager/api/custom_correlations.py — CRUD API for analyst-defined correlation rules.

Routes (prefix /api/v1/custom-correlations):
  GET    /               list all rules
  POST   /               create rule
  GET    /{id}           get single rule
  PUT    /{id}           update rule
  DELETE /{id}           delete rule
  POST   /{id}/toggle    enable / disable
  POST   /{id}/test      dry-run against recent findings (no side effects)
  POST   /import-yaml    import rules from a YAML file body
  POST   /reload-rules   reload rulepack YAML from disk (pull-all for fresh deployments)
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

log = logging.getLogger("manager.api.custom_correlations")


# ── Pydantic models ───────────────────────────────────────────────────────────

class ConditionRule(BaseModel):
    field: str
    op: str
    value: Any


class Conditions(BaseModel):
    operator: str = "AND"
    rules: list[ConditionRule] = []


class CustomRuleBody(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    layer: str = "correlation"     # raw | correlation
    action: str = "alert"          # alert | suppress | elevate | tag
    severity: str = "medium"
    confidence: int = Field(70, ge=0, le=99)
    conditions: Conditions = Conditions()
    required_count: int = Field(1, ge=1)
    time_window_hours: int = Field(24, ge=1, le=8760)
    tags: list[str] = []
    attack_chain: list[dict] = []
    recommendation: str = ""

    def validate_layer(self) -> None:
        if self.layer not in {"raw", "correlation"}:
            raise ValueError(f"layer must be 'raw' or 'correlation', got {self.layer!r}")


# ── Router factory ────────────────────────────────────────────────────────────

def make_custom_correlations_router(intel_db) -> APIRouter:
    router = APIRouter(tags=["custom-correlations"])

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _row_to_dict(row) -> dict:
        if row is None:
            return {}
        r = dict(row)
        for field in ("conditions", "attack_chain", "tags"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except Exception:
                    r[field] = {} if field == "conditions" else []
        r["enabled"] = bool(r.get("enabled", 1))
        return r

    async def _get_or_404(rule_id: str) -> dict:
        row = await intel_db._fetchone(
            "SELECT * FROM custom_correlation_rules WHERE id = ?", (rule_id,)
        )
        if not row:
            raise HTTPException(status_code=404, detail="Custom rule not found")
        return _row_to_dict(row)

    async def _write(sql: str, args: tuple) -> None:
        """Execute a write statement on the shared write connection.

        write_txn rolls back on failure so a bad statement here cannot poison
        the connection for every other endpoint.
        """
        async with intel_db.write_txn() as conn:
            await conn.execute(sql, args)

    # ── GET /  ────────────────────────────────────────────────────────────────
    @router.get("")
    async def list_rules():
        try:
            rows = await intel_db._fetchall(
                "SELECT * FROM custom_correlation_rules ORDER BY created_at DESC", ()
            )
            rules = [_row_to_dict(r) for r in rows]
            return {"rules": rules, "total": len(rules)}
        except Exception as exc:
            log.error("list_rules error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── POST /  ───────────────────────────────────────────────────────────────
    @router.post("")
    async def create_rule(body: CustomRuleBody):
        try:
            body.validate_layer()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        now     = time.time()
        rule_id = str(uuid.uuid4())
        try:
            await _write(
                """INSERT INTO custom_correlation_rules
                   (id, name, description, enabled, layer, action, severity, confidence,
                    conditions, required_count, time_window_hours, tags, attack_chain,
                    recommendation, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rule_id, body.name, body.description, int(body.enabled),
                    body.layer, body.action, body.severity, body.confidence,
                    json.dumps(body.conditions.model_dump()),
                    body.required_count, body.time_window_hours,
                    json.dumps(body.tags), json.dumps(body.attack_chain),
                    body.recommendation, "analyst", now, now,
                ),
            )
            return await _get_or_404(rule_id)
        except HTTPException:
            raise
        except Exception as exc:
            log.error("create_rule error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── GET /{id}  ────────────────────────────────────────────────────────────
    @router.get("/{rule_id}")
    async def get_rule(rule_id: str):
        return await _get_or_404(rule_id)

    # ── PUT /{id}  ────────────────────────────────────────────────────────────
    @router.put("/{rule_id}")
    async def update_rule(rule_id: str, body: CustomRuleBody):
        try:
            body.validate_layer()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        await _get_or_404(rule_id)
        now = time.time()
        try:
            await _write(
                """UPDATE custom_correlation_rules SET
                   name=?, description=?, enabled=?, layer=?, action=?, severity=?, confidence=?,
                   conditions=?, required_count=?, time_window_hours=?, tags=?,
                   attack_chain=?, recommendation=?, updated_at=?
                   WHERE id=?""",
                (
                    body.name, body.description, int(body.enabled), body.layer,
                    body.action, body.severity, body.confidence,
                    json.dumps(body.conditions.model_dump()),
                    body.required_count, body.time_window_hours,
                    json.dumps(body.tags), json.dumps(body.attack_chain),
                    body.recommendation, now, rule_id,
                ),
            )
            return await _get_or_404(rule_id)
        except HTTPException:
            raise
        except Exception as exc:
            log.error("update_rule error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── DELETE /{id}  ─────────────────────────────────────────────────────────
    @router.delete("/{rule_id}")
    async def delete_rule(rule_id: str):
        await _get_or_404(rule_id)
        try:
            await _write(
                "DELETE FROM custom_correlation_rules WHERE id=?", (rule_id,)
            )
            return {"deleted": True, "id": rule_id}
        except HTTPException:
            raise
        except Exception as exc:
            log.error("delete_rule error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── POST /{id}/toggle  ────────────────────────────────────────────────────
    @router.post("/{rule_id}/toggle")
    async def toggle_rule(rule_id: str):
        rule = await _get_or_404(rule_id)
        new_state = 0 if rule.get("enabled") else 1
        try:
            await _write(
                "UPDATE custom_correlation_rules SET enabled=?, updated_at=? WHERE id=?",
                (new_state, time.time(), rule_id),
            )
            return {"id": rule_id, "enabled": bool(new_state)}
        except Exception as exc:
            log.error("toggle_rule error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── POST /{id}/test  ──────────────────────────────────────────────────────
    @router.post("/{rule_id}/test")
    async def test_rule(rule_id: str, body: Optional[dict] = None):
        """Dry-run a rule against active findings — no writes, no side effects."""
        rule = await _get_or_404(rule_id)
        agent_id = (body or {}).get("agent_id") if body else None

        try:
            import time as _t

            from ..attacklens.custom_correlator import _matches_conditions

            if agent_id:
                findings_raw = await intel_db._fetchall(
                    "SELECT * FROM findings WHERE is_active=1 AND agent_id=? ORDER BY last_detected_at DESC LIMIT 500",
                    (agent_id,),
                )
            else:
                findings_raw = await intel_db._fetchall(
                    "SELECT * FROM findings WHERE is_active=1 ORDER BY last_detected_at DESC LIMIT 500",
                    (),
                )

            now      = _t.time()
            cutoff   = now - float(rule.get("time_window_hours", 24)) * 3600.0
            conditions = rule.get("conditions") or {}
            matched  = [
                dict(f) for f in findings_raw
                if (dict(f).get("last_detected_at") or dict(f).get("first_detected_at") or 0) >= cutoff
                and _matches_conditions(conditions, dict(f))
            ]

            would_fire = len(matched) >= int(rule.get("required_count", 1))
            return {
                "would_fire":       would_fire,
                "matched_count":    len(matched),
                "required_count":   rule.get("required_count", 1),
                "scanned":          len(findings_raw),
                "matched_findings": [
                    {
                        "id":       f.get("id"),
                        "title":    f.get("title"),
                        "category": f.get("category"),
                        "severity": f.get("severity"),
                        "agent_id": f.get("agent_id"),
                    }
                    for f in matched[:20]
                ],
            }
        except Exception as exc:
            log.error("test_rule error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    # ── POST /import-yaml  ───────────────────────────────────────────────────
    @router.post("/import-yaml")
    async def import_yaml_rules(request: Request):
        """Import custom rules from a YAML body.

        Accepts:
          - A single rule object (dict)
          - A list of rule objects
          - A dict with a 'rules' key containing a list

        Each rule follows the same schema as CustomRuleBody.  Existing rules
        with the same name are skipped (idempotent).  Returns a summary.
        """
        try:
            raw_bytes = await request.body()
            payload = yaml.safe_load(raw_bytes)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

        if isinstance(payload, dict) and "rules" in payload:
            rule_list = payload["rules"]
        elif isinstance(payload, list):
            rule_list = payload
        elif isinstance(payload, dict):
            rule_list = [payload]
        else:
            raise HTTPException(status_code=400, detail="YAML must be a rule dict, list, or {rules: [...]}")

        if not isinstance(rule_list, list):
            raise HTTPException(status_code=400, detail="Expected a list of rules")

        created, skipped, errors = 0, 0, []

        # Build set of existing rule names to skip duplicates
        existing_rows = await intel_db._fetchall(
            "SELECT name FROM custom_correlation_rules", ()
        )
        existing_names = {r["name"] for r in existing_rows}

        now = time.time()
        for entry in rule_list:
            if not isinstance(entry, dict):
                errors.append(f"Skipped non-dict entry: {entry!r}")
                continue
            name = str(entry.get("name", "")).strip()
            if not name:
                errors.append("Skipped entry with missing name")
                continue
            if name in existing_names:
                skipped += 1
                continue
            try:
                body = CustomRuleBody(
                    name=name,
                    description=str(entry.get("description", "")),
                    enabled=bool(entry.get("enabled", True)),
                    layer=str(entry.get("layer", "correlation")),
                    action=str(entry.get("action", "alert")),
                    severity=str(entry.get("severity", "medium")),
                    confidence=int(entry.get("confidence", 70)),
                    required_count=int(entry.get("required_count", 1)),
                    time_window_hours=int(entry.get("time_window_hours", 24)),
                    tags=list(entry.get("tags") or []),
                    recommendation=str(entry.get("recommendation", "")),
                )
                body.validate_layer()
                conditions_raw = entry.get("conditions") or {}
                if isinstance(conditions_raw, str):
                    conditions_raw = json.loads(conditions_raw)

                rule_id = str(uuid.uuid4())
                await _write(
                    """INSERT INTO custom_correlation_rules
                       (id, name, description, enabled, layer, action, severity, confidence,
                        conditions, required_count, time_window_hours, tags, attack_chain,
                        recommendation, created_by, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rule_id, body.name, body.description, int(body.enabled),
                        body.layer, body.action, body.severity, body.confidence,
                        json.dumps(conditions_raw),
                        body.required_count, body.time_window_hours,
                        json.dumps(body.tags), "[]",
                        body.recommendation, "yaml_import", now, now,
                    ),
                )
                existing_names.add(name)
                created += 1
            except Exception as exc:
                errors.append(f"Rule '{name}': {exc}")

        return {
            "imported": created,
            "skipped_duplicates": skipped,
            "errors": errors,
            "total_processed": len(rule_list),
        }

    # ── POST /reload-rules  ──────────────────────────────────────────────────
    @router.post("/reload-rules")
    async def reload_rules():
        """Reload the built-in YAML rule packs from disk.

        Call this after dropping new YAML files into the rulepacks directory,
        or on a fresh deployment to pull the full current rule set.
        Returns a summary of loaded packs and rule counts.
        """
        try:
            from ..attacklens.rulepack import RulePackDetector, default_rulepack_dir
            detector = RulePackDetector.load()
            rulepack_dir = str(default_rulepack_dir())
            yaml_files = list(Path(rulepack_dir).glob("*.yml")) + list(Path(rulepack_dir).glob("*.yaml"))
            inventory = detector.execution_inventory()
            return {
                "status": "ok",
                "rulepack_dir": rulepack_dir,
                "yaml_files_found": len(yaml_files),
                "yaml_files": [f.name for f in yaml_files],
                "sections_loaded": len(detector._rules),
                **inventory,
                "reloaded_at": time.time(),
            }
        except Exception as exc:
            log.error("reload_rules error: %s", exc)
            raise HTTPException(status_code=500, detail=f"Reload failed: {exc}")

    return router
