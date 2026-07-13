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
"""
from __future__ import annotations

import json
import logging
import time
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Optional

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
    action: str = "alert"          # alert | suppress | elevate | tag
    severity: str = "medium"
    confidence: int = Field(70, ge=0, le=99)
    conditions: Conditions = Conditions()
    required_count: int = Field(1, ge=1)
    time_window_hours: int = Field(24, ge=1, le=8760)
    tags: list[str] = []
    attack_chain: list[dict] = []
    recommendation: str = ""


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
        """Execute a write statement on the shared write connection."""
        await intel_db._conn.execute(sql, args)
        await intel_db._conn.commit()

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
        now     = time.time()
        rule_id = str(uuid.uuid4())
        try:
            await _write(
                """INSERT INTO custom_correlation_rules
                   (id, name, description, enabled, action, severity, confidence,
                    conditions, required_count, time_window_hours, tags, attack_chain,
                    recommendation, created_by, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    rule_id, body.name, body.description, int(body.enabled),
                    body.action, body.severity, body.confidence,
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
        await _get_or_404(rule_id)
        now = time.time()
        try:
            await _write(
                """UPDATE custom_correlation_rules SET
                   name=?, description=?, enabled=?, action=?, severity=?, confidence=?,
                   conditions=?, required_count=?, time_window_hours=?, tags=?,
                   attack_chain=?, recommendation=?, updated_at=?
                   WHERE id=?""",
                (
                    body.name, body.description, int(body.enabled), body.action,
                    body.severity, body.confidence,
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
            from ..attacklens.custom_correlator import _matches_conditions
            import time as _t

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

    return router
