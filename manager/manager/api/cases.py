"""
manager/manager/api/cases.py — Per-finding case management API.

Routes (prefix /api/v1/cases):
  GET  /{finding_id}          get case (404 if never opened)
  PUT  /{finding_id}          upsert case (open or update fields + status)
  GET  /{finding_id}/timeline list all timeline events oldest-first
  POST /{finding_id}/notes    add an investigation note to the timeline
"""
from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


def _now() -> float:
    return time.time()


class CaseUpsert(BaseModel):
    status:     str           = "new"
    assignee:   str           = ""
    priority:   int           = 3
    due_date:   str           = ""
    notes:      str           = ""
    sla_due_at: str           = ""
    actor:      str           = "analyst"


class NoteCreate(BaseModel):
    actor:       str           = "analyst"
    note:        str           = ""
    from_status: str | None = None
    to_status:   str | None = None


def make_cases_router(intel_db) -> APIRouter:
    router = APIRouter()

    async def _write(sql: str, args: tuple) -> None:
        await intel_db._conn.execute(sql, args)
        await intel_db._conn.commit()

    async def _finding_context(finding_id: int) -> dict:
        row = await intel_db._fetchone(
            "SELECT agent_id, finding_uid FROM findings WHERE id = ?", (finding_id,)
        )
        return dict(row) if row else {}

    async def _require_finding_context(finding_id: int) -> dict:
        ctx = await _finding_context(finding_id)
        if not ctx.get("agent_id"):
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        return ctx

    async def _log_case_activity(
        finding_id: int,
        action: str,
        actor: str,
        old_value: str = "",
        new_value: str = "",
        detail: str = "",
        changed_fields: dict | None = None,
    ) -> None:
        ctx = await _finding_context(finding_id)
        if not ctx.get("agent_id"):
            return
        await intel_db._log_activity(
            finding_id,
            ctx["agent_id"],
            action,
            actor or "analyst",
            old_value,
            new_value,
            detail,
            _now(),
            finding_uid=ctx.get("finding_uid") or "",
            changed_fields=changed_fields or {},
        )
        await intel_db._conn.commit()

    def _row(row) -> dict:
        if row is None:
            return {}
        d = dict(row)
        d["created_at_iso"] = datetime.fromtimestamp(
            d.get("created_at") or 0, tz=UTC
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["updated_at_iso"] = datetime.fromtimestamp(
            d.get("updated_at") or 0, tz=UTC
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return d

    # ── GET /{finding_id} ────────────────────────────────────────────────────
    @router.get("/{finding_id}")
    async def get_case(finding_id: int):
        await _require_finding_context(finding_id)
        row = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        # Return empty object (not 404) — the UI polls this on any finding view
        # and should treat absence as "no case opened yet", not an error.
        return _row(row)

    # ── PUT /{finding_id} ────────────────────────────────────────────────────
    @router.put("/{finding_id}")
    async def upsert_case(finding_id: int, body: CaseUpsert):
        await _require_finding_context(finding_id)
        now = _now()
        existing = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        if existing:
            old = dict(existing)
            old_status = old["status"]
            await _write(
                """UPDATE finding_cases
                   SET status=?, assignee=?, priority=?, due_date=?, notes=?,
                       sla_due_at=?, updated_at=?
                   WHERE finding_id=?""",
                (body.status, body.assignee, body.priority, body.due_date,
                 body.notes, body.sla_due_at, now, finding_id),
            )
            changed_fields: dict[str, dict] = {}
            for field, new_value in {
                "status": body.status,
                "assignee": body.assignee,
                "priority": body.priority,
                "due_date": body.due_date,
                "notes": body.notes,
                "sla_due_at": body.sla_due_at,
            }.items():
                if old.get(field) != new_value:
                    changed_fields[field] = {"old": old.get(field), "new": new_value}
            if old_status != body.status:
                await _write(
                    """INSERT INTO finding_timeline
                       (finding_id, actor, action, from_status, to_status, created_at)
                       VALUES (?, ?, 'status change', ?, ?, ?)""",
                    (finding_id, body.actor, old_status, body.status, now),
                )
                await _log_case_activity(
                    finding_id,
                    "case_status_change",
                    body.actor,
                    old_status,
                    body.status,
                    "Case status changed",
                    changed_fields,
                )
            if old.get("assignee") != body.assignee:
                previous_assignee = old.get("assignee") or "unassigned"
                next_assignee = body.assignee or "unassigned"
                await _log_case_activity(
                    finding_id,
                    "case_assigned",
                    body.actor,
                    old.get("assignee") or "",
                    body.assignee or "",
                    f"{previous_assignee} -> {next_assignee}",
                    changed_fields,
                )
            other_fields = set(changed_fields) - {"status", "assignee"}
            if other_fields:
                await _log_case_activity(
                    finding_id,
                    "case_updated",
                    body.actor,
                    "",
                    "",
                    "Case fields updated: " + ", ".join(sorted(other_fields)),
                    {k: changed_fields[k] for k in sorted(other_fields)},
                )
        else:
            await _write(
                """INSERT INTO finding_cases
                   (finding_id, status, assignee, priority, due_date,
                    notes, sla_due_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, body.status, body.assignee, body.priority,
                 body.due_date, body.notes, body.sla_due_at, now, now),
            )
            await _write(
                """INSERT INTO finding_timeline
                   (finding_id, actor, action, to_status, created_at)
                   VALUES (?, ?, 'opened', ?, ?)""",
                (finding_id, body.actor, body.status, now),
            )
            await _log_case_activity(
                finding_id,
                "case_opened",
                body.actor,
                "",
                body.status,
                (body.notes or "Case opened")[:200],
                {
                    "status": {"old": "", "new": body.status},
                    "assignee": {"old": "", "new": body.assignee},
                    "priority": {"old": None, "new": body.priority},
                },
            )
        row = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        return _row(row)

    # ── GET /{finding_id}/timeline ───────────────────────────────────────────
    @router.get("/{finding_id}/timeline")
    async def get_timeline(finding_id: int):
        await _require_finding_context(finding_id)
        return {"timeline": await intel_db.get_finding_timeline(finding_id)}

    # ── POST /{finding_id}/notes ─────────────────────────────────────────────
    @router.post("/{finding_id}/notes", status_code=201)
    async def add_note(finding_id: int, body: NoteCreate):
        await _require_finding_context(finding_id)
        if not (body.note or "").strip():
            raise HTTPException(status_code=422, detail="Note cannot be empty")
        now = _now()
        await _write(
            """INSERT INTO finding_timeline
               (finding_id, actor, action, from_status, to_status, note, created_at)
               VALUES (?, ?, 'note', ?, ?, ?, ?)""",
            (finding_id, body.actor, body.from_status, body.to_status,
             body.note.strip(), now),
        )
        await _log_case_activity(
            finding_id,
            "case_note",
            body.actor,
            body.from_status or "",
            body.to_status or "",
            body.note.strip()[:200],
        )
        return {"ok": True, "elapsed": "just now"}

    return router
