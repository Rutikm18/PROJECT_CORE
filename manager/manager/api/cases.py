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
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


def _now() -> float:
    return time.time()


def _elapsed(ts: float) -> str:
    sec = int(time.time() - (ts or 0))
    if sec < 60:    return f"{sec}s ago"
    if sec < 3600:  return f"{sec // 60}m ago"
    if sec < 86400: return f"{sec // 3600}h ago"
    return f"{sec // 86400}d ago"


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
    from_status: Optional[str] = None
    to_status:   Optional[str] = None


def make_cases_router(intel_db) -> APIRouter:
    router = APIRouter()

    async def _write(sql: str, args: tuple) -> None:
        await intel_db._conn.execute(sql, args)
        await intel_db._conn.commit()

    def _row(row) -> dict:
        if row is None:
            return {}
        d = dict(row)
        d["created_at_iso"] = datetime.fromtimestamp(
            d.get("created_at") or 0, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["updated_at_iso"] = datetime.fromtimestamp(
            d.get("updated_at") or 0, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return d

    # ── GET /{finding_id} ────────────────────────────────────────────────────
    @router.get("/{finding_id}")
    async def get_case(finding_id: int):
        row = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        # Return empty object (not 404) — the UI polls this on any finding view
        # and should treat absence as "no case opened yet", not an error.
        return _row(row)

    # ── PUT /{finding_id} ────────────────────────────────────────────────────
    @router.put("/{finding_id}")
    async def upsert_case(finding_id: int, body: CaseUpsert):
        now = _now()
        existing = await intel_db._fetchone(
            "SELECT status FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        if existing:
            old_status = existing["status"]
            await _write(
                """UPDATE finding_cases
                   SET status=?, assignee=?, priority=?, due_date=?, notes=?,
                       sla_due_at=?, updated_at=?
                   WHERE finding_id=?""",
                (body.status, body.assignee, body.priority, body.due_date,
                 body.notes, body.sla_due_at, now, finding_id),
            )
            if old_status != body.status:
                await _write(
                    """INSERT INTO finding_timeline
                       (finding_id, actor, action, from_status, to_status, created_at)
                       VALUES (?, ?, 'status change', ?, ?, ?)""",
                    (finding_id, body.actor, old_status, body.status, now),
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
                   VALUES (?, 'system', 'opened', ?, ?)""",
                (finding_id, body.status, now),
            )
        row = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        return _row(row)

    # ── GET /{finding_id}/timeline ───────────────────────────────────────────
    @router.get("/{finding_id}/timeline")
    async def get_timeline(finding_id: int):
        rows = await intel_db._fetchall(
            """SELECT id, finding_id, actor, action, from_status, to_status, note, created_at
               FROM finding_timeline
               WHERE finding_id = ?
               ORDER BY id ASC""",
            (finding_id,),
        )
        return {
            "timeline": [
                {**dict(r), "elapsed": _elapsed(r["created_at"] or 0)}
                for r in rows
            ]
        }

    # ── POST /{finding_id}/notes ─────────────────────────────────────────────
    @router.post("/{finding_id}/notes", status_code=201)
    async def add_note(finding_id: int, body: NoteCreate):
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
        return {"ok": True, "elapsed": "just now"}

    return router
