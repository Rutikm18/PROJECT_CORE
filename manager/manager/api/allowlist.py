"""
manager/manager/api/allowlist.py — Allowlist management API.

Endpoints (mounted at /api/v1/allowlist):
  GET  /suggestions                     — list allowlist suggestions (pending/approved/rejected)
  POST /suggestions/{sid}/approve       — approve suggestion → create allowlist entry
  POST /suggestions/{sid}/reject        — reject suggestion
  GET  /entries                         — list active allowlist entries
  POST /entries                         — create allowlist entry manually
  DELETE /entries/{eid}                 — delete allowlist entry
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

log = logging.getLogger("manager.allowlist")


class AllowlistEntryIn(BaseModel):
    rule_id: str
    entity_key: str
    reason: str
    expires_at: Optional[float] = None
    created_by: str = "analyst"


class RejectIn(BaseModel):
    reviewed_by: str = "analyst"


class ApproveIn(BaseModel):
    reviewed_by: str = "analyst"


def make_allowlist_router(intel_db):
    router = APIRouter()

    @router.get("/suggestions")
    async def list_suggestions(
        status: str = Query(default="pending", description="pending | approved | rejected | all"),
    ):
        if status == "all":
            rows = []
            for s in ("pending", "approved", "rejected"):
                rows.extend(await intel_db.list_allowlist_suggestions(s))
        else:
            rows = await intel_db.list_allowlist_suggestions(status)
        return {"suggestions": rows, "count": len(rows)}

    @router.post("/suggestions/{sid}/approve")
    async def approve_suggestion(sid: int, body: ApproveIn = ApproveIn()):
        s = await intel_db.get_allowlist_suggestion(sid)
        if s is None:
            raise HTTPException(status_code=404, detail="suggestion not found")
        if s["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"suggestion already {s['status']}")

        await intel_db.upsert_allowlist_entry(
            rule_id=s["rule_id"],
            entity_key=s["entity_key"],
            reason=f"Auto-approved after {s['fp_count']} FPs",
            created_by=body.reviewed_by,
        )
        await intel_db.update_suggestion_status(sid, "approved", body.reviewed_by)
        log.info("Allowlist suggestion %d approved by %s (rule=%s entity=%s)",
                 sid, body.reviewed_by, s["rule_id"], s["entity_key"])
        return {"ok": True, "sid": sid}

    @router.post("/suggestions/{sid}/reject")
    async def reject_suggestion(sid: int, body: RejectIn = RejectIn()):
        s = await intel_db.get_allowlist_suggestion(sid)
        if s is None:
            raise HTTPException(status_code=404, detail="suggestion not found")
        if s["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"suggestion already {s['status']}")

        await intel_db.update_suggestion_status(sid, "rejected", body.reviewed_by)
        log.info("Allowlist suggestion %d rejected by %s", sid, body.reviewed_by)
        return {"ok": True, "sid": sid}

    @router.get("/entries")
    async def list_entries():
        entries = await intel_db.list_allowlist_entries()
        return {"entries": entries, "count": len(entries)}

    @router.post("/entries", status_code=201)
    async def create_entry(body: AllowlistEntryIn):
        await intel_db.upsert_allowlist_entry(
            rule_id=body.rule_id,
            entity_key=body.entity_key,
            reason=body.reason,
            created_by=body.created_by,
            expires_at=body.expires_at,
        )
        log.info("Allowlist entry created: rule=%s entity=%s by=%s",
                 body.rule_id, body.entity_key, body.created_by)
        return {"ok": True}

    @router.delete("/entries/{eid}", status_code=200)
    async def delete_entry(eid: int):
        await intel_db.execute(
            "DELETE FROM detection_allowlist WHERE id = ?", (eid,)
        )
        log.info("Allowlist entry %d deleted", eid)
        return {"ok": True, "eid": eid}

    return router
