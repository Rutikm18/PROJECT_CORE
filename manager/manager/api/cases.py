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

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..case_management import (
    CaseNotFound,
    CaseService,
    CaseVersionConflict,
    normalize_legacy_case,
)


def _now() -> float:
    return time.time()


def _actor_from_request(request: Request, body_actor: str = "") -> str:
    """Return the authenticated actor; request-body actor is never trusted."""
    user = getattr(request.state, "user", None)
    if isinstance(user, dict) and user.get("email"):
        return str(user["email"])[:200]
    token = request.cookies.get("al_session", "")
    bearer = request.headers.get("Authorization", "")
    if not token and bearer.startswith("Bearer "):
        token = bearer.removeprefix("Bearer ").strip()
    if token:
        try:
            from .auth_ui import _verify_token
            payload = _verify_token(token)
            if payload and payload.get("sub"):
                return str(payload["sub"])[:200]
        except Exception:
            pass
    return "system"


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


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=5000)
    status: str = Field(default="open", pattern="^(open|in_progress|resolved|closed)$")
    priority: str = Field(default="medium", pattern="^(critical|high|medium|low)$")
    owner_user_id: str = Field(default="", max_length=200)
    due_at: float = Field(default=0, ge=0)
    finding_ids: list[int] = Field(default_factory=list, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=30)


class CasePatch(BaseModel):
    version: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=5000)
    status: str | None = Field(default=None, pattern="^(open|in_progress|resolved|closed)$")
    priority: str | None = Field(default=None, pattern="^(critical|high|medium|low)$")
    owner_user_id: str | None = Field(default=None, max_length=200)
    due_at: float | None = Field(default=None, ge=0)
    tags: list[str] | None = Field(default=None, max_length=30)


class CaseNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class CaseFindingsLink(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=500)
    relation_type: str = Field(default="related", min_length=1, max_length=40)


class LegacyCaseImport(BaseModel):
    cases: list[dict] = Field(min_length=1, max_length=100)


def make_cases_router(intel_db, *, auth_required: bool = False) -> APIRouter:
    router = APIRouter()

    def _principal(request: Request, *, write: bool = False) -> dict:
        user = getattr(request.state, "user", None)
        payload = user if isinstance(user, dict) else None
        if payload is None:
            token = request.cookies.get("al_session", "")
            bearer = request.headers.get("Authorization", "")
            if not token and bearer.startswith("Bearer "):
                token = bearer.removeprefix("Bearer ").strip()
            if token:
                from .auth_ui import _verify_token
                payload = _verify_token(token)
        if payload is None:
            if auth_required:
                raise HTTPException(401, "Authentication required")
            payload = {"sub": "system", "role": "admin", "tenant_id": "default"}
        role = str(payload.get("role") or "viewer").lower()
        if role not in {"admin", "analyst", "viewer"}:
            raise HTTPException(403, "Unknown case-management role")
        if write and role not in {"admin", "analyst"}:
            raise HTTPException(403, "Case mutation requires analyst or admin role")
        return payload

    def _service(request: Request, *, write: bool = False) -> CaseService:
        principal = _principal(request, write=write)
        tenant_id = str(principal.get("tenant_id") or "default").strip()[:120]
        return CaseService(intel_db, tenant_id=tenant_id or "default")

    def _request_id(request: Request) -> str:
        return request.headers.get("X-Request-ID", "")[:200]

    @router.get("")
    async def list_cases(
        request: Request,
        status: str = Query("", pattern="^(|open|in_progress|resolved|closed)$"),
        priority: str = Query("", pattern="^(|critical|high|medium|low)$"),
        owner_user_id: str = Query("", max_length=200),
        finding_id: int = Query(0, ge=0),
        cursor: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=100),
    ):
        return await _service(request).list_cases(
            status=status, priority=priority, owner_user_id=owner_user_id,
            finding_id=finding_id, cursor=cursor, limit=limit,
        )

    @router.get("/metrics")
    async def case_metrics(request: Request):
        return await _service(request).metrics()

    @router.post("", status_code=201)
    async def create_case(
        body: CaseCreate,
        request: Request,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
    ):
        service = _service(request, write=True)
        try:
            return await service.create_case(
                body.model_dump(),
                actor=_actor_from_request(request),
                idempotency_key=idempotency_key,
                request_id=_request_id(request),
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/records/{case_id}")
    async def get_case_record(case_id: int, request: Request):
        try:
            return await _service(request).get_case(case_id)
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc

    @router.patch("/records/{case_id}")
    async def update_case_record(case_id: int, body: CasePatch, request: Request):
        service = _service(request, write=True)
        changes = body.model_dump(exclude={"version"}, exclude_none=True)
        try:
            return await service.update_case(
                case_id, changes,
                actor=_actor_from_request(request),
                expected_version=body.version,
                request_id=_request_id(request),
            )
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc
        except CaseVersionConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.post("/records/{case_id}/notes", status_code=201)
    async def add_case_note(case_id: int, body: CaseNoteCreate, request: Request):
        service = _service(request, write=True)
        try:
            return await service.add_note(
                case_id, body.body,
                actor=_actor_from_request(request),
                request_id=_request_id(request),
            )
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.post("/records/{case_id}/findings")
    async def link_case_findings(
        case_id: int,
        body: CaseFindingsLink,
        request: Request,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
    ):
        service = _service(request, write=True)
        try:
            return await service.link_findings(
                case_id, body.finding_ids,
                actor=_actor_from_request(request),
                relation_type=body.relation_type,
                request_id=idempotency_key or _request_id(request),
            )
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.delete("/records/{case_id}/findings")
    async def unlink_case_findings(
        case_id: int,
        body: CaseFindingsLink,
        request: Request,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
    ):
        try:
            return await _service(request, write=True).unlink_findings(
                case_id, body.finding_ids,
                actor=_actor_from_request(request),
                request_id=idempotency_key or _request_id(request),
            )
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/records/{case_id}/timeline")
    async def get_case_timeline(
        case_id: int,
        request: Request,
        cursor: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
    ):
        try:
            return await _service(request).list_timeline(
                case_id, cursor=cursor, limit=limit,
            )
        except CaseNotFound as exc:
            raise HTTPException(404, "Case not found") from exc

    @router.post("/import", status_code=201)
    async def import_legacy_cases(body: LegacyCaseImport, request: Request):
        service = _service(request, write=True)
        actor = _actor_from_request(request)
        imported: list[dict] = []
        for raw in body.cases:
            normalized = normalize_legacy_case(raw)
            if not normalized["title"]:
                continue
            case = await service.create_case(
                normalized,
                actor=actor,
                idempotency_key=normalized["idempotency_key"],
                request_id=_request_id(request),
            )
            imported.append({
                "legacy_id": str(raw.get("id") or ""),
                "case_id": case["id"],
                "external_id": case["external_id"],
            })
        return {"imported": imported, "count": len(imported)}

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
    async def get_case(finding_id: int, request: Request):
        _principal(request)
        await _require_finding_context(finding_id)
        row = await intel_db._fetchone(
            "SELECT * FROM finding_cases WHERE finding_id = ?", (finding_id,)
        )
        # Return empty object (not 404) — the UI polls this on any finding view
        # and should treat absence as "no case opened yet", not an error.
        return _row(row)

    # ── PUT /{finding_id} ────────────────────────────────────────────────────
    @router.put("/{finding_id}")
    async def upsert_case(finding_id: int, body: CaseUpsert, request: Request):
        _principal(request, write=True)
        await _require_finding_context(finding_id)
        actor = _actor_from_request(request, body.actor)
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
                    (finding_id, actor, old_status, body.status, now),
                )
                await _log_case_activity(
                    finding_id,
                    "case_status_change",
                    actor,
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
                    actor,
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
                    actor,
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
                (finding_id, actor, body.status, now),
            )
            await _log_case_activity(
                finding_id,
                "case_opened",
                actor,
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
    async def get_timeline(finding_id: int, request: Request):
        _principal(request)
        await _require_finding_context(finding_id)
        return {"timeline": await intel_db.get_finding_timeline(finding_id)}

    # ── POST /{finding_id}/notes ─────────────────────────────────────────────
    @router.post("/{finding_id}/notes", status_code=201)
    async def add_note(finding_id: int, body: NoteCreate, request: Request):
        _principal(request, write=True)
        await _require_finding_context(finding_id)
        actor = _actor_from_request(request, body.actor)
        if not (body.note or "").strip():
            raise HTTPException(status_code=422, detail="Note cannot be empty")
        now = _now()
        await _write(
            """INSERT INTO finding_timeline
               (finding_id, actor, action, from_status, to_status, note, created_at)
               VALUES (?, ?, 'note', ?, ?, ?, ?)""",
            (finding_id, actor, body.from_status, body.to_status,
             body.note.strip(), now),
        )
        await _log_case_activity(
            finding_id,
            "case_note",
            actor,
            body.from_status or "",
            body.to_status or "",
            body.note.strip()[:200],
        )
        return {"ok": True, "elapsed": "just now"}

    return router
