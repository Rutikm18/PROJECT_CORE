"""Transactional backend service for SOC cases."""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

_STATUSES = {"open", "in_progress", "resolved", "closed"}
_PRIORITIES = {"critical", "high", "medium", "low"}


def case_external_id(case_id: int, created_at: float) -> str:
    year = datetime.fromtimestamp(created_at, tz=UTC).year
    return f"CASE-{year}-{int(case_id):06d}"


def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def normalize_legacy_case(value: dict) -> dict:
    """Normalize one browser-local ``al_cases`` record for safe import."""
    status = _text(value.get("status"), 30)
    priority = _text(value.get("priority"), 30)
    tags: list[str] = []
    for raw in value.get("tags") or []:
        tag = _text(raw, 80)
        if tag and tag not in tags and len(tags) < 30:
            tags.append(tag)
    finding_ids: list[int] = []
    for raw in value.get("findings") or []:
        try:
            finding_id = int(raw)
        except (TypeError, ValueError):
            continue
        if finding_id > 0 and finding_id not in finding_ids and len(finding_ids) < 500:
            finding_ids.append(finding_id)
    legacy_id = _text(value.get("id"), 120)
    return {
        "title": _text(value.get("title"), 240),
        "description": _text(value.get("description"), 5000),
        "status": status if status in _STATUSES else "open",
        "priority": priority if priority in _PRIORITIES else "medium",
        "owner_user_id": _text(value.get("assignee"), 200),
        "tags": tags,
        "finding_ids": finding_ids,
        "idempotency_key": f"legacy:{legacy_id}" if legacy_id else "",
    }


def shape_case(row: dict, *, finding_ids=None, tags=None) -> dict:
    shaped = dict(row)
    shaped["findings"] = list(finding_ids or [])
    shaped["tags"] = list(tags or [])
    return shaped


class CaseNotFound(LookupError):
    pass


class CaseVersionConflict(RuntimeError):
    pass


class CaseService:
    """Owns transactional case writes and append-only audit/outbox events."""

    def __init__(self, intel_db, *, tenant_id: str = "default") -> None:
        self._db = intel_db
        self._tenant_id = tenant_id

    async def _conn_one(self, sql: str, args: tuple):
        cursor = await self._db._conn.execute(sql, args)
        return await cursor.fetchone()

    async def _event(
        self,
        case_id: int,
        event_type: str,
        actor: str,
        old_value: dict,
        new_value: dict,
        request_id: str,
        now: float,
    ) -> None:
        old_json = json.dumps(old_value, default=str, sort_keys=True)
        new_json = json.dumps(new_value, default=str, sort_keys=True)
        await self._db._conn.execute(
            "INSERT INTO case_events "
            "(case_id,event_type,actor_user_id,old_value_json,new_value_json,request_id,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (case_id, event_type, actor, old_json, new_json, request_id, now),
        )
        await self._db._conn.execute(
            "INSERT INTO case_outbox(case_id,event_type,payload_json,created_at) "
            "VALUES(?,?,?,?)",
            (case_id, event_type, new_json, now),
        )

    async def create_case(
        self,
        data: dict,
        *,
        actor: str,
        idempotency_key: str = "",
        request_id: str = "",
    ) -> dict:
        now = time.time()
        actor = _text(actor, 200) or "system"
        idempotency_key = _text(idempotency_key, 200)
        title = _text(data.get("title"), 240)
        if not title:
            raise ValueError("case title is required")
        status = _text(data.get("status"), 30)
        priority = _text(data.get("priority"), 30)
        if status not in _STATUSES:
            raise ValueError("invalid case status")
        if priority not in _PRIORITIES:
            raise ValueError("invalid case priority")

        async with self._db._lock:
            try:
                cursor = await self._db._conn.execute(
                    """INSERT INTO cases
                       (tenant_id,title,description,status,priority,owner_user_id,
                        due_at,created_by,created_at,updated_at,idempotency_key)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT (tenant_id,idempotency_key)
                       WHERE idempotency_key != '' DO NOTHING RETURNING id""",
                    (
                        self._tenant_id, title,
                        _text(data.get("description"), 5000), status, priority,
                        _text(data.get("owner_user_id"), 200),
                        float(data.get("due_at") or 0), actor, now, now,
                        idempotency_key,
                    ),
                )
                inserted = await cursor.fetchone()
                if inserted is None:
                    existing = await self._conn_one(
                        "SELECT id FROM cases WHERE tenant_id=? AND idempotency_key=?",
                        (self._tenant_id, idempotency_key),
                    )
                    if existing is None:
                        raise RuntimeError("idempotent case insert produced no record")
                    case_id = int(existing["id"])
                    await self._db._conn.commit()
                    return await self.get_case(case_id)

                case_id = int(inserted["id"])
                external_id = case_external_id(case_id, now)
                await self._db._conn.execute(
                    "UPDATE cases SET external_id=? WHERE id=?",
                    (external_id, case_id),
                )
                for finding_id in sorted(set(data.get("finding_ids") or []))[:500]:
                    await self._db._conn.execute(
                        """INSERT INTO case_findings
                           (case_id,finding_id,relation_type,added_by,added_at)
                           SELECT ?,id,'related',?,? FROM findings WHERE id=?
                           ON CONFLICT (case_id,finding_id) DO NOTHING""",
                        (case_id, actor, now, int(finding_id)),
                    )
                for tag in list(dict.fromkeys(data.get("tags") or []))[:30]:
                    cleaned = _text(tag, 80)
                    if cleaned:
                        await self._db._conn.execute(
                            "INSERT INTO case_tags(case_id,tag) VALUES(?,?) "
                            "ON CONFLICT (case_id,tag) DO NOTHING",
                            (case_id, cleaned),
                        )
                await self._event(
                    case_id, "case.created", actor, {},
                    {"external_id": external_id, "title": title}, request_id, now,
                )
                await self._db._conn.commit()
            except Exception:
                await self._db._conn.rollback()
                raise
        return await self.get_case(case_id)

    async def get_case(self, case_id: int) -> dict:
        row = await self._db._fetchone(
            "SELECT * FROM cases WHERE id=? AND tenant_id=?",
            (case_id, self._tenant_id),
        )
        if row is None:
            raise CaseNotFound(case_id)
        finding_rows = await self._db._fetchall(
            "SELECT finding_id FROM case_findings WHERE case_id=? ORDER BY finding_id",
            (case_id,),
        )
        tag_rows = await self._db._fetchall(
            "SELECT tag FROM case_tags WHERE case_id=? ORDER BY tag", (case_id,),
        )
        return shape_case(
            dict(row),
            finding_ids=[int(item["finding_id"]) for item in finding_rows],
            tags=[str(item["tag"]) for item in tag_rows],
        )

    async def list_cases(
        self,
        *,
        status: str = "",
        priority: str = "",
        owner_user_id: str = "",
        finding_id: int = 0,
        cursor: int = 0,
        limit: int = 50,
    ) -> dict:
        parts = ["tenant_id=?"]
        args: list[Any] = [self._tenant_id]
        if status:
            parts.append("status=?")
            args.append(status)
        if priority:
            if priority not in _PRIORITIES:
                raise ValueError("invalid case priority")
            parts.append("priority=?")
            args.append(priority)
        if owner_user_id:
            parts.append("owner_user_id=?")
            args.append(_text(owner_user_id, 200))
        if finding_id:
            parts.append(
                "EXISTS (SELECT 1 FROM case_findings cf "
                "WHERE cf.case_id=cases.id AND cf.finding_id=?)"
            )
            args.append(int(finding_id))
        if cursor:
            parts.append("id<?")
            args.append(cursor)
        args.append(limit + 1)
        rows = await self._db._fetchall(
            "SELECT * FROM cases WHERE " + " AND ".join(parts)
            + " ORDER BY id DESC LIMIT ?",
            tuple(args),
        )
        has_more = len(rows) > limit
        selected = rows[:limit]
        ids = [int(row["id"]) for row in selected]
        findings: dict[int, list[int]] = {case_id: [] for case_id in ids}
        tags: dict[int, list[str]] = {case_id: [] for case_id in ids}
        if ids:
            marks = ",".join("?" for _ in ids)
            for row in await self._db._fetchall(
                f"SELECT case_id,finding_id FROM case_findings WHERE case_id IN ({marks}) "
                "ORDER BY finding_id", tuple(ids),
            ):
                findings[int(row["case_id"])].append(int(row["finding_id"]))
            for row in await self._db._fetchall(
                f"SELECT case_id,tag FROM case_tags WHERE case_id IN ({marks}) ORDER BY tag",
                tuple(ids),
            ):
                tags[int(row["case_id"])].append(str(row["tag"]))
        cases = [
            shape_case(dict(row), finding_ids=findings[int(row["id"])], tags=tags[int(row["id"])])
            for row in selected
        ]
        return {
            "cases": cases,
            "next_cursor": ids[-1] if has_more and ids else None,
            "has_more": has_more,
        }

    async def metrics(self) -> dict:
        """Return tenant-scoped operational case metrics."""
        now = time.time()
        row = await self._db._fetchone(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status IN ('open','in_progress') THEN 1 ELSE 0 END) AS backlog, "
            "SUM(CASE WHEN status IN ('open','in_progress') AND due_at>0 AND due_at<? "
            "THEN 1 ELSE 0 END) AS sla_breached, "
            "SUM(CASE WHEN status IN ('open','in_progress') AND owner_user_id='' "
            "THEN 1 ELSE 0 END) AS unowned, "
            "AVG(CASE WHEN status IN ('open','in_progress') THEN ?-created_at END) "
            "AS average_open_age_seconds "
            "FROM cases WHERE tenant_id=?",
            (now, now, self._tenant_id),
        )
        values = dict(row or {})
        linked = await self._db._fetchone(
            "SELECT COUNT(DISTINCT cf.finding_id) AS linked_findings "
            "FROM case_findings cf JOIN cases c ON c.id=cf.case_id "
            "WHERE c.tenant_id=?",
            (self._tenant_id,),
        )
        return {
            "total": int(values.get("total") or 0),
            "backlog": int(values.get("backlog") or 0),
            "sla_breached": int(values.get("sla_breached") or 0),
            "unowned": int(values.get("unowned") or 0),
            "average_open_age_seconds": round(
                float(values.get("average_open_age_seconds") or 0.0), 3,
            ),
            "linked_findings": int(dict(linked or {}).get("linked_findings") or 0),
            "observed_at": now,
        }

    async def update_case(
        self,
        case_id: int,
        changes: dict,
        *,
        actor: str,
        expected_version: int,
        request_id: str = "",
    ) -> dict:
        now = time.time()
        async with self._db._lock:
            try:
                current_row = await self._conn_one(
                    "SELECT * FROM cases WHERE id=? AND tenant_id=?",
                    (case_id, self._tenant_id),
                )
                if current_row is None:
                    raise CaseNotFound(case_id)
                current = dict(current_row)
                if int(current["version"]) != int(expected_version):
                    raise CaseVersionConflict(
                        f"expected version {expected_version}, current version {current['version']}"
                    )
                next_values = {
                    "title": _text(changes.get("title", current["title"]), 240),
                    "description": _text(changes.get("description", current["description"]), 5000),
                    "status": _text(changes.get("status", current["status"]), 30),
                    "priority": _text(changes.get("priority", current["priority"]), 30),
                    "owner_user_id": _text(changes.get("owner_user_id", current["owner_user_id"]), 200),
                    "due_at": float(changes.get("due_at", current["due_at"]) or 0),
                }
                if next_values["status"] not in _STATUSES:
                    raise ValueError("invalid case status")
                if next_values["priority"] not in _PRIORITIES:
                    raise ValueError("invalid case priority")
                closed_at = now if next_values["status"] == "closed" else 0.0
                updated = await self._db._conn.execute(
                    """UPDATE cases SET title=?,description=?,status=?,priority=?,
                       owner_user_id=?,due_at=?,closed_at=?,updated_at=?,version=version+1
                       WHERE id=? AND tenant_id=? AND version=?""",
                    (
                        next_values["title"], next_values["description"],
                        next_values["status"], next_values["priority"],
                        next_values["owner_user_id"], next_values["due_at"],
                        closed_at, now, case_id, self._tenant_id, expected_version,
                    ),
                )
                if updated.rowcount != 1:
                    raise CaseVersionConflict(
                        "case changed concurrently; reload before retrying"
                    )
                if "tags" in changes:
                    await self._db._conn.execute(
                        "DELETE FROM case_tags WHERE case_id=?", (case_id,),
                    )
                    for tag in list(dict.fromkeys(changes.get("tags") or []))[:30]:
                        cleaned = _text(tag, 80)
                        if cleaned:
                            await self._db._conn.execute(
                                "INSERT INTO case_tags(case_id,tag) VALUES(?,?)",
                                (case_id, cleaned),
                            )
                await self._event(
                    case_id, "case.updated", _text(actor, 200) or "system",
                    {k: current.get(k) for k in next_values}, next_values,
                    request_id, now,
                )
                await self._db._conn.commit()
            except Exception:
                await self._db._conn.rollback()
                raise
        return await self.get_case(case_id)

    async def add_note(
        self, case_id: int, body: str, *, actor: str, request_id: str = "",
    ) -> dict:
        note = _text(body, 5000)
        if not note:
            raise ValueError("note cannot be empty")
        now = time.time()
        async with self._db._lock:
            try:
                exists = await self._conn_one(
                    "SELECT id FROM cases WHERE id=? AND tenant_id=?",
                    (case_id, self._tenant_id),
                )
                if exists is None:
                    raise CaseNotFound(case_id)
                cursor = await self._db._conn.execute(
                    "INSERT INTO case_notes(case_id,body,created_by,created_at) "
                    "VALUES(?,?,?,?) RETURNING id",
                    (case_id, note, actor, now),
                )
                row = await cursor.fetchone()
                await self._event(
                    case_id, "case.note_added", actor, {}, {"note_id": row["id"]},
                    request_id, now,
                )
                await self._db._conn.commit()
            except Exception:
                await self._db._conn.rollback()
                raise
        return {"id": int(row["id"]), "case_id": case_id, "body": note,
                "created_by": actor, "created_at": now}

    async def list_timeline(
        self,
        case_id: int,
        *,
        cursor: int = 0,
        limit: int = 100,
    ) -> dict:
        """Return an append-only, tenant-scoped case event page."""
        exists = await self._db._fetchone(
            "SELECT id FROM cases WHERE id=? AND tenant_id=?",
            (case_id, self._tenant_id),
        )
        if exists is None:
            raise CaseNotFound(case_id)
        bounded_limit = max(1, min(int(limit), 500))
        rows = await self._db._fetchall(
            "SELECT * FROM case_events WHERE case_id=? AND id>? "
            "ORDER BY id ASC LIMIT ?",
            (case_id, max(0, int(cursor)), bounded_limit + 1),
        )
        has_more = len(rows) > bounded_limit
        selected = [dict(row) for row in rows[:bounded_limit]]
        return {
            "events": selected,
            "next_cursor": int(selected[-1]["id"]) if has_more and selected else None,
            "has_more": has_more,
        }

    async def link_findings(
        self,
        case_id: int,
        finding_ids: list[int],
        *,
        actor: str,
        relation_type: str = "related",
        request_id: str = "",
    ) -> dict:
        ids = sorted({int(value) for value in finding_ids if int(value) > 0})[:500]
        if not ids:
            raise ValueError("at least one finding id is required")
        relation_type = _text(relation_type, 40) or "related"
        now = time.time()
        async with self._db._lock:
            try:
                exists = await self._conn_one(
                    "SELECT id FROM cases WHERE id=? AND tenant_id=?",
                    (case_id, self._tenant_id),
                )
                if exists is None:
                    raise CaseNotFound(case_id)
                for finding_id in ids:
                    await self._db._conn.execute(
                        """INSERT INTO case_findings
                           (case_id,finding_id,relation_type,added_by,added_at)
                           SELECT ?,id,?,?,? FROM findings WHERE id=?
                           ON CONFLICT (case_id,finding_id) DO NOTHING""",
                        (case_id, relation_type, actor, now, finding_id),
                    )
                await self._db._conn.execute(
                    "UPDATE cases SET updated_at=?,version=version+1 WHERE id=?",
                    (now, case_id),
                )
                await self._event(
                    case_id, "case.findings_linked", actor, {},
                    {"finding_ids": ids, "relation_type": relation_type},
                    request_id, now,
                )
                await self._db._conn.commit()
            except Exception:
                await self._db._conn.rollback()
                raise
        return await self.get_case(case_id)

    async def unlink_findings(
        self,
        case_id: int,
        finding_ids: list[int],
        *,
        actor: str,
        request_id: str = "",
    ) -> dict:
        ids = sorted({int(value) for value in finding_ids if int(value) > 0})[:500]
        if not ids:
            raise ValueError("at least one finding id is required")
        now = time.time()
        async with self._db._lock:
            try:
                exists = await self._conn_one(
                    "SELECT id FROM cases WHERE id=? AND tenant_id=?",
                    (case_id, self._tenant_id),
                )
                if exists is None:
                    raise CaseNotFound(case_id)
                marks = ",".join("?" for _ in ids)
                await self._db._conn.execute(
                    f"DELETE FROM case_findings WHERE case_id=? "
                    f"AND finding_id IN ({marks})",
                    (case_id, *ids),
                )
                await self._db._conn.execute(
                    "UPDATE cases SET updated_at=?,version=version+1 "
                    "WHERE id=? AND tenant_id=?",
                    (now, case_id, self._tenant_id),
                )
                await self._event(
                    case_id, "case.findings_unlinked", _text(actor, 200) or "system",
                    {"finding_ids": ids}, {}, request_id, now,
                )
                await self._db._conn.commit()
            except Exception:
                await self._db._conn.rollback()
                raise
        return await self.get_case(case_id)
