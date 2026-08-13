from __future__ import annotations

import asyncio
import time

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from manager.manager.api.cases import _actor_from_request
from manager.manager.api.cases import make_cases_router
from manager.manager.api.auth_ui import _make_token
from manager.manager.case_management import (
    CaseService,
    CaseVersionConflict,
    case_external_id,
    normalize_legacy_case,
)
from manager.manager.indexer import _SCHEMA
from manager.manager.indexer import IntelDB


def test_case_schema_supports_many_to_many_audit_and_outbox() -> None:
    for table in (
        "cases", "case_findings", "case_notes", "case_events", "case_tags",
        "case_outbox",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in _SCHEMA
    assert "PRIMARY KEY(case_id, finding_id)" in _SCHEMA
    assert "version" in _SCHEMA
    assert "idempotency_key" in _SCHEMA


def test_case_external_id_is_human_readable() -> None:
    assert case_external_id(42, 1_704_067_200) == "CASE-2024-000042"


def test_legacy_case_import_is_bounded_and_deduplicated() -> None:
    normalized = normalize_legacy_case({
        "id": "CASE-LOCAL",
        "title": "  Suspicious build chain  ",
        "description": "review",
        "priority": "critical",
        "status": "in_progress",
        "assignee": "alice@example.com",
        "tags": ["mesh", "mesh", "  supply-chain "],
        "findings": [3, 3, "4", -1, "bad"],
    })

    assert normalized["title"] == "Suspicious build chain"
    assert normalized["status"] == "in_progress"
    assert normalized["tags"] == ["mesh", "supply-chain"]
    assert normalized["finding_ids"] == [3, 4]
    assert normalized["idempotency_key"] == "legacy:CASE-LOCAL"


def test_case_actor_never_uses_body_actor() -> None:
    request = Request({"type": "http", "headers": [], "state": {}})

    assert _actor_from_request(request, body_actor="forged@example.com") == "system"


@pytest.mark.asyncio
async def test_case_create_commits_case_links_audit_and_outbox_together() -> None:
    class Cursor:
        def __init__(self, row=None) -> None:
            self.row = row

        async def fetchone(self):
            return self.row

    class Connection:
        def __init__(self) -> None:
            self.queries: list[str] = []
            self.commits = 0
            self.rollbacks = 0

        async def execute(self, query: str, _args: tuple = ()):
            self.queries.append(query)
            if "INSERT INTO cases" in query:
                return Cursor({"id": 7})
            return Cursor()

        async def commit(self) -> None:
            self.commits += 1

        async def rollback(self) -> None:
            self.rollbacks += 1

    class DB:
        def __init__(self) -> None:
            self._conn = Connection()
            self._lock = asyncio.Lock()

        async def _fetchone(self, _query: str, _args: tuple):
            return {
                "id": 7, "external_id": "CASE-2024-000007", "title": "Case",
                "tenant_id": "default", "version": 1,
            }

        async def _fetchall(self, query: str, _args: tuple):
            if "case_findings" in query:
                return [{"finding_id": 11}]
            if "case_tags" in query:
                return [{"tag": "mesh"}]
            return []

    db = DB()
    service = CaseService(db)

    result = await service.create_case(
        {
            "title": "Case", "status": "open", "priority": "high",
            "finding_ids": [11], "tags": ["mesh"],
        },
        actor="alice@example.com",
        idempotency_key="request-1",
    )

    combined = "\n".join(db._conn.queries)
    assert "INSERT INTO case_findings" in combined
    assert "INSERT INTO case_events" in combined
    assert "INSERT INTO case_outbox" in combined
    assert db._conn.commits == 1
    assert db._conn.rollbacks == 0
    assert result["findings"] == [11]
    assert result["tags"] == ["mesh"]


@pytest.mark.asyncio
async def test_case_update_rejects_stale_version() -> None:
    class Cursor:
        async def fetchone(self):
            return {"id": 9, "version": 2}

    class Connection:
        def __init__(self) -> None:
            self.rollbacks = 0

        async def execute(self, _query: str, _args: tuple = ()):
            return Cursor()

        async def rollback(self) -> None:
            self.rollbacks += 1

    db = type("DB", (), {"_conn": Connection(), "_lock": asyncio.Lock()})()

    with pytest.raises(CaseVersionConflict):
        await CaseService(db).update_case(
            9, {"status": "closed"}, actor="alice", expected_version=1,
        )

    assert db._conn.rollbacks == 1


@pytest.mark.asyncio
async def test_case_collection_route_does_not_fall_into_legacy_finding_route() -> None:
    class DB:
        async def _fetchall(self, _query: str, _args: tuple):
            return []

    app = FastAPI()
    app.include_router(make_cases_router(DB()), prefix="/api/v1/cases")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        response = await client.get("/api/v1/cases")

    assert response.status_code == 200
    assert response.json() == {"cases": [], "next_cursor": None, "has_more": False}


@pytest.mark.asyncio
async def test_case_routes_require_authentication_when_enabled() -> None:
    app = FastAPI()
    app.include_router(
        make_cases_router(object(), auth_required=True), prefix="/api/v1/cases",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as client:
        response = await client.get("/api/v1/cases")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_viewer_cannot_mutate_cases() -> None:
    token, _jti, _expires = _make_token("viewer@example.com", "viewer")
    app = FastAPI()
    app.include_router(
        make_cases_router(object(), auth_required=True), prefix="/api/v1/cases",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        response = await client.post("/api/v1/cases", json={"title": "Denied"})

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_case_timeline_is_tenant_scoped_and_cursor_paginated() -> None:
    class DB:
        async def _fetchone(self, query: str, args: tuple):
            assert "tenant_id=?" in query
            assert args == (7, "tenant-a")
            return {"id": 7}

        async def _fetchall(self, query: str, args: tuple):
            assert "case_id=?" in query
            assert args == (7, 0, 3)
            return [
                {"id": 1, "case_id": 7, "event_type": "case.created"},
                {"id": 2, "case_id": 7, "event_type": "case.note_added"},
                {"id": 3, "case_id": 7, "event_type": "case.updated"},
            ]

    result = await CaseService(DB(), tenant_id="tenant-a").list_timeline(
        7, cursor=0, limit=2,
    )

    assert [event["id"] for event in result["events"]] == [1, 2]
    assert result["next_cursor"] == 2
    assert result["has_more"] is True


@pytest.mark.asyncio
async def test_case_lifecycle_is_atomic_and_idempotent_in_postgres(pg_intel_dsn) -> None:
    idb = IntelDB(pg_intel_dsn)
    await idb.init()
    try:
        await idb.upsert_finding(
            {
                "agent_id": "case-agent",
                "category": "package",
                "item_key": "case-cve",
                "title": "Case CVE",
                "severity": "high",
            },
            time.time(),
        )
        finding = await idb._fetchone(
            "SELECT id FROM findings WHERE agent_id=? AND item_key=?",
            ("case-agent", "case-cve"),
        )
        service = CaseService(idb)
        payload = {
            "title": "Investigate case CVE",
            "description": "Correlate the package exposure.",
            "status": "open",
            "priority": "high",
            "finding_ids": [int(finding["id"])],
            "tags": ["mesh", "supply-chain"],
        }

        created = await service.create_case(
            payload,
            actor="analyst@example.com",
            idempotency_key="case-request-1",
            request_id="trace-1",
        )
        replayed = await service.create_case(
            payload,
            actor="analyst@example.com",
            idempotency_key="case-request-1",
            request_id="trace-1-retry",
        )
        updated = await service.update_case(
            created["id"],
            {"status": "in_progress", "owner_user_id": "owner@example.com"},
            actor="analyst@example.com",
            expected_version=created["version"],
            request_id="trace-2",
        )
        note = await service.add_note(
            created["id"],
            "Confirmed on the production asset.",
            actor="owner@example.com",
            request_id="trace-3",
        )

        assert replayed["id"] == created["id"]
        assert created["findings"] == [int(finding["id"])]
        assert created["tags"] == ["mesh", "supply-chain"]
        assert updated["status"] == "in_progress"
        assert updated["version"] == created["version"] + 1
        assert note["created_by"] == "owner@example.com"
        assert int((await idb._fetchone(
            "SELECT COUNT(*) AS n FROM cases WHERE idempotency_key=?",
            ("case-request-1",),
        ))["n"]) == 1
        assert int((await idb._fetchone(
            "SELECT COUNT(*) AS n FROM case_events WHERE case_id=?",
            (created["id"],),
        ))["n"]) == 3
        assert int((await idb._fetchone(
            "SELECT COUNT(*) AS n FROM case_outbox WHERE case_id=?",
            (created["id"],),
        ))["n"]) == 3
    finally:
        await idb.close()
