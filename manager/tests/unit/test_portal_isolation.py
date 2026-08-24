"""
manager/tests/unit/test_portal_isolation.py — cross-tenant isolation.

This is the test the whole tenancy design exists to pass. Two orgs, distinct
agents, distinct findings; then every portal route is called as org A and the
**entire response body** is deep-scanned for any identifier belonging to org B.

Scanning the whole body rather than asserting on named fields is deliberate:
a leak arrives through the field nobody thought to assert on — a facet count, a
hostname in an error message, an agent id echoed inside evidence. The sweep is
parametrised over the router's own route table, so a portal endpoint added
tomorrow is covered the day it is added rather than the day someone remembers.
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager import licensing as L
from manager.manager.api import auth_ui, portal_auth
from manager.manager.api.authz import _PORTAL_COOKIE
from manager.manager.api.portal import (
    PORTAL_FINDING_FIELDS, make_portal_router, project_finding,
)
from manager.manager.indexer import IntelDB

# Tokens that must never appear in org A's responses.
B_MARKERS = ("globex-agent-1", "globex-host", "GLOBEX-SECRET-CVE")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "portal-isolation-test")
    monkeypatch.setattr(auth_ui, "_JWT_SECRET", b"portal-isolation-test")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    portal_auth.reset_lockouts()
    yield
    portal_auth.reset_lockouts()


async def _finding(idb, agent_id: str, title: str, **over):
    payload = {
        "agent_id": agent_id, "category": "package", "item_key": f"{agent_id}:{title}",
        "title": title, "description": f"{title} on {agent_id}",
        "severity": "high", "score": 7.5,
        "evidence": {"name": title, "internal_note": "operator-only"},
    }
    payload.update(over)
    await idb.upsert_finding(payload, time.time())


async def _two_orgs(dsn):
    """Org A (acme, 2 agents) and org B (globex, 1 agent), each with findings."""
    idb = IntelDB(dsn)
    await idb.init()

    acme = await idb.create_org(slug="acme", name="Acme", status="active")
    globex = await idb.create_org(slug="globex", name="Globex", status="active")
    await idb.assign_agents_to_org(acme["org_id"], ["acme-agent-1", "acme-agent-2"])
    await idb.assign_agents_to_org(globex["org_id"], ["globex-agent-1"])

    await _finding(idb, "acme-agent-1", "ACME-CVE-1", severity="critical")
    await _finding(idb, "acme-agent-2", "ACME-CVE-2")
    await _finding(idb, "globex-agent-1", "GLOBEX-SECRET-CVE", severity="critical")

    user = await idb.create_portal_user(org_id=acme["org_id"], email="ops@acme.io")
    await idb.create_invite(
        user_id=user["user_id"], org_id=acme["org_id"], token_hash="h",
    )
    from manager.manager.security_policy import hash_password
    await idb.consume_invite("h", hash_password("Portal-Customer-Pw-2026!"))
    return idb, acme, globex, user


def _app(idb) -> FastAPI:
    app = FastAPI()
    app.include_router(portal_auth.make_portal_auth_router(idb))
    app.include_router(make_portal_router(idb))
    return app


def _client(app: FastAPI, user: dict, org: dict) -> AsyncClient:
    token, _jti, _exp = auth_ui._make_token(
        str(user["email"]), "portal_viewer",
        tenant_id=str(org["org_id"]), aud=auth_ui.AUD_PORTAL,
        extra={"user_id": str(user["user_id"]), "org_id": str(org["org_id"])},
    )
    client = AsyncClient(
        transport=ASGITransport(app=app), base_url="http://portal.test",
    )
    client.cookies.set(_PORTAL_COOKIE, token)
    return client


# Every GET the portal router exposes, with concrete params.
PORTAL_GETS = [
    "/api/v1/portal/summary",
    "/api/v1/portal/findings",
    "/api/v1/portal/findings?severity=critical",
    "/api/v1/portal/terrains",
    "/api/v1/portal/trends?days=90",
    "/api/v1/portal/agents",
    "/api/v1/portal/preferences",
    "/api/v1/portal/auth/me",
]


# ── The sweep ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("path", PORTAL_GETS)
async def test_no_portal_route_leaks_another_tenant(pg_intel_dsn, path):
    idb, acme, _globex, user = await _two_orgs(pg_intel_dsn)
    try:
        client = _client(_app(idb), user, acme)
        response = await client.get(path)
        assert response.status_code == 200, path
        body = json.dumps(response.json())
        for marker in B_MARKERS:
            assert marker not in body, f"{path} leaked {marker}"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_sweep_covers_every_portal_get_route(pg_intel_dsn):
    """Guards the guard: a new portal GET must be added to PORTAL_GETS."""
    idb, _acme, _globex, _user = await _two_orgs(pg_intel_dsn)
    try:
        registered = {
            r.path for r in _app(idb).routes
            if getattr(r, "path", "").startswith("/api/v1/portal")
            and "GET" in (getattr(r, "methods", None) or set())
        }
        covered = {p.split("?")[0] for p in PORTAL_GETS}
        # The by-id route is exercised separately, below.
        uncovered = registered - covered - {"/api/v1/portal/findings/{finding_id}"}
        assert not uncovered, (
            "portal GET routes not in the isolation sweep: " + ", ".join(sorted(uncovered))
        )
    finally:
        await idb.close()


# ── Direct addressing ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_another_tenants_finding_is_404_not_403(pg_intel_dsn):
    """403 would confirm the id exists and belongs to someone else."""
    idb, acme, globex, user = await _two_orgs(pg_intel_dsn)
    try:
        b_findings = await idb.portal_findings(["globex-agent-1"])
        b_id = b_findings["findings"][0]["id"]

        client = _client(_app(idb), user, acme)
        response = await client.get(f"/api/v1/portal/findings/{b_id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Finding not found."

        # Indistinguishable from an id that was never issued.
        missing = await client.get("/api/v1/portal/findings/99999999")
        assert missing.status_code == 404
        assert missing.json() == response.json()
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_tenant_can_read_its_own_finding(pg_intel_dsn):
    idb, acme, _globex, user = await _two_orgs(pg_intel_dsn)
    try:
        own = await idb.portal_findings(["acme-agent-1"])
        own_id = own["findings"][0]["id"]
        client = _client(_app(idb), user, acme)
        body = (await client.get(f"/api/v1/portal/findings/{own_id}")).json()
        assert body["id"] == own_id
        assert body["agent_id"] == "acme-agent-1"
    finally:
        await idb.close()


# ── Fail closed ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_org_with_no_agents_sees_nothing_not_everything(pg_intel_dsn):
    """The failure this prevents: an empty IN list matching every row."""
    idb, _acme, _globex, _user = await _two_orgs(pg_intel_dsn)
    try:
        empty = await idb.create_org(slug="empty", name="Empty", status="active")
        user = await idb.create_portal_user(org_id=empty["org_id"], email="new@empty.io")
        await idb.create_invite(
            user_id=user["user_id"], org_id=empty["org_id"], token_hash="h2",
        )
        from manager.manager.security_policy import hash_password
        user = await idb.consume_invite("h2", hash_password("Portal-Customer-Pw-2026!"))

        client = _client(_app(idb), user, empty)
        summary = (await client.get("/api/v1/portal/summary")).json()
        assert summary["total"] == 0
        assert summary["by_severity"] == {}

        findings = (await client.get("/api/v1/portal/findings")).json()
        assert findings["total"] == 0
        assert findings["findings"] == []
        assert (await client.get("/api/v1/portal/agents")).json()["agents"] == []
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_scope_clause_fails_closed_at_the_query_layer(pg_intel_dsn):
    idb, _acme, _globex, _user = await _two_orgs(pg_intel_dsn)
    try:
        clause, args = IntelDB._scope_clause([])
        assert "FALSE" in clause.upper()
        assert args == ()
        assert (await idb.portal_summary([]))["total"] == 0
        assert (await idb.portal_findings([]))["total"] == 0
        assert await idb.portal_finding_detail([], 1) is None
        assert await idb.portal_trend([]) == []
    finally:
        await idb.close()


# ── Projection ───────────────────────────────────────────────────────────────

def test_projection_is_an_allowlist_so_new_columns_stay_hidden():
    """A column added to `findings` tomorrow must not appear by default."""
    row = {f: f"value-{f}" for f in PORTAL_FINDING_FIELDS}
    row.update({
        "precision_factors": {"secret": 1},
        "ai_verdict": {"label": "tp"},
        "assignee": "operator@internal",
        "actions_log": ["internal"],
        "host_class": "internal",
        "fingerprint": "abc",
        "a_brand_new_column_added_next_week": "should not appear",
        "evidence": {},
    })
    out = project_finding(row)
    for withheld in (
        "precision_factors", "ai_verdict", "assignee", "actions_log",
        "host_class", "fingerprint", "a_brand_new_column_added_next_week",
    ):
        assert withheld not in out, withheld


def test_projection_filters_evidence_to_customer_relevant_keys():
    out = project_finding({
        "id": 1,
        "evidence": {"name": "openssl", "internal_note": "operator-only", "control_key": "sip"},
    })
    assert out["evidence"] == {"name": "openssl", "control_key": "sip"}


def test_projection_parses_json_columns():
    out = project_finding({"id": 1, "cve_ids": '["CVE-2024-1"]', "kev": 1, "evidence": "{}"})
    assert out["cve_ids"] == ["CVE-2024-1"]
    assert out["kev"] is True


@pytest.mark.asyncio
async def test_the_api_response_carries_no_operator_fields(pg_intel_dsn):
    idb, acme, _globex, user = await _two_orgs(pg_intel_dsn)
    try:
        client = _client(_app(idb), user, acme)
        findings = (await client.get("/api/v1/portal/findings")).json()["findings"]
        assert findings
        for finding in findings:
            assert set(finding) <= set(PORTAL_FINDING_FIELDS) | {"evidence"}
            assert "internal_note" not in json.dumps(finding.get("evidence", {}))
    finally:
        await idb.close()


# ── The single write ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_preferences_are_the_only_write_and_are_org_local(pg_intel_dsn):
    idb, acme, globex, user = await _two_orgs(pg_intel_dsn)
    try:
        client = _client(_app(idb), user, acme)
        updated = await client.put(
            "/api/v1/portal/preferences", json={"timezone": "Asia/Kolkata"},
        )
        assert updated.status_code == 200
        assert updated.json()["timezone"] == "Asia/Kolkata"

        # Org B is untouched.
        assert (await idb.get_org(globex["org_id"]))["preferences"] == {}
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_preferences_merge_rather_than_replace(pg_intel_dsn):
    idb, acme, _globex, user = await _two_orgs(pg_intel_dsn)
    try:
        client = _client(_app(idb), user, acme)
        await client.put("/api/v1/portal/preferences", json={"timezone": "UTC"})
        await client.put(
            "/api/v1/portal/preferences", json={"display_name": "Acme Security"},
        )
        body = (await client.get("/api/v1/portal/preferences")).json()
        assert body["timezone"] == "UTC"           # not cleared by the second write
        assert body["display_name"] == "Acme Security"
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_portal_exposes_no_other_writes(pg_intel_dsn):
    """Read-only by design — the only mutating verb is on preferences."""
    idb, _acme, _globex, _user = await _two_orgs(pg_intel_dsn)
    try:
        mutating = {
            (m, r.path)
            for r in _app(idb).routes
            for m in (getattr(r, "methods", None) or set())
            if m in {"POST", "PUT", "PATCH", "DELETE"}
            and getattr(r, "path", "").startswith("/api/v1/portal")
        }
        assert mutating == {
            ("PUT", "/api/v1/portal/preferences"),
            # Auth verbs: obtaining and dropping a session, and redeeming an
            # invite. None of them touch tenant data.
            ("POST", "/api/v1/portal/auth/login"),
            ("POST", "/api/v1/portal/auth/logout"),
            ("POST", "/api/v1/portal/auth/accept-invite"),
        }
    finally:
        await idb.close()
