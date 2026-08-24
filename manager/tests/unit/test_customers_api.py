"""
manager/tests/unit/test_customers_api.py — provisioning customer dashboards.

Two properties carry most of the weight here.

**Shown once.** The licence key and the invite link exist in exactly one HTTP
response and nowhere else — the database keeps only their SHA-256. If either
could be read back later, a database read would become a customer login or a
forged entitlement, and the whole point of hashing them would be lost.

**Operator-only.** A portal principal must not reach any of this. The audience
check refuses it before a handler runs.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager import licensing as L
from manager.manager.api import auth_ui, portal_auth
from manager.manager.api.authz import _PORTAL_COOKIE
from manager.manager.api.customers import make_customers_router
from manager.manager.indexer import IntelDB


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "customers-api-test")
    monkeypatch.setattr(auth_ui, "_JWT_SECRET", b"customers-api-test")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    portal_auth.reset_lockouts()
    yield


async def _db(dsn) -> IntelDB:
    idb = IntelDB(dsn)
    await idb.init()
    return idb


def _app(idb) -> FastAPI:
    app = FastAPI()
    app.include_router(make_customers_router(idb))
    return app


def _admin_client(app: FastAPI) -> AsyncClient:
    token, _jti, _exp = auth_ui._make_token("admin@attacklens.ai", "admin")
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://ops.test")
    client.cookies.set("al_session", token)
    return client


def _anon_client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://ops.test")


async def _create(client, slug="acme", **over):
    body = {"name": slug.title(), "slug": slug, "max_agents": 5}
    body.update(over)
    return await client.post("/api/v1/customers", json=body)


# ── Access control ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_provisioning_requires_authentication(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _anon_client(_app(idb))
        assert (await client.get("/api/v1/customers")).status_code == 401
        assert (await _create(client)).status_code == 401
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_portal_token_cannot_provision(pg_intel_dsn):
    """The customer must not be able to create customers."""
    idb = await _db(pg_intel_dsn)
    try:
        client = _anon_client(_app(idb))
        portal_token, _jti, _exp = auth_ui._make_token(
            "ops@acme.io", "portal_viewer", aud=auth_ui.AUD_PORTAL,
            extra={"user_id": "pu_1", "org_id": "org_1"},
        )
        client.cookies.set("al_session", portal_token)
        assert (await client.get("/api/v1/customers")).status_code == 403
        assert (await _create(client)).status_code == 403
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_non_admin_operator_cannot_provision(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _anon_client(_app(idb))
        viewer, _jti, _exp = auth_ui._make_token("viewer@attacklens.ai", "viewer")
        client.cookies.set("al_session", viewer)
        assert (await client.get("/api/v1/customers")).status_code == 403
    finally:
        await idb.close()


# ── Shown once ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_licence_key_is_returned_once_and_never_again(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        created = await _create(client)
        assert created.status_code == 201
        body = created.json()
        key = body["license_key"]
        assert key and "shown once" in body["notice"].lower()

        org_id = body["customer"]["org_id"]
        for path in ("/api/v1/customers", f"/api/v1/customers/{org_id}"):
            payload = json.dumps((await client.get(path)).json())
            assert key not in payload, f"{path} returned the licence key"
            assert "license_key_hash" not in payload
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_issued_licence_actually_verifies(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        body = (await _create(client, max_agents=42, valid_days=30)).json()
        ent = L.verify(body["license_key"])
        assert ent.org_slug == "acme"
        assert ent.max_agents == 42
        assert ent.days_remaining == 29
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_invite_link_is_returned_once_and_never_again(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client)).json()["customer"]["org_id"]
        created = await client.post(
            f"/api/v1/customers/{org_id}/users", json={"email": "ops@acme.io"},
        )
        assert created.status_code == 201
        invite = created.json()["invite_path"]
        assert "token=" in invite
        token = invite.split("token=")[1]

        listed = json.dumps((await client.get(f"/api/v1/customers/{org_id}/users")).json())
        assert token not in listed
        assert "password_hash" not in listed
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_resending_an_invite_kills_the_previous_link(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client)).json()["customer"]["org_id"]
        first = (await client.post(
            f"/api/v1/customers/{org_id}/users", json={"email": "ops@acme.io"},
        )).json()
        user_id = first["user"]["user_id"]
        second = (await client.post(
            f"/api/v1/customers/{org_id}/users/{user_id}/invite",
        )).json()
        assert second["invite_path"] != first["invite_path"]

        old = first["invite_path"].split("token=")[1]
        assert await idb.consume_invite(portal_auth.hash_invite_token(old), "h") is None
        new = second["invite_path"].split("token=")[1]
        assert await idb.consume_invite(portal_auth.hash_invite_token(new), "h") is not None
    finally:
        await idb.close()


# ── Lifecycle ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_duplicate_slug_is_refused(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        assert (await _create(client)).status_code == 201
        assert (await _create(client)).status_code == 409
    finally:
        await idb.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("slug", ["A", "ab", "-acme", "acme-", "ac me", "a" * 60])
async def test_invalid_slugs_are_refused(pg_intel_dsn, slug):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        assert (await _create(client, slug=slug)).status_code == 422
    finally:
        await idb.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("typed,stored", [
    ("Acme", "acme"), ("  ACME  ", "acme"), ("Acme-Corp", "acme-corp"),
])
async def test_mixed_case_slugs_are_normalised_not_rejected(pg_intel_dsn, typed, stored):
    """An operator typing a company name naturally should not hit a validation
    error — and the stored slug has to be canonical, since login and lookup
    both normalise."""
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        created = await _create(client, slug=typed)
        assert created.status_code == 201
        assert created.json()["customer"]["slug"] == stored
        assert L.verify(created.json()["license_key"]).org_slug == stored
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_agent_assignment_respects_the_seat_cap(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client, max_agents=2)).json()["customer"]["org_id"]

        ok = await client.post(
            f"/api/v1/customers/{org_id}/agents", json={"agent_ids": ["a", "b"]},
        )
        assert ok.status_code == 200
        over = await client.post(
            f"/api/v1/customers/{org_id}/agents", json={"agent_ids": ["c"]},
        )
        assert over.status_code == 409
        assert "allows 2 agents" in over.json()["detail"]
        assert (await client.get(
            f"/api/v1/customers/{org_id}/agents",
        )).json()["agent_ids"] == ["a", "b"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_agent_already_owned_is_refused_with_a_usable_message(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        a = (await _create(client, slug="acme")).json()["customer"]["org_id"]
        b = (await _create(client, slug="globex")).json()["customer"]["org_id"]
        await client.post(f"/api/v1/customers/{a}/agents", json={"agent_ids": ["shared"]})
        clash = await client.post(
            f"/api/v1/customers/{b}/agents", json={"agent_ids": ["shared"]},
        )
        assert clash.status_code == 409
        assert "already assigned" in clash.json()["detail"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_unassigning_frees_the_agent(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client)).json()["customer"]["org_id"]
        await client.post(f"/api/v1/customers/{org_id}/agents", json={"agent_ids": ["a"]})
        assert (await client.delete(
            f"/api/v1/customers/{org_id}/agents/a",
        )).json()["agent_ids"] == []
        assert (await client.delete(
            f"/api/v1/customers/{org_id}/agents/a",
        )).status_code == 404
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_suspend_says_what_it_actually_does(pg_intel_dsn):
    """The operator needs to know this ends live sessions, not just next login."""
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client)).json()["customer"]["org_id"]
        body = (await client.post(
            f"/api/v1/customers/{org_id}/status?status=suspended",
        )).json()
        assert body["customer"]["status"] == "suspended"
        assert "next request" in body["effect"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_rotating_the_licence_issues_a_new_verifiable_key(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        created = (await _create(client, max_agents=5)).json()
        org_id = created["customer"]["org_id"]

        rotated = (await client.post(
            f"/api/v1/customers/{org_id}/license/rotate",
            json={"max_agents": 99, "valid_days": 30},
        )).json()
        assert rotated["license_key"] != created["license_key"]
        assert L.verify(rotated["license_key"]).max_agents == 99
        assert (await client.get(f"/api/v1/customers/{org_id}"))\
            .json()["max_agents"] == 99
        # Honest about what rotation cannot do offline.
        assert "verifying offline" in rotated["notice"]
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_unknown_customer_is_404_everywhere(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        for path, verb in (
            ("/api/v1/customers/org_nope", "get"),
            ("/api/v1/customers/org_nope/agents", "get"),
            ("/api/v1/customers/org_nope/users", "get"),
            ("/api/v1/customers/org_nope/audit", "get"),
        ):
            assert (await getattr(client, verb)(path)).status_code == 404
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_duplicate_portal_email_is_refused(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        a = (await _create(client, slug="acme")).json()["customer"]["org_id"]
        b = (await _create(client, slug="globex")).json()["customer"]["org_id"]
        assert (await client.post(
            f"/api/v1/customers/{a}/users", json={"email": "dup@x.io"},
        )).status_code == 201
        assert (await client.post(
            f"/api/v1/customers/{b}/users", json={"email": "dup@x.io"},
        )).status_code == 409
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_provisioning_is_audited(pg_intel_dsn):
    idb = await _db(pg_intel_dsn)
    try:
        client = _admin_client(_app(idb))
        org_id = (await _create(client)).json()["customer"]["org_id"]
        await client.post(f"/api/v1/customers/{org_id}/agents", json={"agent_ids": ["a"]})
        await client.post(f"/api/v1/customers/{org_id}/status?status=suspended")

        actions = [
            e["action"]
            for e in (await client.get(f"/api/v1/customers/{org_id}/audit")).json()["entries"]
        ]
        assert "org.created" in actions
        assert "org.agents.assigned" in actions
        assert "org.access.suspended" in actions
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_missing_signing_key_is_reported_as_configuration(pg_intel_dsn, monkeypatch):
    """Not a 500 — the operator can fix this, so tell them what to fix."""
    idb = await _db(pg_intel_dsn)
    try:
        monkeypatch.delenv("LICENSE_SIGNING_KEY", raising=False)
        client = _admin_client(_app(idb))
        response = await _create(client)
        assert response.status_code == 503
        assert "LICENSE_SIGNING_KEY" in response.json()["detail"]
    finally:
        await idb.close()
