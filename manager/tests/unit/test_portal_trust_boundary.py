"""
manager/tests/unit/test_portal_trust_boundary.py — the customer principal.

The portal is a separate product surface, not a filtered view of the operator
dashboard. What makes that true is the `aud` claim: a portal token presented to
an operator route is refused, and an operator token is refused by the portal.
Without it, two login pages issue interchangeable sessions and the separation
is cosmetic.

The other half is that org and user state is re-read on every request rather
than trusted from the token, so "disable access" ends a live session instead of
merely preventing the next login.
"""
from __future__ import annotations

import time

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from manager.manager import licensing as L
from manager.manager.api import auth_ui, portal_auth
from manager.manager.api.authz import (
    PortalScope, _PORTAL_COOKIE, make_require_portal_user, require_session,
)
from manager.manager.indexer import IntelDB
from manager.manager.security_policy import hash_password

GOOD_PASSWORD = "Portal-Customer-Pw-2026!"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "portal-boundary-test")
    monkeypatch.setattr(auth_ui, "_JWT_SECRET", b"portal-boundary-test")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", L.generate_signing_key())
    portal_auth.reset_lockouts()
    yield
    portal_auth.reset_lockouts()


async def _seeded(dsn) -> tuple[IntelDB, dict, dict]:
    """An active org with one active portal user owning two agents."""
    idb = IntelDB(dsn)
    await idb.init()
    key, ent = L.issue(org_id="pending", org_slug="acme", max_agents=10)
    org = await idb.create_org(
        slug="acme", name="Acme", license_key_hash=L.key_fingerprint(key),
        entitlements=ent.to_dict(), status="active",
    )
    user = await idb.create_portal_user(org_id=org["org_id"], email="ops@acme.io")
    await idb.create_invite(
        user_id=user["user_id"], org_id=org["org_id"], token_hash="tok-hash",
    )
    user = await idb.consume_invite("tok-hash", hash_password(GOOD_PASSWORD))
    await idb.assign_agents_to_org(org["org_id"], ["mac-1", "mac-2"])
    return idb, org, user


def _app(idb) -> FastAPI:
    """Operator route and portal route side by side, on one app."""
    app = FastAPI()
    app.include_router(portal_auth.make_portal_auth_router(idb))
    require_portal_user = make_require_portal_user(idb)

    @app.get("/operator-only", dependencies=[Depends(require_session)])
    async def operator_only():
        return {"ok": True}

    @app.get("/portal-only")
    async def portal_only(scope: PortalScope = Depends(require_portal_user)):
        return {"org": scope.org_id, "agents": list(scope.agent_ids)}

    return app


def _client(app: FastAPI) -> AsyncClient:
    """In-loop ASGI client.

    Not TestClient: it drives the app from its own event loop in a worker
    thread, so the asyncpg connection created in this test's loop would be used
    concurrently from two loops ("another operation is in progress"). An
    ASGITransport client stays in one loop.
    """
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://portal.test")


async def _login(client: AsyncClient, email="ops@acme.io", password=GOOD_PASSWORD):
    return await client.post(
        "/api/v1/portal/auth/login", json={"email": email, "password": password},
    )


# ── The audience boundary ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_portal_token_cannot_reach_an_operator_route(pg_intel_dsn):
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        login = await _login(client)
        assert login.status_code == 200
        assert (await client.get("/portal-only")).status_code == 200

        # Two independent defences, and both are worth pinning.
        #
        # 1. Cookie isolation. Login set `al_portal_session`; `require_session`
        #    reads `al_session`, so the operator route never even sees the
        #    portal credential and reports an anonymous caller.
        assert (await client.get("/operator-only")).status_code == 401

        # 2. The audience check, for when the token *is* presented — copied
        #    into the operator cookie, or sent as a bearer. Here the caller is
        #    authenticated but is not an operator, so 403 rather than 401: a
        #    401 would send the portal SPA into a re-login loop against a
        #    credential that was never going to work.
        portal_token = login.json()["token"]
        assert (await client.get(
            "/operator-only", headers={"Authorization": f"Bearer {portal_token}"},
        )).status_code == 403

        client.cookies.set("al_session", portal_token)
        assert (await client.get("/operator-only")).status_code == 403
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_operator_token_cannot_reach_a_portal_route(pg_intel_dsn):
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        operator, _jti, _exp = auth_ui._make_token("admin@attacklens.ai", "admin")
        client.cookies.set(_PORTAL_COOKIE, operator)
        assert (await client.get("/portal-only")).status_code == 403
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_a_token_with_no_audience_is_treated_as_operator(pg_intel_dsn):
    """Backward compatibility: every token issued before `aud` existed was an
    operator session. The permissive direction must never mint a customer."""
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        assert auth_ui.token_audience({"sub": "x"}) == auth_ui.AUD_MANAGER
        client = _client(_app(idb))
        legacy, _jti, _exp = auth_ui._make_token("admin@attacklens.ai", "admin")
        client.cookies.set("al_session", legacy)
        assert (await client.get("/operator-only")).status_code == 200
        client.cookies.set(_PORTAL_COOKIE, legacy)
        assert (await client.get("/portal-only")).status_code == 403
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_extra_claims_cannot_override_the_audience(pg_intel_dsn):
    """A caller must not be able to smuggle aud=manager into a portal token."""
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        token, _jti, _exp = auth_ui._make_token(
            "x@y.z", "portal_viewer", aud=auth_ui.AUD_PORTAL,
            extra={"aud": auth_ui.AUD_MANAGER, "sub": "admin@attacklens.ai"},
        )
        payload = auth_ui._verify_token(token)
        assert payload["aud"] == auth_ui.AUD_PORTAL
        assert payload["sub"] == "x@y.z"
    finally:
        await idb.close()


# ── Live state, not token state ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_suspending_an_org_ends_a_live_session(pg_intel_dsn):
    """The whole point of re-reading per request: "disable access" is immediate."""
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        assert (await _login(client)).status_code == 200
        assert (await client.get("/portal-only")).status_code == 200

        await idb.set_org_status(org["org_id"], "suspended")
        assert (await client.get("/portal-only")).status_code == 403
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_disabling_a_user_ends_a_live_session(pg_intel_dsn):
    idb, _org, user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        assert (await _login(client)).status_code == 200
        await idb.set_portal_user_status(user["user_id"], "disabled")
        assert (await client.get("/portal-only")).status_code == 401
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_the_scope_carries_only_the_orgs_agents(pg_intel_dsn):
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        other = await idb.create_org(slug="globex", name="Globex", status="active")
        await idb.assign_agents_to_org(other["org_id"], ["globex-1"])

        client = _client(_app(idb))
        await _login(client)
        body = (await client.get("/portal-only")).json()
        assert body["org"] == org["org_id"]
        assert body["agents"] == ["mac-1", "mac-2"]
        assert "globex-1" not in body["agents"]
    finally:
        await idb.close()


# ── Login behaviour ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_every_failure_mode_returns_the_same_answer(pg_intel_dsn):
    """Unknown email, wrong password and suspended org must be indistinguishable,
    or the login form becomes a customer directory."""
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        unknown = await _login(client, email="nobody@nowhere.io")
        portal_auth.reset_lockouts()
        wrong = await _login(client, password="Wrong-Password-Here-1!")
        portal_auth.reset_lockouts()
        await idb.set_org_status(org["org_id"], "suspended")
        suspended = await _login(client)

        for response in (unknown, wrong, suspended):
            assert response.status_code == 401
            assert response.json() == {"error": "Invalid email or password."}
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_invited_user_cannot_log_in_before_activating(pg_intel_dsn):
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        await idb.create_portal_user(org_id=org["org_id"], email="new@acme.io")
        client = _client(_app(idb))
        assert (await _login(client, email="new@acme.io", password=GOOD_PASSWORD)).status_code == 401
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_portal_lockout_does_not_touch_the_operator_account(pg_intel_dsn):
    """Shared counters would make the portal a DoS against the operators."""
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        for _ in range(6):
            await _login(client, password="Wrong-Password-Here-1!")
        # Portal is locked out, and a *correct* password is still refused.
        assert (await _login(client)).status_code == 429

        # The operator login keeps its own counters, in its own module-level
        # state. Shared buckets would let anyone holding a customer's email
        # lock out the people who run the platform.
        assert portal_auth._ip_failures is not auth_ui._ip_fail_log
        assert auth_ui._ip_fail_log == {}
        assert auth_ui._acct_fail_log == {}
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_me_reports_org_and_read_only_capabilities(pg_intel_dsn):
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        await _login(client)
        body = (await client.get("/api/v1/portal/auth/me")).json()
        assert body["org"]["org_id"] == org["org_id"]
        assert body["agent_count"] == 2
        caps = body["capabilities"]
        assert caps["view_findings"] is True
        # Raw telemetry is the customer's OWN endpoint data, and both db.py and
        # raw.py scope it per tenant, so Deep Analysis works in the portal.
        assert caps["view_raw_telemetry"] is True
        # Read-only by design — anything that changes infrastructure or crosses
        # a tenant is withheld, and listed rather than omitted so the boundary
        # is legible from the response itself.
        for withheld in (
            "manage_agents", "manage_users", "manage_license",
            "update_finding", "manage_platform_settings",
        ):
            assert caps[withheld] is False, withheld
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_logout_clears_the_portal_session(pg_intel_dsn):
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        await _login(client)
        assert (await client.get("/portal-only")).status_code == 200
        await client.post("/api/v1/portal/auth/logout")
        assert (await client.get("/portal-only")).status_code == 401
    finally:
        await idb.close()


# ── Invite redemption ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_accept_invite_sets_the_password_once(pg_intel_dsn):
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        new = await idb.create_portal_user(org_id=org["org_id"], email="new@acme.io")
        token = "setup-token-abcdefghijklmnop"
        await idb.create_invite(
            user_id=new["user_id"], org_id=org["org_id"],
            token_hash=portal_auth.hash_invite_token(token),
        )
        client = _client(_app(idb))
        first = await client.post(
            "/api/v1/portal/auth/accept-invite",
            json={"token": token, "password": GOOD_PASSWORD},
        )
        assert first.status_code == 200
        assert (await _login(client, email="new@acme.io")).status_code == 200

        replay = await client.post(
            "/api/v1/portal/auth/accept-invite",
            json={"token": token, "password": "Another-Password-99!"},
        )
        assert replay.status_code == 400
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_accept_invite_enforces_the_password_policy(pg_intel_dsn):
    idb, org, _user = await _seeded(pg_intel_dsn)
    try:
        new = await idb.create_portal_user(org_id=org["org_id"], email="weak@acme.io")
        token = "setup-token-abcdefghijklmnop"
        await idb.create_invite(
            user_id=new["user_id"], org_id=org["org_id"],
            token_hash=portal_auth.hash_invite_token(token),
        )
        client = _client(_app(idb))
        assert (await client.post(
            "/api/v1/portal/auth/accept-invite",
            json={"token": token, "password": "short"},
        )).status_code == 422
        # The invite survives a rejected password so the customer can retry.
        assert (await client.post(
            "/api/v1/portal/auth/accept-invite",
            json={"token": token, "password": GOOD_PASSWORD},
        )).status_code == 200
    finally:
        await idb.close()


@pytest.mark.asyncio
async def test_an_unknown_invite_token_gives_nothing_away(pg_intel_dsn):
    idb, _org, _user = await _seeded(pg_intel_dsn)
    try:
        client = _client(_app(idb))
        response = await client.post(
            "/api/v1/portal/auth/accept-invite",
            json={"token": "never-issued-token-xxxx", "password": GOOD_PASSWORD},
        )
        assert response.status_code == 400
        assert "already been used" in response.json()["detail"]
    finally:
        await idb.close()
