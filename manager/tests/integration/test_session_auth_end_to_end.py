"""
manager/tests/integration/test_session_auth_end_to_end.py

Reproduces the AWS "401 after login" against the REAL require_session /
require_admin dependencies (via TestClient), and proves the fix. The 401 is
decided in the auth dependency, before any route handler or DB call, so a
minimal app mounting a route behind the real dependency reproduces the exact
decision the manager makes for GET /api/v1/agents.

Facts pinned here:

  1. A bearer-only request is accepted (this is what the client apiFetch wrapper
     now sends, and why it is the primary fix — it works even against the old
     server, which fell back to the bearer whenever no cookie was present).
  2. A request with a STALE cookie AND a valid bearer is accepted. This is the
     case the server-side fix exists for: the old code verified the dead cookie
     and stopped, 401'ing a request that carried a perfectly valid bearer.
  3. No credential, or two bad credentials, are refused with 401.
  4. A customer/portal-audience token is refused from the operator API (403),
     never silently accepted.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

_SECRET = "dGVzdC1zZWNyZXQtMzJieXRlcy1sb25nLWVub3VnaC0xMjM0"   # base64, 32+ bytes
_STALE_COOKIE = "eyJhbGciOiJIUzI1NiJ9.c3RhbGU.deadbeefsignature"   # well-formed, wrong sig


@pytest.fixture()
def env():
    """Reload auth_ui with a fixed secret; hand back the real dependencies."""
    import os

    os.environ["JWT_SECRET"] = _SECRET
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)
    from manager.manager.api import authz

    app = FastAPI()

    @app.get("/agents", dependencies=[Depends(authz.require_session)])
    async def agents():
        return {"ok": True}

    @app.get("/customers", dependencies=[Depends(authz.require_admin)])
    async def customers():
        return {"ok": True}

    client = TestClient(app)
    try:
        yield auth_ui, client
    finally:
        importlib.reload(auth_ui)


def _manager_token(auth_ui, role: str = "admin") -> str:
    token, _jti, _exp = auth_ui._make_token("operator@example.com", role)
    return token


# ── The failure the user reported ────────────────────────────────────────────

def test_no_credential_is_401(env):
    _auth_ui, client = env
    assert client.get("/agents").status_code == 401


def test_bearer_only_is_accepted(env):
    """The primary fix: the client now sends this and the server honours it."""
    auth_ui, client = env
    token = _manager_token(auth_ui)
    r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text


def test_valid_cookie_only_is_accepted(env):
    auth_ui, client = env
    token = _manager_token(auth_ui)
    r = client.get("/agents", cookies={"al_session": token})
    assert r.status_code == 200, r.text


def test_stale_cookie_plus_valid_bearer_is_accepted(env):
    """The server-side fix: a dead cookie must not shadow a good bearer."""
    auth_ui, client = env
    token = _manager_token(auth_ui)
    r = client.get(
        "/agents",
        cookies={"al_session": _STALE_COOKIE},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text


def test_two_bad_credentials_are_401(env):
    _auth_ui, client = env
    r = client.get(
        "/agents",
        cookies={"al_session": _STALE_COOKIE},
        headers={"Authorization": "Bearer also.invalid.token"},
    )
    assert r.status_code == 401


# ── The admin route (Settings → Customers, the original symptom) ──────────────

def test_admin_route_accepts_bearer_with_stale_cookie(env):
    auth_ui, client = env
    token = _manager_token(auth_ui, role="admin")
    r = client.get(
        "/customers",
        cookies={"al_session": _STALE_COOKIE},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text


def test_admin_route_forbids_non_admin_role(env):
    """A valid session that is not admin/owner is 403, not 401 — distinct signal."""
    auth_ui, client = env
    token = _manager_token(auth_ui, role="viewer")
    r = client.get("/customers", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


# ── Audience isolation must survive the multi-token change ────────────────────

def test_portal_token_is_refused_from_operator_api(env):
    auth_ui, client = env
    token, _jti, _exp = auth_ui._make_token(
        "cust@example.com", "portal_viewer", aud=auth_ui.AUD_PORTAL,
        extra={"org_id": "org1", "user_id": "u1"},
    )
    r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403, r.text
