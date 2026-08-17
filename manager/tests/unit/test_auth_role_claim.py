"""
manager/tests/unit/test_auth_role_claim.py — the JWT role claim must mean
something.

Two defects this pins:

  * login minted `_make_token(email, "admin")` — a string literal — so every
    session was an administrator and the claim carried no information at all.
  * GET /auth/me read `payload.get("role", "admin")`, defaulting an *absent*
    claim to full administrator. A token with no role — an older session, or
    one minted by a bug — was reported to the UI as an admin.

Both now resolve through KNOWN_ROLES and fall back to the least privilege.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _reload(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from manager.manager.api import auth_ui
    return importlib.reload(auth_ui)


@pytest.fixture(autouse=True)
def _restore_module():
    """Reloading the module under test must not leak into other test files."""
    yield
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)


# ── Role resolution ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("configured,expected", [
    ("admin", "admin"),
    ("analyst", "analyst"),
    ("viewer", "viewer"),
    ("owner", "owner"),
    ("  Admin  ", "admin"),      # trimmed and lowercased
])
def test_known_roles_are_honoured(monkeypatch, configured, expected):
    auth_ui = _reload(monkeypatch, DASHBOARD_ROLE=configured)
    assert auth_ui._configured_role() == expected


@pytest.mark.parametrize("configured", ["superuser", "root", "", "admin;drop", "Admin User"])
def test_an_unknown_role_falls_back_to_least_privilege(monkeypatch, configured):
    """A typo in DASHBOARD_ROLE must never mint an administrator."""
    auth_ui = _reload(monkeypatch, DASHBOARD_ROLE=configured)
    assert auth_ui._configured_role() == "viewer"


def test_the_default_is_still_admin(monkeypatch):
    """Unset means unchanged behaviour for existing single-operator installs."""
    monkeypatch.delenv("DASHBOARD_ROLE", raising=False)
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)
    assert auth_ui._configured_role() == "admin"


def test_the_configured_role_reaches_the_token(monkeypatch):
    auth_ui = _reload(
        monkeypatch, DASHBOARD_ROLE="analyst", JWT_SECRET="role-claim-test",
    )
    token, _jti, _exp = auth_ui._make_token("a@b.c", auth_ui._configured_role())
    assert auth_ui._verify_token(token)["role"] == "analyst"


# ── /auth/me fails closed ────────────────────────────────────────────────────

def _me_client(auth_ui) -> TestClient:
    app = FastAPI()
    app.include_router(auth_ui.router)
    return TestClient(app)


def test_me_reports_the_role_carried_by_the_token(monkeypatch):
    auth_ui = _reload(
        monkeypatch, DASHBOARD_ROLE="analyst", JWT_SECRET="role-claim-test",
    )
    token, _jti, _exp = auth_ui._make_token("jane.doe@corp.io", "analyst")
    client = _me_client(auth_ui)
    client.cookies.set("al_session", token)

    body = client.get("/api/v1/auth/me").json()
    assert body["role"] == "analyst"
    assert body["email"] == "jane.doe@corp.io"


def test_me_does_not_promote_a_roleless_token_to_admin(monkeypatch):
    """The regression: a missing claim used to default straight to admin."""
    auth_ui = _reload(monkeypatch, JWT_SECRET="role-claim-test")

    # Mint a token with no role claim at all, signed with the live secret.
    import hashlib, hmac, json, time
    payload = auth_ui._b64url(json.dumps({
        "sub": "ghost@corp.io", "jti": "x", "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }).encode())
    header = auth_ui._b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    sig = auth_ui._b64url(
        hmac.new(auth_ui._JWT_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    token = f"{header}.{payload}.{sig}"
    assert auth_ui._verify_token(token) is not None, "token must verify, only the role is absent"

    client = _me_client(auth_ui)
    client.cookies.set("al_session", token)
    assert client.get("/api/v1/auth/me").json()["role"] == "viewer"


def test_me_rejects_an_unrecognised_role_in_the_token(monkeypatch):
    """A forged-but-signed role must not be echoed back as authoritative."""
    auth_ui = _reload(monkeypatch, JWT_SECRET="role-claim-test")
    token, _jti, _exp = auth_ui._make_token("x@y.z", "superuser")

    client = _me_client(auth_ui)
    client.cookies.set("al_session", token)
    assert client.get("/api/v1/auth/me").json()["role"] == "viewer"


def test_me_401s_without_a_session(monkeypatch):
    auth_ui = _reload(monkeypatch, JWT_SECRET="role-claim-test")
    assert _me_client(auth_ui).get("/api/v1/auth/me").status_code == 401


# ── Display identity ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("email,name,initials", [
    ("jane.doe@corp.io", "Jane Doe", "JD"),
    ("admin@attacklens.ai", "Admin", "A"),
    ("first_last@x.com", "First Last", "FL"),
])
def test_display_identity_is_derived_not_hardcoded(monkeypatch, email, name, initials):
    """Every user was shown as "Admin" / "A" regardless of who signed in."""
    from manager.manager.api import auth_ui
    got = auth_ui._display_identity(email, "analyst")
    assert got == {"name": name, "initials": initials}


def test_display_identity_survives_a_junk_email(monkeypatch):
    from manager.manager.api import auth_ui
    assert auth_ui._display_identity("", "viewer") == {"name": "Viewer", "initials": "V"}
