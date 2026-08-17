"""
tests/unit/test_ai_settings_authz.py — Authorization on the AI provider API.

Before this, /api/v1/ai/* was registered with no auth dependency at all, so
anyone who could reach the manager could read the provider config, replace the
stored API key, or delete it. These tests pin the guard in place.
"""
from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from manager.manager.api.authz import require_admin, require_session


ADMIN_TOKEN = "sk-admin-test-value"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", ADMIN_TOKEN)

    app = FastAPI()

    @app.post("/admin-only")
    async def admin_only(actor: dict = Depends(require_admin)):
        return actor

    @app.get("/any-session")
    async def any_session(actor: dict = Depends(require_session)):
        return actor

    return TestClient(app)


def _session_cookie(role: str = "admin") -> str:
    from manager.manager.api import auth_ui
    token, _jti, _exp = auth_ui._make_token("analyst@example.com", role)
    return token


# ── Anonymous access ──────────────────────────────────────────────────────────

def test_anonymous_cannot_reach_admin_route(client):
    resp = client.post("/admin-only")
    assert resp.status_code == 401


def test_anonymous_cannot_reach_session_route(client):
    resp = client.get("/any-session")
    assert resp.status_code == 401


def test_wrong_admin_token_is_rejected(client):
    resp = client.post("/admin-only", headers={"X-Admin-Token": "sk-admin-wrong"})
    assert resp.status_code == 401


def test_empty_admin_token_header_is_rejected(client):
    resp = client.post("/admin-only", headers={"X-Admin-Token": ""})
    assert resp.status_code == 401


def test_unset_admin_token_does_not_authenticate_empty_header(monkeypatch):
    """An unset ADMIN_TOKEN must disable the header path, not match ''."""
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    app = FastAPI()

    @app.post("/admin-only")
    async def admin_only(actor: dict = Depends(require_admin)):
        return actor

    resp = TestClient(app).post("/admin-only", headers={"X-Admin-Token": ""})
    assert resp.status_code == 401


# ── Admin token path ──────────────────────────────────────────────────────────

def test_valid_admin_token_is_accepted(client):
    resp = client.post("/admin-only", headers={"X-Admin-Token": ADMIN_TOKEN})
    assert resp.status_code == 200
    assert resp.json()["via"] == "x-admin-token"


def test_admin_token_also_satisfies_session_routes(client):
    resp = client.get("/any-session", headers={"X-Admin-Token": ADMIN_TOKEN})
    assert resp.status_code == 200


# ── Session path ──────────────────────────────────────────────────────────────

def test_admin_session_cookie_is_accepted(client):
    client.cookies.set("al_session", _session_cookie("admin"))
    resp = client.post("/admin-only")
    assert resp.status_code == 200
    assert resp.json()["via"] == "session"
    assert resp.json()["principal"] == "analyst@example.com"


def test_bearer_token_is_accepted(client):
    resp = client.post(
        "/admin-only",
        headers={"Authorization": f"Bearer {_session_cookie('admin')}"},
    )
    assert resp.status_code == 200


def test_non_admin_session_gets_403_not_401(client):
    """403 distinguishes 'your account cannot' from 'you are not signed in'."""
    client.cookies.set("al_session", _session_cookie("viewer"))
    resp = client.post("/admin-only")
    assert resp.status_code == 403


def test_non_admin_session_can_still_read(client):
    client.cookies.set("al_session", _session_cookie("viewer"))
    resp = client.get("/any-session")
    assert resp.status_code == 200


def test_tampered_session_is_rejected(client):
    token = _session_cookie("admin")
    client.cookies.set("al_session", token[:-4] + "AAAA")
    resp = client.post("/admin-only")
    assert resp.status_code == 401


# ── Route coverage ────────────────────────────────────────────────────────────

def test_every_ai_route_declares_a_guard():
    """No /api/v1/ai/* route may ship without an auth dependency."""
    import re
    from pathlib import Path

    src = Path("manager/manager/api/ai_settings.py").read_text()
    blocks = re.split(r"\n(?=@router\.)", src)

    unguarded = []
    for block in blocks:
        match = re.match(r'@router\.(\w+)\("([^"]+)"\)', block)
        if not match:
            continue
        signature = block.split(") -> dict:")[0]
        if "require_admin" not in signature and "require_session" not in signature:
            unguarded.append(f"{match.group(1).upper()} {match.group(2)}")

    assert unguarded == [], f"routes without an auth guard: {unguarded}"


def test_config_mutations_require_admin_not_just_a_session():
    """Writing or deleting the provider key must not be reachable by a viewer."""
    import re
    from pathlib import Path

    src = Path("manager/manager/api/ai_settings.py").read_text()
    blocks = re.split(r"\n(?=@router\.)", src)

    must_be_admin = {
        ("POST", "/provider"),
        ("DELETE", "/provider"),
        ("POST", "/test"),
        ("POST", "/task-models"),
        ("DELETE", "/task-models/{task}"),
    }
    seen = set()
    for block in blocks:
        match = re.match(r'@router\.(\w+)\("([^"]+)"\)', block)
        if not match:
            continue
        key = (match.group(1).upper(), match.group(2))
        if key in must_be_admin:
            assert "require_admin" in block.split(") -> dict:")[0], f"{key} is not admin-guarded"
            seen.add(key)

    assert seen == must_be_admin, f"missing routes: {must_be_admin - seen}"
