"""
manager/tests/unit/test_default_credential_exposure.py — the built-in default
dashboard password is disabled entirely.

For client deployments the first-run convenience was removed: the hardcoded
default credential is NEVER surfaced on the login screen and NEVER authenticates.
An operator must configure DASHBOARD_PASSWORD_HASH (or a custom DASHBOARD_PASSWORD)
before anyone can sign in; until then login is refused with a clear message.

What must stay true:
  * GET /api/v1/auth/policy never returns the default credential, on any address
  * the whole policy payload is free of the default password
  * the default password does not authenticate when no password is configured
  * login is refused with an actionable error until a password is configured
  * a configured password authenticates normally
  * the login screen still gets its password rules (login must remain possible)
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from manager.manager.security_policy import hash_password

PUBLIC_ENV_KEYS = ("DOMAIN", "PUBLIC_IP", "DASHBOARD_PASSWORD_HASH", "DASHBOARD_PASSWORD")


def _reload(monkeypatch, **env):
    # Clear every input first, so a variable leaking in from the developer's own
    # shell cannot make a failing case look like it passes.
    for key in PUBLIC_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from manager.manager.api import auth_ui
    return importlib.reload(auth_ui)


def _client(module) -> TestClient:
    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app)


def _policy(module) -> dict:
    return _client(module).get("/api/v1/auth/policy").json()


@pytest.fixture(autouse=True)
def _restore_module():
    """Reloading the module under test must not leak into other test files."""
    yield
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)


# ── The default is never exposed, on any address ─────────────────────────────

@pytest.mark.parametrize("env", [
    {},                                   # laptop first-run — used to surface it
    {"DOMAIN": "attacklens.example.com"},
    {"PUBLIC_IP": "203.0.113.10"},
])
def test_policy_never_returns_the_default_credential(monkeypatch, env):
    creds = _policy(_reload(monkeypatch, **env))["default_credentials"]
    assert creds["active"] is False
    assert creds["password"] is None
    assert creds["email"] is None


def test_no_response_field_leaks_the_default_password(monkeypatch):
    import json
    module = _reload(monkeypatch)                       # even on a bare laptop
    body = json.dumps(_policy(module))
    assert module._DEFAULT_PASSWORD not in body


# ── The default does not authenticate ────────────────────────────────────────

def test_unconfigured_default_password_does_not_authenticate(monkeypatch):
    module = _reload(monkeypatch)                       # no hash, no custom pw
    assert module._PASSWORD_CONFIGURED is False
    assert module.verify_password(module._DEFAULT_PASSWORD, module._stored_hash) is False


def test_login_is_refused_until_a_password_is_configured(monkeypatch):
    module = _reload(monkeypatch)
    r = _client(module).post(
        "/api/v1/auth/login",
        json={"email": module._ADMIN_EMAIL, "password": module._DEFAULT_PASSWORD},
    )
    assert r.status_code == 503
    assert "not configured" in r.json()["error"].lower()


# ── A configured password works ──────────────────────────────────────────────

def test_configured_hash_authenticates(monkeypatch):
    module = _reload(monkeypatch, DASHBOARD_PASSWORD_HASH=hash_password("Str0ng!Passw0rd#2026"))
    assert module._PASSWORD_CONFIGURED is True
    assert module.verify_password("Str0ng!Passw0rd#2026", module._stored_hash) is True


def test_custom_plaintext_marks_password_configured(monkeypatch):
    module = _reload(monkeypatch, DASHBOARD_PASSWORD="Str0ng!Passw0rd#2026")
    assert module._PASSWORD_CONFIGURED is True
    assert module.verify_password("Str0ng!Passw0rd#2026", module._stored_hash) is True


# ── The login screen still gets its rules (login must remain possible) ────────

def test_login_screen_still_gets_its_password_rules(monkeypatch):
    policy = _policy(_reload(monkeypatch, DOMAIN="attacklens.example.com"))
    assert policy["password"]["min_length"] == 16
    assert policy["password"]["require_special"] is True
    assert "session" in policy and "lockout" in policy
