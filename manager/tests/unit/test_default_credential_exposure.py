"""
manager/tests/unit/test_default_credential_exposure.py — the built-in default
dashboard password must not be published to the internet.

GET /api/v1/auth/policy is unauthenticated by necessity: the login screen needs
the password rules before anyone can log in. While the built-in default is in
use it also carries that default as click-to-autofill, and the default is
hardcoded in auth_ui.py — byte-identical on every install. On a deployment that
has been pointed at a public address, that publishes an admin credential at a
well-known path to anyone who asks.

The gate is deliberately config-based (DOMAIN / PUBLIC_IP), not client-IP based:
behind the bundled Caddy the manager only ever sees the proxy's private
container address, so an IP check would pass for every internet visitor, and
X-Forwarded-For is set by the caller.

What must stay true:
  * laptop first-run keeps the autofill convenience
  * a publicly-addressed deployment never returns the password
  * setting DASHBOARD_PASSWORD_HASH suppresses it regardless of address
  * suppression is cosmetic only — it must never lock an operator out
"""
from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

PUBLIC_ENV_KEYS = ("DOMAIN", "PUBLIC_IP", "DASHBOARD_PASSWORD_HASH", "DASHBOARD_PASSWORD")


def _reload(monkeypatch, **env):
    # Clear every input to the gate first, so a variable leaking in from the
    # developer's own shell cannot make a failing case look like it passes.
    for key in PUBLIC_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from manager.manager.api import auth_ui
    return importlib.reload(auth_ui)


def _policy(module) -> dict:
    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app).get("/api/v1/auth/policy").json()


@pytest.fixture(autouse=True)
def _restore_module():
    """Reloading the module under test must not leak into other test files."""
    yield
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)


# ── The exposure ─────────────────────────────────────────────────────────────

def test_public_domain_never_returns_the_default_password(monkeypatch):
    creds = _policy(_reload(monkeypatch, DOMAIN="attacklens.example.com"))["default_credentials"]
    assert creds["active"] is False
    assert creds["password"] is None
    assert creds["email"] is None


def test_public_ip_never_returns_the_default_password(monkeypatch):
    creds = _policy(_reload(monkeypatch, PUBLIC_IP="203.0.113.10"))["default_credentials"]
    assert creds["active"] is False
    assert creds["password"] is None


def test_operator_supplied_hash_suppresses_it_even_on_a_laptop(monkeypatch):
    from manager.manager.security_policy import hash_password
    module = _reload(monkeypatch, DASHBOARD_PASSWORD_HASH=hash_password("Str0ng!Passw0rd#2026"))
    creds = _policy(module)["default_credentials"]
    assert creds["active"] is False
    assert creds["password"] is None


def test_no_response_field_leaks_the_default_password(monkeypatch):
    """Not just default_credentials — the whole payload must be clean."""
    import json
    module = _reload(monkeypatch, DOMAIN="attacklens.example.com")
    body = json.dumps(_policy(module))
    assert module._DEFAULT_PASSWORD not in body


# ── The convenience it must not break ────────────────────────────────────────

def test_laptop_first_run_still_offers_autofill(monkeypatch):
    """No DOMAIN, no PUBLIC_IP, no hash — the first-run flow is the whole reason
    this endpoint carries the credential, so it has to survive the fix."""
    creds = _policy(_reload(monkeypatch))["default_credentials"]
    assert creds["active"] is True
    assert creds["password"] is not None
    assert creds["email"] is not None


def test_login_screen_still_gets_its_password_rules_when_suppressed(monkeypatch):
    policy = _policy(_reload(monkeypatch, DOMAIN="attacklens.example.com"))
    assert policy["password"]["min_length"] == 16
    assert policy["password"]["require_special"] is True
    assert "session" in policy and "lockout" in policy


def test_suppression_does_not_disable_the_password(monkeypatch):
    """Cosmetic only. Hiding the credential must not lock out an operator who is
    mid-setup — the default keeps authenticating until a real one replaces it."""
    module = _reload(monkeypatch, DOMAIN="attacklens.example.com")
    assert module.verify_password(module._DEFAULT_PASSWORD, module._stored_hash) is True
