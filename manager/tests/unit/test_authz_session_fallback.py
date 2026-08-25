"""
manager/tests/unit/test_authz_session_fallback.py

Pins the credential-precedence fix in authz._session_principal: a valid
Authorization: Bearer token must be honoured even when the browser also sends a
stale/invalid al_session cookie. Before the fix the cookie was verified and,
failing, 401'd the request without ever trying the bearer — the exact shape of
the "login works, every API call 401s behind the AWS proxy" report.
"""
from __future__ import annotations

import importlib
import types

import pytest

_SECRET = "dGVzdC1zZWNyZXQtMzJieXRlcy1sb25nLWVub3VnaC0xMjM0"   # base64, 32+ bytes


def _reload_with_secret(monkeypatch):
    # Only auth_ui is reloaded (to pick up JWT_SECRET). authz imports
    # _verify_token lazily at call time, so it uses the refreshed secret without
    # a reload — and reloading it would swap the require_session/require_admin
    # identities that the route-coverage test matches on, polluting other tests.
    monkeypatch.setenv("JWT_SECRET", _SECRET)
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)
    from manager.manager.api import authz
    return auth_ui, authz


@pytest.fixture(autouse=True)
def _restore_modules():
    yield
    from manager.manager.api import auth_ui
    importlib.reload(auth_ui)


class _FakeRequest:
    """Just enough of starlette's Request for _session_principal."""

    def __init__(self, cookie: str = "", authorization: str = ""):
        self.state = types.SimpleNamespace()   # no .user → middleware didn't run
        self.cookies = {"al_session": cookie} if cookie else {}
        self.headers = {"Authorization": authorization} if authorization else {}

    # starlette's .headers/.cookies are mappings with .get — dict already is one.


def _valid_manager_token(auth_ui) -> str:
    token, _jti, _exp = auth_ui._make_token("operator@example.com", "admin")
    return token


def test_bearer_is_honoured_despite_a_stale_cookie(monkeypatch):
    auth_ui, authz = _reload_with_secret(monkeypatch)
    token = _valid_manager_token(auth_ui)

    req = _FakeRequest(cookie="garbage.not-a-jwt.value", authorization=f"Bearer {token}")
    payload = authz._session_principal(req)

    assert payload is not None
    assert payload.get("sub") == "operator@example.com"
    assert auth_ui.token_audience(payload) == auth_ui.AUD_MANAGER


def test_valid_cookie_alone_still_works(monkeypatch):
    auth_ui, authz = _reload_with_secret(monkeypatch)
    token = _valid_manager_token(auth_ui)

    req = _FakeRequest(cookie=token)
    assert authz._session_principal(req) is not None


def test_two_bad_credentials_are_refused(monkeypatch):
    _auth_ui, authz = _reload_with_secret(monkeypatch)

    req = _FakeRequest(cookie="bad.cookie.jwt", authorization="Bearer also.bad.jwt")
    assert authz._session_principal(req) is None


def test_no_credentials_is_refused(monkeypatch):
    _auth_ui, authz = _reload_with_secret(monkeypatch)
    assert authz._session_principal(_FakeRequest()) is None
