"""
manager/tests/unit/test_api_auth_coverage.py — the authentication boundary.

Before this existed, every /api/v1/* data route answered anonymous callers with
200 and the full fleet: detection.py declared no dependencies and the app had no
auth middleware. The login screen gated the React bundle, not the data.

The fix was to attach `dependencies=[Depends(require_session)]` at each
`include_router()` call in server.py. The risk with that fix is that it is easy
to reverse by accident — someone adds a router, forgets the dependency, and
nothing complains. So the boundary is asserted here rather than trusted:

  * every /api/v1/* route resolves an auth dependency, or is on the allowlist
  * the allowlist is closed — an unexpected entry fails too, so a route cannot
    be quietly parked there without a matching change to this file
  * require_session itself rejects anonymous and forged callers

The route walk needs no database: it inspects the app object rather than
serving traffic.
"""
from __future__ import annotations

import os

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from manager.manager.api.authz import require_admin, require_session

# Auth dependencies. A route is protected when any of these appears anywhere in
# its resolved dependency tree, at router level or on the endpoint.
_AUTH_CALLABLES = {require_session, require_admin}

# ── The allowlist ────────────────────────────────────────────────────────────
# Routes that legitimately answer without a dashboard session. Each entry needs
# a reason, and the reason has to be "it carries a different credential", never
# "it seemed harmless".
_ALLOWLIST: dict[str, str] = {
    "/api/v1/ingest":
        "Agent telemetry. Authenticated per-payload by HMAC signature + nonce, "
        "not by a browser session.",
    "/api/v1/enroll":
        "Agents must reach enrolment before they hold any credential. Gated by "
        "ENROLLMENT_TOKENS / OPEN_ENROLLMENT.",
    "/api/v1/auth/login":
        "Cannot require a session in order to issue one.",
    "/api/v1/auth/logout":
        "Verifies and revokes its own token; must still work on an expired one.",
    "/api/v1/auth/me":
        "Reads the caller's own token and 401s itself when absent.",
    "/api/v1/auth/policy":
        "Password and session policy the login screen renders before sign-in.",
    "/api/v1/portal/auth/login":
        "Customer portal login. Cannot require a session in order to issue one. "
        "Has its own lockout counters so it cannot be used to lock the operator "
        "account.",
    "/api/v1/portal/auth/logout":
        "Clears the portal cookie; must work on an already-expired session.",
    "/api/v1/portal/auth/accept-invite":
        "Redeems a single-use setup token. The token IS the credential, so the "
        "caller has no session yet by definition.",
}


def _app():
    """Build the real app. No DB connection happens until the startup event."""
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@127.0.0.1:5432")
    os.environ.setdefault("JWT_SECRET", "test-secret-for-route-coverage")
    os.environ.setdefault("MANAGER_ROLES", "api,intel")
    from manager.manager.server import create_app

    return create_app()


def _dependency_calls(route) -> set:
    """Every callable in a route's resolved dependency tree, nested included."""
    found: set = set()
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return found
    stack = [dependant]
    while stack:
        node = stack.pop()
        call = getattr(node, "call", None)
        if call is not None:
            found.add(call)
        stack.extend(getattr(node, "dependencies", []) or [])
    return found


def _is_protected(route) -> bool:
    """Whether a route resolves any authentication dependency.

    Two mechanisms, because the portal dependency is a closure built per
    database handle and so has no stable identity to compare against: match the
    module-level dependencies by identity, and closures by the
    ``__auth_dependency__`` marker they set on themselves.
    """
    calls = _dependency_calls(route)
    if _AUTH_CALLABLES & calls:
        return True
    return any(getattr(call, "__auth_dependency__", False) for call in calls)


def _api_routes(app) -> list:
    return [
        r for r in app.routes
        if getattr(r, "path", "").startswith("/api/")
        and getattr(r, "methods", None)
    ]


@pytest.fixture(scope="module")
def app():
    return _app()


# ── The boundary ─────────────────────────────────────────────────────────────

def test_every_api_route_is_protected_or_allowlisted(app):
    unprotected = sorted(
        f"{','.join(sorted(r.methods - {'HEAD', 'OPTIONS'}))} {r.path}"
        for r in _api_routes(app)
        if r.path not in _ALLOWLIST
        and not _is_protected(r)
    )
    assert not unprotected, (
        "These /api/v1 routes answer anonymous callers. Add the router to the "
        "session-protected block in server.py, or add the route to _ALLOWLIST "
        "here with the credential scheme it uses instead:\n  "
        + "\n  ".join(unprotected)
    )


# The portal routers are registered only when ATTACKLENS_CUSTOMER_PORTAL is
# set, so their allowlist entries are conditional too.
_PORTAL_ALLOWLIST = {p for p in _ALLOWLIST if p.startswith("/api/v1/portal")}


def test_the_allowlist_is_closed(app):
    """A stale allowlist entry is as dangerous as a missing dependency."""
    live = {r.path for r in _api_routes(app)}
    stale = sorted(set(_ALLOWLIST) - live - _PORTAL_ALLOWLIST)
    assert not stale, f"_ALLOWLIST names routes that no longer exist: {stale}"


def test_allowlisted_routes_did_not_silently_grow(app):
    """Nine exemptions today. A tenth must be a deliberate edit to this file."""
    assert len(_ALLOWLIST) == 9
    live = {r.path for r in _api_routes(app)}
    # Every non-portal exemption must exist; the portal ones only when enabled.
    assert (live & set(_ALLOWLIST)) >= (set(_ALLOWLIST) - _PORTAL_ALLOWLIST)


def test_the_customer_portal_is_off_by_default(app):
    """"Coming soon" has to mean the routes are absent, not merely hidden.

    A portal login that still answered while the dashboard showed a placeholder
    would be the worst of both — an unadvertised, unmonitored way in.
    """
    import os
    if os.environ.get("ATTACKLENS_CUSTOMER_PORTAL", "").strip().lower() in (
        "1", "true", "yes", "on",
    ):
        pytest.skip("portal explicitly enabled in this environment")
    portal_routes = sorted(
        r.path for r in _api_routes(app)
        if r.path.startswith("/api/v1/portal") or r.path.startswith("/api/v1/customers")
    )
    assert not portal_routes, (
        "customer portal routes are registered while the feature is off: "
        + ", ".join(portal_routes)
    )


def test_the_high_value_routes_are_covered(app):
    """Spot-check the routes that leaked real data, by name.

    The sweep above would catch these, but naming them documents what the
    incident actually exposed.
    """
    want = {
        "/api/v1/detection/all",       # 2,205 findings with CVE detail
        "/api/v1/settings",            # org identity and licence key
        "/api/v1/assets",              # full asset registry
        "/api/v1/raw/query",           # raw endpoint telemetry
        "/api/v1/dashboard/ws-token",  # handed out the master API key
        "/api/v1/meta",                # build/version fingerprinting
        "/api/v1/ingest/health",       # operator route on the agent router
    }
    by_path = {r.path: r for r in _api_routes(app)}
    missing = sorted(p for p in want if p not in by_path)
    assert not missing, f"expected routes are gone from the app: {missing}"
    for path in sorted(want):
        assert _is_protected(by_path[path]), path


def test_openapi_schema_is_not_served_by_default(app):
    """The schema published the entire route map, parameters and models."""
    assert app.openapi_url is None
    assert app.docs_url is None
    assert app.redoc_url is None


# ── The dependency itself ────────────────────────────────────────────────────

def _probe_client() -> TestClient:
    """A minimal app carrying only the dependency, so no DB startup is needed."""
    probe = FastAPI()

    @probe.get("/guarded", dependencies=[Depends(require_session)])
    async def guarded():
        return {"ok": True}

    return TestClient(probe)


def test_require_session_rejects_anonymous_callers():
    response = _probe_client().get("/guarded")
    assert response.status_code == 401
    assert "Authentication" in response.json()["detail"]


def test_require_session_rejects_a_forged_token():
    client = _probe_client()
    assert client.get(
        "/guarded", headers={"Authorization": "Bearer not.a.token"},
    ).status_code == 401
    # A structurally valid token signed with the wrong key must fail too.
    assert client.get(
        "/guarded", headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.zzz"},
    ).status_code == 401


def test_require_session_accepts_a_real_session(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test-secret-for-route-coverage")
    from manager.manager.api import auth_ui

    monkeypatch.setattr(auth_ui, "_JWT_SECRET", b"test-secret-for-route-coverage")
    token, _jti, _exp = auth_ui._make_token("admin@attacklens.ai", "admin")

    client = _probe_client()
    # Both delivery mechanisms the SPA uses.
    assert client.get(
        "/guarded", headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200
    client.cookies.set("al_session", token)
    assert client.get("/guarded").status_code == 200
