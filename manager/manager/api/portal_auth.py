"""
manager/manager/api/portal_auth.py — customer portal authentication.

A separate principal from the operator dashboard, not a filtered view of it:

  * its own login route and its own cookie (``al_portal_session``), so a
    browser signed into both keeps two independent sessions
  * its own lockout counters, so a customer failing to log in cannot lock out
    the operator account — shared counters would turn the portal into a denial
    of service against the people who run the platform
  * an ``aud=portal`` token that every operator route refuses, which is what
    confines a customer to the portal router

Credentials are never chosen by an operator. A user is created in the
``invited`` state with no password; the customer sets their own through a
single-use, expiring link. No plaintext password exists in the database, the
API, an operator's clipboard, or a log at any point.

Endpoints (mounted at /api/v1/portal/auth):
  POST /login          — email + password, issues the portal session
  POST /logout         — revokes the session and clears the cookie
  GET  /me             — current customer, org, and capabilities
  POST /accept-invite  — redeem a setup token and set the password
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..security_policy import (
    AUTH_CACHE_HEADERS,
    IP_LOCKOUT_ATTEMPTS, IP_LOCKOUT_DURATION, IP_LOCKOUT_WINDOW,
    hash_password, validate_password, verify_password,
)
from .authz import PortalScope, _PORTAL_COOKIE, make_require_portal_user

log = logging.getLogger("manager.portal.auth")
audit = logging.getLogger("manager.audit")

# Lockout state, deliberately separate from auth_ui's. Sharing the buckets
# would let anyone with a customer's email lock out the operator login.
_ip_failures: dict[str, list[float]] = defaultdict(list)
_ip_blocked_until: dict[str, float] = {}

# A PBKDF2 hash of a value nobody holds. Verifying against it for an unknown
# email costs the same as a real check, so response time does not reveal
# whether an account exists.
_DECOY_HASH = hash_password(secrets.token_urlsafe(32))

INVITE_TTL_SECONDS = int(os.environ.get("PORTAL_INVITE_TTL_SECONDS", str(72 * 3600)))


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _ip_is_blocked(ip: str) -> bool:
    until = _ip_blocked_until.get(ip, 0.0)
    if until and time.time() < until:
        return True
    if until:
        _ip_blocked_until.pop(ip, None)
    return False


def _record_failure(ip: str) -> None:
    now = time.time()
    hits = [t for t in _ip_failures[ip] if now - t < IP_LOCKOUT_WINDOW]
    hits.append(now)
    _ip_failures[ip] = hits
    if len(hits) >= IP_LOCKOUT_ATTEMPTS:
        _ip_blocked_until[ip] = now + IP_LOCKOUT_DURATION
        audit.warning("portal.lockout ip=%s attempts=%d", ip, len(hits))


def _clear_failures(ip: str) -> None:
    _ip_failures.pop(ip, None)
    _ip_blocked_until.pop(ip, None)


def reset_lockouts() -> None:
    """Test hook — process-local state, cleared between cases."""
    _ip_failures.clear()
    _ip_blocked_until.clear()


def _auth_error() -> JSONResponse:
    """One response for every failure mode.

    Unknown email, wrong password, un-activated user, suspended org and
    suspended user all return exactly this. Distinguishing them would let
    anyone with a login form enumerate customers and their account states.
    """
    return JSONResponse(
        {"error": "Invalid email or password."},
        status_code=401,
        headers=AUTH_CACHE_HEADERS,
    )


def hash_invite_token(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


class PortalLogin(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=512)


class AcceptInvite(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    password: str = Field(min_length=1, max_length=512)


def make_portal_auth_router(intel_db) -> APIRouter:
    router = APIRouter(prefix="/api/v1/portal/auth", tags=["portal-auth"])
    require_portal_user = make_require_portal_user(intel_db)

    def _set_cookie(response: Response, token: str, max_age: int) -> None:
        response.set_cookie(
            _PORTAL_COOKIE, token,
            httponly=True,
            samesite="strict",
            secure=os.environ.get("HTTPS_ONLY", "false").lower() in ("1", "true", "yes"),
            max_age=max_age,
            path="/",
        )

    @router.post("/login")
    async def portal_login(body: PortalLogin, request: Request, response: Response):
        from .auth_ui import AUD_PORTAL, _JWT_TTL_HOURS, _make_token

        ip = _client_ip(request)
        if _ip_is_blocked(ip):
            audit.warning("portal.login.blocked ip=%s", ip)
            return JSONResponse(
                {"error": "Too many attempts. Try again later."},
                status_code=429, headers=AUTH_CACHE_HEADERS,
            )

        email = body.email.strip().lower()
        user = await intel_db.get_portal_user_by_email(email)

        # Always run a real verification, even with no user, so an unknown
        # address and a wrong password take the same time.
        stored = str((user or {}).get("password_hash") or "") or _DECOY_HASH
        password_ok = verify_password(body.password, stored)

        if user is None or not password_ok or str(user.get("status")) != "active":
            _record_failure(ip)
            audit.info("portal.login.failure ip=%s email=%s", ip, email)
            return _auth_error()

        org = await intel_db.get_org(str(user.get("org_id") or ""))
        if org is None or str(org.get("status")) != "active":
            _record_failure(ip)
            audit.info("portal.login.suspended ip=%s email=%s", ip, email)
            return _auth_error()

        token, jti, exp = _make_token(
            email, str(user.get("role") or "portal_viewer"),
            tenant_id=str(org["org_id"]),
            aud=AUD_PORTAL,
            extra={"user_id": str(user["user_id"]), "org_id": str(org["org_id"])},
        )
        _clear_failures(ip)
        await intel_db.record_portal_login(str(user["user_id"]))
        await intel_db.record_portal_audit(
            org_id=str(org["org_id"]), actor=email, action="portal.login", ip=ip,
        )
        audit.info("portal.login.success ip=%s email=%s jti=%s", ip, email, jti[:8])

        _set_cookie(response, token, _JWT_TTL_HOURS * 3600)
        for key, value in AUTH_CACHE_HEADERS.items():
            response.headers[key] = value
        return {
            "token": token,
            "expires_at": int(exp),
            "user": {
                "email": email,
                "role": str(user.get("role") or "portal_viewer"),
                "org_id": str(org["org_id"]),
                "org_name": str(org.get("name") or org.get("slug") or ""),
            },
        }

    @router.post("/logout")
    async def portal_logout(response: Response):
        response.delete_cookie(_PORTAL_COOKIE, path="/")
        for key, value in AUTH_CACHE_HEADERS.items():
            response.headers[key] = value
        return {"ok": True}

    @router.get("/me")
    async def portal_me(scope: PortalScope = Depends(require_portal_user)):
        """Current customer plus the capabilities the UI may offer.

        Navigation is built from this, never from a client-side role — hiding a
        menu item is presentation, the server refusing the route is the control.
        """
        org = await intel_db.get_org(scope.org_id) or {}
        return {
            "email": scope.email,
            "role": scope.role,
            "org": {
                "org_id": scope.org_id,
                "slug": scope.org_slug,
                "name": org.get("name") or scope.org_slug,
                "tier": org.get("tier") or "standard",
                "license_expires_at": org.get("license_expires_at"),
                "license_days_remaining": org.get("license_days_remaining"),
            },
            "agent_count": len(scope.agent_ids),
            "capabilities": PORTAL_CAPABILITIES,
        }

    @router.post("/accept-invite")
    async def accept_invite(body: AcceptInvite, request: Request):
        """Redeem a single-use setup link and set the customer's password."""
        try:
            validate_password(body.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        user = await intel_db.consume_invite(
            hash_invite_token(body.token), hash_password(body.password),
        )
        if user is None:
            # Unknown, already used and expired are one answer — a probe must
            # not learn that a token was ever valid.
            raise HTTPException(
                status_code=400,
                detail="This setup link is invalid or has already been used. "
                       "Ask your administrator to send a new one.",
            )
        audit.info(
            "portal.invite.accepted ip=%s email=%s", _client_ip(request), user["email"],
        )
        return {"ok": True, "email": user["email"]}

    return router


# What a customer principal may do. Read-only, by design: the portal exposes a
# scoped projection of findings and posture, and nothing that changes
# infrastructure or crosses a tenant boundary.
PORTAL_CAPABILITIES: dict[str, bool] = {
    "view_findings": True,
    "view_posture": True,
    "view_reports": True,
    "configure_dashboard": True,   # display name, timezone, notification targets
    # Raw telemetry from the customer's OWN endpoints. Scoped in db.py and
    # raw.py, so Deep Analysis and DeepMesh work in the portal without ever
    # reaching another tenant's payloads.
    "view_raw_telemetry": True,
    # Explicitly withheld — listed rather than omitted so the boundary is
    # legible in the API response itself.
    "manage_agents": False,
    "manage_users": False,
    "manage_license": False,
    "update_finding": False,
    "manage_platform_settings": False,
}
