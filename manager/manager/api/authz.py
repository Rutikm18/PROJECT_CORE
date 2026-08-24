"""
manager/manager/api/authz.py — Shared authorization dependencies.

Two credentials are already in use across the manager and both are legitimate:

  • the ``al_session`` dashboard JWT issued by ``auth_ui.py`` — what the UI has
  • the ``X-Admin-Token`` header checked by ``keys.py``  — what scripts and curl
    have, and the only credential available before anyone logs in

``require_admin`` accepts either, so a route protected with it is reachable from
the dashboard and from automation without giving one of them a second secret.

Usage:

    from .authz import require_admin

    @router.post("/provider")
    async def set_provider(_: dict = Depends(require_admin)):
        ...

Returns the acting principal as a dict so handlers can attribute the action.
"""
from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Request

log = logging.getLogger("manager.api.authz")

_ADMIN_ROLES = {"admin", "owner"}


def _bearer_or_cookie(request: Request) -> str:
    """Pull the session token from the al_session cookie or an Authorization header."""
    token = request.cookies.get("al_session", "")
    if token:
        return token
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return bearer.removeprefix("Bearer ").strip()
    return ""


def _session_principal(request: Request) -> Optional[dict]:
    """Return the verified session payload, or None when there is no valid session."""
    # Populated by upstream middleware when present; fall back to verifying here.
    user = getattr(request.state, "user", None)
    if isinstance(user, dict) and user.get("sub"):
        return user

    token = _bearer_or_cookie(request)
    if not token:
        return None
    try:
        from .auth_ui import _verify_token
        return _verify_token(token)
    except Exception:                                    # pragma: no cover
        log.debug("session verification failed", exc_info=True)
        return None


def _admin_token_matches(supplied: str) -> bool:
    """Constant-time compare against ADMIN_TOKEN.

    An unset ADMIN_TOKEN disables this path entirely rather than matching the
    empty string — otherwise omitting the header would authenticate.
    """
    configured = os.environ.get("ADMIN_TOKEN", "").strip()
    if not configured or not supplied:
        return False
    return hmac.compare_digest(supplied.strip().encode(), configured.encode())


async def require_admin(
    request: Request,
    x_admin_token: str = Header(default=""),
) -> dict:
    """Allow admin dashboard sessions and valid X-Admin-Token holders.

    Raises 401 for anonymous callers and 403 for an authenticated non-admin, so
    the caller can tell "log in" apart from "your account cannot do this".
    """
    if _admin_token_matches(x_admin_token):
        return {"principal": "admin-token", "role": "admin", "via": "x-admin-token"}

    payload = _session_principal(request)
    if payload is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "Authentication required. Sign in to the dashboard, or send the "
                "X-Admin-Token header."
            ),
        )

    role = str(payload.get("role") or "").lower()
    if role not in _ADMIN_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role or 'unknown'}' is not permitted to change this setting.",
        )

    return {
        "principal": str(payload.get("sub") or "unknown")[:200],
        "role": role,
        "via": "session",
    }


def _portal_principal_or_none(request: Request) -> Optional[dict]:
    """A customer principal resolved by TenantScopeMiddleware, if any.

    The scope is the gate, not the principal: `tenant_agent_ids` is set only
    after the middleware verified the token, confirmed the user is active and
    the org is not suspended, refused every mutating method, and refused every
    operator-only path. A principal without a resolved scope means the
    middleware did not run, and granting access on that basis is precisely the
    failure this layer exists to prevent — so it is refused.
    """
    principal = getattr(request.state, "portal_principal", None)
    scope = getattr(request.state, "tenant_agent_ids", None)
    if principal is None or scope is None:
        return None

    # Publish the scope into the request's context so the query compiler
    # applies it without every handler having to pass it down.
    from .tenant_scope import set_current_tenant

    set_current_tenant(tuple(scope))
    return {
        "principal": str(principal.get("email") or "portal-user")[:200],
        "role": "portal_viewer",
        "via": "portal-session",
        "org_id": str(principal.get("org_id") or ""),
    }


async def require_session(request: Request) -> dict:
    """Any authenticated caller — operator, or a scoped customer.

    The customer portal mirrors the operator dashboard page for page, so a
    customer principal has to reach these same routes. What keeps that safe is
    that it can only arrive here already confined: TenantScopeMiddleware has
    refused every mutating method and every operator-only path, and attached
    the tenant scope that the query compiler applies.

    Operator-only routes use `require_admin` instead, which never accepts a
    customer.

    The X-Admin-Token header satisfies this too, so automation that can write a
    setting can always read it back.
    """
    if _admin_token_matches(request.headers.get("X-Admin-Token", "")):
        return {"principal": "admin-token", "role": "admin", "via": "x-admin-token"}

    payload = _session_principal(request)
    if payload is None:
        # No operator session. A customer signs in with a different cookie, so
        # check whether the middleware resolved one before refusing.
        portal = _portal_principal_or_none(request)
        if portal is not None:
            return portal
        raise HTTPException(status_code=401, detail="Authentication required.")

    from .auth_ui import AUD_MANAGER, token_audience

    if token_audience(payload) != AUD_MANAGER:
        portal = _portal_principal_or_none(request)
        if portal is not None:
            return portal
        raise HTTPException(
            status_code=403,
            detail="This credential is not valid for the operator API.",
        )
    return {
        "principal": str(payload.get("sub") or "unknown")[:200],
        "role": str(payload.get("role") or "").lower(),
        "via": "session",
    }


# ── Portal principal ─────────────────────────────────────────────────────────

_PORTAL_COOKIE = "al_portal_session"


@dataclass(frozen=True)
class PortalScope:
    """A resolved customer principal and the data it may address.

    `agent_ids` is the tenant boundary. Every portal query filters on it, and
    an empty tuple means the org owns no agents — which must return nothing,
    never everything.
    """

    user_id: str
    email: str
    org_id: str
    org_slug: str
    role: str
    agent_ids: tuple[str, ...]

    def owns(self, agent_id: str) -> bool:
        return str(agent_id or "") in self.agent_ids


def _portal_token(request: Request) -> str:
    """Portal session, from its own cookie or a bearer header.

    A distinct cookie name from the operator session, so a browser signed into
    both keeps two independent principals and neither silently satisfies the
    other's routes.
    """
    token = request.cookies.get(_PORTAL_COOKIE, "")
    if token:
        return token
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return bearer.removeprefix("Bearer ").strip()
    return ""


def make_require_portal_user(intel_db):
    """Build the portal dependency bound to a database handle.

    State is re-read on **every request**, not trusted from the token: the JWT
    says which org the caller belongs to, but whether that org is still active
    is a fact that can change mid-session. Reading it per request is what makes
    "disable access" take effect immediately rather than at next login.
    """

    async def require_portal_user(request: Request) -> PortalScope:
        from .auth_ui import AUD_PORTAL, _verify_token, token_audience

        token = _portal_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="Authentication required.")
        payload = _verify_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Session expired or invalid.")
        if token_audience(payload) != AUD_PORTAL:
            raise HTTPException(
                status_code=403,
                detail="This credential is not valid for the customer portal.",
            )

        user_id = str(payload.get("user_id") or "")
        if not user_id:
            raise HTTPException(status_code=401, detail="Session expired or invalid.")

        user = await intel_db.get_portal_user(user_id)
        if user is None or str(user.get("status")) != "active":
            # Covers a deleted user and a disabled one with the same message —
            # a live session should not report which.
            raise HTTPException(status_code=401, detail="Session is no longer valid.")

        org = await intel_db.get_org(str(user.get("org_id") or ""))
        if org is None or str(org.get("status")) != "active":
            raise HTTPException(
                status_code=403,
                detail="This account's access has been suspended.",
            )

        agent_ids = await intel_db.agent_ids_for_org(org["org_id"])
        return PortalScope(
            user_id=user_id,
            email=str(user.get("email") or ""),
            org_id=str(org["org_id"]),
            org_slug=str(org.get("slug") or ""),
            role=str(user.get("role") or "portal_viewer"),
            agent_ids=tuple(agent_ids),
        )

    # Marks this closure as an authentication dependency. The route-coverage
    # test identifies protected routes by their dependency callables, and a
    # closure has no stable identity to compare against — without this marker a
    # portal route would look unprotected and the test would demand it be
    # allowlisted, which is the opposite of the truth.
    require_portal_user.__auth_dependency__ = True     # type: ignore[attr-defined]
    return require_portal_user
