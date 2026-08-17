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


async def require_session(request: Request) -> dict:
    """Any authenticated caller — for reads that are safe but not public.

    The X-Admin-Token header satisfies this too, so automation that can write a
    setting can always read it back.
    """
    if _admin_token_matches(request.headers.get("X-Admin-Token", "")):
        return {"principal": "admin-token", "role": "admin", "via": "x-admin-token"}

    payload = _session_principal(request)
    if payload is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return {
        "principal": str(payload.get("sub") or "unknown")[:200],
        "role": str(payload.get("role") or "").lower(),
        "via": "session",
    }
