"""
manager/manager/api/tenant_scope.py — the customer boundary on shared routes.

The customer portal is an exact mirror of the operator dashboard: the same
pages, the same functionality, the same API. That means a customer principal
has to reach the operator routes, which in turn means the tenant boundary can
no longer be "a separate router they cannot leave". It has to be enforced per
request, on routes that were written with no notion of a tenant.

This middleware is that enforcement, and it is deliberately the *only* place a
customer principal is granted anything:

  1. **Resolve once.** The principal is decided from the cookie/bearer before
     any handler runs, and stashed on ``request.state``.
  2. **Read-only.** A portal principal may only issue safe methods. Every
     mutating verb is refused outright, so no operator write path needs to
     defend itself individually.
  3. **Operator-only paths are refused.** Settings, keys, AI configuration,
     customer provisioning, allowlists, correlation rules, enrolment and raw
     telemetry are unreachable regardless of method.
  4. **Scope is attached, never assumed.** ``request.state.tenant_agent_ids``
     is a tuple for a customer and ``None`` for an operator. Handlers pass it
     into their queries; a handler that forgets returns *nothing* for a
     customer rather than everything, because the query layer treats a missing
     scope on a portal request as an error.

The ordering matters: deny-by-method and deny-by-path both run before scope is
attached, so a route that has not yet been scoped is unreachable rather than
unfiltered.
"""
from __future__ import annotations

import contextvars
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger("manager.api.tenant_scope")

# The active tenant scope for the request being handled.
#
# A ContextVar rather than a parameter threaded through every handler, because
# the portal mirrors the *whole* operator dashboard: dozens of endpoints, each
# of which would otherwise have to remember to pass the scope, and forgetting
# is a silent cross-tenant leak. Reading it inside the query compiler means a
# customer's request is scoped whether or not the handler knows tenants exist.
#
# Set from a dependency, not from the middleware: Starlette's
# BaseHTTPMiddleware runs `call_next` in a separate anyio task, so a ContextVar
# set in `dispatch` does not reliably reach the endpoint. Dependencies run in
# the endpoint's own context, so the value is visible where it is needed.
_CURRENT_TENANT: contextvars.ContextVar[Optional[tuple[str, ...]]] = (
    contextvars.ContextVar("attacklens_tenant_agent_ids", default=None)
)


def set_current_tenant(agent_ids: Optional[tuple[str, ...]]) -> None:
    _CURRENT_TENANT.set(agent_ids)


def current_tenant() -> Optional[tuple[str, ...]]:
    """Tenant scope for the in-flight request, or None for an operator."""
    return _CURRENT_TENANT.get()

# Methods a customer may issue. Everything else is refused before routing.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Path prefixes a customer principal may never reach, whatever the method.
# Each is operator-only because it either configures the platform, exposes
# another tenant's data by construction, or is an agent-facing credential path.
OPERATOR_ONLY_PREFIXES: tuple[str, ...] = (
    "/api/v1/settings",              # platform + validation configuration
    "/api/v1/customers",             # provisioning other customers
    "/api/v1/keys",                  # agent credentials
    "/api/v1/ai",                    # AI provider config and investigations
    "/api/v1/allowlist",             # suppression rules, fleet-wide
    "/api/v1/custom-correlations",   # detection logic
    "/api/v1/enroll",                # agent enrolment
    "/api/v1/ingest",                # agent telemetry
    # /api/v1/raw is NOT here: raw telemetry is the customer's own data and the
    # portal shows it. Its list and count paths are scoped in db.py via the
    # same request ContextVar, and its single-agent paths check membership in
    # raw.py, returning 404 for an agent outside the caller's scope.
    "/api/v1/integrations",          # platform dependency health
    "/api/v1/accuracy",              # cross-tenant detection quality metrics
    "/api/v1/dashboard/ws-token",    # hands out the master API key
)

# Portal-owned paths, which handle their own auth and scope.
PORTAL_PREFIXES: tuple[str, ...] = ("/api/v1/portal",)


def is_operator_only(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in OPERATOR_ONLY_PREFIXES)


def is_portal_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PORTAL_PREFIXES)


def _portal_token(request: Request) -> str:
    from .authz import _PORTAL_COOKIE

    token = request.cookies.get(_PORTAL_COOKIE, "")
    if token:
        return token
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        candidate = bearer.removeprefix("Bearer ").strip()
        # Only treat a bearer as a portal credential when it actually says so,
        # so an operator's bearer is never mistaken for a customer's.
        from .auth_ui import AUD_PORTAL, _verify_token, token_audience
        payload = _verify_token(candidate)
        if payload is not None and token_audience(payload) == AUD_PORTAL:
            return candidate
    return ""


def _deny(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


class TenantScopeMiddleware(BaseHTTPMiddleware):
    """Resolve the principal and confine a customer before routing."""

    def __init__(self, app, intel_db):
        super().__init__(app)
        self._intel_db = intel_db

    async def dispatch(self, request: Request, call_next):
        # Default: operator (or anonymous — the route's own dependency decides).
        # None means "no tenant restriction"; only a resolved customer narrows it.
        request.state.tenant_agent_ids = None
        request.state.portal_principal = None

        path = request.url.path
        if not path.startswith("/api/") or is_portal_path(path):
            return await call_next(request)

        token = _portal_token(request)
        if not token:
            return await call_next(request)

        from .auth_ui import AUD_PORTAL, _verify_token, token_audience

        payload = _verify_token(token)
        if payload is None or token_audience(payload) != AUD_PORTAL:
            return await call_next(request)

        # ── From here the caller is a customer ───────────────────────────────
        if request.method.upper() not in SAFE_METHODS:
            return _deny(
                403, "The customer portal is read-only.",
            )
        if is_operator_only(path):
            return _deny(
                403, "This endpoint is not available in the customer portal.",
            )

        user_id = str(payload.get("user_id") or "")
        if not user_id:
            return _deny(401, "Session expired or invalid.")

        try:
            user = await self._intel_db.get_portal_user(user_id)
            if user is None or str(user.get("status")) != "active":
                return _deny(401, "Session is no longer valid.")
            org = await self._intel_db.get_org(str(user.get("org_id") or ""))
            if org is None or str(org.get("status")) != "active":
                return _deny(403, "This account's access has been suspended.")
            agent_ids = await self._intel_db.agent_ids_for_org(org["org_id"])
        except Exception as exc:
            # Fail closed. A lookup failure must not silently downgrade the
            # caller to an unrestricted operator.
            log.warning("tenant scope resolution failed: %s", exc)
            return _deny(503, "Could not verify your account. Try again shortly.")

        request.state.tenant_agent_ids = tuple(agent_ids)
        request.state.portal_principal = {
            "user_id": user_id,
            "email": str(user.get("email") or ""),
            "org_id": str(org["org_id"]),
            "org_slug": str(org.get("slug") or ""),
        }
        return await call_next(request)


def tenant_agent_ids(request: Request) -> Optional[tuple[str, ...]]:
    """The caller's tenant scope: a tuple for a customer, None for an operator.

    Handlers pass this straight into ``FindingQuery.tenant_agent_ids``. Reading
    it through this helper rather than touching ``request.state`` directly keeps
    the default in one place — if the middleware did not run, an operator is
    unrestricted and a customer could not have been resolved at all.
    """
    return getattr(request.state, "tenant_agent_ids", None)


def is_portal_request(request: Request) -> bool:
    return getattr(request.state, "portal_principal", None) is not None
