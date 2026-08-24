"""
manager/manager/api/customers.py — provisioning customer dashboards.

The operator side of the portal: create an org, issue its licence, bind agents
to it, invite its users, and switch its access off. Every route requires an
operator admin (``require_admin``), so a portal token cannot reach any of it —
``aud=portal`` is refused before the handler runs.

SHOWN ONCE
    Two values are returned exactly once, by the call that creates them, and
    are unrecoverable afterwards: the licence key and the invite link. The
    database holds only their SHA-256. That is not an inconvenience to design
    around — it is the reason a database read cannot be turned into a customer
    login or a forged entitlement. Every response that returns one says so.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from .. import licensing as L
from .authz import require_admin
from .portal_auth import INVITE_TTL_SECONDS, hash_invite_token

log = logging.getLogger("manager.api.customers")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")


class CreateOrg(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str = Field(min_length=3, max_length=40)
    contact_email: str = Field(default="", max_length=320)
    max_agents: int = Field(default=25, ge=1, le=100_000)
    valid_days: int = Field(default=365, ge=0, le=3650)
    tier: str = Field(default="standard", max_length=32)

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not _SLUG_RE.match(v):
            raise ValueError(
                "slug must be lowercase letters, digits and hyphens, and start "
                "and end with a letter or digit"
            )
        return v


class AssignAgents(BaseModel):
    agent_ids: list[str] = Field(min_length=1, max_length=5000)


class CreateUser(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default="portal_viewer", max_length=32)


class RotateLicense(BaseModel):
    max_agents: int = Field(default=25, ge=1, le=100_000)
    valid_days: int = Field(default=365, ge=0, le=3650)
    tier: str = Field(default="standard", max_length=32)


def _actor(request: Request) -> tuple[str, str]:
    user = getattr(request.state, "user", None)
    actor = str((user or {}).get("sub") or "admin") if isinstance(user, dict) else "admin"
    ip = (request.client.host if request.client else "")[:64]
    return actor, ip


def make_customers_router(intel_db) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/customers",
        tags=["customers"],
        dependencies=[Depends(require_admin)],
    )

    async def _org_or_404(org_id: str) -> dict:
        org = await intel_db.get_org(org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Customer not found.")
        return org

    # ── Orgs ────────────────────────────────────────────────────────────────

    @router.get("")
    async def list_customers():
        return {"customers": await intel_db.list_orgs()}

    @router.post("", status_code=201)
    async def create_customer(body: CreateOrg, request: Request):
        """Create a customer and issue its licence.

        The licence key is in this response and nowhere else, ever.
        """
        actor, ip = _actor(request)
        if await intel_db.get_org_by_slug(body.slug) is not None:
            raise HTTPException(
                status_code=409, detail=f"A customer with slug {body.slug!r} already exists.",
            )
        try:
            key, ent = L.issue(
                org_id="pending", org_slug=body.slug,
                valid_days=body.valid_days, max_agents=body.max_agents,
                tier=body.tier,
            )
        except L.LicenseError as exc:
            # A missing signing key is an operator configuration problem, not a
            # bad request — say so plainly rather than 500ing.
            raise HTTPException(status_code=503, detail=str(exc))

        org = await intel_db.create_org(
            slug=body.slug, name=body.name, contact_email=body.contact_email,
            license_key_hash=L.key_fingerprint(key),
            entitlements=ent.to_dict(), actor=actor, status="active",
        )
        await intel_db.record_portal_audit(
            org_id=org["org_id"], actor=actor, action="org.created",
            detail={"slug": body.slug, "max_agents": body.max_agents}, ip=ip,
        )
        return {
            "customer": org,
            "license_key": L.format_grouped(key),
            "entitlements": ent.to_dict(),
            "notice": (
                "This licence key is shown once and cannot be recovered. Only "
                "its hash is stored. Copy it now; rotate the licence if it is lost."
            ),
        }

    @router.get("/{org_id}")
    async def get_customer(org_id: str):
        org = await _org_or_404(org_id)
        org["agents"] = await intel_db.agent_ids_for_org(org_id)
        org["users"] = await intel_db.list_portal_users(org_id)
        return org

    @router.post("/{org_id}/status")
    async def set_status(
        org_id: str, request: Request,
        status: str = Query(..., pattern="^(active|suspended)$"),
    ):
        """Enable or disable access. Suspension takes effect on the customer's
        next request, not at their next login — `require_portal_user` re-reads
        org status every time."""
        await _org_or_404(org_id)
        actor, ip = _actor(request)
        await intel_db.set_org_status(org_id, status, actor=actor)
        await intel_db.record_portal_audit(
            org_id=org_id, actor=actor, action=f"org.access.{status}", ip=ip,
        )
        return {
            "customer": await intel_db.get_org(org_id),
            "effect": (
                "Live sessions lose access on their next request."
                if status == "suspended" else "Access restored."
            ),
        }

    @router.post("/{org_id}/license/rotate")
    async def rotate_license(org_id: str, body: RotateLicense, request: Request):
        org = await _org_or_404(org_id)
        actor, ip = _actor(request)
        try:
            key, ent = L.issue(
                org_id=org_id, org_slug=str(org["slug"]),
                valid_days=body.valid_days, max_agents=body.max_agents,
                tier=body.tier,
            )
        except L.LicenseError as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        await intel_db.update_org_license(
            org_id, license_key_hash=L.key_fingerprint(key),
            entitlements=ent.to_dict(), actor=actor,
        )
        await intel_db.record_portal_audit(
            org_id=org_id, actor=actor, action="org.license.rotated", ip=ip,
        )
        return {
            "customer": await intel_db.get_org(org_id),
            "license_key": L.format_grouped(key),
            "entitlements": ent.to_dict(),
            "notice": (
                "Shown once. The previous key stops being the record of "
                "entitlement immediately, but any copy already issued keeps "
                "verifying offline until it expires."
            ),
        }

    # ── Agents ──────────────────────────────────────────────────────────────

    @router.get("/{org_id}/agents")
    async def list_agents(org_id: str):
        await _org_or_404(org_id)
        return {"agent_ids": await intel_db.agent_ids_for_org(org_id)}

    @router.get("/-/unassigned-agents")
    async def unassigned_agents():
        """Agents not yet bound to any customer — the pool to assign from."""
        return {"agent_ids": await intel_db.unassigned_agent_ids()}

    @router.post("/{org_id}/agents")
    async def assign_agents(org_id: str, body: AssignAgents, request: Request):
        """Bind agents. This is the control that decides what the customer sees."""
        await _org_or_404(org_id)
        actor, ip = _actor(request)
        try:
            result = await intel_db.assign_agents_to_org(
                org_id, body.agent_ids, actor=actor,
            )
        except ValueError as exc:
            # Seat cap exceeded, or an agent already belongs elsewhere. Both are
            # the operator's to resolve, so surface the message.
            raise HTTPException(status_code=409, detail=str(exc))
        await intel_db.record_portal_audit(
            org_id=org_id, actor=actor, action="org.agents.assigned",
            detail={"count": len(result["assigned"])}, ip=ip,
        )
        return result

    @router.delete("/{org_id}/agents/{agent_id}")
    async def unassign_agent(org_id: str, agent_id: str, request: Request):
        await _org_or_404(org_id)
        actor, _ip = _actor(request)
        removed = await intel_db.unassign_agent(agent_id, actor=actor)
        if not removed:
            raise HTTPException(status_code=404, detail="Agent is not assigned.")
        return {"agent_ids": await intel_db.agent_ids_for_org(org_id)}

    # ── Users and invites ───────────────────────────────────────────────────

    @router.get("/{org_id}/users")
    async def list_users(org_id: str):
        await _org_or_404(org_id)
        return {"users": await intel_db.list_portal_users(org_id)}

    @router.post("/{org_id}/users", status_code=201)
    async def create_user(org_id: str, body: CreateUser, request: Request):
        """Create a customer login and return its one-time setup link.

        No password is set here and none is chosen by the operator — the
        customer sets their own through this link. The link is in this response
        and nowhere else.
        """
        await _org_or_404(org_id)
        actor, ip = _actor(request)
        existing = await intel_db.get_portal_user_by_email(body.email)
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="That email address already has a portal account.",
            )
        try:
            user = await intel_db.create_portal_user(
                org_id=org_id, email=body.email, role=body.role, actor=actor,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        token = secrets.token_urlsafe(32)
        await intel_db.create_invite(
            user_id=user["user_id"], org_id=org_id,
            token_hash=hash_invite_token(token),
            ttl_seconds=INVITE_TTL_SECONDS, actor=actor,
        )
        await intel_db.record_portal_audit(
            org_id=org_id, actor=actor, action="portal_user.invited",
            detail={"email": body.email}, ip=ip,
        )
        return {
            "user": {k: v for k, v in user.items() if k != "password_hash"},
            "invite_path": f"/portal/accept-invite?token={token}",
            "expires_in_hours": round(INVITE_TTL_SECONDS / 3600),
            "notice": (
                "This setup link is shown once and is single-use. Send it to the "
                "customer over a channel you trust; they choose their own password."
            ),
        }

    @router.post("/{org_id}/users/{user_id}/invite")
    async def resend_invite(org_id: str, user_id: str, request: Request):
        """Issue a fresh setup link, invalidating any outstanding one."""
        await _org_or_404(org_id)
        actor, _ip = _actor(request)
        user = await intel_db.get_portal_user(user_id)
        if user is None or str(user.get("org_id")) != org_id:
            raise HTTPException(status_code=404, detail="User not found.")
        token = secrets.token_urlsafe(32)
        await intel_db.create_invite(
            user_id=user_id, org_id=org_id, token_hash=hash_invite_token(token),
            ttl_seconds=INVITE_TTL_SECONDS, actor=actor,
        )
        return {
            "invite_path": f"/portal/accept-invite?token={token}",
            "expires_in_hours": round(INVITE_TTL_SECONDS / 3600),
            "notice": "Shown once. Any previous link for this user is now dead.",
        }

    @router.post("/{org_id}/users/{user_id}/status")
    async def set_user_status(
        org_id: str, user_id: str, request: Request,
        status: str = Query(..., pattern="^(active|disabled)$"),
    ):
        await _org_or_404(org_id)
        actor, _ip = _actor(request)
        user = await intel_db.get_portal_user(user_id)
        if user is None or str(user.get("org_id")) != org_id:
            raise HTTPException(status_code=404, detail="User not found.")
        await intel_db.set_portal_user_status(user_id, status, actor=actor)
        return {"users": await intel_db.list_portal_users(org_id)}

    # ── Audit ───────────────────────────────────────────────────────────────

    @router.get("/{org_id}/audit")
    async def org_audit(org_id: str, limit: int = Query(100, ge=1, le=500)):
        await _org_or_404(org_id)
        return {"entries": await intel_db.portal_audit_for_org(org_id, limit=limit)}

    return router
