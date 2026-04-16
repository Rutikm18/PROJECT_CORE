"""
manager/manager/api/keys.py — Key management endpoints.

All routes require X-Admin-Token header matching ADMIN_TOKEN env var.

Routes
──────
  GET    /api/v1/keys                      — list all agent key metadata
  GET    /api/v1/keys/{agent_id}           — single agent key metadata
  POST   /api/v1/keys/{agent_id}/rotate    — generate + store a new key
  PATCH  /api/v1/keys/{agent_id}/expiry    — set / extend / clear expiry
  POST   /api/v1/keys/{agent_id}/revoke    — mark key revoked (agent can't ingest)
  DELETE /api/v1/keys/{agent_id}           — hard-delete key (agent must re-enroll)

The actual key hex is NEVER returned by GET endpoints — only metadata.
The new key is returned only on POST /rotate (one-time visibility).
"""
from __future__ import annotations

import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel

log = logging.getLogger("manager.keys")


# ── Admin auth dependency ─────────────────────────────────────────────────────

def _make_admin_auth(admin_token: str):
    """Returns a FastAPI dependency that checks X-Admin-Token."""
    async def _check(x_admin_token: str = Header(default="")):
        if not admin_token:
            raise HTTPException(
                status_code=503,
                detail="Key management API unavailable: ADMIN_TOKEN not configured",
            )
        if x_admin_token.strip() != admin_token:
            raise HTTPException(status_code=401, detail="Invalid admin token")
    return _check


# ── Request models ────────────────────────────────────────────────────────────

class ExpiryRequest(BaseModel):
    """
    expires_at: absolute unix epoch (0 = never expires).
    expires_in_days: convenience — number of days from now.
    If both are provided, expires_in_days takes precedence.
    """
    expires_at:      int = 0
    expires_in_days: int = 0


class RotateRequest(BaseModel):
    """Optional label for the new key (for audit purposes)."""
    label: str = ""


# ── Router factory ────────────────────────────────────────────────────────────

def make_keys_router(db, admin_token: str) -> APIRouter:
    router   = APIRouter()
    auth_dep = _make_admin_auth(admin_token)

    # ── List all keys ─────────────────────────────────────────────────────────

    @router.get("")
    async def list_keys(_: None = Depends(auth_dep)):
        """Return metadata for every agent's key (no key hex values)."""
        return {"keys": await db.list_key_meta()}

    # ── Single agent key metadata ─────────────────────────────────────────────

    @router.get("/{agent_id}")
    async def get_key(agent_id: str, _: None = Depends(auth_dep)):
        meta = await db.get_key_meta(agent_id)
        if not meta:
            raise HTTPException(status_code=404, detail="Agent not found")
        return meta

    # ── Rotate key ────────────────────────────────────────────────────────────

    @router.post("/{agent_id}/rotate")
    async def rotate_key(
        agent_id: str,
        body: RotateRequest = RotateRequest(),
        _: None = Depends(auth_dep),
    ):
        """
        Generate a new 256-bit key for the agent and store it.
        Returns the new key (one-time — save it now, it won't be shown again).
        The agent must call POST /api/v1/enroll again to receive the new key,
        or you can push the key out-of-band via your own mechanism.

        The old key is invalidated immediately after this call.
        """
        existing = await db.get_key_meta(agent_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Agent not found")

        new_key = secrets.token_hex(32)
        await db.upsert_agent_key(
            agent_id, new_key,
            enrolled_ip=existing.get("enrollment_ip", ""),
            expires_at=existing.get("expires_at", 0),
            label=body.label or existing.get("key_label", ""),
        )
        log.info("Key rotated for agent_id=%s", agent_id)

        return {
            "ok":        True,
            "agent_id":  agent_id,
            "api_key":   new_key,      # show once — agent needs to re-enroll
            "rotated_at": int(time.time()),
            "note": (
                "The agent must re-enroll (POST /api/v1/enroll with a valid "
                "enrollment token) to receive and store the new key automatically, "
                "or manually update the key in the agent's keystore."
            ),
        }

    # ── Set expiry ────────────────────────────────────────────────────────────

    @router.patch("/{agent_id}/expiry")
    async def set_expiry(
        agent_id: str,
        body: ExpiryRequest,
        _: None = Depends(auth_dep),
    ):
        """
        Set or update key expiry.
        - expires_in_days=30 → expires 30 days from now
        - expires_at=<epoch>  → expires at that exact timestamp
        - expires_at=0        → never expires (clear expiry)
        """
        if body.expires_in_days > 0:
            expires_at = int(time.time()) + body.expires_in_days * 86400
        else:
            expires_at = body.expires_at

        ok = await db.set_key_expiry(agent_id, expires_at)
        if not ok:
            raise HTTPException(status_code=404, detail="Agent not found")

        log.info(
            "Key expiry updated: agent_id=%s expires_at=%s",
            agent_id, expires_at or "never",
        )
        return {
            "ok":        True,
            "agent_id":  agent_id,
            "expires_at": expires_at,
            "expires_human": (
                "never" if expires_at == 0
                else time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                   time.gmtime(expires_at))
            ),
        }

    # ── Revoke key ────────────────────────────────────────────────────────────

    @router.post("/{agent_id}/revoke")
    async def revoke_key(agent_id: str, _: None = Depends(auth_dep)):
        """
        Revoke the agent's key immediately. The agent can no longer send data.
        The key record is kept (use DELETE to remove it entirely).
        To restore access: rotate the key or set a new one via re-enrollment.
        """
        ok = await db.revoke_key(agent_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Agent not found")
        log.warning("Key revoked for agent_id=%s", agent_id)
        return {"ok": True, "agent_id": agent_id, "revoked": True}

    # ── Hard delete key ───────────────────────────────────────────────────────

    @router.delete("/{agent_id}")
    async def delete_key(agent_id: str, _: None = Depends(auth_dep)):
        """
        Hard-delete the agent's key record.
        The agent must re-enroll with a valid enrollment token to resume sending.
        """
        ok = await db.delete_agent_key(agent_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Agent key not found")
        log.warning("Key deleted for agent_id=%s", agent_id)
        return {"ok": True, "agent_id": agent_id, "deleted": True}

    return router
