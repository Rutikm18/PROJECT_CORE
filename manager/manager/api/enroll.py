"""
manager/manager/api/enroll.py — POST /api/v1/enroll

Agent enrollment endpoint.

Key generation model (v2)
─────────────────────────
The MANAGER generates the 256-bit API key and returns it in the response body.
The agent stores the returned key in its keystore.  This gives the operator
full control: keys can be rotated, expired, or revoked from the manager side
at any time without the agent needing to know ahead of time.

Enrollment modes
────────────────
  open_enrollment=True  (default, OPEN_ENROLLMENT env var)
    Any agent can enroll without a token.  Best for single-operator use or
    internal networks.  The first agent with a given agent_id wins; subsequent
    calls from the same ID rotate the key.

  open_enrollment=False (token required)
    Agent must send X-Enrollment-Token matching ENROLLMENT_TOKENS env var.
    Use this when multiple operators share a manager and you need to gate
    which machines can connect.

Flow
────
  1. Agent calls POST /api/v1/enroll with optional X-Enrollment-Token +
     agent metadata (agent_id, name, hostname, os, arch, timestamp).
  2. Manager validates token if required.
  3. Manager generates secrets.token_hex(32) → 64-hex API key.
  4. Manager stores agent_id → api_key in SQLite with optional expiry.
  5. Manager returns {"ok": true, "api_key": "<64hex>", "expires_at": <ts>}.
  6. Agent saves the returned key; uses it for all subsequent ingest calls.
"""
from __future__ import annotations

import logging
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

log = logging.getLogger("manager.enroll")

_HEX_CHARS = frozenset("0123456789abcdef")

# Default key validity: 0 = never expires.
import os as _os
_DEFAULT_EXPIRY_DAYS = int(_os.environ.get("DEFAULT_KEY_EXPIRY_DAYS", "0"))


class EnrollRequest(BaseModel):
    agent_id:   str
    agent_name: str
    hostname:   str
    os:         str
    arch:       str
    timestamp:  int
    # api_key is optional — old agents may send it; new agents omit it.
    api_key:    str | None = None


def make_enroll_router(
    db,
    enrollment_tokens: list[str],
    open_enrollment: bool = True,
) -> APIRouter:
    router = APIRouter()

    @router.post("/enroll")
    async def enroll(req: Request, body: EnrollRequest):
        client_ip = req.client.host if req.client else "unknown"

        # ── Token check (skipped in open-enrollment mode) ─────────────────────
        if not open_enrollment:
            token = req.headers.get("X-Enrollment-Token", "").strip()
            if not enrollment_tokens:
                log.error(
                    "Token-mode enrollment but ENROLLMENT_TOKENS not set — "
                    "set OPEN_ENROLLMENT=true or configure ENROLLMENT_TOKENS"
                )
                raise HTTPException(status_code=503, detail="Enrollment not configured")
            if not token or token not in enrollment_tokens:
                log.warning(
                    "Enrollment rejected: bad token from %s (agent_id=%s)",
                    client_ip, body.agent_id,
                )
                raise HTTPException(status_code=401, detail="Invalid enrollment token")

        # ── Validate agent_id ─────────────────────────────────────────────────
        agent_id = body.agent_id.strip()
        if not agent_id or len(agent_id) > 128:
            raise HTTPException(status_code=400, detail="Invalid agent_id")

        # ── Timestamp skew (±5 min) ───────────────────────────────────────────
        if abs(time.time() - body.timestamp) > 300:
            raise HTTPException(status_code=400, detail="Timestamp out of range")

        # ── Key: accept agent-provided OR generate a new one ──────────────────
        if body.api_key:
            key = body.api_key.lower()
            if len(key) != 64 or not all(c in _HEX_CHARS for c in key):
                raise HTTPException(
                    status_code=400,
                    detail="api_key must be exactly 64 lowercase hex chars",
                )
        else:
            key = secrets.token_hex(32)   # manager-generated 256-bit key

        # ── Compute expiry ────────────────────────────────────────────────────
        expires_at = 0
        if _DEFAULT_EXPIRY_DAYS > 0:
            expires_at = int(time.time()) + _DEFAULT_EXPIRY_DAYS * 86400

        # ── Store ─────────────────────────────────────────────────────────────
        is_rotation = (await db.get_agent_key(agent_id)) is not None
        await db.upsert_agent_key(
            agent_id, key,
            enrolled_ip=client_ip,
            expires_at=expires_at,
        )
        await db.upsert_agent(agent_id, body.agent_name, client_ip)

        action = "re-enrolled (key rotation)" if is_rotation else "enrolled"
        mode   = "open" if open_enrollment else "token"
        log.info(
            "Agent %s [%s]: agent_id=%s name=%r os=%s arch=%s hostname=%s ip=%s",
            action, mode, agent_id, body.agent_name,
            body.os, body.arch, body.hostname, client_ip,
        )

        return {
            "ok":           True,
            "agent_id":     agent_id,
            "api_key":      key,           # returned to agent for storage
            "expires_at":   expires_at,    # 0 = never
            "rotated":      is_rotation,
            "open_enrollment": open_enrollment,
        }

    return router
