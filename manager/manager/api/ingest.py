"""
manager/manager/api/ingest.py — POST /api/v1/ingest router.

Receives encrypted agent payloads, verifies them (schema → timestamp →
nonce → HMAC → decrypt), persists them, and broadcasts to WebSocket
subscribers.

This module is a router factory — it takes dependencies as arguments
instead of using global state, making it cleanly unit-testable.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request

from ..models import IngestResponse

if TYPE_CHECKING:
    from ..db import Database
    from ..ws_hub import WebSocketHub

log = logging.getLogger("manager.api.ingest")


def make_ingest_router(
    db: "Database",
    hub: "WebSocketHub",
    enc_key: bytes,
    mac_key: bytes,
    nonce_cache: dict,
) -> APIRouter:
    """
    Router factory — inject dependencies at app startup.

    Parameters
    ----------
    db          : Database layer (aiosqlite)
    hub         : WebSocket broadcast hub
    enc_key     : AES-256-GCM encryption key (from HKDF)
    mac_key     : HMAC-SHA256 MAC key (from HKDF)
    nonce_cache : Shared dict used for replay-nonce deduplication
    """
    from ..auth import verify_envelope

    router = APIRouter()

    @router.post("/ingest", response_model=IngestResponse)
    async def ingest(request: Request) -> IngestResponse:

        # ── 1. Parse body ────────────────────────────────────────────────
        try:
            envelope = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        # ── 2. Verify (schema → timestamp → nonce → HMAC → decrypt) ─────
        try:
            payload = verify_envelope(envelope, enc_key, mac_key, nonce_cache)
        except ValueError as exc:
            # Log the real reason internally; never leak crypto details.
            log.warning(
                "Ingest rejected  agent=%s  reason=%s",
                envelope.get("agent_id", "?"),
                exc,
            )
            raise HTTPException(401, "Verification failed")

        # ── 3. Extract fields ────────────────────────────────────────────
        agent_id   = payload.get("agent_id",    envelope["agent_id"])
        section    = payload.get("section",      envelope.get("section", "unknown"))
        collected  = payload.get("collected_at", int(envelope["timestamp"]))
        agent_name = payload.get("agent_name",   "")
        data       = payload.get("data",         {})
        client_ip  = request.client.host if request.client else ""

        # ── 4. Persist ───────────────────────────────────────────────────
        await db.upsert_agent(agent_id, agent_name, client_ip)
        await db.insert_payload(agent_id, section, collected, data)

        # ── 5. Broadcast to WebSocket subscribers ────────────────────────
        await hub.broadcast(agent_id, {
            "type":         "payload",
            "agent_id":     agent_id,
            "section":      section,
            "collected_at": collected,
            "data":         data,
        })

        return IngestResponse()

    return router
