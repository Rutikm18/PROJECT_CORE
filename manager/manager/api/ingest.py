"""
manager/manager/api/ingest.py — POST /api/v1/ingest router.

Pipeline per request:
  1. Parse JSON body
  2. Schema check (required envelope fields)
  3. Timestamp replay window (cheap, no crypto)
  4. Nonce dedup cache
  5. HMAC verify + AES-256-GCM decrypt
  6. Extract canonical fields
  7. Upsert agent registry (SQLite)
  8. Write to TelemetryStore (NDJSON+gzip file store)
  9. Insert payload summary into SQLite (for /agents/{id} section timestamps)
 10. Broadcast to WebSocket subscribers
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request

from ..models import IngestResponse
from shared.wire import (
    REQUIRED_ENVELOPE_FIELDS,
    REPLAY_WINDOW_SECONDS,
)

if TYPE_CHECKING:
    from ..db    import Database
    from ..store import TelemetryStore
    from ..ws_hub import WebSocketHub

log = logging.getLogger("manager.api.ingest")


def make_ingest_router(
    db:          "Database",
    store:       "TelemetryStore",
    hub:         "WebSocketHub",
    nonce_cache: dict,
    jarvis=None,
) -> APIRouter:
    """
    Per-agent key lookup: each enrolled agent has its own 256-bit key stored
    in the agent_keys table.  The ingest pipeline looks up the key by agent_id
    (plaintext field in envelope) before running HMAC+decrypt.

    Even if an attacker spoofs agent_id, HMAC will reject the payload because
    the derived keys will not match the forged agent_id's stored key.
    """
    from ..crypto  import decrypt, derive_keys

    router = APIRouter()

    @router.post("/ingest", response_model=IngestResponse)
    async def ingest(request: Request) -> IngestResponse:

        # ── 1. Parse ─────────────────────────────────────────────────────────
        try:
            envelope = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        # ── 2. Schema check ───────────────────────────────────────────────────
        for field in REQUIRED_ENVELOPE_FIELDS:
            if field not in envelope:
                raise HTTPException(400, f"Missing field: {field}")

        # ── 3. Timestamp window (cheap — before DB + crypto) ─────────────────
        skew = abs(time.time() - float(envelope["timestamp"]))
        if skew > REPLAY_WINDOW_SECONDS:
            raise HTTPException(401, "Timestamp out of window")

        # ── 4. Per-agent key lookup ───────────────────────────────────────────
        raw_agent_id = envelope.get("agent_id", "")
        api_key_hex  = await db.get_agent_key(raw_agent_id)
        if not api_key_hex:
            log.warning("Ingest from unenrolled agent_id=%s — rejected", raw_agent_id)
            raise HTTPException(401, "Agent not enrolled — run enrollment first")
        enc_key, mac_key = derive_keys(api_key_hex)

        # ── 5. HMAC + decrypt ─────────────────────────────────────────────────
        try:
            payload = decrypt(envelope, enc_key, mac_key)
        except ValueError as exc:
            log.warning("Decrypt failed agent=%s: %s", raw_agent_id, exc)
            raise HTTPException(401, "Verification failed")

        # ── 6. Nonce dedup (after successful decrypt — avoids locking out retries) ─
        nonce = envelope["nonce"]
        if nonce in nonce_cache:
            raise HTTPException(401, "Duplicate nonce")
        nonce_cache[nonce] = time.time() + REPLAY_WINDOW_SECONDS

        # ── 7. Extract fields ──────────────────────────────────────────────────
        agent_id   = payload.get("agent_id",    envelope["agent_id"])
        section    = payload.get("section",      envelope.get("section", "unknown"))
        collected  = payload.get("collected_at", int(float(envelope["timestamp"])))
        agent_name = payload.get("agent_name",   "")
        os_name    = payload.get("os",           "macos")
        hostname   = payload.get("hostname",     "")
        data       = payload.get("data",         {})
        client_ip  = request.client.host if request.client else ""

        # ── 8. Agent registry ─────────────────────────────────────────────────
        await db.upsert_agent(agent_id, agent_name, client_ip)

        # ── 9. File store (NDJSON+gzip, three-tier) ───────────────────────────
        try:
            await store.write(
                agent_id=agent_id,
                section=section,
                ts=float(collected),
                data=data,
                os=os_name,
                hostname=hostname,
            )
        except Exception as exc:
            # Non-fatal — log and continue so the agent doesn't retry
            log.error("Store write failed agent=%s section=%s: %s", agent_id, section, exc)

        # ── 10. SQLite payload summary (section timestamps for dashboard) ──────
        await db.insert_payload(agent_id, section, collected, data)

        # ── 11. Jarvis analysis (async, non-blocking) — raw telemetry → verified findings
        if jarvis is not None:
            import asyncio
            asyncio.create_task(jarvis.process(agent_id, section, data))

        # ── 12. WebSocket broadcast ────────────────────────────────────────────
        await hub.broadcast(agent_id, {
            "type":         "payload",
            "agent_id":     agent_id,
            "section":      section,
            "collected_at": collected,
            "data":         data,
        })

        return IngestResponse()

    return router
