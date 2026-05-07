"""
manager/manager/api/ingest.py — POST /api/v1/ingest router.

Pipeline per request
--------------------
  1. Parse JSON body
  2. Schema check (required envelope fields)
  3. Timestamp replay window (cheap, no crypto)
  4. Per-agent key lookup
  5. HMAC verify + AES-256-GCM decrypt
  6. Nonce dedup cache
  7. Extract canonical fields
  8. Upsert agent registry

  [Queue mode — RABBITMQ_URL is set]
  9a. Publish to "agent.telemetry" queue → return 202 immediately
      TelemetryWorker handles file store + SQLite + WS + Jarvis asynchronously.

  [Sync fallback — no RABBITMQ_URL]
  9b. Write to TelemetryStore (NDJSON+gzip file store)
  10b. Insert payload summary into SQLite
  11b. Broadcast to WebSocket subscribers
  12b. Run Jarvis analysis (asyncio.create_task — non-blocking)

The HTTP response is identical either way from the agent's perspective.
`queued=True` in the JSON body indicates which path ran.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request

from ..models import IngestResponse
from shared.wire import (
    REQUIRED_ENVELOPE_FIELDS,
    REPLAY_WINDOW_SECONDS,
)

if TYPE_CHECKING:
    from ..db             import Database
    from ..store          import TelemetryStore
    from ..ws_hub         import WebSocketHub
    from ..queue.producer import QueueProducer

log = logging.getLogger("manager.api.ingest")


def make_ingest_router(
    db:          "Database",
    store:       "TelemetryStore",
    hub:         "WebSocketHub",
    nonce_cache: dict,
    jarvis:      Optional[object] = None,
    producer:    Optional["QueueProducer"] = None,
) -> APIRouter:
    """
    producer=None  → synchronous pipeline (backward-compatible default).
    producer=QueueProducer  → publish-and-return (queue mode).
    """
    from ..crypto        import decrypt, derive_keys
    from ..queue.schemas import build_telemetry_msg

    router = APIRouter()

    @router.post("/ingest", response_model=IngestResponse)
    async def ingest(request: Request) -> IngestResponse:

        # ── 1. Parse ──────────────────────────────────────────────────────────
        try:
            envelope = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON body")

        # ── 2. Schema check ───────────────────────────────────────────────────
        for field in REQUIRED_ENVELOPE_FIELDS:
            if field not in envelope:
                raise HTTPException(400, f"Missing field: {field}")

        # ── 3. Timestamp replay window ────────────────────────────────────────
        skew = abs(time.time() - float(envelope["timestamp"]))
        if skew > REPLAY_WINDOW_SECONDS:
            raise HTTPException(400, "Timestamp out of window")

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

        # ── 6. Nonce dedup (after successful decrypt) ─────────────────────────
        nonce = envelope["nonce"]
        if nonce in nonce_cache:
            raise HTTPException(401, "Duplicate nonce")
        nonce_cache[nonce] = time.time() + REPLAY_WINDOW_SECONDS

        # ── 7. Extract fields ─────────────────────────────────────────────────
        agent_id   = payload.get("agent_id",    envelope["agent_id"])
        section    = payload.get("section",      envelope.get("section", "unknown"))
        collected  = payload.get("collected_at", int(float(envelope["timestamp"])))
        agent_name = payload.get("agent_name",   "")
        os_name    = payload.get("os",           "macos")
        hostname   = payload.get("hostname",     "")
        data       = payload.get("data",         {})
        client_ip  = request.client.host if request.client else ""

        # ── 8. Agent registry (always — even in queue mode) ───────────────────
        await db.upsert_agent(agent_id, agent_name, client_ip)

        # ── 9a. Queue mode ────────────────────────────────────────────────────
        if producer is not None and producer.ready:
            try:
                await producer.publish_telemetry(
                    build_telemetry_msg(
                        agent_id     = agent_id,
                        agent_name   = agent_name,
                        hostname     = hostname,
                        os_name      = os_name,
                        section      = section,
                        collected_at = float(collected),
                        client_ip    = client_ip,
                        data         = data,
                    )
                )
                log.debug("Queued: agent=%s section=%s", agent_id, section)
                return IngestResponse(status="queued", queued=True)
            except Exception as exc:
                # Publish failed — degrade gracefully to sync pipeline.
                log.error(
                    "Queue publish failed (sync fallback) agent=%s: %s",
                    agent_id, exc,
                )

        # ── 9b–12b. Sync pipeline (no queue or publish failure) ───────────────
        try:
            await store.write(
                agent_id=agent_id, section=section, ts=float(collected),
                data=data, os=os_name, hostname=hostname,
            )
        except Exception as exc:
            log.error("Store write failed agent=%s section=%s: %s", agent_id, section, exc)

        await db.insert_payload(agent_id, section, collected, data)

        if jarvis is not None:
            asyncio.create_task(jarvis.process(agent_id, section, data))

        await hub.broadcast(agent_id, {
            "type":         "payload",
            "agent_id":     agent_id,
            "section":      section,
            "collected_at": collected,
            "data":         data,
        })

        return IngestResponse(status="ok", queued=False)

    return router
