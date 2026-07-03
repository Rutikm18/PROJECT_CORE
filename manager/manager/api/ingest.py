"""
manager/manager/api/ingest.py — POST /api/v1/ingest router.

Pipeline per request
--------------------
  1. Parse JSON body
  2. Schema check (required envelope fields)
  3. Timestamp replay window (cheap, no crypto)
  4. Per-agent rate limit check (token bucket — returns 429 if exceeded)
  5. Per-agent concurrency slot (semaphore — returns 429 if agent queue full)
  6. Per-agent key lookup
  7. HMAC verify + AES-256-GCM decrypt
  8. Nonce dedup (DB-backed, restart-safe)
  9. Extract canonical fields
  10. Upsert agent registry

  [Queue mode — RABBITMQ_URL is set]
  11a. Publish to "agent.telemetry" queue → return 202 immediately

  [Sync fallback — no RABBITMQ_URL]
  11b. Write to TelemetryStore (NDJSON+gzip file store)
  12b. Insert payload summary into SQLite
  13b. Broadcast to WebSocket subscribers
  14b. Run AttackLens detection engine (asyncio.create_task — non-blocking)

Rate control algorithm:
  Token bucket (10 req/s sustained, burst 30) per agent.
  Per-agent asyncio.Semaphore (max 4 concurrent) for fair multi-agent queuing.
  Both limits prevent a single agent from monopolising ingest capacity.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request

from ..models import IngestResponse
from shared.wire import (
    REQUIRED_ENVELOPE_FIELDS,
    REPLAY_WINDOW_SECONDS,
    validate_payload,
)

if TYPE_CHECKING:
    from ..db             import Database
    from ..store          import TelemetryStore
    from ..ws_hub         import WebSocketHub
    from ..queue.producer import QueueProducer
    from ..pool           import AgentRateLimiter

log = logging.getLogger("manager.api.ingest")

# Payload-schema validation mode. Default OFF (flag-and-tag) for backward
# compatibility — set ATTACKLENS_INGEST_STRICT_PAYLOAD=1 to reject payloads
# missing required fields with HTTP 422.
_STRICT_PAYLOAD = os.environ.get(
    "ATTACKLENS_INGEST_STRICT_PAYLOAD", ""
).strip().lower() in ("1", "true", "yes", "on")

# In-process observability: per-field gap counts since boot, so the validation
# status page / a metrics scrape can surface "which fields are empty" as a real
# signal instead of silent blanks. Bounded by the fixed field vocabulary.
_SCHEMA_GAPS: Counter = Counter()

# Per-stage ingest counters — turns "no data" into "data stops at stage X".
# Stages: received → decrypt_ok/decrypt_failed → unenrolled → duplicate →
# stored_raw → index_ok/index_failed → detection_dispatched → queued.
_INGEST_STATS: Counter = Counter()
_LAST_INGEST_ERROR: dict = {"stage": None, "error": None, "ts": None}


def schema_gap_stats() -> dict:
    """Snapshot of payload-schema gaps seen since boot (field → count)."""
    return dict(_SCHEMA_GAPS)


def ingest_stats() -> dict:
    """Per-stage ingest counters since boot, for the health/diagnostics endpoint.

    Lets an operator pinpoint where telemetry stops: if `received` climbs but
    `stored_raw` doesn't, the failure is in decrypt/dedup/store; if `stored_raw`
    climbs but `index_ok` doesn't, Deep Analysis (the SQLite index) is the gap;
    if `queued` climbs but raw never lands, the queue workers aren't draining.
    """
    return {
        "counters":   dict(_INGEST_STATS),
        "last_error": dict(_LAST_INGEST_ERROR),
        "schema_gaps": dict(_SCHEMA_GAPS),
        "strict_payload": _STRICT_PAYLOAD,
    }


def _stat(stage: str, n: int = 1) -> None:
    _INGEST_STATS[stage] += n


def _note_error(stage: str, error: str) -> None:
    _INGEST_STATS[f"{stage}_failed"] += 1
    _LAST_INGEST_ERROR.update({"stage": stage, "error": str(error)[:300], "ts": time.time()})


def _record_schema_gaps(agent_id: str, section: str, report: dict) -> None:
    """Count + log a payload that failed schema validation (degraded mode)."""
    for f in report["missing"]:
        _SCHEMA_GAPS[f"missing:{f}"] += 1
    for f in report["empty"]:
        _SCHEMA_GAPS[f"empty:{f}"] += 1
    for f in report["recommended_missing"]:
        _SCHEMA_GAPS[f"recommended_missing:{f}"] += 1
    if report["data_error"]:
        _SCHEMA_GAPS["data_error"] += 1
    elif report["data_empty"]:
        _SCHEMA_GAPS["data_empty"] += 1
    log.warning(
        "payload schema gap agent=%s section=%s missing=%s empty=%s "
        "data_empty=%s data_error=%s recommended_missing=%s",
        agent_id, section, report["missing"], report["empty"],
        report["data_empty"], report["data_error"], report["recommended_missing"],
    )


def make_ingest_router(
    db:           "Database",
    store:        "TelemetryStore",
    hub:          "WebSocketHub",
    nonce_cache:  dict,            # kept for API compatibility; no longer used
    engine:       Optional[object] = None,
    producer:     Optional["QueueProducer"] = None,
    rate_limiter: Optional["AgentRateLimiter"] = None,
) -> APIRouter:
    """
    producer=None       → synchronous pipeline (backward-compatible default).
    producer=QueueProducer → publish-and-return (queue mode).
    rate_limiter=None   → no rate limiting (dev/test only).
    """
    from ..crypto        import decrypt, derive_keys
    from ..queue.schemas import build_telemetry_msg

    router = APIRouter()

    @router.get("/ingest/health")
    async def ingest_health() -> dict:
        """Per-stage ingest diagnostics — pinpoint where telemetry stops.

        `mode` reflects whether queue mode is active (raw store + detection then
        run in the workers, not here). If `received` grows but `stored_raw`
        doesn't, the break is upstream of storage; if `queued` grows in queue
        mode but you see no raw data, the workers aren't draining.
        """
        s = ingest_stats()
        s["mode"] = "queue" if (producer is not None and getattr(producer, "ready", False)) else "sync"
        # Surface the bounded detection executor's live throughput/backlog so an
        # operator can see if detection (not ingest) is the bottleneck under load.
        if engine is not None and hasattr(engine, "detection_stats"):
            try:
                s["detection"] = engine.detection_stats()
            except Exception:
                pass
        # Ledger lag: payloads stored but not yet detected. A growing pending
        # count / oldest_age means the detection pipeline is falling behind or
        # stuck — the reconciler replays these, but persistent lag is a signal.
        try:
            s["ledger"] = await db.ledger_lag()
        except Exception:
            pass
        return s

    @router.post("/ingest", response_model=IngestResponse)
    async def ingest(request: Request) -> IngestResponse:

        _stat("received")
        # ── 1. Parse ──────────────────────────────────────────────────────────
        try:
            envelope = await request.json()
        except Exception:
            _note_error("parse", "invalid JSON")
            raise HTTPException(400, "Invalid JSON body")

        # ── 2. Schema check ───────────────────────────────────────────────────
        for field in REQUIRED_ENVELOPE_FIELDS:
            if field not in envelope:
                raise HTTPException(400, f"Missing field: {field}")

        # ── 3. Timestamp replay window ────────────────────────────────────────
        # 401 (not 400): stale timestamp is a security rejection (replay protection),
        # not a client schema error.
        skew = abs(time.time() - float(envelope["timestamp"]))
        if skew > REPLAY_WINDOW_SECONDS:
            raise HTTPException(401, "Timestamp out of window — replay rejected")

        raw_agent_id = envelope.get("agent_id", "")

        # ── 4. Per-agent rate limit ───────────────────────────────────────────
        if rate_limiter is not None:
            if not rate_limiter.check_rate(raw_agent_id):
                raise HTTPException(
                    429,
                    detail=f"Rate limit exceeded for agent {raw_agent_id}. "
                           "Retry after 1s.",
                    headers={"Retry-After": "1"},
                )

        # ── 5. Per-agent concurrency slot ─────────────────────────────────────
        if rate_limiter is not None:
            try:
                slot_ctx = rate_limiter.agent_slot(raw_agent_id, timeout=8.0)
            except Exception:
                slot_ctx = None  # type: ignore[assignment]
        else:
            slot_ctx = None

        async def _run_pipeline():
            # ── 6. Per-agent key lookup ───────────────────────────────────────
            api_key_hex = await db.get_agent_key(raw_agent_id)
            if not api_key_hex:
                log.warning("Ingest from unenrolled agent_id=%s — rejected", raw_agent_id)
                raise HTTPException(401, "Agent not enrolled — run enrollment first")
            enc_key, mac_key = derive_keys(api_key_hex)

            # ── 7. HMAC + decrypt ─────────────────────────────────────────────
            try:
                payload = decrypt(envelope, enc_key, mac_key)
            except ValueError as exc:
                _note_error("decrypt", exc)
                log.warning("Decrypt failed agent=%s: %s", raw_agent_id, exc)
                raise HTTPException(401, "Verification failed")

            # ── 8. Nonce dedup (DB-backed, IDEMPOTENT) ────────────────────────
            # The nonce is recorded only AFTER successful persistence (below), so
            # a nonce we've already seen means the payload was fully stored once.
            # We ACK it idempotently (200) instead of returning 401 — an
            # at-least-once retry (e.g. the agent's 200 response was lost) must
            # not be miscounted by the agent as an auth failure, which would
            # trip the re-enrollment spiral and wipe its spool. A retry whose
            # original persistence FAILED (503) was never recorded, so it falls
            # through and is reprocessed here — no silent loss.
            nonce = envelope["nonce"]
            if await db.nonce_seen(nonce):
                _stat("duplicate")
                log.debug("Idempotent duplicate agent=%s nonce=%s — already stored",
                          raw_agent_id, nonce[:12])
                return IngestResponse(status="duplicate", queued=False)

            # ── 8b. Payload-schema validation ─────────────────────────────────
            # The envelope was validated at step 2; the *payload* historically
            # was not — missing/empty inner fields were silently defaulted. Now
            # we validate against the canonical contract and either flag (count +
            # log, default) or reject (HTTP 422, strict mode). Backward-compatible.
            report = validate_payload(payload)
            if not report["ok"]:
                _record_schema_gaps(
                    payload.get("agent_id", raw_agent_id),
                    payload.get("section", envelope.get("section", "unknown")),
                    report,
                )
                if _STRICT_PAYLOAD and (report["missing"] or report["empty"]):
                    raise HTTPException(
                        422,
                        detail=("Payload schema invalid — "
                                f"missing={report['missing']} empty={report['empty']}"),
                    )

            # ── 9. Extract fields ─────────────────────────────────────────────
            agent_id   = payload.get("agent_id",    envelope["agent_id"])
            section    = payload.get("section",      envelope.get("section", "unknown"))
            collected  = payload.get("collected_at", int(float(envelope["timestamp"])))
            agent_name = payload.get("agent_name",   "")
            os_name    = payload.get("os",           "macos")
            hostname   = payload.get("hostname",     "")
            data       = payload.get("data",         {})
            client_ip  = request.client.host if request.client else ""

            # ── 10. Agent registry ────────────────────────────────────────────
            await db.upsert_agent(agent_id, agent_name, client_ip)

            # ── 11a. Queue mode ───────────────────────────────────────────────
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
                    # Durably handed off → record nonce so retries are idempotent.
                    await db.store_nonce(nonce, REPLAY_WINDOW_SECONDS)
                    _stat("queued")
                    log.debug("Queued: agent=%s section=%s", agent_id, section)
                    return IngestResponse(status="queued", queued=True)
                except Exception as exc:
                    log.error(
                        "Queue publish failed (sync fallback) agent=%s: %s",
                        agent_id, exc,
                    )

            # ── 11b–14b. Sync pipeline ────────────────────────────────────────

            # Step 1: persist to file store.
            # On failure return 503 so the agent spools and retries — never
            # return 200 here, that would cause silent permanent data loss.
            try:
                await store.write(
                    agent_id=agent_id, section=section, ts=float(collected),
                    data=data, os=os_name, hostname=hostname,
                )
            except OSError as exc:
                log.error(
                    "Store write I/O error agent=%s section=%s path=%s: %s",
                    agent_id, section,
                    getattr(exc, "filename", "unknown"),
                    exc,
                )
                raise HTTPException(
                    503,
                    detail="Storage unavailable — agent should retry",
                ) from exc
            except Exception as exc:
                log.error(
                    "Store write failed agent=%s section=%s: %s",
                    agent_id, section, exc,
                )
                raise HTTPException(
                    503,
                    detail="Storage error — agent should retry",
                ) from exc

            _stat("stored_raw")
            # Persisted durably to the file store → NOW record the nonce, so any
            # retry of this exact envelope is idempotently ack'd rather than
            # reprocessed. (Stored after store.write, never before — a 503 above
            # leaves the nonce unrecorded so the retry is reprocessed, not lost.)
            await db.store_nonce(nonce, REPLAY_WINDOW_SECONDS)

            # Step 2: update SQLite index. Failure here is non-fatal for the
            # file-store record (already written above) but we log clearly so
            # operators can detect index drift.
            try:
                await db.insert_payload(agent_id, section, int(float(collected)), data)
                _stat("index_ok")
            except Exception as exc:
                # NOTE: this is the SILENT failure that makes Deep Analysis empty —
                # /api/v1/raw reads this SQLite index. Surfaced via the counter +
                # last_error so it's no longer invisible. Still non-fatal (the file
                # store has the record and the index can be rebuilt).
                _note_error("index", exc)
                log.error(
                    "DB index write failed agent=%s section=%s ts=%s: %s — "
                    "file-store record exists but DB index (Deep Analysis) is behind",
                    agent_id, section, collected, exc,
                )

            # Step 3: hand to the bounded detection executor (non-blocking,
            # never crashes ingest). engine.enqueue() caps concurrent detection
            # at a fixed worker pool instead of spawning an unbounded task per
            # payload — keeps ingest latency flat and detection memory bounded
            # under large data volumes. A saturated queue drops + counts (raw
            # telemetry is already persisted above and is reprocessable).
            if engine is not None:
                accepted = engine.enqueue(
                    agent_id, section, data, collected_at=float(collected)
                )
                _stat("detection_dispatched" if accepted else "detection_dropped")

            # Step 4: push to live dashboard — totally optional; never crashes ingest.
            try:
                await hub.broadcast(agent_id, {
                    "type":         "payload",
                    "agent_id":     agent_id,
                    "section":      section,
                    "collected_at": collected,
                    "data":         data,
                })
            except Exception as exc:
                log.debug("WebSocket broadcast failed (non-fatal) agent=%s: %s",
                          agent_id, exc)

            return IngestResponse(status="ok", queued=False)

        # Run inside concurrency slot if rate limiter is active
        if slot_ctx is not None:
            try:
                async with slot_ctx:
                    return await _run_pipeline()
            except asyncio.TimeoutError:
                raise HTTPException(
                    429,
                    detail=f"Agent {raw_agent_id} queue full — retry in a moment.",
                    headers={"Retry-After": "2"},
                )
        else:
            return await _run_pipeline()

    return router
