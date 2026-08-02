"""
manager/manager/workers/telemetry.py — TelemetryWorker.

Consumes the "agent.telemetry" queue and performs the storage pipeline:
  1. Commit the exact event outbox and idempotent PostgreSQL raw row
  2. Optionally mirror to the local NDJSON+gzip archive
  3. Broadcast to WebSocket subscribers
  4. Publish every chunk to the "attacklens.work" queue

This offloads all heavy I/O from the ingest HTTP request path.
The HTTP handler now returns in <5ms (crypto + publish only).

Concurrency model
-----------------
Runs as an asyncio task within the FastAPI process.
Reconnects automatically on RabbitMQ failure (exponential backoff, max 60s).
Prefetch = 20: process up to 20 messages concurrently (bounded by asyncio event loop).
Messages are manually ACK'd after successful processing.
On exception → NACK without requeue → message goes to mac_intel.dead DLQ.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import TYPE_CHECKING

import aio_pika

from ..queue.connection import declare_topology
from ..queue.schemas import QUEUE_TELEMETRY, build_attacklens_msg
from ..queue.producer import QueueProducer
from ..chunker import CHUNK_SIZE, split as chunk_split
from shared.sections import canonical_section

if TYPE_CHECKING:
    from ..db    import Database
    from ..store import TelemetryStore
    from ..ws_hub import WebSocketHub

log = logging.getLogger("manager.workers.telemetry")

_PREFETCH   = max(1, int(os.environ.get("TELEMETRY_RABBIT_CONCURRENCY", "20")))
_RETRY_BASE = 5      # initial reconnect delay (seconds)
_RETRY_MAX  = 60     # max reconnect delay


class TelemetryWorker:
    """
    Async consumer for the agent.telemetry queue.
    Run via: asyncio.create_task(worker.run())
    """

    def __init__(
        self,
        rabbitmq_url: str,
        db:           "Database",
        store:        "TelemetryStore",
        hub:          "WebSocketHub",
        producer:     QueueProducer,
    ) -> None:
        self._url      = rabbitmq_url
        self._db       = db
        self._store    = store
        self._hub      = hub
        self._producer = producer
        self._running  = True
        self._agent_locks: dict[str, asyncio.Lock] = {}
        self._tasks: set[asyncio.Task] = set()
        self._connection = None

    async def run(self) -> None:
        """Main loop: connect → consume → reconnect on failure."""
        delay = _RETRY_BASE
        while self._running:
            try:
                await self._connect_and_consume()
                delay = _RETRY_BASE  # reset after clean exit
            except asyncio.CancelledError:
                break
            except Exception as exc:
                if not self._running:
                    break
                log.error("TelemetryWorker error — retry in %ss: %s", delay, exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RETRY_MAX)

    async def stop(self) -> None:
        self._running = False
        if self._connection is not None:
            try:
                await self._connection.close()
            except Exception:
                pass

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _connect_and_consume(self) -> None:
        conn    = await aio_pika.connect_robust(self._url)
        self._connection = conn
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=_PREFETCH)

        _, _ = await declare_topology(channel)
        queue = await channel.get_queue(QUEUE_TELEMETRY)

        log.info("TelemetryWorker consuming from %s (prefetch=%d)", QUEUE_TELEMETRY, _PREFETCH)

        try:
            async with queue.iterator() as msgs:
                async for msg in msgs:
                    if not self._running:
                        break
                    task = asyncio.create_task(self._handle(msg))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        finally:
            pending = list(self._tasks)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            try:
                await conn.close()
            finally:
                if self._connection is conn:
                    self._connection = None

    async def _handle(self, msg: aio_pika.IncomingMessage) -> None:
        try:
            async with msg.process(requeue=False, ignore_processed=True):
                body = json.loads(msg.body)
                agent_id = str(body.get("agent_id") or "")
                lock = self._agent_locks.setdefault(agent_id, asyncio.Lock())
                async with lock:
                    await self._process(body)
        except Exception as exc:
            log.error(
                "TelemetryWorker failed to process msg agent=%s: %s",
                msg.body[:80] if msg.body else "?", exc,
            )

    async def _process(self, msg: dict) -> None:
        agent_id    = msg["agent_id"]
        section     = canonical_section(msg["section"])
        data        = msg["data"]
        collected   = float(msg.get("collected_at", time.time()))
        agent_name  = msg.get("agent_name", "")
        os_name     = msg.get("os", "macos")
        hostname    = msg.get("hostname", "")
        event_id = str(msg.get("event_id") or "")
        if not event_id:
            event_id = "legacy:" + hashlib.sha256(
                json.dumps(msg, sort_keys=True, default=str).encode()
            ).hexdigest()
        chunks = chunk_split(data, chunk_set_id=event_id)

        # Critical source of truth: exact event outbox + idempotent PostgreSQL
        # raw row. Both are safe with many telemetry workers/manager replicas.
        await self._db.ledger_received(
            agent_id, section, collected,
            event_id=event_id, data=data, chunk_total=len(chunks), chunk_size=CHUNK_SIZE,
            metadata={"agent_name": agent_name, "os": os_name, "hostname": hostname},
        )
        await self._db.insert_payload(
            agent_id, section, int(collected), data, event_id=event_id,
        )
        await self._db.ledger_received(
            agent_id, section, collected,
            event_id=event_id, data=data, chunk_total=len(chunks), chunk_size=CHUNK_SIZE,
            stored=True,
            metadata={"agent_name": agent_name, "os": os_name, "hostname": hostname},
        )

        # Optional file archive. It is disabled in horizontally-scaled mode;
        # PostgreSQL remains authoritative for Deep Analysis and replay.
        try:
            await self._store.write(
                agent_id=agent_id, section=section, ts=collected, data=data,
                os=os_name, hostname=hostname, event_id=event_id,
            )
        except Exception as exc:
            log.warning("optional telemetry archive write failed event_id=%s: %s", event_id, exc)

        # 3. WebSocket broadcast (best-effort — dashboard update)
        try:
            await self._hub.broadcast(agent_id, {
                "type":         "payload",
                "agent_id":     agent_id,
                "section":      section,
                "collected_at": collected,
                "data":         data,
            })
        except Exception as exc:
            log.debug("WS broadcast failed agent=%s: %s", agent_id, exc)

        # 4. Fan-out to attacklens.work — CRITICAL (this IS the detection trigger).
        # A failure here must NOT ack: losing it means the payload is stored but
        # never analysed. Re-raise → nack → DLQ → replayer. Re-processing is safe:
        # PostgreSQL writes are idempotent by event_id and detection dedups by
        # durable event/chunk completion plus finding fingerprint.
        for chunk in chunks:
            await self._producer.publish_attacklens_work(
                build_attacklens_msg(
                    agent_id=agent_id,
                    section=section,
                    collected_at=collected,
                    data=chunk.data,
                    event_id=event_id,
                    chunk_set_id=chunk.chunk_set_id,
                    chunk_index=chunk.chunk_index,
                    chunk_total=chunk.chunk_total,
                )
            )
        if len(chunks) > 1:
            log.info(
                "Chunked: agent=%s section=%s items=%d → %d chunks",
                agent_id, section, len(data), len(chunks),
            )

        log.debug("Telemetry processed: agent=%s section=%s", agent_id, section)
