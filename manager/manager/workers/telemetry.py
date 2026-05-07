"""
manager/manager/workers/telemetry.py — TelemetryWorker.

Consumes the "agent.telemetry" queue and performs the storage pipeline:
  1. Write payload to three-tier file store (NDJSON+gzip)
  2. Insert payload summary into SQLite (section timestamps for dashboard)
  3. Broadcast to WebSocket subscribers
  4. Publish pre-validated payload to "jarvis.work" queue

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
import json
import logging
import time
from typing import TYPE_CHECKING

import aio_pika

from ..queue.connection import declare_topology
from ..queue.schemas import QUEUE_TELEMETRY, build_jarvis_msg
from ..queue.producer import QueueProducer
from ..chunker import split as chunk_split

if TYPE_CHECKING:
    from ..db    import Database
    from ..store import TelemetryStore
    from ..ws_hub import WebSocketHub

log = logging.getLogger("manager.workers.telemetry")

_PREFETCH   = 20     # concurrent messages in flight
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
                log.error("TelemetryWorker error — retry in %ss: %s", delay, exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RETRY_MAX)

    async def stop(self) -> None:
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _connect_and_consume(self) -> None:
        conn    = await aio_pika.connect_robust(self._url)
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=_PREFETCH)

        _, _ = await declare_topology(channel)
        queue = await channel.get_queue(QUEUE_TELEMETRY)

        log.info("TelemetryWorker consuming from %s (prefetch=%d)", QUEUE_TELEMETRY, _PREFETCH)

        async with queue.iterator() as msgs:
            async for msg in msgs:
                if not self._running:
                    break
                async with msg.process(requeue=False, ignore_processed=True):
                    try:
                        body = json.loads(msg.body)
                        await self._process(body)
                    except Exception as exc:
                        log.error(
                            "TelemetryWorker failed to process msg agent=%s section=%s: %s",
                            msg.body[:80] if msg.body else "?", "", exc,
                        )
                        raise  # nack → DLQ

        await conn.close()

    async def _process(self, msg: dict) -> None:
        agent_id    = msg["agent_id"]
        section     = msg["section"]
        data        = msg["data"]
        collected   = float(msg.get("collected_at", time.time()))
        agent_name  = msg.get("agent_name", "")
        os_name     = msg.get("os", "macos")
        hostname    = msg.get("hostname", "")

        # 1. Three-tier file store
        try:
            await self._store.write(
                agent_id=agent_id,
                section=section,
                ts=collected,
                data=data,
                os=os_name,
                hostname=hostname,
            )
        except Exception as exc:
            log.error("Store write failed agent=%s section=%s: %s", agent_id, section, exc)

        # 2. SQLite payload summary (section timestamps for dashboard)
        try:
            await self._db.insert_payload(agent_id, section, int(collected), data)
        except Exception as exc:
            log.error("DB insert_payload failed agent=%s section=%s: %s", agent_id, section, exc)

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

        # 4. Fan-out to jarvis.work — chunk large list payloads
        try:
            chunks = chunk_split(data)
            for chunk in chunks:
                await self._producer.publish_jarvis_work(
                    build_jarvis_msg(
                        agent_id=agent_id,
                        section=section,
                        collected_at=collected,
                        data=chunk.data,
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
        except Exception as exc:
            log.warning("Jarvis publish failed agent=%s section=%s: %s", agent_id, section, exc)

        log.debug("Telemetry processed: agent=%s section=%s", agent_id, section)
