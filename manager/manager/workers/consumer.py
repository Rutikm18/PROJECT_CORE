"""manager/manager/workers/consumer.py — High-throughput agent.telemetry consumer."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING

import aio_pika

from ..queue.connection import declare_topology
from ..queue.schemas    import QUEUE_TELEMETRY, build_jarvis_msg
from ..chunker          import split as chunk_split

if TYPE_CHECKING:
    from ..db              import Database
    from ..store           import TelemetryStore
    from ..ws_hub          import WebSocketHub
    from ..queue.producer  import QueueProducer
    from ..jarvis.engine   import JarvisEngine

log = logging.getLogger("manager.workers.consumer")

_PREFETCH    = 50
_MAX_INFLIGHT = 10
_RETRY_BASE  = 2
_RETRY_MAX   = 60


class TelemetryConsumer:
    """At-least-once consumer of agent.telemetry — drives store, db, jarvis, ws."""

    def __init__(
        self,
        rabbitmq_url: str,
        db:           "Database",
        store:        "TelemetryStore",
        hub:          "WebSocketHub",
        producer:     "QueueProducer",
        jarvis:       "JarvisEngine | None" = None,
    ) -> None:
        self._url      = rabbitmq_url
        self._db       = db
        self._store    = store
        self._hub      = hub
        self._producer = producer
        self._jarvis   = jarvis
        self._running  = True
        self._sem      = asyncio.Semaphore(_MAX_INFLIGHT)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        delay = _RETRY_BASE
        while self._running:
            try:
                await self._connect_and_consume()
                delay = _RETRY_BASE
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("TelemetryConsumer error — retry in %ss: %s", delay, exc)
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    break
                delay = min(delay * 2, _RETRY_MAX)

    async def stop(self) -> None:
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _connect_and_consume(self) -> None:
        conn    = await aio_pika.connect_robust(self._url)
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=_PREFETCH)

        await declare_topology(channel)
        queue = await channel.get_queue(QUEUE_TELEMETRY)

        log.info(
            "TelemetryConsumer consuming from %s (prefetch=%d, inflight=%d)",
            QUEUE_TELEMETRY, _PREFETCH, _MAX_INFLIGHT,
        )

        try:
            async with queue.iterator() as msgs:
                async for msg in msgs:
                    if not self._running:
                        break
                    await self._sem.acquire()
                    asyncio.create_task(self._handle(msg))
        finally:
            try:
                await conn.close()
            except Exception:
                pass

    async def _handle(self, msg: aio_pika.IncomingMessage) -> None:
        try:
            try:
                body = json.loads(msg.body)
            except Exception as exc:
                # Bad payload: nack without requeue → DLQ
                log.error("TelemetryConsumer: malformed body — %s", exc)
                await msg.nack(requeue=False)
                return

            try:
                await self._process(body)
            except Exception as exc:
                log.error(
                    "TelemetryConsumer process error agent=%s section=%s: %s",
                    body.get("agent_id", "?"), body.get("section", "?"), exc,
                )
                try:
                    await msg.nack(requeue=False)
                except Exception:
                    pass
                return

            try:
                await msg.ack()
            except Exception as exc:
                log.warning("TelemetryConsumer ack failed: %s", exc)
        finally:
            self._sem.release()

    async def _process(self, msg: dict) -> None:
        agent_id   = msg["agent_id"]
        section    = msg["section"]
        data       = msg.get("data")
        collected  = float(msg.get("collected_at", time.time()))
        agent_name = msg.get("agent_name", "")
        os_name    = msg.get("os", "macos")
        hostname   = msg.get("hostname", "")

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
            log.error("store.write failed agent=%s section=%s: %s", agent_id, section, exc)
            raise

        # 2. SQLite payload summary — best-effort, not all builds expose this
        insert = (
            getattr(self._db, "insert_telemetry", None)
            or getattr(self._db, "insert_payload", None)
        )
        if insert is not None:
            try:
                await insert(agent_id, section, int(collected), data)
            except TypeError:
                try:
                    await insert(agent_id, section, data, collected)
                except Exception as exc:
                    log.debug("db insert skipped agent=%s section=%s: %s", agent_id, section, exc)
            except Exception as exc:
                log.debug("db insert skipped agent=%s section=%s: %s", agent_id, section, exc)

        # 3. Fan-out to jarvis.work (chunked for large list payloads)
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
        except Exception as exc:
            log.warning("jarvis publish failed agent=%s section=%s: %s", agent_id, section, exc)

        # 4. WebSocket broadcast — best-effort
        try:
            await self._hub.broadcast(agent_id, {
                "type":         "payload",
                "agent_id":     agent_id,
                "agent_name":   agent_name,
                "section":      section,
                "collected_at": collected,
                "data":         data,
            })
        except Exception as exc:
            log.debug("ws broadcast failed agent=%s: %s", agent_id, exc)
