"""
manager/manager/workers/attacklens.py — AttackLensWorker.

Consumes the "attacklens.work" queue and runs the AttackLens detection engine:
  1. Route section → analyzer(s) via AttackLensEngine.process()
  2. Analyzers emit findings → upserted into intel.db
  3. Cross-section correlation runs every 3 payloads per agent
  4. Behavioral baseline updated

This is the CPU-heavier stage: threat-feed lookups, CVE matching,
behavioral anomaly scoring. Prefetch is lower (5) to avoid overloading
the event loop with concurrent heavy analysis tasks.

Concurrency model
-----------------
Same as TelemetryWorker: asyncio task within the FastAPI process.
Reconnects automatically on failure.
Messages manually ACK'd after processing.
On exception → NACK without requeue → mac_intel.dead DLQ.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import TYPE_CHECKING

import aio_pika

from ..queue.connection import declare_topology
from ..queue.schemas import QUEUE_ATTACKLENS

if TYPE_CHECKING:
    from ..attacklens.engine    import AttackLensEngine

log = logging.getLogger("manager.workers.attacklens")

_PREFETCH   = max(1, int(os.environ.get("ATTACKLENS_RABBIT_CONCURRENCY", "10")))
_RETRY_BASE = 5
_RETRY_MAX  = 60


class AttackLensWorker:
    """
    Async consumer for the attacklens.work queue.
    Run via: asyncio.create_task(worker.run())
    """

    def __init__(
        self,
        rabbitmq_url: str,
        engine:       "AttackLensEngine",
        tracker=None,
    ) -> None:
        self._url     = rabbitmq_url
        self._engine  = engine
        # `tracker` is accepted for rolling-upgrade compatibility only. Chunk
        # completion is now durable in Postgres and shared by all replicas.
        self._running = True
        # Temporal detector windows are process-local. Parallelize different
        # endpoints, but serialize every event for the same endpoint so its
        # sequence cannot be split or raced inside this worker.
        self._agent_locks: dict[str, asyncio.Lock] = {}
        self._tasks: set[asyncio.Task] = set()
        self._connection = None

    async def run(self) -> None:
        """Main loop: connect → consume → reconnect on failure."""
        delay = _RETRY_BASE
        while self._running:
            try:
                await self._connect_and_consume()
                delay = _RETRY_BASE
            except asyncio.CancelledError:
                break
            except Exception as exc:
                if not self._running:
                    break
                log.error("AttackLensWorker error — retry in %ss: %s", delay, exc)
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
        queue = await channel.get_queue(QUEUE_ATTACKLENS)

        log.info("AttackLensWorker consuming from %s (prefetch=%d)", QUEUE_ATTACKLENS, _PREFETCH)

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
            # msg.process has already nacked processing failures to the DLQ.
            log.error("AttackLensWorker failed to process msg: %s", exc)

    async def _process(self, msg: dict) -> None:
        agent_id     = msg["agent_id"]
        section      = msg["section"]
        data         = msg["data"]
        collected_at = float(msg.get("collected_at", time.time()))
        chunk_set_id = msg.get("chunk_set_id", "")
        chunk_index  = int(msg.get("chunk_index", 0))
        chunk_total  = int(msg.get("chunk_total", 1))
        event_id     = str(msg.get("event_id") or chunk_set_id)
        if not event_id:
            raise ValueError("attacklens work message missing event_id")
        is_chunked   = chunk_total > 1

        start = time.monotonic()
        completed = await self._engine.process(
            agent_id, section, data,
            skip_correlation=is_chunked,
            collected_at=collected_at,
            event_id=event_id,
            chunk_index=chunk_index,
            chunk_total=chunk_total,
        )
        elapsed = time.monotonic() - start

        log.debug(
            "AttackLens processed: agent=%s section=%s chunk=%d/%d in %.3fs",
            agent_id, section, chunk_index + 1, chunk_total, elapsed,
        )

        if completed:
            log.debug(
                "Detection event %s complete agent=%s section=%s",
                event_id, agent_id, section,
            )
