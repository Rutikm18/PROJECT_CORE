"""
manager/manager/workers/jarvis.py — JarvisWorker.

Consumes the "jarvis.work" queue and runs the Jarvis correlation engine:
  1. Route section → analyzer(s) via JarvisEngine.process()
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
import time
from typing import TYPE_CHECKING

import aio_pika

from ..queue.connection import declare_topology
from ..queue.schemas import QUEUE_JARVIS

if TYPE_CHECKING:
    from ..jarvis.engine    import JarvisEngine
    from ..chunk_tracker    import ChunkTracker

log = logging.getLogger("manager.workers.jarvis")

_PREFETCH   = 5
_RETRY_BASE = 5
_RETRY_MAX  = 60


class JarvisWorker:
    """
    Async consumer for the jarvis.work queue.
    Run via: asyncio.create_task(worker.run())
    """

    def __init__(
        self,
        rabbitmq_url: str,
        jarvis:       "JarvisEngine",
        tracker:      "ChunkTracker",
    ) -> None:
        self._url     = rabbitmq_url
        self._jarvis  = jarvis
        self._tracker = tracker
        self._running = True

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
                log.error("JarvisWorker error — retry in %ss: %s", delay, exc)
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
        queue = await channel.get_queue(QUEUE_JARVIS)

        log.info("JarvisWorker consuming from %s (prefetch=%d)", QUEUE_JARVIS, _PREFETCH)

        async with queue.iterator() as msgs:
            async for msg in msgs:
                if not self._running:
                    break
                async with msg.process(requeue=False, ignore_processed=True):
                    try:
                        body = json.loads(msg.body)
                        await self._process(body)
                    except Exception as exc:
                        log.error("JarvisWorker failed to process msg: %s", exc)
                        raise  # nack → DLQ

        await conn.close()

    async def _process(self, msg: dict) -> None:
        agent_id     = msg["agent_id"]
        section      = msg["section"]
        data         = msg["data"]
        chunk_set_id = msg.get("chunk_set_id", "")
        chunk_index  = int(msg.get("chunk_index", 0))
        chunk_total  = int(msg.get("chunk_total", 1))
        is_chunked   = chunk_total > 1

        start = time.monotonic()
        await self._jarvis.process(
            agent_id, section, data,
            skip_correlation=is_chunked,
        )
        elapsed = time.monotonic() - start

        log.debug(
            "Jarvis processed: agent=%s section=%s chunk=%d/%d in %.3fs",
            agent_id, section, chunk_index + 1, chunk_total, elapsed,
        )

        if not is_chunked:
            return

        # Register the chunk set (idempotent — safe from any chunk order)
        await self._tracker.register(chunk_set_id, chunk_total)
        all_done = await self._tracker.mark_done(chunk_set_id, chunk_index)
        if all_done:
            await self._jarvis.run_correlations(agent_id)
            log.debug(
                "ChunkSet %s complete → correlation triggered agent=%s section=%s",
                chunk_set_id, agent_id, section,
            )
