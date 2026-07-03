"""
manager/manager/workers/reconciler.py — PayloadReconciler.

The safety net that makes "raw is stored, so it's reprocessable" TRUE. Phase 1
made detection-handoff failures nack→DLQ→replay, but some gaps survive every
queue mechanism: a worker that crashes between store.write and the fan-out
publish, a DLQ message that exhausts its retries and is parked, a sync-path
detection dropped on executor saturation. In all of them the raw payload is
durably stored but no detection ran — and nothing noticed.

This reconciler closes that gap. The telemetry worker records each stored
payload as 'received' in the payload_ledger; engine.process marks it 'processed'
once detection runs. The reconciler periodically finds payloads that are
received-but-not-processed past a grace window and replays the section's current
snapshot through detection, then collapses that section's backlog (snapshot-
based detection means re-driving the latest payload recovers current state — we
don't replay every missed historical payload). A section whose replay keeps
failing crosses max_attempts and stops being retried, surfacing as ledger lag on
the health endpoint instead of looping forever.

Concurrency model: an asyncio task in the FastAPI process, like the other
workers; only meaningful in queue mode (it re-publishes to attacklens.work).
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..chunker import split as chunk_split
from ..queue.schemas import build_attacklens_msg

if TYPE_CHECKING:
    from ..db import Database
    from ..store import TelemetryStore
    from ..queue.producer import QueueProducer

log = logging.getLogger("manager.workers.reconciler")


class PayloadReconciler:
    """Replays stored-but-undetected payloads. Run via asyncio.create_task(r.run())."""

    def __init__(
        self,
        db:           "Database",
        store:        "TelemetryStore",
        producer:     "QueueProducer",
        *,
        interval_sec: float = 60.0,
        grace_sec:    float = 120.0,   # don't replay before the normal path has had a fair shot
        max_attempts: int   = 5,
        batch:        int   = 100,
    ) -> None:
        self._db           = db
        self._store        = store
        self._producer     = producer
        self._interval     = interval_sec
        self._grace        = grace_sec
        self._max_attempts = max_attempts
        self._batch        = batch
        self._running      = True
        self.stats = {"cycles": 0, "sections_replayed": 0, "rows_reconciled": 0, "give_ups": 0}

    async def run(self) -> None:
        log.info("PayloadReconciler started (interval=%ss grace=%ss max_attempts=%d)",
                 self._interval, self._grace, self._max_attempts)
        while self._running:
            try:
                await asyncio.sleep(self._interval)
                if not self._running:
                    break
                await self._reconcile_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error("PayloadReconciler cycle error: %s", exc)

    async def stop(self) -> None:
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _reconcile_once(self) -> None:
        self.stats["cycles"] += 1
        try:
            rows = await self._db.ledger_unprocessed_sections(
                self._grace, self._max_attempts, self._batch,
            )
        except Exception as exc:
            log.error("reconciler: ledger query failed: %s", exc)
            return

        if not rows:
            return
        log.info("reconciler: %d section(s) stored-but-undetected — replaying", len(rows))

        for r in rows:
            agent_id = r["agent_id"]
            section  = r["section"]
            latest   = float(r["latest_unprocessed"])
            await self._replay_section(agent_id, section, latest, int(r.get("pending", 0)))

    async def _replay_section(
        self, agent_id: str, section: str, latest_unprocessed: float, pending: int
    ) -> None:
        # Read the section's current snapshot back from the durable store.
        try:
            payload = await self._store.latest(agent_id, section)
        except Exception as exc:
            log.warning("reconciler: store read failed agent=%s section=%s: %s",
                        agent_id, section, exc)
            payload = None

        if not payload or payload.get("data") is None:
            # Can't recover the raw — count an attempt so a permanently-
            # unreadable section eventually crosses max_attempts and stops.
            await self._db.ledger_bump_attempt(agent_id, section)
            self.stats["give_ups"] += 1
            log.warning("reconciler: no readable snapshot for agent=%s section=%s "
                        "(attempt recorded)", agent_id, section)
            return

        data      = payload["data"]
        # Store records key the timestamp as "ts" (see store.write).
        collected = float(payload.get("ts", payload.get("collected_at", latest_unprocessed)))

        # Re-publish the current snapshot to detection. Publisher confirms mean a
        # returned publish() is durably enqueued → it WILL be processed, so it's
        # safe to collapse the backlog afterwards.
        try:
            for chunk in chunk_split(data):
                await self._producer.publish_attacklens_work(
                    build_attacklens_msg(
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
            await self._db.ledger_bump_attempt(agent_id, section)
            log.warning("reconciler: republish failed agent=%s section=%s: %s",
                        agent_id, section, exc)
            return

        # Collapse the known backlog for this section up to the snapshot we just
        # replayed. The replay's own processing will mark its collected_at.
        n = await self._db.ledger_reconcile_section(agent_id, section, latest_unprocessed)
        self.stats["sections_replayed"] += 1
        self.stats["rows_reconciled"]   += n
        log.info("reconciler: replayed agent=%s section=%s snapshot → detection; "
                 "reconciled %d backlog row(s)", agent_id, section, n)
