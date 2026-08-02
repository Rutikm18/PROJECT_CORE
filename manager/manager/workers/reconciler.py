"""
manager/manager/workers/reconciler.py — PayloadReconciler.

The safety net that makes "raw is stored, so it's reprocessable" TRUE. Phase 1
made detection-handoff failures nack→DLQ→replay, but some gaps survive every
queue mechanism: a worker that crashes between store.write and the fan-out
publish, a DLQ message that exhausts its retries and is parked, a sync-path
detection dropped on executor saturation. In all of them the raw payload is
durably stored but no detection ran — and nothing noticed.

This reconciler closes that gap. The telemetry worker writes the exact payload
to the event-level detection outbox; engine.process marks its chunks complete.
The reconciler republishes each missed event verbatim and leaves it pending until
the detector itself records completion. It never substitutes a newer snapshot
and never marks an event processed merely because publish succeeded.

Concurrency model: an asyncio task in the FastAPI process, like the other
workers; only meaningful in queue mode (it re-publishes to attacklens.work).
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..chunker import split as chunk_split
from ..queue.schemas import build_attacklens_msg, build_telemetry_msg

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
        self.stats = {"cycles": 0, "events_replayed": 0, "replay_errors": 0}

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
            rows = await self._db.ledger_unprocessed_events(
                self._grace, self._max_attempts, self._batch,
            )
        except Exception as exc:
            log.error("reconciler: ledger query failed: %s", exc)
            return

        if not rows:
            return
        log.info("reconciler: %d event(s) stored-but-undetected — replaying", len(rows))

        for r in rows:
            await self._replay_event(str(r["event_id"]))

    async def _replay_event(self, event_id: str) -> None:
        # Read the exact event from the durable outbox, not latest(agent,section).
        try:
            payload = await self._db.ledger_event_payload(event_id)
        except Exception as exc:
            log.warning("reconciler: event read failed event_id=%s: %s", event_id, exc)
            payload = None

        if not payload or payload.get("data") is None:
            await self._db.ledger_bump_attempt(event_id)
            self.stats["replay_errors"] += 1
            log.warning("reconciler: no readable payload event_id=%s", event_id)
            return

        agent_id = str(payload["agent_id"])
        section = str(payload["section"])
        data = payload["data"]
        collected = float(payload["collected_at"])
        chunk_size = max(1, int(payload.get("chunk_size", 50)))
        metadata = payload.get("metadata") or {}

        # Count the attempt before publishing. Completion remains pending until
        # every republished chunk succeeds in AttackLens and commits its chunk row.
        await self._db.ledger_bump_attempt(event_id)
        try:
            if payload.get("stored_at") is None:
                await self._producer.publish_telemetry(build_telemetry_msg(
                    agent_id=agent_id,
                    agent_name=str(metadata.get("agent_name") or ""),
                    hostname=str(metadata.get("hostname") or ""),
                    os_name=str(metadata.get("os") or ""),
                    section=section,
                    collected_at=collected,
                    client_ip=str(metadata.get("client_ip") or ""),
                    data=data,
                    event_id=event_id,
                ))
                self.stats["events_replayed"] += 1
                log.info("reconciler: replayed pre-storage event_id=%s", event_id)
                return

            chunks = chunk_split(data, chunk_size=chunk_size, chunk_set_id=event_id)
            expected_total = int(payload.get("chunk_total", len(chunks)))
            if len(chunks) != expected_total:
                raise ValueError(
                    f"chunk topology changed for {event_id}: {len(chunks)} != {expected_total}"
                )
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
        except Exception as exc:
            self.stats["replay_errors"] += 1
            log.warning("reconciler: republish failed event_id=%s: %s", event_id, exc)
            return

        self.stats["events_replayed"] += 1
        log.info("reconciler: replayed exact event_id=%s agent=%s section=%s",
                 event_id, agent_id, section)
