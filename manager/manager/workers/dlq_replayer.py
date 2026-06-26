"""
manager/manager/workers/dlq_replayer.py — Dead-letter queue replayer.

Closes a real gap: messages that a worker NACKs (store/detection failure, a
transient Postgres blip during a deploy, a poison payload) land in the fanout
DLQ "mac_intel.dead" — which previously had ZERO consumers, so the telemetry
just sat there forever. On a security tool that is silent, permanent
missed-detection.

This consumer drains the DLQ and:
  • Re-routes each message back to its ORIGINAL queue (agent.telemetry /
    attacklens.work) via the main exchange, with EXPONENTIAL BACKOFF — a
    transient failure (broker reconnect, brief DB outage) self-heals on retry.
  • After `max_attempts` failed replays, PARKS the message (drops it from the
    DLQ) and logs at ERROR level so it surfaces as a poison-message alert
    instead of looping forever.

Retry bookkeeping uses our own `x-replay-attempts` header (predictable across
republishes) rather than RabbitMQ's `x-death` count, which only tells us the
original queue/routing-key (used here to route back). Backoff is an in-process
sleep with prefetch=1, so retries serialise — fine because the DLQ should be
near-empty in steady state; genuine failure volume is low by construction.

Concurrency model: an asyncio task in the FastAPI process, same as the other
workers; reconnects automatically.
"""
from __future__ import annotations

import asyncio
import json
import logging

import aio_pika
from aio_pika import DeliveryMode, Message

from ..queue.connection import declare_topology
from ..queue.schemas import (
    EXCHANGE_MAIN, QUEUE_DEAD,
    QUEUE_TELEMETRY, QUEUE_ATTACKLENS,
    ROUTING_TELEMETRY, ROUTING_ATTACKLENS,
)

log = logging.getLogger("manager.workers.dlq_replayer")

_PREFETCH   = 1            # serialise retries (low volume by design)
_RETRY_BASE = 5
_RETRY_MAX  = 60

# Map an original queue name → the routing key that reaches it, for when the
# x-death record is missing/garbled.
_QUEUE_TO_ROUTING = {
    QUEUE_TELEMETRY:  ROUTING_TELEMETRY,
    QUEUE_ATTACKLENS: ROUTING_ATTACKLENS,
}


class DLQReplayer:
    """Drains mac_intel.dead, replays to the origin queue with backoff, parks
    poison messages after max_attempts. Run via asyncio.create_task(r.run())."""

    def __init__(
        self,
        rabbitmq_url:  str,
        max_attempts:  int = 5,
        base_delay_s:  float = 2.0,
        max_delay_s:   float = 60.0,
    ) -> None:
        self._url          = rabbitmq_url
        self._max_attempts = max_attempts
        self._base_delay   = base_delay_s
        self._max_delay    = max_delay_s
        self._running      = True
        self.stats = {"replayed": 0, "parked": 0, "seen": 0}

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
                log.error("DLQReplayer error — retry in %ss: %s", delay, exc)
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RETRY_MAX)

    async def stop(self) -> None:
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _connect_and_consume(self) -> None:
        conn    = await aio_pika.connect_robust(self._url)
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=_PREFETCH)

        main_ex, _ = await declare_topology(channel)
        dead_q = await channel.get_queue(QUEUE_DEAD)

        log.info("DLQReplayer consuming from %s (max_attempts=%d)",
                 QUEUE_DEAD, self._max_attempts)

        async with dead_q.iterator() as msgs:
            async for msg in msgs:
                if not self._running:
                    break
                # requeue=False: we either successfully republish to the origin
                # queue (then ack/drop from the DLQ) or park it (ack/drop). Never
                # requeue back onto the DLQ — that would hot-loop.
                async with msg.process(requeue=False, ignore_processed=True):
                    await self._handle(msg, main_ex)

        await conn.close()

    async def _handle(self, msg: aio_pika.IncomingMessage, main_ex) -> None:
        self.stats["seen"] += 1
        headers = dict(msg.headers or {})

        # Where did it originally come from? RabbitMQ records this in x-death.
        orig_queue, routing_key = self._origin(headers)
        if routing_key is None:
            log.error("DLQ: cannot determine origin for a dead message "
                      "(queue=%s) — parking. headers=%s", orig_queue, list(headers))
            self.stats["parked"] += 1
            return

        attempts = int(headers.get("x-replay-attempts", 0)) + 1
        if attempts > self._max_attempts:
            log.error(
                "DLQ: POISON message exhausted %d retries (origin=%s rk=%s) — "
                "PARKED + dropped. First 120 bytes: %s",
                self._max_attempts, orig_queue, routing_key,
                (msg.body or b"")[:120],
            )
            self.stats["parked"] += 1
            return

        delay = min(self._base_delay * (2 ** (attempts - 1)), self._max_delay)
        await asyncio.sleep(delay)

        headers["x-replay-attempts"] = attempts
        headers.pop("x-death", None)   # let RabbitMQ start fresh death tracking
        await main_ex.publish(
            Message(
                body          = msg.body,
                content_type  = msg.content_type or "application/json",
                delivery_mode = DeliveryMode.PERSISTENT,
                headers       = headers,
            ),
            routing_key=routing_key,
        )
        self.stats["replayed"] += 1
        log.info(
            "DLQ: replayed → %s (origin=%s, attempt %d/%d, backoff %.1fs)",
            routing_key, orig_queue, attempts, self._max_attempts, delay,
        )

    def _origin(self, headers: dict) -> tuple[str, str | None]:
        """Return (original_queue, routing_key_to_reach_it) from the x-death
        header, with a queue→routing-key fallback."""
        xdeath = headers.get("x-death") or []
        orig_queue = "?"
        routing_key = None
        if xdeath:
            first = xdeath[0] if isinstance(xdeath, list) else xdeath
            try:
                orig_queue = first.get("queue", "?")
                rks = first.get("routing-keys") or first.get("routing_keys") or []
                routing_key = rks[0] if rks else None
            except AttributeError:
                pass
        if routing_key is None:
            routing_key = _QUEUE_TO_ROUTING.get(orig_queue)
        return orig_queue, routing_key
