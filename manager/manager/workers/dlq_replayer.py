"""Durable dead-letter retry scheduling and poison-message parking.

Failures are scheduled through broker-owned delay queues, so one bad event does
not block other agents and a manager restart does not erase the backoff. After
the retry budget is exhausted, the complete persistent message is copied to a
durable parking queue before the DLQ delivery is acknowledged.
"""
from __future__ import annotations

import asyncio
import logging
import time

import aio_pika
from aio_pika import DeliveryMode, Message

from ..queue.connection import declare_topology
from ..queue.schemas import (
    EXCHANGE_PARKING,
    EXCHANGE_RETRY,
    QUEUE_ATTACKLENS,
    QUEUE_DEAD,
    QUEUE_TELEMETRY,
    RETRY_DELAYS_MS,
    ROUTING_ATTACKLENS,
    ROUTING_PARKED,
    ROUTING_TELEMETRY,
    retry_routing_key,
)

log = logging.getLogger("manager.workers.dlq_replayer")

_PREFETCH = 20
_RETRY_BASE = 5
_RETRY_MAX = 60

_QUEUE_TO_ROUTING = {
    QUEUE_TELEMETRY: ROUTING_TELEMETRY,
    QUEUE_ATTACKLENS: ROUTING_ATTACKLENS,
}


class DLQReplayer:
    """Schedule transient failures and persist poison messages for operators."""

    def __init__(
        self,
        rabbitmq_url: str,
        max_attempts: int = 5,
        base_delay_s: float = 2.0,
        max_delay_s: float = 60.0,
    ) -> None:
        self._url = rabbitmq_url
        self._max_attempts = max_attempts
        self._base_delay = base_delay_s
        self._max_delay = max_delay_s
        self._running = True
        self.stats = {"replayed": 0, "parked": 0, "seen": 0}

    async def run(self) -> None:
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

    async def _connect_and_consume(self) -> None:
        conn = await aio_pika.connect_robust(self._url)
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=_PREFETCH)

        await declare_topology(channel)
        retry_ex = await channel.get_exchange(EXCHANGE_RETRY)
        parking_ex = await channel.get_exchange(EXCHANGE_PARKING)
        dead_q = await channel.get_queue(QUEUE_DEAD)

        log.info("DLQReplayer consuming from %s (max_attempts=%d)",
                 QUEUE_DEAD, self._max_attempts)
        async with dead_q.iterator() as msgs:
            async for msg in msgs:
                if not self._running:
                    break
                # A retry/parking publish failure must retain the only durable
                # copy in the DLQ.
                async with msg.process(requeue=True, ignore_processed=True):
                    await self._handle(msg, retry_ex, parking_ex)
        await conn.close()

    async def _handle(self, msg: aio_pika.IncomingMessage, retry_ex, parking_ex) -> None:
        self.stats["seen"] += 1
        headers = dict(msg.headers or {})
        orig_queue, routing_key = self._origin(headers)

        if routing_key is None:
            await self._park(msg, parking_ex, headers, orig_queue, "unknown_origin")
            self.stats["parked"] += 1
            log.error("DLQ: parked message with unknown origin headers=%s", list(headers))
            return

        attempts = int(headers.get("x-replay-attempts", 0)) + 1
        if attempts > self._max_attempts:
            await self._park(
                msg, parking_ex, headers, orig_queue, "retries_exhausted",
            )
            self.stats["parked"] += 1
            log.error(
                "DLQ: poison message persisted to parking queue after %d retries "
                "(origin=%s rk=%s event=%s)",
                self._max_attempts, orig_queue, routing_key,
                self._event_id(msg.body),
            )
            return

        desired = min(self._base_delay * (2 ** (attempts - 1)), self._max_delay)
        delay_ms = next(
            (candidate for candidate in RETRY_DELAYS_MS if candidate >= desired * 1000),
            RETRY_DELAYS_MS[-1],
        )
        headers.update({
            "x-replay-attempts": attempts,
            "x-origin-queue": orig_queue,
            "x-origin-routing-key": routing_key,
        })
        headers.pop("x-death", None)
        await retry_ex.publish(
            Message(
                body=msg.body,
                content_type=msg.content_type or "application/json",
                delivery_mode=DeliveryMode.PERSISTENT,
                headers=headers,
            ),
            routing_key=retry_routing_key(routing_key, delay_ms),
        )
        self.stats["replayed"] += 1
        log.info(
            "DLQ: scheduled %s retry attempt %d/%d in %.1fs",
            routing_key, attempts, self._max_attempts, delay_ms / 1000,
        )

    async def _park(
        self,
        msg: aio_pika.IncomingMessage,
        parking_ex,
        headers: dict,
        orig_queue: str,
        reason: str,
    ) -> None:
        parked_headers = dict(headers)
        parked_headers.pop("x-death", None)
        parked_headers.update({
            "x-park-reason": reason,
            "x-parked-at": time.time(),
            "x-origin-queue": orig_queue,
        })
        await parking_ex.publish(
            Message(
                body=msg.body,
                content_type=msg.content_type or "application/json",
                delivery_mode=DeliveryMode.PERSISTENT,
                headers=parked_headers,
            ),
            routing_key=ROUTING_PARKED,
        )

    def _origin(self, headers: dict) -> tuple[str, str | None]:
        custom_queue = str(headers.get("x-origin-queue") or "")
        custom_routing = str(headers.get("x-origin-routing-key") or "")
        if custom_routing in _QUEUE_TO_ROUTING.values():
            return custom_queue or "?", custom_routing

        deaths = headers.get("x-death") or []
        deaths = deaths if isinstance(deaths, list) else [deaths]
        for death in deaths:
            try:
                queue = death.get("queue", "?")
                if queue not in _QUEUE_TO_ROUTING:
                    continue
                keys = death.get("routing-keys") or death.get("routing_keys") or []
                return queue, (keys[0] if keys else _QUEUE_TO_ROUTING[queue])
            except AttributeError:
                continue
        return "?", None

    @staticmethod
    def _event_id(body: bytes) -> str:
        try:
            import json
            return str((json.loads(body) or {}).get("event_id") or "unknown")
        except Exception:
            return "unknown"
