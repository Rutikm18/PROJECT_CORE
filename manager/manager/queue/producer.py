"""
manager/manager/queue/producer.py — QueueProducer: publishes messages to RabbitMQ.

Usage
-----
    producer = QueueProducer("amqp://guest:guest@localhost/")
    await producer.start()
    await producer.publish_telemetry(build_telemetry_msg(...))
    await producer.publish_jarvis_work(build_jarvis_msg(...))
    await producer.stop()

Design
------
- Uses a single persistent channel per producer instance.
- Messages are PERSISTENT (delivery_mode=2) — survive broker restart.
- If the channel is closed (broker blip), publish() raises; caller handles retry.
- `start()` is idempotent — calling again after a drop re-establishes the channel.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aio_pika
from aio_pika import DeliveryMode, Message

from .connection import declare_topology
from .schemas import ROUTING_TELEMETRY, ROUTING_JARVIS

log = logging.getLogger("manager.queue.producer")


class QueueProducer:
    """Non-blocking message publisher for the ingest hot path."""

    def __init__(self, rabbitmq_url: str) -> None:
        self._url      = rabbitmq_url
        self._conn     = None
        self._channel  = None
        self._exchange = None

    @property
    def ready(self) -> bool:
        return self._exchange is not None

    async def start(self, max_attempts: int = 10) -> None:
        """Connect and declare topology, retrying until RabbitMQ AMQP port is ready.

        Docker healthchecks (`rabbitmq-diagnostics ping`) pass before port 5672
        accepts AMQP connections — this retry loop bridges that gap.
        """
        delay = 2.0
        for attempt in range(1, max_attempts + 1):
            try:
                self._conn    = await aio_pika.connect_robust(self._url)
                self._channel = await self._conn.channel()
                # Publisher confirms: broker ACKs each message before publish() returns.
                # Adds ~1ms latency but guarantees no silent drops.
                await self._channel.set_qos(prefetch_count=0)
                self._exchange, _ = await declare_topology(self._channel)
                log.info("QueueProducer connected → %s", self._url.split("@")[-1])
                return
            except Exception as exc:
                if attempt == max_attempts:
                    log.error(
                        "QueueProducer: RabbitMQ not reachable after %d attempts — giving up: %s",
                        max_attempts, exc,
                    )
                    raise
                log.warning(
                    "QueueProducer: attempt %d/%d failed (%s), retrying in %.0fs…",
                    attempt, max_attempts, exc, delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def stop(self) -> None:
        """Graceful shutdown."""
        try:
            if self._conn:
                await self._conn.close()
        except Exception:
            pass
        self._conn = self._channel = self._exchange = None
        log.info("QueueProducer stopped")

    # ── Publish helpers ───────────────────────────────────────────────────────

    async def publish_telemetry(self, msg: dict) -> None:
        """Publish a raw-telemetry message to the agent.telemetry queue."""
        await self._publish(msg, ROUTING_TELEMETRY)

    async def publish_jarvis_work(self, msg: dict) -> None:
        """Publish a pre-validated payload to the jarvis.work queue."""
        await self._publish(msg, ROUTING_JARVIS)

    async def _publish(self, body: dict, routing_key: str) -> None:
        if self._exchange is None:
            raise RuntimeError("QueueProducer not started — call await producer.start()")
        await self._exchange.publish(
            Message(
                body          = json.dumps(body, default=str).encode(),
                content_type  = "application/json",
                delivery_mode = DeliveryMode.PERSISTENT,
            ),
            routing_key=routing_key,
        )
