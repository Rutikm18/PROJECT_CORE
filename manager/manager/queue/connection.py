"""
manager/manager/queue/connection.py — RabbitMQ topology declaration.

Called once on startup to declare all exchanges, queues, and bindings.
Idempotent: safe to call on every reconnect.
"""
from __future__ import annotations

import logging
from typing import Tuple

import aio_pika
from aio_pika import Channel, Exchange, ExchangeType

from .schemas import (
    EXCHANGE_MAIN, EXCHANGE_DLX,
    EXCHANGE_RETRY, EXCHANGE_PARKING,
    QUEUE_TELEMETRY, QUEUE_ATTACKLENS, QUEUE_DEAD, QUEUE_PARKED,
    ROUTING_TELEMETRY, ROUTING_ATTACKLENS, ROUTING_PARKED,
    QUEUE_MAX_TELEMETRY, QUEUE_MAX_ATTACKLENS, RETRY_DELAYS_MS,
    retry_routing_key,
)

log = logging.getLogger("manager.queue")


async def declare_topology(channel: Channel) -> Tuple[Exchange, Exchange]:
    """
    Declare all exchanges, queues, and bindings.
    Returns (main_exchange, dlx_exchange).
    Safe to call multiple times — RabbitMQ ignores re-declarations with same args.
    """
    # Dead-letter exchange (fanout — all dead letters land in one queue)
    dlx = await channel.declare_exchange(
        EXCHANGE_DLX, ExchangeType.FANOUT, durable=True,
    )

    # Dead-letter queue — catch all rejected / TTL-expired messages
    dead_q = await channel.declare_queue(
        QUEUE_DEAD, durable=True, arguments={"x-queue-type": "quorum"},
    )
    await dead_q.bind(dlx)

    parking_ex = await channel.declare_exchange(
        EXCHANGE_PARKING, ExchangeType.DIRECT, durable=True,
    )
    parked_q = await channel.declare_queue(
        QUEUE_PARKED, durable=True, arguments={"x-queue-type": "quorum"},
    )
    await parked_q.bind(parking_ex, routing_key=ROUTING_PARKED)

    # Main exchange (direct routing by routing_key)
    main_ex = await channel.declare_exchange(
        EXCHANGE_MAIN, ExchangeType.DIRECT, durable=True,
    )

    # agent.telemetry queue
    tel_q = await channel.declare_queue(
        QUEUE_TELEMETRY,
        durable=True,
        arguments={
            "x-max-length":           QUEUE_MAX_TELEMETRY,
            "x-overflow":             "reject-publish",
            "x-dead-letter-exchange": EXCHANGE_DLX,
            "x-queue-type":           "quorum",
        },
    )
    await tel_q.bind(main_ex, routing_key=ROUTING_TELEMETRY)

    # attacklens.work queue
    al_q = await channel.declare_queue(
        QUEUE_ATTACKLENS,
        durable=True,
        arguments={
            "x-max-length":           QUEUE_MAX_ATTACKLENS,
            "x-overflow":             "reject-publish",
            "x-dead-letter-exchange": EXCHANGE_DLX,
            "x-queue-type":           "quorum",
        },
    )
    await al_q.bind(main_ex, routing_key=ROUTING_ATTACKLENS)

    # Delay queues keep the DLQ consumer non-blocking. Messages expire into the
    # main exchange at their original routing key; no application sleep holds a
    # delivery or serializes unrelated agent failures.
    retry_ex = await channel.declare_exchange(
        EXCHANGE_RETRY, ExchangeType.DIRECT, durable=True,
    )
    for origin in (ROUTING_TELEMETRY, ROUTING_ATTACKLENS):
        for delay_ms in RETRY_DELAYS_MS:
            retry_key = retry_routing_key(origin, delay_ms)
            retry_q = await channel.declare_queue(
                f"mac_intel.retry.{origin}.{delay_ms}",
                durable=True,
                arguments={
                    "x-message-ttl": delay_ms,
                    "x-dead-letter-exchange": EXCHANGE_MAIN,
                    "x-dead-letter-routing-key": origin,
                    "x-queue-type": "quorum",
                },
            )
            await retry_q.bind(retry_ex, routing_key=retry_key)

    log.info(
        "Queue topology declared: %s → [%s, %s]",
        EXCHANGE_MAIN, QUEUE_TELEMETRY, QUEUE_ATTACKLENS,
    )
    return main_ex, dlx
