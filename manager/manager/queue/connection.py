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
    QUEUE_TELEMETRY, QUEUE_JARVIS, QUEUE_DEAD,
    ROUTING_TELEMETRY, ROUTING_JARVIS,
    MSG_TTL_MS, QUEUE_MAX_TELEMETRY, QUEUE_MAX_JARVIS,
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
    dead_q = await channel.declare_queue(QUEUE_DEAD, durable=True)
    await dead_q.bind(dlx)

    # Main exchange (direct routing by routing_key)
    main_ex = await channel.declare_exchange(
        EXCHANGE_MAIN, ExchangeType.DIRECT, durable=True,
    )

    # agent.telemetry queue
    tel_q = await channel.declare_queue(
        QUEUE_TELEMETRY,
        durable=True,
        arguments={
            "x-message-ttl":          MSG_TTL_MS,
            "x-max-length":           QUEUE_MAX_TELEMETRY,
            "x-overflow":             "drop-head",       # drop oldest on overflow
            "x-dead-letter-exchange": EXCHANGE_DLX,
        },
    )
    await tel_q.bind(main_ex, routing_key=ROUTING_TELEMETRY)

    # jarvis.work queue
    jar_q = await channel.declare_queue(
        QUEUE_JARVIS,
        durable=True,
        arguments={
            "x-message-ttl":          MSG_TTL_MS,
            "x-max-length":           QUEUE_MAX_JARVIS,
            "x-overflow":             "drop-head",
            "x-dead-letter-exchange": EXCHANGE_DLX,
        },
    )
    await jar_q.bind(main_ex, routing_key=ROUTING_JARVIS)

    log.info(
        "Queue topology declared: %s → [%s, %s]",
        EXCHANGE_MAIN, QUEUE_TELEMETRY, QUEUE_JARVIS,
    )
    return main_ex, dlx
