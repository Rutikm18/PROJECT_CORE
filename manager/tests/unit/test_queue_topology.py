"""RabbitMQ topology must backpressure, not evict telemetry."""
from __future__ import annotations

import asyncio

from manager.manager.queue.connection import declare_topology
from manager.manager.queue.schemas import (
    QUEUE_ATTACKLENS,
    QUEUE_PARKED,
    QUEUE_TELEMETRY,
    RETRY_DELAYS_MS,
)


class _Exchange:
    async def bind(self, *_args, **_kwargs):
        return None


class _Queue:
    async def bind(self, *_args, **_kwargs):
        return None


class _Channel:
    def __init__(self):
        self.queues = {}

    async def declare_exchange(self, *_args, **_kwargs):
        return _Exchange()

    async def declare_queue(self, name, *, durable, arguments=None):
        self.queues[name] = {"durable": durable, "arguments": arguments or {}}
        return _Queue()


def test_main_queues_reject_new_publish_instead_of_dropping_old_data():
    channel = _Channel()
    asyncio.run(declare_topology(channel))

    for name in (QUEUE_TELEMETRY, QUEUE_ATTACKLENS):
        args = channel.queues[name]["arguments"]
        assert args["x-overflow"] == "reject-publish"
        assert args["x-queue-type"] == "quorum"
        assert "x-message-ttl" not in args


def test_retry_and_parking_queues_are_durable_quorum_queues():
    channel = _Channel()
    asyncio.run(declare_topology(channel))

    assert channel.queues[QUEUE_PARKED]["arguments"]["x-queue-type"] == "quorum"
    retry_names = [name for name in channel.queues if name.startswith("mac_intel.retry.")]
    assert len(retry_names) == 2 * len(RETRY_DELAYS_MS)
    for name in retry_names:
        args = channel.queues[name]["arguments"]
        assert args["x-queue-type"] == "quorum"
        assert args["x-message-ttl"] in RETRY_DELAYS_MS
