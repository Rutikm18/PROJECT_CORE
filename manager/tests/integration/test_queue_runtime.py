"""RabbitMQ runtime contract; enabled explicitly against an isolated broker."""
from __future__ import annotations

import json
import os

import pytest

from manager.manager.queue.producer import QueueProducer
from manager.manager.queue.schemas import QUEUE_ATTACKLENS, QUEUE_TELEMETRY


_URL = os.environ.get("RABBITMQ_TEST_URL", "")
pytestmark = pytest.mark.skipif(
    not _URL, reason="set RABBITMQ_TEST_URL to run broker integration",
)


@pytest.mark.asyncio
async def test_quorum_topology_accepts_confirmed_publish_and_delivery():
    producer = QueueProducer(_URL)
    await producer.start(max_attempts=1)
    try:
        telemetry = await producer._channel.get_queue(QUEUE_TELEMETRY, ensure=True)
        await producer._channel.get_queue(QUEUE_ATTACKLENS, ensure=True)
        await producer.publish_telemetry({
            "event_id": "rabbit-runtime-contract",
            "agent_id": "test-agent",
            "section": "metrics",
            "data": {"cpu_pct": 1},
        })
        message = await telemetry.get(timeout=3)
        assert message is not None
        async with message.process(requeue=False):
            assert json.loads(message.body)["event_id"] == "rabbit-runtime-contract"
    finally:
        await producer.stop()
