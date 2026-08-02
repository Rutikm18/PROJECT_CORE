"""The telemetry consumer never fans out detection before durable raw storage."""
from __future__ import annotations

import asyncio
import json

import pytest

from manager.manager.workers.telemetry import TelemetryWorker
from manager.manager.workers.attacklens import AttackLensWorker


class _DB:
    def __init__(self, *, fail_insert: bool = False):
        self.fail_insert = fail_insert
        self.calls = []

    async def ledger_received(self, *args, **kwargs):
        self.calls.append(("ledger", kwargs.get("stored", False)))

    async def insert_payload(self, *args, **kwargs):
        self.calls.append(("raw", kwargs.get("event_id")))
        if self.fail_insert:
            raise RuntimeError("postgres unavailable")


class _Store:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.writes = 0

    async def write(self, **_kwargs):
        self.writes += 1
        if self.fail:
            raise RuntimeError("optional archive unavailable")


class _Hub:
    async def broadcast(self, *_args, **_kwargs):
        return None


class _Producer:
    def __init__(self):
        self.messages = []

    async def publish_attacklens_work(self, body):
        self.messages.append(body)


def _message():
    return {
        "event_id": "event-1",
        "agent_id": "agent-1",
        "section": "ports",
        "collected_at": 1_700_000_000,
        "data": [{"port": 22}],
    }


def test_postgres_failure_prevents_detection_fanout():
    db = _DB(fail_insert=True)
    producer = _Producer()
    worker = TelemetryWorker("amqp://unused", db, _Store(), _Hub(), producer)

    with pytest.raises(RuntimeError, match="postgres unavailable"):
        asyncio.run(worker._process(_message()))

    assert db.calls == [("ledger", False), ("raw", "event-1")]
    assert producer.messages == []


def test_optional_archive_failure_does_not_block_detection():
    db = _DB()
    producer = _Producer()
    worker = TelemetryWorker("amqp://unused", db, _Store(fail=True), _Hub(), producer)

    asyncio.run(worker._process(_message()))

    assert db.calls == [
        ("ledger", False), ("raw", "event-1"), ("ledger", True),
    ]
    assert len(producer.messages) == 1
    assert producer.messages[0]["event_id"] == "event-1"


class _ProcessContext:
    def __init__(self, message):
        self.message = message

    async def __aenter__(self):
        return self.message

    async def __aexit__(self, exc_type, _exc, _tb):
        self.message.rejected = exc_type is not None
        return False


class _Message:
    def __init__(self, body):
        self.body = json.dumps(body).encode()
        self.rejected = False

    def process(self, **_kwargs):
        return _ProcessContext(self)


def test_attacklens_parallelizes_agents_but_serializes_each_agent():
    worker = AttackLensWorker("amqp://unused", object())
    active = {}
    max_by_agent = {}
    fleet_active = 0
    fleet_max = 0

    async def process(body):
        nonlocal fleet_active, fleet_max
        agent = body["agent_id"]
        active[agent] = active.get(agent, 0) + 1
        max_by_agent[agent] = max(max_by_agent.get(agent, 0), active[agent])
        fleet_active += 1
        fleet_max = max(fleet_max, fleet_active)
        await asyncio.sleep(0.01)
        active[agent] -= 1
        fleet_active -= 1

    worker._process = process

    async def run_all():
        await asyncio.gather(
            worker._handle(_Message({"agent_id": "a"})),
            worker._handle(_Message({"agent_id": "a"})),
            worker._handle(_Message({"agent_id": "b"})),
        )

    asyncio.run(run_all())
    assert max_by_agent == {"a": 1, "b": 1}
    assert fleet_max == 2
