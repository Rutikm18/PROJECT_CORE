"""
manager/tests/unit/test_dlq_replayer.py — DLQ replayer routing + retry policy.

Pins the Phase-1 fix that closed the dead-letter black hole: mac_intel.dead had
no consumer, so any nack'd telemetry/detection work was silently lost forever.
The replayer must (a) route a dead message back to its ORIGINAL queue using the
x-death header, (b) fall back to a queue→routing-key map when x-death is absent,
(c) schedule retry with durable broker backoff, and (d) persist poison messages
to a parking queue once attempts are exhausted.

Pure-logic tests: a fake exchange captures republishes; no live RabbitMQ.
"""
from __future__ import annotations

import asyncio

from manager.manager.workers.dlq_replayer import DLQReplayer
from manager.manager.queue.schemas import (
    QUEUE_TELEMETRY, QUEUE_ATTACKLENS, ROUTING_TELEMETRY, ROUTING_ATTACKLENS,
    ROUTING_PARKED, retry_routing_key,
)


class _FakeExchange:
    def __init__(self):
        self.published = []

    async def publish(self, message, routing_key):
        self.published.append((routing_key, message))


class _FakeMessage:
    """Minimal stand-in for aio_pika.IncomingMessage (only what _handle reads)."""
    def __init__(self, body=b"{}", headers=None, content_type="application/json"):
        self.body = body
        self.headers = headers or {}
        self.content_type = content_type


def _xdeath(queue, routing_key):
    return [{"queue": queue, "routing-keys": [routing_key], "count": 1}]


# ── _origin: route a dead message back to where it came from ──────────────────

def test_origin_reads_routing_key_from_xdeath():
    r = DLQReplayer("amqp://x")
    q, rk = r._origin({"x-death": _xdeath(QUEUE_ATTACKLENS, ROUTING_ATTACKLENS)})
    assert q == QUEUE_ATTACKLENS and rk == ROUTING_ATTACKLENS


def test_origin_falls_back_to_queue_map_when_routing_keys_missing():
    r = DLQReplayer("amqp://x")
    # x-death present but without routing-keys → fall back via queue name
    q, rk = r._origin({"x-death": [{"queue": QUEUE_TELEMETRY, "count": 1}]})
    assert q == QUEUE_TELEMETRY and rk == ROUTING_TELEMETRY


def test_origin_unknown_returns_none_routing_key():
    r = DLQReplayer("amqp://x")
    q, rk = r._origin({})                       # no x-death at all
    assert rk is None
    q2, rk2 = r._origin({"x-death": [{"queue": "some.other.queue", "count": 1}]})
    assert rk2 is None                          # unknown queue, no map entry


# ── _handle: replay vs park ──────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def test_handle_replays_to_origin_and_increments_attempts():
    r = DLQReplayer("amqp://x", base_delay_s=0.0)   # no real backoff sleep
    retry = _FakeExchange()
    parking = _FakeExchange()
    msg = _FakeMessage(body=b'{"agent_id":"a"}',
                       headers={"x-death": _xdeath(QUEUE_TELEMETRY, ROUTING_TELEMETRY)})

    _run(r._handle(msg, retry, parking))

    assert len(retry.published) == 1
    rk, message = retry.published[0]
    assert rk == retry_routing_key(ROUTING_TELEMETRY, 5_000)
    assert message.headers["x-replay-attempts"] == 1
    assert "x-death" not in message.headers          # reset for fresh tracking
    assert parking.published == []
    assert r.stats["replayed"] == 1 and r.stats["parked"] == 0


def test_handle_parks_after_max_attempts():
    r = DLQReplayer("amqp://x", base_delay_s=0.0, max_attempts=3)
    retry = _FakeExchange()
    parking = _FakeExchange()
    # already retried max times → next handle must PARK, not republish
    msg = _FakeMessage(headers={
        "x-death": _xdeath(QUEUE_ATTACKLENS, ROUTING_ATTACKLENS),
        "x-replay-attempts": 3,
    })

    _run(r._handle(msg, retry, parking))

    assert retry.published == []
    assert parking.published[0][0] == ROUTING_PARKED
    assert parking.published[0][1].headers["x-park-reason"] == "retries_exhausted"
    assert r.stats["parked"] == 1 and r.stats["replayed"] == 0


def test_handle_parks_unroutable_message():
    r = DLQReplayer("amqp://x", base_delay_s=0.0)
    retry = _FakeExchange()
    parking = _FakeExchange()
    msg = _FakeMessage(headers={})                   # no origin info at all

    _run(r._handle(msg, retry, parking))

    assert retry.published == []
    assert parking.published[0][1].headers["x-park-reason"] == "unknown_origin"
    assert r.stats["parked"] == 1


def test_backoff_grows_with_attempts():
    r = DLQReplayer("amqp://x", base_delay_s=2.0, max_delay_s=60.0)
    # attempt N delay = base * 2^(N-1), capped at max_delay
    assert min(r._base_delay * (2 ** 0), r._max_delay) == 2.0
    assert min(r._base_delay * (2 ** 3), r._max_delay) == 16.0
    assert min(r._base_delay * (2 ** 10), r._max_delay) == 60.0   # capped
