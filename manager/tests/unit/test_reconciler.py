"""
manager/tests/unit/test_reconciler.py — PayloadReconciler orchestration.

Pins event-level replay with fakes (no live store/broker/DB): the exact missed
payload is republished and remains pending until detection completes it.
"""
from __future__ import annotations

import asyncio

from manager.manager.workers.reconciler import PayloadReconciler


class _FakeDB:
    def __init__(self, work, payload):
        self._work = work
        self._payload = payload
        self.attempts = []

    async def ledger_unprocessed_events(self, grace, max_attempts, batch):
        return self._work

    async def ledger_event_payload(self, event_id):
        return self._payload

    async def ledger_bump_attempt(self, event_id):
        self.attempts.append(event_id)


class _FakeStore:
    def __init__(self, payload):
        self._payload = payload
    async def latest(self, agent_id, section):
        return self._payload


class _FakeProducer:
    def __init__(self, fail=False):
        self.published = []
        self._fail = fail
    async def publish_attacklens_work(self, msg):
        if self._fail:
            raise RuntimeError("broker down")
        self.published.append(msg)
    async def publish_telemetry(self, msg):
        if self._fail:
            raise RuntimeError("broker down")
        self.published.append(msg)


def _run(coro):
    return asyncio.run(coro)


def _work_item():
    return [{"event_id": "event-1", "agent_id": "a1", "section": "ports"}]


def _payload():
    return {
        "event_id": "event-1", "agent_id": "a1", "section": "ports",
        "collected_at": 1005.0, "data": [{"port": 4444}],
        "chunk_total": 1, "chunk_size": 50, "stored_at": 1006.0,
    }


def test_replays_exact_event_without_marking_it_processed():
    db  = _FakeDB(_work_item(), _payload())
    store = _FakeStore({"ts": 9999.0, "data": [{"port": 22}]})
    prod = _FakeProducer()
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert len(prod.published) == 1                     # snapshot replayed
    assert prod.published[0]["agent_id"] == "a1"
    assert prod.published[0]["event_id"] == "event-1"
    assert prod.published[0]["collected_at"] == 1005.0
    assert db.attempts == ["event-1"]
    assert r.stats["events_replayed"] == 1


def test_unreadable_event_records_attempt_and_stays_pending():
    db = _FakeDB(_work_item(), None)
    store = _FakeStore({"data": [{"port": 22}]})      # latest store is irrelevant
    prod = _FakeProducer()
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert prod.published == []
    assert db.attempts == ["event-1"]
    assert r.stats["replay_errors"] == 1


def test_publish_failure_leaves_event_pending():
    db = _FakeDB(_work_item(), _payload())
    store = _FakeStore(None)
    prod = _FakeProducer(fail=True)
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert db.attempts == ["event-1"]
    assert r.stats["replay_errors"] == 1


def test_pre_storage_event_replays_through_telemetry_pipeline():
    payload = _payload()
    payload["stored_at"] = None
    payload["metadata"] = {"agent_name": "Mac", "hostname": "mac.local", "os": "macos"}
    db = _FakeDB(_work_item(), payload)
    prod = _FakeProducer()
    r = PayloadReconciler(db, _FakeStore(None), prod)

    _run(r._reconcile_once())

    assert len(prod.published) == 1
    assert prod.published[0]["event_id"] == "event-1"
    assert prod.published[0]["hostname"] == "mac.local"
