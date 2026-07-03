"""
manager/tests/unit/test_reconciler.py — PayloadReconciler orchestration.

Pins the replay path with fakes (no live store/broker/DB): an unprocessed
section's current snapshot is re-published to detection and its backlog
collapsed; an unreadable snapshot records an attempt (eventual give-up) instead
of looping; a republish failure does NOT collapse the backlog (so it's retried).
"""
from __future__ import annotations

import asyncio

from manager.manager.workers.reconciler import PayloadReconciler


class _FakeDB:
    def __init__(self, work):
        self._work = work          # list of section dicts
        self.reconciled = []       # (agent, section, up_to)
        self.attempts = []         # (agent, section)

    async def ledger_unprocessed_sections(self, grace, max_attempts, batch):
        return self._work

    async def ledger_reconcile_section(self, agent_id, section, up_to):
        self.reconciled.append((agent_id, section, up_to))
        return 3

    async def ledger_bump_attempt(self, agent_id, section):
        self.attempts.append((agent_id, section))


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


def _run(coro):
    return asyncio.run(coro)


def _work_item():
    return [{"agent_id": "a1", "section": "ports", "latest_unprocessed": 1000.0, "pending": 3}]


def test_replays_snapshot_and_collapses_backlog():
    db  = _FakeDB(_work_item())
    store = _FakeStore({"ts": 1005.0, "data": [{"port": 4444}]})
    prod = _FakeProducer()
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert len(prod.published) == 1                     # snapshot replayed
    assert prod.published[0]["agent_id"] == "a1"
    assert db.reconciled == [("a1", "ports", 1000.0)]   # backlog collapsed
    assert db.attempts == []
    assert r.stats["sections_replayed"] == 1 and r.stats["rows_reconciled"] == 3


def test_unreadable_snapshot_records_attempt_not_collapse():
    db = _FakeDB(_work_item())
    store = _FakeStore(None)                            # nothing readable back
    prod = _FakeProducer()
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert prod.published == []
    assert db.reconciled == []                          # must NOT collapse
    assert db.attempts == [("a1", "ports")]             # attempt recorded → eventual give-up
    assert r.stats["give_ups"] == 1


def test_publish_failure_does_not_collapse_backlog():
    db = _FakeDB(_work_item())
    store = _FakeStore({"ts": 1005.0, "data": [{"port": 4444}]})
    prod = _FakeProducer(fail=True)
    r = PayloadReconciler(db, store, prod)

    _run(r._reconcile_once())

    assert db.reconciled == []                          # not collapsed → will retry
    assert db.attempts == [("a1", "ports")]
