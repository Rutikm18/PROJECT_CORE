"""
manager/tests/unit/test_detection_executor.py — bounded detection executor.

Ingest used to dispatch detection with an unbounded asyncio.create_task per
payload. Under a burst (many agents × sections × high frequency) that piles
thousands of in-flight process() coroutines into memory, and every one of them
ultimately serializes on IntelDB's single write connection — a thundering herd
that makes all writers slower.

The executor replaces that with a bounded queue drained by a fixed worker pool:
  - concurrent process() is capped at _DETECTION_WORKERS (steady, shallow
    write-lock queue instead of a herd),
  - memory is bounded by the queue cap,
  - ingest never blocks (enqueue is a non-blocking put_nowait),
  - saturation drops + counts rather than blocking ingest or growing unbounded
    (raw telemetry is already persisted by ingest, so the drop is recoverable
    and observable via detection_stats).
"""
from __future__ import annotations

import asyncio

import pytest

from manager.manager.attacklens import engine as engine_mod
from manager.manager.attacklens.engine import AttackLensEngine


class _StubEngine(AttackLensEngine):
    """Engine with process() stubbed so we test ONLY the executor mechanics
    (queue, workers, counters, backpressure) without DB or detection logic."""
    def __init__(self):
        # Skip the heavy __init__ (DB handles etc.) — set just what the
        # executor touches.
        self._detect_queue = None
        self._detect_workers = []
        self._detect_stats = {"enqueued": 0, "processed": 0,
                              "dropped_queue_full": 0, "errors": 0}
        self._processed_order: list = []
        self._gate: asyncio.Event | None = None
        self._max_concurrent = 0
        self._cur_concurrent = 0

    async def process(self, agent_id, section, data, skip_correlation=False,
                      collected_at=None):
        self._cur_concurrent += 1
        self._max_concurrent = max(self._max_concurrent, self._cur_concurrent)
        try:
            if self._gate is not None:
                await self._gate.wait()
            else:
                await asyncio.sleep(0)
            self._processed_order.append((agent_id, section))
        finally:
            self._cur_concurrent -= 1


async def _start_executor(eng, workers=4, qmax=2000, monkeypatch=None):
    monkeypatch.setattr(engine_mod, "_DETECTION_WORKERS", workers)
    monkeypatch.setattr(engine_mod, "_DETECTION_QUEUE_MAX", qmax)
    eng._detect_queue = asyncio.Queue(maxsize=qmax)
    eng._detect_workers = [
        asyncio.create_task(eng._detection_worker(i)) for i in range(workers)
    ]


async def _stop_executor(eng):
    for t in eng._detect_workers:
        t.cancel()
    await asyncio.gather(*eng._detect_workers, return_exceptions=True)


@pytest.mark.asyncio
async def test_enqueue_before_start_falls_back_to_task():
    """Before start(), enqueue must not crash — it preserves legacy
    fire-and-forget so nothing depends on start() ordering."""
    eng = _StubEngine()
    assert eng._detect_queue is None
    accepted = eng.enqueue("a1", "ports", [])
    assert accepted is True
    await asyncio.sleep(0.02)
    assert ("a1", "ports") in eng._processed_order


@pytest.mark.asyncio
async def test_all_enqueued_payloads_are_processed(monkeypatch):
    eng = _StubEngine()
    await _start_executor(eng, workers=4, monkeypatch=monkeypatch)
    try:
        for i in range(50):
            assert eng.enqueue(f"agent{i%3}", "ports", [{"i": i}]) is True
        await eng._detect_queue.join()
        assert eng._detect_stats["enqueued"] == 50
        assert eng._detect_stats["processed"] == 50
        assert len(eng._processed_order) == 50
    finally:
        await _stop_executor(eng)


@pytest.mark.asyncio
async def test_concurrency_is_capped_at_worker_count(monkeypatch):
    """The whole point: no matter how many payloads are enqueued at once, at
    most _DETECTION_WORKERS run process() concurrently."""
    eng = _StubEngine()
    eng._gate = asyncio.Event()  # hold all process() calls open simultaneously
    await _start_executor(eng, workers=3, monkeypatch=monkeypatch)
    try:
        for i in range(40):
            eng.enqueue("a", "ports", [{"i": i}])
        await asyncio.sleep(0.05)        # let workers pick up and block on gate
        assert eng._max_concurrent <= 3, eng._max_concurrent
        assert eng._cur_concurrent == 3  # exactly the pool size is in flight
        eng._gate.set()                  # release
        await eng._detect_queue.join()
        assert eng._detect_stats["processed"] == 40
    finally:
        eng._gate.set()
        await _stop_executor(eng)


@pytest.mark.asyncio
async def test_saturation_drops_and_counts_without_blocking(monkeypatch):
    """When the queue is full, enqueue returns False and increments the drop
    counter — it never blocks the caller (ingest) or raises."""
    eng = _StubEngine()
    eng._gate = asyncio.Event()  # workers block, so the queue fills and stays full
    await _start_executor(eng, workers=2, qmax=5, monkeypatch=monkeypatch)
    try:
        results = [eng.enqueue("a", "ports", [{"i": i}]) for i in range(40)]
        accepted = sum(1 for r in results if r)
        dropped  = sum(1 for r in results if not r)
        assert dropped > 0, "a full queue must drop"
        assert eng._detect_stats["dropped_queue_full"] == dropped
        # accepted is bounded by queue capacity + the few workers pulled off it
        assert accepted <= 5 + 2
    finally:
        eng._gate.set()
        await _stop_executor(eng)


@pytest.mark.asyncio
async def test_worker_survives_a_failing_payload(monkeypatch):
    """One payload raising in process() must not kill the worker — it counts
    an error and keeps draining."""
    eng = _StubEngine()
    orig = eng.process
    async def flaky(agent_id, section, data, skip_correlation=False, collected_at=None):
        if section == "boom":
            raise RuntimeError("kaboom")
        await orig(agent_id, section, data, collected_at=collected_at)
    eng.process = flaky  # type: ignore
    await _start_executor(eng, workers=2, monkeypatch=monkeypatch)
    try:
        eng.enqueue("a", "boom", [])
        eng.enqueue("a", "ports", [])
        await eng._detect_queue.join()
        assert eng._detect_stats["errors"] >= 1
        assert ("a", "ports") in eng._processed_order  # drained past the failure
    finally:
        await _stop_executor(eng)


@pytest.mark.asyncio
async def test_detection_stats_shape(monkeypatch):
    eng = _StubEngine()
    await _start_executor(eng, workers=2, qmax=100, monkeypatch=monkeypatch)
    try:
        s = eng.detection_stats()
        assert s["workers"] == 2 and s["queue_max"] == 100
        assert s["running"] is True
        assert {"enqueued", "processed", "dropped_queue_full", "errors",
                "queue_depth"} <= set(s)
    finally:
        await _stop_executor(eng)
