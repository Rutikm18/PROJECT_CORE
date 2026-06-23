"""
agent/tests/unit/test_collector_timeout.py — hung collectors can't freeze a section.

Regression for a real production finding: 11 of 22 sections on a live agent
were frozen at one fixed timestamp, each for hours to weeks, while the other
11 cycled normally. `len(COLLECTORS) == 22 == max_workers` — the signature of
a hung collector permanently consuming a ThreadPoolExecutor slot. `_run_section`
called `raw = fn()` with no timeout: a hang holds the pool slot forever, AND
the circuit breaker never sees a failure (it only records when fn() returns —
a hang returns neither success nor exception), so the section's freeze was
completely invisible to the existing health heartbeat.

This pins: a hanging collector (a) does not block _run_section past the
timeout, (b) is recorded as a circuit-breaker failure (closing the blind
spot), (c) still results in an enqueued payload so last_collected_at keeps
advancing instead of freezing, and (d) a normal fast collector is unaffected.
"""
from __future__ import annotations

import queue
import threading
import time

import agent.agent.core as core
from agent.agent.core import Orchestrator, _call_with_timeout


def _orch(monkeypatch, cfg=None):
    monkeypatch.setattr(core, "encrypt",
                        lambda payload, *a, **k: {"section": payload["section"]})
    cfg = cfg or {
        "agent": {"id": "mac-test", "name": "T"},
        "manager": {"max_queue_size": 500},
        "collection": {"tick_sec": 5},
    }
    return Orchestrator(cfg, b"\x00" * 32, b"\x00" * 32, queue.Queue())


# ── _call_with_timeout in isolation ──────────────────────────────────────────

def test_fast_function_returns_its_value():
    assert _call_with_timeout(lambda: 42, timeout_sec=1) == 42


def test_raising_function_reraises_the_same_exception():
    def boom():
        raise ValueError("nope")
    try:
        _call_with_timeout(boom, timeout_sec=1)
        assert False, "should have raised"
    except ValueError as exc:
        assert str(exc) == "nope"


def test_hanging_function_raises_timeout_without_waiting_forever():
    never_set = threading.Event()
    start = time.monotonic()
    try:
        _call_with_timeout(lambda: never_set.wait(), timeout_sec=0.2)
        assert False, "should have timed out"
    except TimeoutError:
        pass
    assert time.monotonic() - start < 1.0, "must return promptly, not hang"


# ── Integration through _run_section ─────────────────────────────────────────

def test_hanging_collector_does_not_block_run_section(monkeypatch):
    orch = _orch(monkeypatch)
    monkeypatch.setitem(core.COLLECTORS, "hangy", lambda: threading.Event().wait())

    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(section=section, data=data))

    start = time.monotonic()
    orch._run_section("hangy", {"send": True, "timeout_sec": 0.2})
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, "a hung collector must not block _run_section past its timeout"
    assert captured["section"] == "hangy"
    assert "error" in captured["data"], "a timeout must still enqueue a payload"


def test_hanging_collector_is_recorded_as_a_circuit_breaker_failure(monkeypatch):
    """Closes the actual blind spot: before this, a hang never reached either
    _cbr.success() or _cbr.failure(), so the health heartbeat showed the
    section as falsely healthy (CLOSED, zero failures) while it was frozen."""
    orch = _orch(monkeypatch)
    monkeypatch.setitem(core.COLLECTORS, "hangy", lambda: threading.Event().wait())
    monkeypatch.setattr(orch, "_enqueue", lambda *a, **k: None)

    orch._run_section("hangy", {"send": True, "timeout_sec": 0.2})

    snap = orch._cbr.snapshot()
    assert snap["hangy"]["failures"] == 1
    assert "timed out" in snap["hangy"]["last_result"] or "did not complete" in snap["hangy"]["last_result"]


def test_normal_fast_collector_unaffected(monkeypatch):
    orch = _orch(monkeypatch)
    monkeypatch.setitem(core.COLLECTORS, "fast", lambda: {"ok": True})
    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(section=section, data=data))

    orch._run_section("fast", {"send": True})

    assert captured["data"] == {"ok": True}
    assert orch._cbr.snapshot()["fast"]["failures"] == 0


def test_per_section_timeout_overrides_global_default(monkeypatch):
    """A section can opt into a longer timeout (e.g. binaries hashing many
    files) without changing the global default for everything else."""
    orch = _orch(monkeypatch)
    monkeypatch.setitem(core.COLLECTORS, "slow_but_fine", lambda: (time.sleep(0.3), "done")[1])
    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(data=data))

    orch._run_section("slow_but_fine", {"send": True, "timeout_sec": 2})

    assert captured["data"] == "done", "must complete normally within its own longer timeout"
