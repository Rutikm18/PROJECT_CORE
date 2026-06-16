"""
agent/tests/unit/test_overflow_spill.py — backpressure must spill, never drop.

The historical "data not coming" bug: when the in-memory send queue filled up,
the Orchestrator evicted the oldest envelope and DROPPED it. This pins the fix —
an evicted envelope is handed to the overflow sink (the Sender's disk spool) so
it is persisted and replayed, never lost.
"""
from __future__ import annotations

import queue

from agent.agent.core import Orchestrator


def _orch(overflow_sink, maxq=3):
    cfg = {
        "agent": {"id": "mac-test", "name": "T"},
        "manager": {"max_queue_size": maxq},
        "collection": {"tick_sec": 5},
    }
    q: queue.Queue = queue.Queue()
    o = Orchestrator(cfg, b"\x00" * 32, b"\x00" * 32, q,
                     overflow_sink=overflow_sink)
    return o, q


def test_overflow_is_spilled_not_dropped(monkeypatch):
    spilled = []
    o, q = _orch(spilled.append, maxq=3)

    # Avoid real crypto: make _enqueue's encrypt a passthrough envelope.
    import agent.agent.core as core
    monkeypatch.setattr(core, "encrypt",
                        lambda payload, *a, **k: {"section": payload["section"]})

    # Push more sections than the queue can hold.
    for i in range(10):
        o._enqueue(f"sec{i}", {"i": i})

    # Nothing lost: what's in the queue + what was spilled == everything enqueued.
    in_queue = []
    while True:
        try:
            in_queue.append(q.get_nowait())
        except queue.Empty:
            break

    total = len(in_queue) + len(spilled)
    assert total == 10, f"expected 10 envelopes accounted for, got {total}"
    assert len(spilled) >= 1, "overflow must have spilled at least one envelope"
    # The spilled ones are the OLDEST sections (evicted first).
    spilled_sections = [e["section"] for e in spilled]
    assert "sec0" in spilled_sections


def test_no_sink_falls_back_to_drop_without_crashing(monkeypatch):
    o, q = _orch(overflow_sink=None, maxq=2)
    import agent.agent.core as core
    monkeypatch.setattr(core, "encrypt",
                        lambda payload, *a, **k: {"section": payload["section"]})
    # Must not raise even though there's nowhere to spill.
    for i in range(6):
        o._enqueue(f"s{i}", {"i": i})
    assert q.qsize() <= 3


def test_seed_phase_staggers_same_interval_sections():
    cfg = {
        "agent": {"id": "mac-test", "name": "T"},
        "manager": {},
        "collection": {"tick_sec": 5, "sections": {
            "a": {"enabled": True, "interval_sec": 120, "send": True},
            "b": {"enabled": True, "interval_sec": 120, "send": True},
            "c": {"enabled": True, "interval_sec": 120, "send": True},
        }},
    }
    o = Orchestrator(cfg, b"\x00" * 32, b"\x00" * 32, queue.Queue())
    o._seed_phase()
    # Same interval, but deterministic phases should differ (de-burst).
    import time
    phases = {n: (120 - (time.time() - t)) for n, t in o._last_run.items()}
    # At least two of the three first-fire offsets must differ.
    assert len(set(round(p) for p in phases.values())) >= 2
