"""
agent/tests/unit/test_clock_skew.py — orchestrator survives wall-clock jumps.

The collector scheduler runs on time.time(). A backward jump (NTP correcting the
clock after boot) would leave every section's next-fire time in the future and
silently stall all collection. _maybe_reseed_on_skew re-seeds the schedule so
sections fire promptly; small jitter and forward jumps are ignored.
"""
from __future__ import annotations

import queue

import pytest

from agent.agent.core import Orchestrator, _CLOCK_SKEW_BACKWARD_SEC


def _orch():
    cfg = {
        "agent": {"id": "mac-001", "name": "t"},
        "manager": {"url": "http://127.0.0.1:8080", "max_queue_size": 100},
        "collection": {"tick_sec": 5, "sections": {
            "metrics": {"interval_sec": 60, "enabled": True},
        }},
    }
    return Orchestrator(cfg, b"0" * 32, b"0" * 32, queue.Queue())


def test_backward_jump_reseeds_schedule(monkeypatch):
    import agent.agent.core as core
    clock = {"t": 10_000.0}
    # _seed_phase() re-anchors _last_run using time.time(); patch it to our
    # simulated clock so the re-seed uses the post-jump time, not real wall time.
    monkeypatch.setattr(core.time, "time", lambda: clock["t"])

    o = _orch()
    o._maybe_reseed_on_skew(10_000.0)        # establish baseline at t=10000
    o._last_run["metrics"] = 10_000.0        # would only fire ~60s from baseline

    clock["t"] = 9_800.0                      # NTP corrects clock 200s backward
    assert o._maybe_reseed_on_skew(9_800.0) is True
    # After re-seed the section is anchored to the NEW clock (fires within one
    # interval of post-jump 'now'), not stuck at the old future timestamp.
    assert o._last_run["metrics"] < 9_800.0
    assert o._last_run["metrics"] >= 9_800.0 - 60


def test_small_backward_jitter_does_not_reseed():
    o = _orch()
    o._maybe_reseed_on_skew(10_000.0)
    # 5s backward is under the threshold — normal scheduler noise, not skew.
    assert o._maybe_reseed_on_skew(9_995.0) is False


def test_forward_jump_does_not_reseed():
    o = _orch()
    o._maybe_reseed_on_skew(10_000.0)
    assert o._maybe_reseed_on_skew(10_500.0) is False


def test_first_call_never_reseeds():
    o = _orch()
    # No baseline yet (_last_wall == 0) → never treated as a jump.
    assert o._maybe_reseed_on_skew(10_000.0) is False
