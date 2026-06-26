"""
manager/tests/unit/test_correlation_coalescing.py — real-time correlation scheduling.

Pins the Phase-1 change from sampled correlation ("every 3rd payload") to
correlate-on-every-event with coalescing. The contract:
  • every payload requests a correlation pass (no event goes uncorrelated),
  • at most ONE pass runs per agent at a time (bounded DB load),
  • a request that lands while a pass is in flight folds into exactly one more
    pass after it (burst coalescing — not one pass per payload),
  • agents are independent.

Drives the real AttackLensEngine scheduler (_request_correlation /
_correlation_loop) with _run_correlations stubbed, so no DB/RabbitMQ is needed.
"""
from __future__ import annotations

import asyncio

import pytest

from manager.manager.attacklens.engine import AttackLensEngine


def _engine() -> AttackLensEngine:
    # Bypass __init__ (which wires DB/feeds/AI) — we only exercise the in-memory
    # correlation-coalescing state machine.
    eng = AttackLensEngine.__new__(AttackLensEngine)
    eng._correlate_inflight = set()
    eng._correlate_dirty = set()
    return eng


@pytest.mark.asyncio
async def test_single_request_runs_one_pass():
    eng = _engine()
    runs = []

    async def fake_run(agent_id):
        runs.append(agent_id)
    eng._run_correlations = fake_run

    eng._request_correlation("agentA")
    await asyncio.sleep(0.05)            # let the scheduled task run

    assert runs == ["agentA"]
    assert "agentA" not in eng._correlate_inflight   # cleared on completion


@pytest.mark.asyncio
async def test_burst_while_inflight_coalesces_to_one_extra_pass():
    eng = _engine()
    runs = []
    gate = asyncio.Event()

    async def fake_run(agent_id):
        # Hold the first pass open so the burst arrives mid-flight.
        runs.append(agent_id)
        if len(runs) == 1:
            await gate.wait()
    eng._run_correlations = fake_run

    eng._request_correlation("agentA")   # starts pass #1 (blocks on gate)
    await asyncio.sleep(0.02)
    # 5 payloads arrive while pass #1 is in flight — must collapse to ONE re-run
    for _ in range(5):
        eng._request_correlation("agentA")
    assert eng._correlate_dirty == {"agentA"}

    gate.set()                           # release pass #1
    await asyncio.sleep(0.05)

    assert runs == ["agentA", "agentA"]  # exactly 2 passes, not 6
    assert not eng._correlate_inflight and not eng._correlate_dirty


@pytest.mark.asyncio
async def test_agents_are_independent():
    eng = _engine()
    runs = []

    async def fake_run(agent_id):
        runs.append(agent_id)
    eng._run_correlations = fake_run

    eng._request_correlation("agentA")
    eng._request_correlation("agentB")
    await asyncio.sleep(0.05)

    assert sorted(runs) == ["agentA", "agentB"]
