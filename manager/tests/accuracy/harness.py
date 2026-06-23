"""
manager/tests/accuracy/harness.py — detection accuracy/calibration harness.

The measurement backbone for Phase-1 detection tuning. You cannot calibrate what
you cannot measure: this runs a detection module's `analyze()` against labelled
true-positive / false-positive snapshots and measures, per module:

  • does the TP fire (and at the expected minimum severity)?
  • does the FP stay silent (precision)?
  • detection latency (speed budget)?

Snapshots run in ORDER on a shared fake state store, so baseline/first-run
behaviour (seed-then-change) is exercised exactly as in production — a stale
single-shot fixture would mis-measure modules that seed a baseline on first run.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# Severity ordering for "at least this severe" assertions.
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def sev_rank(sev: Optional[str]) -> int:
    return _SEV_RANK.get((sev or "").lower(), 0)


class FakeStateDB:
    """Minimal stand-in for the manager DB used by detection modules.

    Detection `analyze()` functions only touch entity-state (per-agent baseline
    persistence). Persisting across snapshots within one case is what lets us
    measure first-run-seed → next-snapshot-alert behaviour.
    """

    def __init__(self) -> None:
        self._state: dict = {}

    async def get_entity_state(self, agent_id: str, module: str, key: str):
        return self._state.get((agent_id, module, key))

    async def set_entity_state(self, agent_id: str, module: str, key: str,
                               value: Any, ts: Any = None) -> None:
        self._state[(agent_id, module, key)] = value


@dataclass
class EvalResult:
    findings: list[dict]
    latency_ms: float
    top_severity: Optional[str]
    fired: bool


def _reset_module_state() -> None:
    """Clear the detection modules' MODULE-LEVEL dedup/rate caches so cases are
    isolated. These caches are global per-process; without resetting them an
    entity seen in one case would be dedup-suppressed in the next, corrupting the
    measurement (a real TP would silently "not fire")."""
    import importlib, pkgutil
    import manager.manager.attacklens.detections as pkg
    for mod in pkgutil.iter_modules(pkg.__path__):
        try:
            m = importlib.import_module(f"{pkg.__name__}.{mod.name}")
        except Exception:
            continue
        for attr in ("_dedup_cache", "_rate_counter", "_new_task_times", "_nvd_calls_this_run"):
            cache = getattr(m, attr, None)
            if isinstance(cache, dict):
                cache.clear()


async def _evaluate(analyze_fn: Callable, section: str, snapshots: list,
                    agent_id: str = "acc-agent", hostname: str = "acc-host") -> EvalResult:
    """Run `analyze` over snapshots in order on one shared DB; measure the LAST."""
    _reset_module_state()
    db = FakeStateDB()
    findings: list[dict] = []
    latency_ms = 0.0
    for snap in snapshots:
        t0 = time.perf_counter()
        findings = await analyze_fn(agent_id, section, snap, db, hostname)
        latency_ms = (time.perf_counter() - t0) * 1000.0
    findings = findings or []
    top = max((f.get("severity") for f in findings), key=sev_rank, default=None) if findings else None
    return EvalResult(findings=findings, latency_ms=latency_ms,
                      top_severity=top, fired=len(findings) > 0)


def evaluate(analyze_fn: Callable, section: str, snapshots: list, **kw) -> EvalResult:
    return asyncio.run(_evaluate(analyze_fn, section, snapshots, **kw))


@dataclass
class Case:
    """One labelled accuracy case for a detection module."""
    name: str
    analyze_fn: Callable
    section: str
    snapshots: list                      # run in order; last is the one under test
    expect_fire: bool                    # True = TP must fire, False = FP must stay silent
    min_severity: Optional[str] = None   # for TP: fired finding must be ≥ this
    max_latency_ms: float = 250.0        # speed budget per snapshot
    rule_id: Optional[str] = None        # optional: require this rule_id present
    label: str = "tp"                    # "tp" | "fp" (reporting only)
