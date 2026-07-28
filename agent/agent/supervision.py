"""
agent/agent/supervision.py — in-process supervision tree + heartbeats (matrix R6).

The failure this closes: the main process can be perfectly healthy while a worker
thread (the sender, the orchestrator) is dead or WEDGED — alive but making no
progress — so launchd's KeepAlive never fires and telemetry silently stops.

Model (single lifecycle owner = launchd):
  • Each worker publishes a heartbeat: `last_alive` every loop iteration, and
    `last_success` whenever it does real work (a delivered payload, a completed
    collection tick).
  • A Supervisor evaluates staleness and returns a verdict per component:
      - healthy   → nothing to do
      - escalate  → alive but not succeeding (wedged on a dependency); surface it
      - restart   → not even ticking (thread dead/hung) → bounded in-process restart
  • Bounded restarts: after `max_restarts` within `window_sec`, the Supervisor
    returns `terminate` so the caller does a clean `sys.exit(non-zero)` and lets
    launchd perform a full, deterministic restart — never spawn a competing
    supervisor (that would violate the single-owner invariant, matrix R7).

All decision functions are pure (clock injected) → unit-testable without threads,
sleeps, launchd, or a live manager.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

# Verdicts
HEALTHY = "healthy"
ESCALATE = "escalate"
RESTART = "restart"
TERMINATE = "terminate"


@dataclass
class ComponentHealth:
    started_at: float
    last_alive: float
    last_success: float | None = None


class HeartbeatRegistry:
    """Thread-safe store of component heartbeats. Workers call `beat()`."""

    def __init__(self):
        self._h: dict[str, ComponentHealth] = {}
        self._lock = threading.Lock()

    def register(self, name: str, now: float | None = None) -> None:
        now = _now(now)
        with self._lock:
            self._h[name] = ComponentHealth(started_at=now, last_alive=now)

    def beat(self, name: str, success: bool = False, now: float | None = None) -> None:
        now = _now(now)
        with self._lock:
            h = self._h.get(name)
            if h is None:
                h = ComponentHealth(started_at=now, last_alive=now)
                self._h[name] = h
            h.last_alive = now
            if success:
                h.last_success = now

    def get(self, name: str) -> ComponentHealth | None:
        with self._lock:
            return self._h.get(name)

    def snapshot(self, now: float | None = None) -> dict:
        now = _now(now)
        with self._lock:
            return {
                name: {
                    "alive_age": round(now - h.last_alive, 1),
                    "success_age": (round(now - h.last_success, 1)
                                    if h.last_success is not None else None),
                }
                for name, h in self._h.items()
            }


def evaluate(
    h: ComponentHealth,
    now: float,
    *,
    alive_stale: float,
    success_stale: float,
    grace: float = 30.0,
) -> str:
    """Pure verdict for one component. See module docstring for the model."""
    # Not even ticking → the thread is dead or hung. Highest priority.
    if now - h.last_alive > alive_stale:
        return RESTART
    # Alive but not succeeding for too long → wedged on a dependency.
    if h.last_success is not None:
        if now - h.last_success > success_stale:
            return ESCALATE
    else:
        # Never succeeded yet: allow a startup grace before escalating.
        if now - h.started_at > success_stale + grace:
            return ESCALATE
    return HEALTHY


@dataclass
class RestartTracker:
    """Bounded-restart budget per component within a sliding window."""
    max_restarts: int = 3
    window_sec: float = 300.0
    _events: dict[str, list] = field(default_factory=dict)

    def record(self, name: str, now: float) -> bool:
        """Record a restart. Returns True if still within budget, False if the
        budget is exhausted (caller should escalate to process termination)."""
        evs = [t for t in self._events.get(name, []) if now - t <= self.window_sec]
        evs.append(now)
        self._events[name] = evs
        return len(evs) <= self.max_restarts


class Supervisor:
    """Ties the registry + evaluate + restart budget together for a periodic loop.

    `check(now)` returns a list of (component, verdict) actions. The caller owns
    the actual restart/terminate side effects (this class stays free of threads
    and sys.exit so it is fully testable).
    """

    def __init__(
        self,
        registry: HeartbeatRegistry,
        *,
        alive_stale: float = 90.0,
        success_stale: float = 600.0,
        grace: float = 60.0,
        max_restarts: int = 3,
        window_sec: float = 300.0,
    ):
        self.registry = registry
        self.alive_stale = alive_stale
        self.success_stale = success_stale
        self.grace = grace
        self._tracker = RestartTracker(max_restarts, window_sec)

    def check(self, now: float | None = None) -> list[tuple[str, str]]:
        now = _now(now)
        actions: list[tuple[str, str]] = []
        # snapshot names under lock, then evaluate each
        for name in list(self.registry._h.keys()):          # noqa: SLF001 - internal
            h = self.registry.get(name)
            if h is None:
                continue
            verdict = evaluate(
                h, now,
                alive_stale=self.alive_stale,
                success_stale=self.success_stale,
                grace=self.grace,
            )
            if verdict == RESTART:
                # If restarts are exhausted, escalate to terminate.
                if not self._tracker.record(name, now):
                    actions.append((name, TERMINATE))
                else:
                    actions.append((name, RESTART))
            elif verdict == ESCALATE:
                actions.append((name, ESCALATE))
        return actions


def _now(now: float | None) -> float:
    return now if now is not None else time.monotonic()
