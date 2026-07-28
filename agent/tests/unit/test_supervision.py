"""
agent/tests/unit/test_supervision.py — supervision tree + heartbeats (R6).
"""
from __future__ import annotations

from agent.agent.supervision import (
    ComponentHealth, HeartbeatRegistry, RestartTracker, Supervisor,
    evaluate, HEALTHY, ESCALATE, RESTART, TERMINATE,
)


# ── evaluate (pure verdict) ────────────────────────────────────────────────────

def test_fresh_component_is_healthy():
    h = ComponentHealth(started_at=0.0, last_alive=100.0, last_success=100.0)
    assert evaluate(h, now=110.0, alive_stale=90, success_stale=600) == HEALTHY


def test_stale_alive_means_restart():
    # Not ticking for > alive_stale → thread dead/hung.
    h = ComponentHealth(started_at=0.0, last_alive=0.0, last_success=0.0)
    assert evaluate(h, now=200.0, alive_stale=90, success_stale=600) == RESTART


def test_alive_but_not_succeeding_escalates():
    # Ticking (fresh last_alive) but no successful work for > success_stale.
    h = ComponentHealth(started_at=0.0, last_alive=1000.0, last_success=100.0)
    assert evaluate(h, now=1000.0, alive_stale=90, success_stale=600) == ESCALATE


def test_never_succeeded_gets_startup_grace_then_escalates():
    h = ComponentHealth(started_at=0.0, last_alive=100.0, last_success=None)
    # Within grace+success_stale → healthy
    assert evaluate(h, now=100.0, alive_stale=90, success_stale=600, grace=60) == HEALTHY
    # Well past grace+success_stale with still no success → escalate
    assert evaluate(h, now=700.0, alive_stale=1000, success_stale=600, grace=60) == ESCALATE


# ── RestartTracker (bounded restart budget) ────────────────────────────────────

def test_restart_budget_allows_up_to_max_then_denies():
    t = RestartTracker(max_restarts=3, window_sec=300)
    assert t.record("sender", 0.0) is True
    assert t.record("sender", 1.0) is True
    assert t.record("sender", 2.0) is True
    assert t.record("sender", 3.0) is False     # 4th within window → over budget


def test_restart_budget_resets_outside_window():
    t = RestartTracker(max_restarts=2, window_sec=100)
    assert t.record("x", 0.0) is True
    assert t.record("x", 1.0) is True
    assert t.record("x", 2.0) is False
    # Far outside the window → old events expire, budget restored.
    assert t.record("x", 500.0) is True


# ── HeartbeatRegistry ──────────────────────────────────────────────────────────

def test_registry_beat_updates_alive_and_success():
    r = HeartbeatRegistry()
    r.register("sender", now=0.0)
    r.beat("sender", now=10.0)                    # alive only
    assert r.get("sender").last_success is None
    r.beat("sender", success=True, now=20.0)      # success
    assert r.get("sender").last_success == 20.0
    assert r.get("sender").last_alive == 20.0


def test_registry_snapshot_ages():
    r = HeartbeatRegistry()
    r.register("s", now=0.0)
    r.beat("s", success=True, now=5.0)
    snap = r.snapshot(now=15.0)
    assert snap["s"]["alive_age"] == 10.0
    assert snap["s"]["success_age"] == 10.0


# ── Supervisor.check (integration of the above) ────────────────────────────────

def test_supervisor_restart_then_terminate_when_budget_exhausted():
    reg = HeartbeatRegistry()
    reg.register("sender", now=0.0)               # last_alive=0, never beats again
    sup = Supervisor(reg, alive_stale=90, success_stale=600,
                     max_restarts=2, window_sec=1000)
    # Each check sees a stale-alive sender → restart, until budget runs out.
    assert sup.check(now=200.0) == [("sender", RESTART)]
    assert sup.check(now=201.0) == [("sender", RESTART)]
    assert sup.check(now=202.0) == [("sender", TERMINATE)]


def test_supervisor_healthy_component_no_action():
    reg = HeartbeatRegistry()
    reg.register("orch", now=0.0)
    reg.beat("orch", success=True, now=100.0)
    sup = Supervisor(reg, alive_stale=90, success_stale=600)
    assert sup.check(now=110.0) == []
