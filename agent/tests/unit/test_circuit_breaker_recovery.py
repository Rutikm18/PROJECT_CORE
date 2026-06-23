"""
agent/tests/unit/test_circuit_breaker_recovery.py — recovery cadence contract.

The tick loop used to gate EVERY re-check (including breaker recovery probes)
on the section's own interval_sec. For a 1-hour section, a failure meant the
next retry chance was an hour away, not the breaker's own 60s cooldown — a
60x slower recovery than circuit_breaker.py's own docstring promises
("probed again after cooldown"). This pins the fix: CircuitBreakerRegistry
exposes a non-mutating state()/cooldown_for() the scheduler uses to shrink
the effective re-check interval to the cooldown while a section is broken,
then lets it widen back out once healthy.
"""
from __future__ import annotations

from agent.agent.circuit_breaker import CircuitBreakerRegistry


def test_state_does_not_mutate_unlike_allow():
    reg = CircuitBreakerRegistry(fail_threshold=1, cooldown_sec=60)
    reg.failure("sec", "boom")
    assert reg.state("sec") == "OPEN"
    # Peeking repeatedly must not itself flip OPEN -> HALF.
    assert reg.state("sec") == "OPEN"
    assert reg.state("sec") == "OPEN"


def test_cooldown_for_reflects_configured_cooldown():
    reg = CircuitBreakerRegistry(fail_threshold=1, cooldown_sec=45)
    reg.failure("sec", "boom")
    assert reg.cooldown_for("sec") == 45


def test_unknown_section_defaults_to_closed():
    reg = CircuitBreakerRegistry()
    assert reg.state("never-seen") == "CLOSED"


def test_effective_interval_shrinks_to_cooldown_when_open():
    """Direct simulation of the scheduling decision in core.py's tick loop."""
    reg = CircuitBreakerRegistry(fail_threshold=1, cooldown_sec=60)
    reg.failure("security", "boom")

    section_interval = 3600   # security's real configured interval
    effective = section_interval
    if reg.state("security") != "CLOSED":
        effective = min(section_interval, reg.cooldown_for("security"))

    assert effective == 60, \
        "an open breaker on a 1-hour section must be re-checked every 60s, not every hour"


def test_effective_interval_stays_full_once_healthy():
    reg = CircuitBreakerRegistry(fail_threshold=3, cooldown_sec=60)
    reg.success("security")   # CLOSED, healthy — never opened

    section_interval = 3600
    effective = section_interval
    if reg.state("security") != "CLOSED":
        effective = min(section_interval, reg.cooldown_for("security"))

    assert effective == 3600, "a healthy section keeps its normal cadence, no needless re-checks"
