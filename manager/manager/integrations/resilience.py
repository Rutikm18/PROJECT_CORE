"""
manager/manager/integrations/resilience.py — Standardized integration resilience.

Primitives shared by every external integration (AI providers, threat-intel
feeds, NVD, email) so reliability behaviour is consistent and observable:

  • Typed errors      — callers distinguish transient vs permanent vs breaker-open
  • RetryPolicy       — exponential backoff + full jitter, honours Retry-After,
                        retries only transient failures (429 / 5xx / network)
  • CircuitBreaker    — three-state (closed→open→half-open), per integration
  • IntegrationMetrics — per-integration counters + latency percentiles + breaker
                        state, exposed via GET /api/v1/integrations/health

This module is dependency-free (stdlib only) so it can wrap any transport.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger("manager.integrations")


# ── Typed errors ───────────────────────────────────────────────────────────────

class IntegrationError(Exception):
    """Base for all integration failures. Carries the integration name."""
    def __init__(self, integration: str, message: str, *, status: Optional[int] = None):
        self.integration = integration
        self.status = status
        super().__init__(f"[{integration}] {message}")


class TransientError(IntegrationError):
    """Retryable: network error, timeout, 429, or 5xx."""


class PermanentError(IntegrationError):
    """Non-retryable: 4xx (except 429), malformed response, auth failure."""


class RateLimitedError(TransientError):
    """429 — carries retry_after seconds when the server provided one."""
    def __init__(self, integration: str, message: str, *, retry_after: Optional[float] = None):
        super().__init__(integration, message, status=429)
        self.retry_after = retry_after


class CircuitOpenError(IntegrationError):
    """The circuit breaker is open — request rejected without a call attempt."""


# ── Retry policy ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RetryPolicy:
    """
    Exponential backoff with full jitter.
    delay = random(0, min(cap, base * 2**attempt)), honouring Retry-After.
    """
    max_attempts: int   = 3       # total tries (1 initial + 2 retries)
    base_delay:   float = 0.5     # seconds
    max_delay:    float = 20.0    # cap per-attempt sleep
    jitter:       bool  = True

    def backoff(self, attempt: int, *, retry_after: Optional[float] = None) -> float:
        """Sleep before `attempt` (0-indexed retry number)."""
        if retry_after is not None and retry_after > 0:
            # Respect the server, but never sleep longer than max_delay * 2.
            return min(retry_after, self.max_delay * 2)
        raw = min(self.max_delay, self.base_delay * (2 ** attempt))
        return random.uniform(0, raw) if self.jitter else raw


# Sensible defaults per integration class.
FAST_API   = RetryPolicy(max_attempts=3, base_delay=0.5, max_delay=8.0)    # AI, REST APIs
BULK_FETCH = RetryPolicy(max_attempts=2, base_delay=2.0, max_delay=30.0)   # large downloads
CRITICAL   = RetryPolicy(max_attempts=4, base_delay=0.5, max_delay=15.0)   # KEV/NVD sync


# ── Circuit breaker ────────────────────────────────────────────────────────────

class BreakerState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """
    Three-state breaker. CLOSED → after `failure_threshold` consecutive failures
    → OPEN (reject for `reset_timeout`s) → HALF_OPEN (one probe) → CLOSED on
    success, OPEN again on failure.
    """
    name:              str
    failure_threshold: int   = 5
    reset_timeout:     float = 60.0

    _failures:  int          = field(default=0, init=False, repr=False)
    _state:     BreakerState = field(default=BreakerState.CLOSED, init=False, repr=False)
    _opened_at: float        = field(default=0.0, init=False, repr=False)

    def allow(self) -> bool:
        if self._state is BreakerState.CLOSED:
            return True
        if self._state is BreakerState.OPEN:
            if time.time() - self._opened_at >= self.reset_timeout:
                self._state = BreakerState.HALF_OPEN
                log.info("breaker[%s] → half-open probe", self.name)
                return True
            return False
        return True  # HALF_OPEN allows a single probe

    def on_success(self) -> None:
        if self._state is not BreakerState.CLOSED:
            log.info("breaker[%s] recovered → closed", self.name)
        self._failures = 0
        self._state = BreakerState.CLOSED

    def on_failure(self, exc: BaseException) -> None:
        self._failures += 1
        if self._state is BreakerState.HALF_OPEN or self._failures >= self.failure_threshold:
            self._state = BreakerState.OPEN
            self._opened_at = time.time()
            log.warning("breaker[%s] OPEN after %d failures (%s)",
                        self.name, self._failures, exc)

    @property
    def state(self) -> str:
        return self._state.value

    def to_dict(self) -> dict:
        secs_until_probe = None
        if self._state is BreakerState.OPEN:
            secs_until_probe = max(0.0, round(self.reset_timeout - (time.time() - self._opened_at), 1))
        return {
            "state":              self.state,
            "consecutive_failures": self._failures,
            "seconds_until_probe": secs_until_probe,
        }


# ── Metrics ────────────────────────────────────────────────────────────────────

@dataclass
class IntegrationMetrics:
    """Per-integration counters + a bounded latency reservoir for percentiles."""
    name:          str
    calls:         int = 0
    successes:     int = 0
    failures:      int = 0
    retries:       int = 0
    timeouts:      int = 0
    rate_limited:  int = 0
    breaker_rejections: int = 0
    last_error:    str = ""
    last_error_at: float = 0.0
    last_success_at: float = 0.0
    _latencies:    deque = field(default_factory=lambda: deque(maxlen=256), repr=False)

    def record_latency(self, ms: float) -> None:
        self._latencies.append(ms)

    def _pct(self, p: float) -> Optional[float]:
        if not self._latencies:
            return None
        s = sorted(self._latencies)
        idx = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
        return round(s[idx], 1)

    @property
    def error_rate(self) -> float:
        return round(self.failures / self.calls, 4) if self.calls else 0.0

    def to_dict(self) -> dict:
        return {
            "name":               self.name,
            "calls":              self.calls,
            "successes":          self.successes,
            "failures":           self.failures,
            "retries":            self.retries,
            "timeouts":           self.timeouts,
            "rate_limited":       self.rate_limited,
            "breaker_rejections": self.breaker_rejections,
            "error_rate":         self.error_rate,
            "latency_ms": {
                "p50": self._pct(50),
                "p95": self._pct(95),
                "p99": self._pct(99),
            },
            "last_error":      self.last_error or None,
            "last_error_at":   self.last_error_at or None,
            "last_success_at": self.last_success_at or None,
        }


class IntegrationRegistry:
    """Process-global registry of per-integration breakers + metrics."""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._metrics:  dict[str, IntegrationMetrics] = {}

    def breaker(self, name: str, **kw) -> CircuitBreaker:
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, **kw)
        return self._breakers[name]

    def metrics(self, name: str) -> IntegrationMetrics:
        if name not in self._metrics:
            self._metrics[name] = IntegrationMetrics(name)
        return self._metrics[name]

    def snapshot(self) -> dict:
        integrations = []
        healthy = degraded = down = 0
        for name in sorted(set(self._metrics) | set(self._breakers)):
            m = self._metrics.get(name)
            b = self._breakers.get(name)
            state = b.state if b else "closed"
            # Health verdict: breaker open = down; recent high error rate = degraded.
            if state == "open":
                status = "down"; down += 1
            elif m and m.calls >= 5 and m.error_rate > 0.25:
                status = "degraded"; degraded += 1
            else:
                status = "healthy"; healthy += 1
            integrations.append({
                "status":  status,
                "breaker": b.to_dict() if b else {"state": "closed"},
                **(m.to_dict() if m else {"name": name, "calls": 0}),
            })
        overall = "healthy" if down == 0 and degraded == 0 else ("down" if down else "degraded")
        return {
            "overall":  overall,
            "counts":   {"healthy": healthy, "degraded": degraded, "down": down},
            "integrations": integrations,
            "at": time.time(),
        }


# Process-global singleton.
registry = IntegrationRegistry()
