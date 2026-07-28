"""
agent/agent/obs.py — structured, deduplicated, rate-limited logging (matrix R15).

A long-running agent that hits a persistent fault (manager down, spool degraded,
a collector permission error) will otherwise emit the SAME log line every cycle
and bury the signal. `log_throttled` emits the first occurrence of a given key
immediately, then at most once per interval per key, annotating the re-emission
with how many identical events were suppressed in between — plus structured
key=value fields (component, code, retry_count, queue_depth, spool_size,
recovery_action) so each record is machine-greppable.

The throttling decision (`Throttle.check`) is pure and injectable-clock, so it is
unit-testable without wall-clock sleeps or a real logger.
"""
from __future__ import annotations

import logging
import threading
import time


class Throttle:
    """Per-key rate limiter. Thread-safe; monotonic-clock based.

    check(key, now) -> (emit: bool, suppressed: int)
      • First time a key is seen, or once `interval` has elapsed since its last
        emit: returns (True, <count suppressed since last emit>).
      • Within the interval: returns (False, <running suppressed count>).
    """

    def __init__(self, interval: float = 60.0):
        self.interval = interval
        self._state: dict[str, dict] = {}   # key -> {last_emit, suppressed}
        self._lock = threading.Lock()

    def check(self, key: str, now: float) -> tuple[bool, int]:
        with self._lock:
            st = self._state.get(key)
            if st is None:
                self._state[key] = {"last_emit": now, "suppressed": 0}
                return True, 0
            if now - st["last_emit"] >= self.interval:
                suppressed = st["suppressed"]
                st["last_emit"] = now
                st["suppressed"] = 0
                return True, suppressed
            st["suppressed"] += 1
            return False, st["suppressed"]

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._state.clear()
            else:
                self._state.pop(key, None)


# Process-wide default throttle for hot-path call sites.
_DEFAULT_THROTTLE = Throttle()


def _format_fields(fields: dict) -> str:
    # Deterministic, greppable key=value rendering. None values are dropped.
    parts = [f"{k}={v}" for k, v in fields.items() if v is not None]
    return (" " + " ".join(parts)) if parts else ""


def log_throttled(
    logger: logging.Logger,
    key: str,
    level: int,
    msg: str,
    *,
    interval: float | None = None,
    throttle: Throttle | None = None,
    now: float | None = None,
    **fields,
) -> bool:
    """Emit `msg` at most once per interval per `key`. Returns True if emitted.

    On re-emission after suppression, appends `suppressed=N`. Extra keyword
    fields are rendered as structured `key=value` pairs (None fields dropped).
    `interval` overrides the throttle's default for this key's cadence check by
    using a dedicated throttle only when supplied; otherwise the shared default
    is used.
    """
    t = throttle or _DEFAULT_THROTTLE
    if interval is not None:
        # Honor a caller-specified cadence without mutating the shared default.
        t = _interval_throttle(interval)
    now = now if now is not None else time.monotonic()
    emit, suppressed = t.check(key, now)
    if not emit:
        return False
    if suppressed:
        fields.setdefault("suppressed", suppressed)
    logger.log(level, "%s%s", msg, _format_fields(fields))
    return True


# Cache of per-interval throttles so distinct cadences don't collide on the
# shared default while still being reused across calls.
_interval_throttles: dict[float, Throttle] = {}
_interval_lock = threading.Lock()


def _interval_throttle(interval: float) -> Throttle:
    with _interval_lock:
        t = _interval_throttles.get(interval)
        if t is None:
            t = Throttle(interval)
            _interval_throttles[interval] = t
        return t
