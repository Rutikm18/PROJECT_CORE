"""Single source of truth for resolving a dashboard time window to (start, end).

Two modes:
  - relative preset  → [now - WINDOW_SECONDS[window], now]
  - absolute range   → explicit [start, end] (epoch seconds)

All windows are half-open-friendly integer epoch seconds. Relative windows are
server-authoritative (never trust a client clock); an absolute end in the future
is clamped to `now` rather than rejected, so mild client-clock skew is tolerated.
"""
from __future__ import annotations

import math
import time

from shared.wire import WINDOW_SECONDS

SKEW_SECONDS = 300  # tolerate an absolute end up to 5 min ahead, then clamp


class WindowError(ValueError):
    """Invalid window input — callers should map this to HTTP 422."""


def resolve_window(
    window: str | None = "1h",
    start: int | None = None,
    end: int | None = None,
    now: int | float | None = None,
) -> tuple[int, int]:
    # Finding timestamps retain fractional seconds. Flooring `now` could make a
    # just-created row newer than the relative window's end until the next
    # clock tick, producing an intermittent empty dashboard after refresh.
    now = math.ceil(now if now is not None else time.time())

    # Absolute mode wins when both bounds are given.
    if start is not None and end is not None:
        start = int(start)
        end = int(end)
        # Tolerate mild client-clock skew: an end up to SKEW_SECONDS ahead of
        # server-now is kept as-is; only a clearly-future end is clamped to now.
        # (The previous form clamped *every* end > now, so SKEW_SECONDS was dead
        # code and a client 2s ahead lost its most recent bucket.)
        if end > now + SKEW_SECONDS:
            end = now
        if start >= end:
            raise WindowError(f"start ({start}) must be < end ({end})")
        return start, end

    # Relative mode.
    key = window or "1h"
    secs = WINDOW_SECONDS.get(key)
    if secs is None:
        valid = ", ".join(sorted(WINDOW_SECONDS))
        raise WindowError(f"unknown window {key!r}; valid: {valid}")
    return now - secs, now
