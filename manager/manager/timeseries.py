"""Adaptive bucket sizing so any time span renders as a bounded number of points."""
from __future__ import annotations

import math

# Human-friendly bucket widths (seconds), ascending.
_LADDER = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 43200, 86400,
           7 * 86400, 30 * 86400]


def bucket_seconds(start: int, end: int, max_points: int = 500) -> int:
    span = max(1, int(end) - int(start))
    for width in _LADDER:
        if math.ceil(span / width) <= max_points:
            return width
    return _LADDER[-1]
