import math
from manager.manager.timeseries import bucket_seconds

LADDER_MIN = 1  # never smaller than 1s

def _points(start, end, w):
    return math.ceil((end - start) / w)

def test_short_window_small_buckets():
    # 30s window → <= 500 points, bucket at least 1s
    w = bucket_seconds(0, 30)
    assert w >= LADDER_MIN
    assert _points(0, 30, w) <= 500

def test_month_window_bounded_points():
    start, end = 0, 2592000  # 30d
    w = bucket_seconds(start, end)
    assert _points(start, end, w) <= 500

def test_custom_year_span_still_bounded():
    start, end = 0, 365 * 86400
    assert _points(start, end, bucket_seconds(start, end)) <= 500

def test_returns_ladder_value():
    # Result is one of the human-friendly ladder steps, not an arbitrary int.
    assert bucket_seconds(0, 3600) in {
        1, 5, 10, 30, 60, 300, 600, 1800, 3600, 21600, 43200, 86400,
    }
