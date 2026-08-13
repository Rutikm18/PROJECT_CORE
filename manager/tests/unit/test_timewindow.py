from shared.wire import WINDOW_SECONDS

EXPECTED = {
    "30s": 30, "1m": 60, "5m": 300, "15m": 900, "1h": 3600,
    "6h": 21600, "1d": 86400, "7d": 604800, "15d": 1296000, "30d": 2592000,
}

def test_all_presets_present_with_correct_seconds():
    for key, secs in EXPECTED.items():
        assert WINDOW_SECONDS[key] == secs

def test_legacy_keys_retained():
    assert WINDOW_SECONDS["8h"] == 28800
    assert WINDOW_SECONDS["90d"] == 7776000


import pytest
from manager.manager.timewindow import resolve_window, WindowError, SKEW_SECONDS

NOW = 1_800_000_000

def test_relative_preset_resolves_to_now_minus_seconds():
    assert resolve_window("1h", now=NOW) == (NOW - 3600, NOW)
    assert resolve_window("30s", now=NOW) == (NOW - 30, NOW)
    assert resolve_window("30d", now=NOW) == (NOW - 2592000, NOW)

def test_default_window_is_1h():
    assert resolve_window(None, now=NOW) == (NOW - 3600, NOW)

def test_relative_window_includes_the_current_fractional_second():
    assert resolve_window("30s", now=NOW + 0.75) == (NOW - 29, NOW + 1)

def test_unknown_preset_raises():
    with pytest.raises(WindowError):
        resolve_window("13h", now=NOW)

def test_absolute_start_end_honoured():
    assert resolve_window(None, start=NOW - 500, end=NOW - 100, now=NOW) == (NOW - 500, NOW - 100)

def test_absolute_overrides_preset():
    assert resolve_window("1h", start=NOW - 50, end=NOW - 10, now=NOW) == (NOW - 50, NOW - 10)

def test_future_end_is_clamped_to_now():
    s, e = resolve_window(None, start=NOW - 100, end=NOW + 10_000, now=NOW)
    assert e == NOW and s == NOW - 100

def test_start_ge_end_raises():
    with pytest.raises(WindowError):
        resolve_window(None, start=NOW, end=NOW, now=NOW)
    with pytest.raises(WindowError):
        resolve_window(None, start=NOW, end=NOW - 5, now=NOW)

def test_end_within_skew_is_tolerated_not_clamped():
    # end slightly in the future but within skew → kept as-is (tolerate client-clock skew)
    end = NOW + SKEW_SECONDS - 1
    s, e = resolve_window(None, start=NOW - 10, end=end, now=NOW)
    assert e == end and s == NOW - 10

def test_end_beyond_skew_is_clamped_to_now():
    # end further than skew in the future → clamped to now
    s, e = resolve_window(None, start=NOW - 10, end=NOW + SKEW_SECONDS + 100, now=NOW)
    assert e == NOW and s == NOW - 10
