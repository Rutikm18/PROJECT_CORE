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
