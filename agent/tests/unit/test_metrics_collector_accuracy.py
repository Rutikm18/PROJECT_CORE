"""
agent/tests/unit/test_metrics_collector_accuracy.py — metrics must be
internally consistent and physically plausible, not just present.

Two real findings from a live agent's actual telemetry (5 consecutive
samples, not a one-off):

  1. cpu_freq_mhz was exactly 4.0 in every sample — 4 megahertz, slower than
     a 1980s computer, on an Apple Silicon chip that runs at multiple
     gigahertz. A known psutil/Apple-Silicon limitation (no public
     per-cluster clock-speed sysctl) was being shipped as a confident,
     wrong number instead of being discarded.

  2. cpu_percent read 2-4x higher than the average of cpu_per_core in every
     sample (e.g. 99.7% aggregate vs 28.3% per-core average) — not load
     variance, a structural bug: the two were measured over DIFFERENT
     windows (a forced fresh 1s sample vs "since the last call", ~one
     collection interval ago).

Both are now: one single sampling window for both aggregate and per-core
CPU (so they're consistent by construction), and a plausibility range that
discards (not ships) an impossible frequency.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import agent.os.macos.collectors.volatile as volatile_mod
from agent.os.macos.collectors.volatile import MetricsCollector


def _fake_psutil(cpu_per_core, cpu_freq_current):
    fake = MagicMock()
    fake.cpu_percent.return_value = cpu_per_core
    fake.virtual_memory.return_value = SimpleNamespace(
        percent=50.0, used=8_000_000_000, total=16_000_000_000, available=8_000_000_000)
    fake.swap_memory.return_value = SimpleNamespace(
        percent=10.0, used=1_000_000_000, total=10_000_000_000)
    fake.boot_time.return_value = 0.0
    fake.getloadavg.return_value = (1.0, 1.0, 1.0)
    fake.cpu_freq.return_value = SimpleNamespace(current=cpu_freq_current)
    fake.cpu_count.return_value = 8
    fake.disk_io_counters.return_value = None
    fake.net_io_counters.return_value = None
    return fake


def test_cpu_percent_is_consistent_with_per_core_average(monkeypatch):
    """Regression: cpu_percent must equal the mean of cpu_per_core — both
    come from the SAME measurement now, so this can't drift apart again."""
    per_core = [10.0, 20.0, 30.0, 40.0]
    monkeypatch.setattr(volatile_mod, "_psutil", _fake_psutil(per_core, 3500.0))

    result = MetricsCollector()._collect_psutil()

    assert result["cpu_per_core"] == per_core
    assert result["cpu_percent"] == sum(per_core) / len(per_core) == 25.0


def test_implausible_cpu_freq_is_discarded_not_shipped(monkeypatch):
    """The exact bug found live: psutil returned 4.0 (MHz label, GHz-scale
    value) on every single sample. Must become None, not a wrong number."""
    monkeypatch.setattr(volatile_mod, "_psutil", _fake_psutil([10.0], 4.0))

    result = MetricsCollector()._collect_psutil()

    assert result["cpu_freq_mhz"] is None


def test_plausible_cpu_freq_is_kept(monkeypatch):
    monkeypatch.setattr(volatile_mod, "_psutil", _fake_psutil([10.0], 3504.0))

    result = MetricsCollector()._collect_psutil()

    assert result["cpu_freq_mhz"] == 3504.0


def test_boundary_values_are_accepted(monkeypatch):
    for freq in (volatile_mod._CPU_FREQ_MIN_MHZ, volatile_mod._CPU_FREQ_MAX_MHZ):
        monkeypatch.setattr(volatile_mod, "_psutil", _fake_psutil([10.0], float(freq)))
        result = MetricsCollector()._collect_psutil()
        assert result["cpu_freq_mhz"] == float(freq)


def test_just_outside_boundary_is_discarded(monkeypatch):
    for freq in (volatile_mod._CPU_FREQ_MIN_MHZ - 1, volatile_mod._CPU_FREQ_MAX_MHZ + 1):
        monkeypatch.setattr(volatile_mod, "_psutil", _fake_psutil([10.0], float(freq)))
        result = MetricsCollector()._collect_psutil()
        assert result["cpu_freq_mhz"] is None


def test_empty_per_core_falls_back_to_direct_measurement(monkeypatch):
    """If the percpu call fails (empty list), cpu_percent must still get a
    real value via the non-percpu fallback, not silently become 0/garbage."""
    fake = _fake_psutil([], 3500.0)
    fake.cpu_percent.side_effect = [[], 42.0]  # first call (percpu) -> [], fallback -> 42.0
    monkeypatch.setattr(volatile_mod, "_psutil", fake)

    result = MetricsCollector()._collect_psutil()

    assert result["cpu_per_core"] == []
    assert result["cpu_percent"] == 42.0
