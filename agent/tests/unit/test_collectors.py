"""
tests/unit/test_collectors.py — Unit tests for the collector registry.

Coverage:
  - All collectors in COLLECTORS are callable
  - Each collector's .name matches its registry key
  - BaseCollector cannot be instantiated directly
  - _run() returns "" on missing command / timeout (never raises)
  - Mocked _run() verifies collectors call it
"""
from __future__ import annotations

import pytest
from unittest.mock import patch

from agent.agent.collectors import COLLECTORS
from agent.agent.collectors.base import BaseCollector, _run


# ── Registry integrity ────────────────────────────────────────────────────────

def test_all_collectors_are_callable():
    for name, collector in COLLECTORS.items():
        assert callable(collector), f"Collector {name!r} is not callable"


def test_collector_name_matches_registry_key():
    for key, collector in COLLECTORS.items():
        assert hasattr(collector, "name"), f"Collector {key!r} has no .name attribute"
        assert collector.name == key, (
            f"Registry key {key!r} does not match collector.name={collector.name!r}"
        )


def test_registry_is_non_empty():
    assert len(COLLECTORS) >= 22, "Expected at least 22 registered collectors"


# ── BaseCollector contract ────────────────────────────────────────────────────

def test_base_collector_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseCollector()  # type: ignore[abstract]


def test_collector_repr_contains_class_and_name():
    from agent.agent.collectors.volatile import MetricsCollector
    c = MetricsCollector()
    assert "MetricsCollector" in repr(c)
    assert "metrics" in repr(c)


# ── _run() safety ─────────────────────────────────────────────────────────────

def test_run_returns_empty_string_for_missing_command():
    result = _run(["__this_command_does_not_exist__"])
    assert result == ""


def test_run_returns_empty_string_on_timeout():
    # timeout=0 will always expire immediately
    result = _run(["sleep", "60"], timeout=0)
    assert result == ""


def test_run_does_not_raise_on_error():
    # Should never raise under any circumstances
    _run(["false"])   # exits with non-zero — should return ""


# ── Collector mock tests ──────────────────────────────────────────────────────

@patch("agent.agent.collectors.base._run", return_value="")
def test_metrics_collector_calls_run(mock_run):
    from agent.agent.collectors.volatile import MetricsCollector
    result = MetricsCollector()()
    assert isinstance(result, dict)
    assert mock_run.call_count >= 1


@patch("agent.agent.collectors.base._run", return_value="")
def test_security_collector_returns_dict(mock_run):
    from agent.agent.collectors.posture import SecurityCollector
    result = SecurityCollector()()
    assert isinstance(result, dict)
    assert "sip" in result
    assert "gatekeeper" in result
    assert "filevault" in result


@patch("agent.agent.collectors.base._run", return_value="")
def test_connections_collector_returns_list(mock_run):
    from agent.agent.collectors.volatile import ConnectionsCollector
    result = ConnectionsCollector()()
    assert isinstance(result, list)
