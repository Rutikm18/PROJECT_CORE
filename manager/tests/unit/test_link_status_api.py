"""
manager/tests/unit/test_link_status_api.py — _link_summary rollup.

Consumer half of capability #5: the assets API condenses the agent_health
`link` block into a per-agent link status the dashboard can render.
"""
from __future__ import annotations

import pytest

from manager.manager.api.assets import _link_summary


def test_none_when_no_link_block():
    # Older agents that never reported link state.
    assert _link_summary({}) is None
    assert _link_summary({"link": "not-a-dict"}) is None
    assert _link_summary(None) is None


def test_healthy_when_online_and_no_backlog():
    out = _link_summary({"link": {
        "manager_online": True, "spool_bytes": 0, "auth_failures": 0,
        "last_contact_ts": 1000, "seconds_since_contact": 3,
    }})
    assert out["status"] == "healthy"
    assert out["manager_online"] is True
    assert out["seconds_since_contact"] == 3


def test_degraded_when_offline_or_spooling():
    offline = _link_summary({"link": {"manager_online": False, "spool_bytes": 0}})
    assert offline["status"] == "degraded"

    # Online but telemetry is buffering to disk → still degraded.
    spooling = _link_summary({"link": {"manager_online": True, "spool_bytes": 4096}})
    assert spooling["status"] == "degraded"
    assert spooling["spool_bytes"] == 4096


def test_auth_failed_takes_precedence():
    out = _link_summary({"link": {
        "manager_online": True, "spool_bytes": 8192, "auth_failures": 3,
    }})
    assert out["status"] == "auth_failed"
    assert out["auth_failures"] == 3


def test_missing_numeric_fields_default_to_zero():
    out = _link_summary({"link": {"manager_online": True}})
    assert out["spool_bytes"] == 0
    assert out["auth_failures"] == 0
    assert out["last_contact_ts"] == 0
    assert out["status"] == "healthy"
