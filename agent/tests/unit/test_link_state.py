"""
agent/tests/unit/test_link_state.py — manager-link health in the heartbeat.

Covers the producer half of capability #5 (connection-check surfacing):
  - Sender.link_state() reflects online/offline, spool backlog, auth failures.
  - The orchestrator's agent_health heartbeat embeds that link snapshot.
The manager half (assets API surfacing) is in
manager/tests/unit/test_link_status_api.py.
"""
from __future__ import annotations

import queue
import time

import pytest

from agent.agent.sender import Sender


def _make_sender(tmp_path) -> Sender:
    config = {
        "manager": {"url": "http://127.0.0.1:9/ingest", "tls_verify": False,
                    "timeout_sec": 1, "retry_attempts": 1, "retry_delay_sec": 0},
        "paths": {"spool_dir": str(tmp_path)},
    }
    return Sender(config, queue.Queue())


# ── Sender.link_state() ───────────────────────────────────────────────────────

def test_link_state_fresh_is_offline_unknown_contact(tmp_path):
    s = _make_sender(tmp_path)
    ls = s.link_state()
    assert ls["manager_online"] is False
    assert ls["spool_bytes"] == 0
    assert ls["auth_failures"] == 0
    assert ls["last_contact_ts"] == 0
    assert ls["seconds_since_contact"] is None   # never contacted → not 0


def test_link_state_online_reports_recent_contact(tmp_path):
    s = _make_sender(tmp_path)
    s._online = True
    s._last_contact_ts = time.time()
    ls = s.link_state()
    assert ls["manager_online"] is True
    assert ls["last_contact_ts"] > 0
    assert ls["seconds_since_contact"] is not None
    assert ls["seconds_since_contact"] >= 0


def test_link_state_reports_spool_backlog_and_auth_failures(tmp_path):
    s = _make_sender(tmp_path)
    s._spool.write({"section": "metrics", "seq": 1})
    s._auth_fail_count = 2
    ls = s.link_state()
    assert ls["spool_bytes"] > 0
    assert ls["auth_failures"] == 2


# ── agent_health heartbeat embeds the link snapshot ───────────────────────────

def test_emit_health_includes_link(monkeypatch):
    from agent.agent.core import Orchestrator

    cfg = {"agent": {"id": "agent-test", "name": "Test"},
           "manager": {"max_queue_size": 500},
           "collection": {"tick_sec": 5}}
    sentinel = {"manager_online": True, "spool_bytes": 0, "auth_failures": 0,
                "last_contact_ts": 123, "seconds_since_contact": 4}
    orch = Orchestrator(cfg, b"e" * 32, b"m" * 32, queue.Queue(),
                        link_state=lambda: sentinel)

    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(section=section, data=data))
    orch._emit_health()

    assert captured["section"] == "agent_health"
    assert captured["data"]["link"] == sentinel


def test_emit_health_without_provider_has_no_link(monkeypatch):
    from agent.agent.core import Orchestrator

    cfg = {"agent": {"id": "agent-test", "name": "Test"},
           "manager": {"max_queue_size": 500},
           "collection": {"tick_sec": 5}}
    orch = Orchestrator(cfg, b"e" * 32, b"m" * 32, queue.Queue())  # no link_state

    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(data=data))
    orch._emit_health()

    assert "link" not in captured["data"]   # older wiring stays clean


def test_emit_health_survives_link_provider_error(monkeypatch):
    """A throwing link provider must not break the heartbeat."""
    from agent.agent.core import Orchestrator

    cfg = {"agent": {"id": "agent-test", "name": "Test"},
           "manager": {"max_queue_size": 500},
           "collection": {"tick_sec": 5}}

    def boom():
        raise RuntimeError("sender gone")

    orch = Orchestrator(cfg, b"e" * 32, b"m" * 32, queue.Queue(), link_state=boom)
    captured = {}
    monkeypatch.setattr(orch, "_enqueue",
                        lambda section, data: captured.update(data=data))
    orch._emit_health()   # must not raise

    assert captured["data"]["agent_id"] == "agent-test"
    assert "link" not in captured["data"]   # failed provider → link omitted, not partial
