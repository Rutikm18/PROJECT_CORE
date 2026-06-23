"""
agent/tests/unit/test_status_file.py — local on-disk health mirror.

The manager-bound agent_health heartbeat is invisible exactly when an operator
most needs it: the manager is unreachable. This pins the local mirror's
contract:

  - _emit_health() writes the heartbeat to disk when [paths] is configured
  - it does NOT touch any default system path when no [paths] table exists
    (so ad-hoc Orchestrator construction in other unit tests stays side-effect-free)
  - `attacklens-agent --status` reads that file back and reports staleness
"""
from __future__ import annotations

import json
import queue
import time

import agent.agent.core as core
from agent.agent.core import Orchestrator


def _orch(monkeypatch, cfg):
    monkeypatch.setattr(core, "encrypt",
                        lambda payload, *a, **k: {"section": payload["section"]})
    return Orchestrator(cfg, b"\x00" * 32, b"\x00" * 32, queue.Queue())


def test_emit_health_writes_status_file_when_paths_configured(tmp_path, monkeypatch):
    status_file = tmp_path / "health.json"
    cfg = {
        "agent": {"id": "mac-test", "name": "T"},
        "manager": {"max_queue_size": 500},
        "collection": {"tick_sec": 5},
        "paths": {"status_file": str(status_file)},
    }
    orch = _orch(monkeypatch, cfg)

    orch._emit_health()

    assert status_file.exists()
    data = json.loads(status_file.read_text())
    assert data["agent_id"] == "mac-test"
    assert "generated_at" in data
    assert "queue_depth" in data


def test_emit_health_skips_status_file_without_paths_table(tmp_path, monkeypatch):
    # Redirect the default so a miss here would be caught instead of silently
    # landing on the real /Library/AttackLens path.
    monkeypatch.setattr(core, "_DEFAULT_STATUS_FILE", str(tmp_path / "health.json"))
    cfg = {
        "agent": {"id": "mac-test", "name": "T"},
        "manager": {"max_queue_size": 500},
        "collection": {"tick_sec": 5},
    }
    orch = _orch(monkeypatch, cfg)

    orch._emit_health()

    assert not (tmp_path / "health.json").exists(), \
        "no [paths] table configured — must not fall back to the default path"


def test_print_status_reads_fresh_file(tmp_path, capsys):
    status_file = tmp_path / "health.json"
    status_file.write_text(json.dumps({
        "agent_id": "mac-test", "generated_at": int(time.time()), "queue_depth": 0,
    }))
    config_path = tmp_path / "agent.toml"
    config_path.write_text(f'[paths]\nstatus_file = "{status_file}"\n')

    core._print_status(str(config_path))

    out = json.loads(capsys.readouterr().out)
    assert out["agent_id"] == "mac-test"
    assert out["_status_file_age_sec"] >= 0
    assert "_warning" not in out


def test_print_status_warns_when_stale(tmp_path, capsys):
    status_file = tmp_path / "health.json"
    status_file.write_text(json.dumps({
        "agent_id": "mac-test", "generated_at": int(time.time()) - 600, "queue_depth": 0,
    }))
    config_path = tmp_path / "agent.toml"
    config_path.write_text(f'[paths]\nstatus_file = "{status_file}"\n')

    core._print_status(str(config_path))

    out = json.loads(capsys.readouterr().out)
    assert out["_warning"]


def test_print_status_missing_file_exits_nonzero(tmp_path, capsys):
    config_path = tmp_path / "agent.toml"
    config_path.write_text(f'[paths]\nstatus_file = "{tmp_path / "missing.json"}"\n')

    import pytest
    with pytest.raises(SystemExit) as exc_info:
        core._print_status(str(config_path))

    assert exc_info.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert "error" in out
