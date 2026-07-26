"""
agent/tests/unit/test_watchdog.py — Tests for the process watchdog.

Failure points covered:
  - Missing binary → logged critical, no exception
  - Non-executable binary → logged critical, no exception
  - World-writable binary → security warning logged
  - Running process → NOT restarted
  - Crashed process (non-None exit code) → restarted
  - Restart rate limiting → backs off after max_restarts
  - Restart window expiry → allows restart after old crashes age out
  - PID file written on start, cleared on stop
  - SIGTERM gracefully stops the agent process
"""
from __future__ import annotations

import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from agent.agent.watchdog import Watchdog


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_cfg(tmp_path, *, agent_bin=None, python=None, config_path="",
             max_restarts=3, restart_window=60, check_interval=1):
    binaries = {"agent": agent_bin or str(tmp_path / "fake-agent")}
    if python is not None:
        binaries["python"] = python
    return {
        "binaries": binaries,
        "watchdog": {
            "check_interval_sec": check_interval,
            "max_restarts":       max_restarts,
            "restart_window_sec": restart_window,
        },
        "paths": {
            "pid_file": str(tmp_path / "agent.pid"),
            "log_dir":  str(tmp_path),
        },
        "logging": {"level": "DEBUG", "max_mb": 1, "backups": 1},
        "_config_path": config_path,
    }


# ── Binary verification ───────────────────────────────────────────────────────

class TestBinaryVerification:
    def test_missing_binary_does_not_raise(self, tmp_path):
        cfg = make_cfg(tmp_path, agent_bin="/no/such/file")
        w = Watchdog(cfg)
        w._start_agent()    # must not raise
        assert w._proc is None

    def test_non_executable_binary_does_not_raise(self, tmp_path):
        fake = tmp_path / "fake-agent"
        fake.write_text("#!/bin/sh")
        fake.chmod(0o644)   # not executable
        cfg = make_cfg(tmp_path, agent_bin=str(fake))
        w = Watchdog(cfg)
        w._start_agent()
        assert w._proc is None

    def test_world_writable_binary_logs_warning(self, tmp_path, caplog):
        import logging
        fake = tmp_path / "fake-agent"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o777)   # world writable — security risk
        cfg = make_cfg(tmp_path, agent_bin=str(fake))
        w = Watchdog(cfg)
        with caplog.at_level(logging.ERROR, logger="watchdog"):
            w._verify_binary()
        assert any("world-writable" in r.message.lower() or
                   "SECURITY" in r.message
                   for r in caplog.records)


# ── Interpreter-launch mode (.py agent target) ────────────────────────────────

class TestInterpreterMode:
    """The macOS deployment ships a non-executable `run_agent.py`; the watchdog
    must launch it via the interpreter instead of FATAL-ing on the X_OK check."""

    def _stub_script(self, tmp_path, name="run_agent.py"):
        script = tmp_path / name
        script.write_text("import time\ntime.sleep(30)\n")
        script.chmod(0o644)   # NOT executable — exactly the deployed case
        return script

    def test_py_target_uses_interpreter(self, tmp_path):
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script), python=sys.executable)
        w = Watchdog(cfg)
        assert w._use_interpreter is True

    def test_non_executable_py_verifies_ok(self, tmp_path):
        """Regression: a non-executable .py must NOT FATAL — it launches via python."""
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script), python=sys.executable)
        w = Watchdog(cfg)
        assert w._verify_binary() is True

    def test_build_cmd_prefixes_interpreter_and_config(self, tmp_path):
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script), python=sys.executable,
                       config_path="/Library/AttackLens/agent.toml")
        w = Watchdog(cfg)
        # The 'run' subcommand is inserted by default (Issue 5b fix): the agent
        # CLI is subcommand-based, so a bare '--config' without 'run' exits 2 and
        # crash-loops. Interpreter mode inserts it just like native-binary mode.
        assert w._build_cmd() == [
            sys.executable, str(script), "run", "--config",
            "/Library/AttackLens/agent.toml",
        ]

    def test_py_target_defaults_to_running_interpreter(self, tmp_path):
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script))   # no [binaries] python
        w = Watchdog(cfg)
        assert w.python_bin == sys.executable
        assert w._verify_binary() is True

    def test_py_target_missing_interpreter_is_fatal(self, tmp_path):
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script),
                       python="/no/such/python-binary")
        w = Watchdog(cfg)
        assert w._verify_binary() is False
        w._start_agent()
        assert w._proc is None

    def test_py_target_actually_starts(self, tmp_path):
        script = self._stub_script(tmp_path)
        cfg = make_cfg(tmp_path, agent_bin=str(script), python=sys.executable)
        w = Watchdog(cfg)
        try:
            w._start_agent()
            assert w._proc is not None, "interpreter-launched agent should start"
            assert w._proc.poll() is None, "agent process should be running"
            assert os.path.exists(cfg["paths"]["pid_file"])
        finally:
            w.stop()

    def test_native_non_executable_still_fatal(self, tmp_path):
        """Non-.py targets keep the strict X_OK contract (unchanged behaviour)."""
        fake = tmp_path / "attacklens-agent"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o644)
        cfg = make_cfg(tmp_path, agent_bin=str(fake))
        w = Watchdog(cfg)
        assert w._use_interpreter is False
        assert w._verify_binary() is False


# ── Process monitoring ────────────────────────────────────────────────────────

class TestProcessMonitoring:
    def test_running_process_not_restarted(self, tmp_path):
        cfg = make_cfg(tmp_path)
        w = Watchdog(cfg)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None   # still running
        w._proc = mock_proc
        started = []
        w._start_agent = lambda: started.append(1)
        w._check_and_maybe_restart()
        assert not started

    def test_crashed_process_triggers_restart(self, tmp_path):
        cfg = make_cfg(tmp_path)
        w = Watchdog(cfg)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1   # exited with error
        mock_proc.pid = 42
        w._proc = mock_proc
        started = []
        w._start_agent = lambda: started.append(1)
        w._check_and_maybe_restart()
        assert started

    def test_none_proc_triggers_restart(self, tmp_path):
        cfg = make_cfg(tmp_path)
        w = Watchdog(cfg)
        w._proc = None
        started = []
        w._start_agent = lambda: started.append(1)
        w._check_and_maybe_restart()
        assert started


# ── Rate limiting ─────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_backs_off_after_max_restarts(self, tmp_path):
        cfg = make_cfg(tmp_path, max_restarts=3, restart_window=60)
        w = Watchdog(cfg)
        now = time.monotonic()
        w._restart_times = [now, now, now]   # already hit max
        started = []
        w._start_agent = lambda: started.append(1)
        w._rate_limited_restart()
        assert not started, "Should NOT restart after hitting rate limit"

    def test_allows_restart_when_under_limit(self, tmp_path):
        cfg = make_cfg(tmp_path, max_restarts=3, restart_window=60)
        w = Watchdog(cfg)
        w._restart_times = [time.monotonic()]   # only 1 of 3 used
        started = []
        w._start_agent = lambda: started.append(1)
        w._rate_limited_restart()
        assert started

    def test_old_crashes_expire_from_window(self, tmp_path):
        cfg = make_cfg(tmp_path, max_restarts=2, restart_window=1)
        w = Watchdog(cfg)
        # Crashes from 5 seconds ago — outside the 1-second window
        w._restart_times = [time.monotonic() - 5, time.monotonic() - 5]
        started = []
        w._start_agent = lambda: started.append(1)
        w._rate_limited_restart()
        assert started, "Old crashes should not block restart"

    def test_restart_count_increments(self, tmp_path):
        cfg = make_cfg(tmp_path, max_restarts=5, restart_window=60)
        w = Watchdog(cfg)
        w._start_agent = lambda: None
        for _ in range(3):
            w._rate_limited_restart()
        assert len(w._restart_times) == 3


# ── PID file ──────────────────────────────────────────────────────────────────

class TestPIDFile:
    def test_pid_written_on_start(self, tmp_path):
        pid_path = str(tmp_path / "agent.pid")
        cfg = make_cfg(tmp_path)
        cfg["paths"]["pid_file"] = pid_path
        w = Watchdog(cfg)
        w._write_pid(12345)
        assert os.path.exists(pid_path)
        with open(pid_path) as f:
            assert f.read() == "12345"

    def test_pid_cleared_on_clear(self, tmp_path):
        pid_path = str(tmp_path / "agent.pid")
        cfg = make_cfg(tmp_path)
        cfg["paths"]["pid_file"] = pid_path
        w = Watchdog(cfg)
        w._write_pid(12345)
        w._clear_pid()
        assert not os.path.exists(pid_path)

    def test_clear_pid_is_idempotent(self, tmp_path):
        cfg = make_cfg(tmp_path)
        w = Watchdog(cfg)
        w._clear_pid()   # no pid file exists — should not raise
        w._clear_pid()   # again — still fine
