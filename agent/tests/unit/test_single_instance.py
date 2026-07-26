"""
agent/tests/unit/test_single_instance.py — cross-process single-instance guard.

flock locks are held per open-file-description, so two separate open()s within
one test process contend exactly like two real processes would.
"""
from __future__ import annotations

import os

import pytest

from agent.agent.single_instance import acquire, AlreadyRunning


@pytest.mark.skipif(os.name != "posix", reason="flock guard is POSIX-only")
class TestSingleInstance:
    def test_first_acquire_succeeds(self, tmp_path):
        lock = str(tmp_path / "agent.lock")
        fd = acquire(lock, wait_sec=0.5)
        assert fd is not None
        assert os.path.exists(lock)
        fd.close()

    def test_second_acquire_raises_while_held(self, tmp_path):
        lock = str(tmp_path / "agent.lock")
        held = acquire(lock, wait_sec=0.5)
        try:
            with pytest.raises(AlreadyRunning):
                acquire(lock, wait_sec=0.3)   # contends, times out, raises
        finally:
            held.close()

    def test_reacquire_after_release(self, tmp_path):
        lock = str(tmp_path / "agent.lock")
        first = acquire(lock, wait_sec=0.5)
        first.close()                          # release
        second = acquire(lock, wait_sec=0.5)   # should now succeed
        assert second is not None
        second.close()

    def test_holder_pid_written_for_diagnostics(self, tmp_path):
        lock = str(tmp_path / "agent.lock")
        fd = acquire(lock, wait_sec=0.5)
        try:
            with open(lock) as f:
                assert f.read().strip() == str(os.getpid())
        finally:
            fd.close()

    def test_lock_dir_created_when_missing(self, tmp_path):
        lock = str(tmp_path / "deep" / "nested" / "agent.lock")
        fd = acquire(lock, wait_sec=0.5)
        assert fd is not None
        assert os.path.isdir(os.path.dirname(lock))
        fd.close()
