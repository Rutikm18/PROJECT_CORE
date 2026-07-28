"""
agent/tests/unit/test_obs.py — deduplicated / rate-limited logging (R15).
"""
from __future__ import annotations

import logging

from agent.agent.obs import Throttle, log_throttled


class TestThrottle:
    def test_first_occurrence_emits(self):
        t = Throttle(interval=60)
        assert t.check("k", now=0.0) == (True, 0)

    def test_within_interval_suppressed_with_running_count(self):
        t = Throttle(interval=60)
        assert t.check("k", 0.0) == (True, 0)
        assert t.check("k", 10.0) == (False, 1)
        assert t.check("k", 20.0) == (False, 2)
        assert t.check("k", 30.0) == (False, 3)

    def test_reemits_after_interval_with_suppressed_count(self):
        t = Throttle(interval=60)
        t.check("k", 0.0)
        t.check("k", 10.0)          # suppressed 1
        t.check("k", 20.0)          # suppressed 2
        emit, suppressed = t.check("k", 61.0)   # interval elapsed
        assert emit is True
        assert suppressed == 2      # reports how many were swallowed

    def test_distinct_keys_are_independent(self):
        t = Throttle(interval=60)
        assert t.check("a", 0.0)[0] is True
        assert t.check("b", 0.0)[0] is True     # different key emits immediately

    def test_reset_clears_key(self):
        t = Throttle(interval=60)
        t.check("k", 0.0)
        assert t.check("k", 1.0)[0] is False
        t.reset("k")
        assert t.check("k", 2.0)[0] is True


class TestLogThrottled:
    def test_emits_once_then_suppresses(self, caplog):
        t = Throttle(interval=60)
        logger = logging.getLogger("test.obs")
        with caplog.at_level(logging.WARNING):
            e1 = log_throttled(logger, "spool_full", logging.WARNING,
                               "spool full", throttle=t, now=0.0, spool_size=123)
            e2 = log_throttled(logger, "spool_full", logging.WARNING,
                               "spool full", throttle=t, now=5.0, spool_size=124)
        assert e1 is True and e2 is False
        assert sum("spool full" in r.message for r in caplog.records) == 1

    def test_structured_fields_rendered(self, caplog):
        t = Throttle(interval=60)
        logger = logging.getLogger("test.obs2")
        with caplog.at_level(logging.ERROR):
            log_throttled(logger, "k", logging.ERROR, "boom", throttle=t, now=0.0,
                          component="sender", code="ENOSPC", retry_count=3)
        msg = caplog.records[-1].message
        assert "component=sender" in msg and "code=ENOSPC" in msg and "retry_count=3" in msg

    def test_none_fields_dropped(self, caplog):
        t = Throttle(interval=60)
        logger = logging.getLogger("test.obs3")
        with caplog.at_level(logging.INFO):
            log_throttled(logger, "k", logging.INFO, "m", throttle=t, now=0.0,
                          present=1, absent=None)
        msg = caplog.records[-1].message
        assert "present=1" in msg and "absent" not in msg
