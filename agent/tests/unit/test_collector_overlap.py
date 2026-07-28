"""
agent/tests/unit/test_collector_overlap.py — per-collector overlap guard (R9)
and Retry-After parsing (R12).
"""
from __future__ import annotations

import queue

from agent.agent.core import Orchestrator
from agent.agent.sender import _parse_retry_after


def _orch():
    cfg = {
        "agent": {"id": "mac-001", "name": "t"},
        "manager": {"url": "http://127.0.0.1:8080", "max_queue_size": 100},
        "collection": {"tick_sec": 5, "sections": {"metrics": {"interval_sec": 1}}},
    }
    return Orchestrator(cfg, b"0" * 32, b"0" * 32, queue.Queue())


class TestOverlapGuard:
    def test_second_claim_blocked_until_cleared(self):
        o = _orch()
        assert o._try_mark_inflight("metrics") is True    # first claim wins
        assert o._try_mark_inflight("metrics") is False   # still running → blocked
        o._clear_inflight("metrics")
        assert o._try_mark_inflight("metrics") is True     # freed → claimable again

    def test_distinct_sections_independent(self):
        o = _orch()
        assert o._try_mark_inflight("metrics") is True
        assert o._try_mark_inflight("processes") is True   # different section unaffected

    def test_run_section_clears_slot_even_on_missing_collector(self):
        o = _orch()
        o._try_mark_inflight("ghost")
        o._run_section("ghost", {})        # no such collector → early return
        # finally-clause must have released the slot
        assert o._try_mark_inflight("ghost") is True

    def test_heartbeat_called_on_successful_section(self):
        o = _orch()
        beats = []
        o.heartbeat = lambda success=False: beats.append(success)
        o._try_mark_inflight("metrics")
        o._run_section("metrics", {"send": False})   # real collector runs, no send
        assert True in beats                          # success beat fired


class TestParseRetryAfter:
    def test_delta_seconds(self):
        assert _parse_retry_after("5") == 5.0

    def test_absent(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None

    def test_garbage(self):
        assert _parse_retry_after("soon") is None

    def test_http_date_in_future_is_positive(self):
        # A far-future HTTP-date parses to a positive delta.
        val = _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
        assert val is not None and val > 0

    def test_http_date_in_past_clamps_to_zero(self):
        val = _parse_retry_after("Wed, 21 Oct 2000 07:28:00 GMT")
        assert val == 0.0
