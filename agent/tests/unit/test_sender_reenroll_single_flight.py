"""
agent/tests/unit/test_sender_reenroll_single_flight.py

Pins the single-flight + backoff contract for re-enrollment (Sender._trigger_reenroll).

Regression guard for the key-rotation spiral: when the manager's key store is
reset, all ~24 section senders cross the 401 threshold at once. The old code
spawned one re-enroll thread per incident, so the key was rotated repeatedly and
every rotation invalidated the requests still in flight under the previous key —
a self-sustaining loop that discarded telemetry forever. The fix coalesces them
into ONE re-enrollment at a time, gated by a growing backoff.
"""
from __future__ import annotations

import queue
import threading
import time

from agent.agent import sender as sender_mod
from agent.agent.sender import Sender


def _make_sender(tmp_path) -> Sender:
    config = {
        "manager": {"url": "https://manager.example", "tls_verify": False,
                    "timeout_sec": 1, "retry_attempts": 1, "retry_delay_sec": 0},
        "paths": {"spool_dir": str(tmp_path)},
    }
    return Sender(config, queue.Queue())


def test_concurrent_401s_trigger_exactly_one_reenroll(tmp_path):
    """24 sections failing together must produce a single re-enrollment, not 24."""
    s = _make_sender(tmp_path)
    calls: list[float] = []
    gate = threading.Event()

    def slow_enroll():
        calls.append(time.monotonic())
        gate.wait(2.0)          # hold the callback so all threads race the guard

    s.on_auth_error = slow_enroll

    threads = [threading.Thread(target=s._trigger_reenroll) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(1.0)

    # Only one re-enroll actually started; the other 23 were coalesced.
    assert len(calls) == 1
    assert s._reenroll_in_flight is True
    gate.set()
    time.sleep(0.05)
    assert s._reenroll_in_flight is False   # runner cleared the flag when done


def test_backoff_suppresses_immediate_second_reenroll(tmp_path):
    """After one re-enroll, another can't start until the backoff window elapses."""
    s = _make_sender(tmp_path)
    calls = []
    s.on_auth_error = lambda: calls.append(1)

    s._trigger_reenroll()
    time.sleep(0.05)                        # let the first runner finish
    assert len(calls) == 1
    assert not s._reenroll_in_flight

    # Immediately again — inside the backoff window → suppressed.
    s._trigger_reenroll()
    time.sleep(0.05)
    assert len(calls) == 1


def test_backoff_grows_then_resets_on_success(tmp_path):
    """Backoff doubles per incident and snaps back to the floor after a 2xx."""
    s = _make_sender(tmp_path)
    s.on_auth_error = lambda: None

    assert s._reenroll_backoff == sender_mod._REENROLL_BACKOFF_MIN
    s._trigger_reenroll()
    time.sleep(0.05)
    assert s._reenroll_backoff == sender_mod._REENROLL_BACKOFF_MIN * 2

    # A delivered 2xx proves the new key stuck — backoff resets to the floor.
    import urllib.request
    from unittest.mock import MagicMock, patch
    resp = MagicMock()
    resp.__enter__ = lambda self: self
    resp.__exit__ = MagicMock(return_value=False)
    resp.status = 200
    resp.headers = {}
    with patch.object(urllib.request, "urlopen", return_value=resp):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is True
    assert s._reenroll_backoff == sender_mod._REENROLL_BACKOFF_MIN


def test_no_callback_is_a_safe_noop(tmp_path):
    """With no on_auth_error wired, _trigger_reenroll must not raise or mark in-flight."""
    s = _make_sender(tmp_path)
    s.on_auth_error = None
    s._trigger_reenroll()
    assert s._reenroll_in_flight is False
