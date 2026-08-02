"""
agent/tests/unit/test_sender_status_handling.py — HTTP status → outcome contract.

Pins down which HTTP statuses _send_with_retry treats as "delivered" vs
"retry/spool". The manager's own ingest.py docstring claims its queue-mode
path "returns 202 immediately", even though the current implementation
replies 200 — and a reverse proxy in front of the manager could legitimately
return 201/204 too. Any 2xx must be treated as delivered; only the actual
2xx check was wrong (`== 200` instead of a range), not what success means.
"""
from __future__ import annotations

import queue
from unittest.mock import MagicMock, patch

from agent.agent.sender import Sender


def _make_sender(tmp_path) -> Sender:
    config = {
        "manager": {"url": "https://manager.example/ingest", "tls_verify": False,
                    "timeout_sec": 1, "retry_attempts": 1, "retry_delay_sec": 0},
        "paths": {"spool_dir": str(tmp_path)},
    }
    return Sender(config, queue.Queue())


def _mock_response(status: int):
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.status = status
    resp.headers = {}
    return resp


def test_200_is_delivered(tmp_path):
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(200)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is True
    assert s._online is True


def test_201_is_delivered(tmp_path):
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(201)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is True


def test_202_queue_mode_accept_is_delivered(tmp_path):
    """The exact case ingest.py's docstring describes for queue mode."""
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(202)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is True


def test_204_is_delivered(tmp_path):
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(204)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is True


def test_401_is_not_delivered_and_counts_auth_failure(tmp_path):
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(401)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is False
    assert s._auth_fail_count == 1


def test_unexpected_3xx_is_not_silently_treated_as_success(tmp_path):
    """A redirect is neither 2xx nor a handled error — must fall through to
    retry/spool, not be misread as delivered."""
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(301)):
        assert s._send_with_retry({"section": "metrics", "agent_id": "a"}) is False


def test_413_is_unrecoverable_but_observable(tmp_path):
    s = _make_sender(tmp_path)
    with patch("urllib.request.urlopen", return_value=_mock_response(413)):
        assert s._send_with_retry({"section": "developer_security", "agent_id": "a"}) is True
    assert s.link_state()["delivery_rejected_4xx"] == 1
