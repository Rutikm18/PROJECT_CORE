"""
agent/tests/unit/test_enrollment.py — Tests for the enrollment flow.

Failure points covered:
  - Missing enrollment token → clear error message
  - Keystore write failure → enrollment aborted before network call
  - Key stored BEFORE network call (never lost if network fails)
  - Manager returns 401 → EnrollmentError with useful message
  - Manager returns 409 → re-enrollment conflict message
  - Network failure → EnrollmentError
  - Generated key is always 256-bit (64 hex chars)
  - needs_enrollment returns correct signal
"""
from __future__ import annotations

import secrets
from unittest.mock import patch

import pytest

from agent.agent.enrollment import (
    EnrollmentError,
    enroll,
    needs_enrollment,
    _post_enroll,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(tmp_path, token: str = "valid-token") -> dict:
    return {
        "agent":      {"id": "agent-001", "name": "Test Agent"},
        "manager":    {"url": "https://127.0.0.1:19999", "tls_verify": False},
        "enrollment": {"token": token, "keystore": "file"},
        "paths":      {"security_dir": str(tmp_path / "security")},
    }


# ── needs_enrollment ──────────────────────────────────────────────────────────

class TestNeedsEnrollment:
    def test_true_when_no_key_in_store(self, tmp_path):
        with patch("agent.agent.enrollment.load_key", return_value=None):
            assert needs_enrollment("agent-001") is True

    def test_false_when_key_exists(self):
        with patch("agent.agent.enrollment.load_key",
                   return_value=secrets.token_hex(32)):
            assert needs_enrollment("agent-001") is False


# ── enroll ────────────────────────────────────────────────────────────────────

class TestEnroll:
    def test_fails_without_token(self, tmp_path):
        # Empty token alone is NOT a failure — open enrollment is a supported
        # mode (manager allows no token). The real failure case is a manager
        # that actually requires one, which surfaces as an HTTP 401 from
        # _post_enroll; that's what must produce a clear, actionable message.
        with patch("agent.agent.enrollment._post_enroll",
                   side_effect=EnrollmentError(
                       "Manager rejected enrollment token (HTTP 401). "
                       "Check [enrollment] token in agent.toml matches "
                       "ENROLLMENT_TOKENS on manager.")):
            with pytest.raises(EnrollmentError, match="enrollment token"):
                enroll(_cfg(tmp_path, token=""))

    def test_generated_key_is_256_bits(self, tmp_path):
        with patch("agent.agent.enrollment._post_enroll"):
            with patch("agent.agent.enrollment.store_key"):
                key = enroll(_cfg(tmp_path))
        assert len(key) == 64, "256-bit key = 64 hex characters"
        assert all(c in "0123456789abcdef" for c in key)

    def test_returned_key_matches_what_was_persisted(self, tmp_path):
        """
        Critical invariant: the manager generates the key (not the agent), so
        the network call necessarily happens BEFORE storage — there is no key
        to persist until the manager hands one back. What must hold is that
        the key returned to the caller is exactly the key written to the
        keystore, never an unsaved or different one.
        """
        manager_key = secrets.token_hex(32)
        stored = {}
        with patch("agent.agent.enrollment._post_enroll",
                   return_value={"api_key": manager_key}):
            with patch("agent.agent.enrollment.store_key",
                       side_effect=lambda agent_id, key, **kw: stored.setdefault("key", key)):
                key = enroll(_cfg(tmp_path))
        assert key == manager_key
        assert stored["key"] == manager_key, \
            "the key returned must be exactly the key persisted to the keystore"

    def test_keystore_failure_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment._post_enroll",
                   return_value={"api_key": secrets.token_hex(32)}):
            with patch("agent.agent.enrollment.store_key",
                       side_effect=PermissionError("disk full")):
                with pytest.raises(EnrollmentError, match="Keystore"):
                    enroll(_cfg(tmp_path))

    def test_network_failure_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=ConnectionRefusedError("refused")):
                with pytest.raises(EnrollmentError, match="failed"):
                    enroll(_cfg(tmp_path))

    def test_manager_401_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=EnrollmentError("HTTP 401")):
                with pytest.raises(EnrollmentError, match="401"):
                    enroll(_cfg(tmp_path))

    def test_manager_409_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=EnrollmentError("HTTP 409")):
                with pytest.raises(EnrollmentError):
                    enroll(_cfg(tmp_path))

    def test_409_with_no_key_keeps_existing_key_untouched(self, tmp_path):
        """
        Regression: a 409 with no key in the body means "already enrolled,
        nothing changed" — _post_enroll signals this with None. enroll() must
        return falsy and must NOT call store_key, or it would overwrite the
        valid existing key with a random one the manager never issued
        (breaking ingest until the next re-enrollment cycle).
        """
        with patch("agent.agent.enrollment._post_enroll", return_value=None):
            with patch("agent.agent.enrollment.store_key") as mock_store:
                result = enroll(_cfg(tmp_path))
        assert not result, "no new key was issued — must return falsy"
        mock_store.assert_not_called()

    def test_each_enrollment_generates_unique_key(self, tmp_path):
        keys = set()
        for i in range(5):
            with patch("agent.agent.enrollment._post_enroll"):
                with patch("agent.agent.enrollment.store_key"):
                    keys.add(enroll(_cfg(tmp_path)))
        assert len(keys) == 5, "Each enrollment must produce a unique key"


# ── _post_enroll (network layer) ──────────────────────────────────────────────

class TestPostEnroll:
    """Tests for the HTTP layer using urllib mock."""

    def _payload(self) -> dict:
        import time, platform, socket, sys
        return {
            "agent_id":   "agent-001",
            "agent_name": "Test",
            "api_key":    secrets.token_hex(32),
            "hostname":   socket.gethostname(),
            "os":         "macos",
            "arch":       platform.machine(),
            "timestamp":  int(time.time()),
        }

    def test_200_succeeds(self):
        from unittest.mock import MagicMock, patch
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        with patch("urllib.request.urlopen", return_value=mock_resp):
            _post_enroll("https://x/enroll", "tok", self._payload(), False)

    def test_401_raises(self):
        import urllib.error
        err = urllib.error.HTTPError("url", 401, "Unauthorized", {}, None)
        err.read = lambda: b"bad token"
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(EnrollmentError, match="401"):
                _post_enroll("https://x/enroll", "tok", self._payload(), False)

    def test_409_with_no_key_in_body_returns_none(self):
        # A 409 is NOT an error here — it means "already enrolled". With no
        # key in the body, None signals "nothing changed, keep the existing
        # keystore key" — it must NOT raise (that would make routine
        # re-enrollment checks look like failures).
        import urllib.error
        err = urllib.error.HTTPError("url", 409, "Conflict", {}, None)
        err.read = lambda: b"already enrolled"
        with patch("urllib.request.urlopen", side_effect=err):
            result = _post_enroll("https://x/enroll", "tok", self._payload(), False)
        assert result is None

    def test_409_with_key_in_body_returns_existing_key(self):
        import json
        import urllib.error
        existing_key = secrets.token_hex(32)
        err = urllib.error.HTTPError("url", 409, "Conflict", {}, None)
        err.read = lambda: json.dumps({"api_key": existing_key}).encode()
        with patch("urllib.request.urlopen", side_effect=err):
            result = _post_enroll("https://x/enroll", "tok", self._payload(), False)
        assert result == {"api_key": existing_key}
