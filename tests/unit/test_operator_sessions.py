"""tests/unit/test_operator_sessions.py — concurrent operator session policy.

Requirement: multiple people may log in from different systems with the SAME
operator credentials and all stay logged in. Historically single-session
enforcement revoked each prior login, so the earlier operator's next /api/v1/*
call returned 401 ("can't see data"). The default is now unlimited concurrent
sessions (OPERATOR_MAX_SESSIONS=0); the cap remains configurable.

We test the session-registration unit directly — that is the exact code path that
decides whether a prior operator's token keeps validating.
"""
from __future__ import annotations

import time
import unittest

from manager.manager.api import auth_ui


def _fresh_session(email: str):
    """Mint a real token+jti and register it under the current cap policy."""
    token, jti, exp = auth_ui._make_token(email, "admin")
    auth_ui._register_session(email, jti, exp)
    return token, jti


class OperatorSessionCapTests(unittest.TestCase):
    EMAIL = "admin@attacklens.ai"

    def setUp(self):
        # Isolate global session state between tests.
        auth_ui._active_sessions.clear()
        auth_ui._revoked.clear()
        self._orig_cap = auth_ui._OPERATOR_MAX_SESSIONS

    def tearDown(self):
        auth_ui._OPERATOR_MAX_SESSIONS = self._orig_cap
        auth_ui._active_sessions.clear()
        auth_ui._revoked.clear()

    def test_default_is_unlimited_concurrent(self):
        """The shipped default (cap=0) lets many systems share one credential and
        all stay valid — this is the regression that fixes the 401 'no data'."""
        auth_ui._OPERATOR_MAX_SESSIONS = 0
        toks = [_fresh_session(self.EMAIL)[0] for _ in range(4)]
        for i, tok in enumerate(toks):
            self.assertIsNotNone(auth_ui._verify_token(tok), f"session {i} must survive")

    def test_cap_one_is_single_session(self):
        """cap=1 restores strict single-session: a second login evicts the first."""
        auth_ui._OPERATOR_MAX_SESSIONS = 1
        tok_a, _ = _fresh_session(self.EMAIL)
        self.assertIsNotNone(auth_ui._verify_token(tok_a))

        tok_b, _ = _fresh_session(self.EMAIL)
        self.assertIsNone(auth_ui._verify_token(tok_a), "first session should be evicted")
        self.assertIsNotNone(auth_ui._verify_token(tok_b))

    def test_cap_n_allows_up_to_n_then_evicts_oldest(self):
        """cap=2 keeps two concurrent sessions; a third evicts the OLDEST (FIFO)."""
        auth_ui._OPERATOR_MAX_SESSIONS = 2
        tok_a, _ = _fresh_session(self.EMAIL)
        tok_b, _ = _fresh_session(self.EMAIL)
        self.assertIsNotNone(auth_ui._verify_token(tok_a))
        self.assertIsNotNone(auth_ui._verify_token(tok_b))

        tok_c, _ = _fresh_session(self.EMAIL)
        self.assertIsNone(auth_ui._verify_token(tok_a), "oldest should be evicted")
        self.assertIsNotNone(auth_ui._verify_token(tok_b))
        self.assertIsNotNone(auth_ui._verify_token(tok_c))

    def test_expired_sessions_are_pruned(self):
        """Under unlimited cap the active list must not grow forever: an already
        expired session is dropped when the next login is registered."""
        auth_ui._OPERATOR_MAX_SESSIONS = 0
        auth_ui._register_session(self.EMAIL, "stale-jti", time.time() - 1)  # already expired
        _fresh_session(self.EMAIL)  # a new login triggers the prune
        jtis = [jti for jti, _exp in auth_ui._active_sessions[self.EMAIL]]
        self.assertNotIn("stale-jti", jtis, "expired session should be pruned")
        self.assertEqual(len(jtis), 1, "only the live session should remain")


class ConcurrentLoginHTTPTests(unittest.TestCase):
    """End-to-end over HTTP: two systems, same credentials, both stay logged in."""

    EMAIL = "admin@attacklens.ai"
    PASSWORD = "Sh4red-Cr3d!-Test-Value"

    def setUp(self):
        from fastapi.testclient import TestClient
        from manager.manager.server import create_app

        # Configure a known operator password so /auth/login succeeds.
        self._saved = {
            "_PASSWORD_CONFIGURED": auth_ui._PASSWORD_CONFIGURED,
            "_ADMIN_EMAIL": auth_ui._ADMIN_EMAIL,
            "_stored_hash": auth_ui._stored_hash,
            "_OPERATOR_MAX_SESSIONS": auth_ui._OPERATOR_MAX_SESSIONS,
        }
        auth_ui._PASSWORD_CONFIGURED = True
        auth_ui._ADMIN_EMAIL = self.EMAIL
        auth_ui._stored_hash = auth_ui.hash_password(self.PASSWORD)
        auth_ui._OPERATOR_MAX_SESSIONS = 0  # unlimited (shipped default)

        auth_ui._active_sessions.clear()
        auth_ui._revoked.clear()
        auth_ui._ip_fail_log.clear()
        auth_ui._acct_fail_log.clear()

        # One app; a separate TestClient per "system" gives each its own cookie
        # jar — the faithful model of different machines sharing one credential.
        # No `with` / lifespan → no DB connection; /login and /me need neither.
        self._TestClient = TestClient
        self.app = create_app()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(auth_ui, k, v)
        auth_ui._active_sessions.clear()
        auth_ui._revoked.clear()

    def _system_logs_in(self):
        """A fresh system (own cookie jar) logs in; returns its client."""
        client = self._TestClient(self.app)
        r = client.post(
            "/api/v1/auth/login",
            json={"email": self.EMAIL, "password": self.PASSWORD},
        )
        self.assertEqual(r.status_code, 200, r.text)
        return client

    def test_two_systems_same_credentials_both_stay_logged_in(self):
        sys_a = self._system_logs_in()          # system A signs in
        sys_b = self._system_logs_in()          # system B signs in with SAME creds

        # Each system reads its own session cookie. The regression: A's session
        # must NOT be evicted by B's login from another machine.
        r_a = sys_a.get("/api/v1/auth/me")
        r_b = sys_b.get("/api/v1/auth/me")
        self.assertEqual(r_a.status_code, 200, f"system A got kicked out: {r_a.text}")
        self.assertEqual(r_b.status_code, 200, f"system B not authenticated: {r_b.text}")
        self.assertEqual(r_a.json()["email"], self.EMAIL)

    def test_single_session_mode_still_evicts_over_http(self):
        auth_ui._OPERATOR_MAX_SESSIONS = 1
        sys_a = self._system_logs_in()
        sys_b = self._system_logs_in()
        self.assertEqual(sys_a.get("/api/v1/auth/me").status_code, 401, "cap=1 should evict A")
        self.assertEqual(sys_b.get("/api/v1/auth/me").status_code, 200)


if __name__ == "__main__":
    unittest.main()
