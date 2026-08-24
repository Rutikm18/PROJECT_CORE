"""
agent/tests/integration/test_enrollment_flow.py
— End-to-end enrollment + ingest pipeline.

Tests the complete flow:
  1. Agent enrolls with manager (POST /api/v1/enroll)
  2. Manager stores agent's generated key
  3. Agent sends encrypted payload (POST /api/v1/ingest)
  4. Manager verifies with the stored per-agent key
  5. Unenrolled agents are rejected at ingest

Uses FastAPI TestClient with in-memory SQLite (no real network).
"""
from __future__ import annotations

import asyncio
import os
import secrets
import time

import pytest
from fastapi.testclient import TestClient

from agent.agent.crypto import derive_keys, encrypt


# ── App fixture with enrollment tokens configured ─────────────────────────────

ENROLLMENT_TOKEN = "test-enroll-token-" + secrets.token_hex(8)


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    db_dir = tmp_path_factory.mktemp("db")
    os.environ["DATA_DIR"]          = str(db_dir)
    os.environ["ENROLLMENT_TOKENS"] = ENROLLMENT_TOKEN
    # API_KEY is now optional — not required for per-agent key flow
    os.environ.pop("API_KEY", None)

    # Throwaway databases, created and dropped around this module.
    #
    # DATA_DIR above is not isolation any more. It was the whole story under
    # SQLite, but Postgres is the authoritative store now and DATA_DIR only
    # redirects TelemetryStore's optional file archive (server.py). Without
    # these two variables create_app() falls back to DATABASE_URL's default and
    # this module enrols its `integ-agent-00N` fixtures straight into whatever
    # real `manager` database the developer has running — polluting it, and
    # letting accumulated state decide whether assertions like
    # test_enrolled_agent_visible_in_agents_list pass.
    from manager.tests.conftest import _create_test_db, _drop_test_db
    manager_dsn, manager_db = asyncio.run(_create_test_db())
    intel_dsn,   intel_db   = asyncio.run(_create_test_db())
    os.environ["MANAGER_DATABASE_URL"] = manager_dsn
    os.environ["INTEL_DATABASE_URL"]   = intel_dsn

    from manager.manager.server import create_app
    try:
        yield create_app()
    finally:
        for key in ("MANAGER_DATABASE_URL", "INTEL_DATABASE_URL"):
            os.environ.pop(key, None)
        # `client` is module-scoped and depends on this fixture, so its
        # TestClient context has already exited and closed the pools by now.
        asyncio.run(_drop_test_db(manager_db))
        asyncio.run(_drop_test_db(intel_db))


@pytest.fixture(scope="module")
def client(app):
    from manager.tests.conftest import authenticate
    with TestClient(app) as c:
        # Enrolment and ingest are allowlisted (agents authenticate per-payload
        # by HMAC), but this flow also asserts the agent shows up on
        # GET /api/v1/agents, which is a dashboard route and needs a session.
        authenticate(c)
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_envelope(agent_id: str, api_key: str, section: str = "metrics") -> dict:
    enc_key, mac_key = derive_keys(api_key)
    payload = {
        "section":      section,
        "agent_id":     agent_id,
        "agent_name":   "Integration Test Agent",
        "collected_at": int(time.time()),
        "data":         {"cpu_pct": 12.5, "mem_pct": 45.0},
    }
    env = encrypt(payload, enc_key, mac_key, agent_id, int(time.time()))
    env["section"] = section
    return env


def enroll_agent(client, agent_id: str, api_key: str,
                 token: str = ENROLLMENT_TOKEN) -> dict:
    import platform, socket, sys
    body = {
        "agent_id":   agent_id,
        "agent_name": "Integration Test Agent",
        "api_key":    api_key,
        "hostname":   socket.gethostname(),
        "os":         "macos",
        "arch":       platform.machine(),
        "timestamp":  int(time.time()),
    }
    r = client.post("/api/v1/enroll", json=body,
                    headers={"X-Enrollment-Token": token})
    return r


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestEnrollmentAndIngestPipeline:
    def test_enrollment_succeeds(self, client):
        api_key  = secrets.token_hex(32)
        r = enroll_agent(client, "integ-agent-001", api_key)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_enrolled_agent_can_ingest(self, client):
        api_key  = secrets.token_hex(32)
        enroll_agent(client, "integ-agent-002", api_key)
        env = make_envelope("integ-agent-002", api_key)
        r   = client.post("/api/v1/ingest", json=env)
        assert r.status_code == 200

    def test_unenrolled_agent_rejected_at_ingest(self, client):
        api_key = secrets.token_hex(32)   # never enrolled
        env = make_envelope("ghost-agent-999", api_key)
        r   = client.post("/api/v1/ingest", json=env)
        assert r.status_code == 401
        assert "enrolled" in r.json()["detail"].lower()

    def test_wrong_key_rejected_at_ingest(self, client):
        correct_key = secrets.token_hex(32)
        wrong_key   = secrets.token_hex(32)
        enroll_agent(client, "integ-agent-003", correct_key)
        env = make_envelope("integ-agent-003", wrong_key)   # wrong key
        r   = client.post("/api/v1/ingest", json=env)
        assert r.status_code == 401

    def test_key_rotation_via_reenrollment(self, client):
        old_key = secrets.token_hex(32)
        new_key = secrets.token_hex(32)

        # Enroll with old key
        enroll_agent(client, "integ-agent-004", old_key)
        # Old key works
        assert client.post("/api/v1/ingest",
                           json=make_envelope("integ-agent-004", old_key)
                           ).status_code == 200

        # Re-enroll with new key
        enroll_agent(client, "integ-agent-004", new_key)
        # Old key rejected
        assert client.post("/api/v1/ingest",
                           json=make_envelope("integ-agent-004", old_key)
                           ).status_code == 401
        # New key accepted
        assert client.post("/api/v1/ingest",
                           json=make_envelope("integ-agent-004", new_key)
                           ).status_code == 200

    def test_replay_attack_is_idempotent(self, client):
        # Replay protection is now IDEMPOTENT, not a 401. The nonce is recorded
        # only after the payload is durably stored, so a re-sent envelope is
        # recognised BEFORE any storage/processing and ack'd with 200
        # status="duplicate" — zero effect (not stored or processed twice).
        # 200-not-401 matters because an at-least-once retry (a lost 200
        # response) must not be miscounted by the agent as an auth failure
        # (which would trip re-enrollment and wipe its spool). The attack still
        # gains nothing; a legitimate retry is no longer punished.
        api_key = secrets.token_hex(32)
        enroll_agent(client, "integ-agent-005", api_key)
        env = make_envelope("integ-agent-005", api_key)
        # First send — accepted + persisted.
        first = client.post("/api/v1/ingest", json=env)
        assert first.status_code == 200
        assert first.json().get("status") == "ok"
        # Same envelope again — idempotently acknowledged, not reprocessed.
        r = client.post("/api/v1/ingest", json=env)
        assert r.status_code == 200
        assert r.json().get("status") == "duplicate"

    def test_stale_timestamp_rejected(self, client):
        api_key = secrets.token_hex(32)
        enroll_agent(client, "integ-agent-006", api_key)
        enc_key, mac_key = derive_keys(api_key)
        stale_ts = int(time.time()) - 400   # > 5-minute window
        payload  = {"section": "metrics", "agent_id": "integ-agent-006",
                    "collected_at": stale_ts, "data": {}}
        env = encrypt(payload, enc_key, mac_key, "integ-agent-006", stale_ts)
        env["section"] = "metrics"
        r = client.post("/api/v1/ingest", json=env)
        assert r.status_code == 401

    def test_enrolled_agent_visible_in_agents_list(self, client):
        api_key = secrets.token_hex(32)
        enroll_agent(client, "integ-agent-007", api_key)
        # Send at least one payload so the agent appears with last_seen
        client.post("/api/v1/ingest",
                    json=make_envelope("integ-agent-007", api_key))
        r = client.get("/api/v1/agents")
        assert r.status_code == 200
        ids = [a["agent_id"] for a in r.json()]
        assert "integ-agent-007" in ids
