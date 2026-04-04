"""
manager/tests/integration/test_ingest.py
— Full enroll → encrypt → POST → verify → store pipeline.

Uses FastAPI TestClient with a temp SQLite database (no real network).
Tests the complete per-agent-key ingest flow without mocking crypto.

Updated for v2: agents must enroll first; global API_KEY removed from ingest.
"""
from __future__ import annotations

import os
import platform
import secrets
import socket
import time

import pytest

from agent.agent.crypto import derive_keys, encrypt

# ── Shared enrollment token for all module-scope fixtures ─────────────────────
_ENROLL_TOKEN = "integ-test-token-" + secrets.token_hex(4)
_AGENT_ID     = "test-agent"
_AGENT_KEY    = secrets.token_hex(32)


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    os.environ["DATA_DIR"]          = str(tmp_path_factory.mktemp("db"))
    os.environ["ENROLLMENT_TOKENS"] = _ENROLL_TOKEN
    os.environ.pop("API_KEY", None)
    from manager.manager.server import create_app
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        # Enroll the test agent once for all tests in this module
        c.post(
            "/api/v1/enroll",
            json={
                "agent_id":   _AGENT_ID,
                "agent_name": "Integration Test Mac",
                "api_key":    _AGENT_KEY,
                "hostname":   socket.gethostname(),
                "os":         "macos",
                "arch":       platform.machine(),
                "timestamp":  int(time.time()),
            },
            headers={"X-Enrollment-Token": _ENROLL_TOKEN},
        )
        yield c


def _envelope(section: str = "metrics") -> dict:
    enc_key, mac_key = derive_keys(_AGENT_KEY)
    payload = {
        "section":      section,
        "agent_id":     _AGENT_ID,
        "agent_name":   "Integration Test Mac",
        "collected_at": int(time.time()),
        "data":         {"cpu_pct": 8.0, "mem_pct": 42.0},
    }
    env = encrypt(payload, enc_key, mac_key, _AGENT_ID, int(time.time()))
    env["section"] = section
    return env


# ── Ingest endpoint ───────────────────────────────────────────────────────────

def test_valid_payload_returns_ok(client):
    r = client.post("/api/v1/ingest", json=_envelope())
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_invalid_json_returns_400(client):
    r = client.post("/api/v1/ingest",
                    content=b"not-json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_missing_hmac_returns_400(client):
    """hmac is a required envelope field — missing it is caught at schema check (400)."""
    env = _envelope()
    del env["hmac"]
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 400
    assert "hmac" in r.json().get("detail", "").lower()


def test_tampered_hmac_returns_401(client):
    env = _envelope()
    env["hmac"] = "00" * 32
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 401


def test_replay_returns_401(client):
    """Same nonce a second time must be rejected."""
    env = _envelope()
    client.post("/api/v1/ingest", json=env)     # first: OK
    r = client.post("/api/v1/ingest", json=env) # second: replay
    assert r.status_code == 401


def test_unenrolled_agent_rejected(client):
    wrong_key = secrets.token_hex(32)
    enc_key, mac_key = derive_keys(wrong_key)
    payload = {"section": "metrics", "agent_id": "ghost-999",
               "collected_at": int(time.time()), "data": {}}
    env = encrypt(payload, enc_key, mac_key, "ghost-999", int(time.time()))
    env["section"] = "metrics"
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 401


def test_stale_timestamp_returns_401(client):
    enc_key, mac_key = derive_keys(_AGENT_KEY)
    ts = int(time.time()) - 400
    payload = {"section": "metrics", "agent_id": _AGENT_ID,
               "collected_at": ts, "data": {}}
    env = encrypt(payload, enc_key, mac_key, _AGENT_ID, ts)
    env["section"] = "metrics"
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 401


# ── Agents endpoint ───────────────────────────────────────────────────────────

def test_agent_appears_after_ingest(client):
    client.post("/api/v1/ingest", json=_envelope())
    r = client.get("/api/v1/agents")
    assert r.status_code == 200
    assert any(a["agent_id"] == _AGENT_ID for a in r.json())


def test_invalid_section_name_returns_400(client):
    r = client.get(f"/api/v1/agents/{_AGENT_ID}/notasection")
    assert r.status_code == 400


# ── Health endpoint ───────────────────────────────────────────────────────────

def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["db"] == "ok"
