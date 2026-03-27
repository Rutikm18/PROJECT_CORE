"""
tests/integration/test_ingest.py — Full encrypt → POST → verify → store pipeline.

Uses FastAPI's TestClient with a temp SQLite database.
Tests the complete ingest flow without mocking crypto.
"""
from __future__ import annotations

import os
import secrets
import time

import pytest

from agent.agent.crypto import derive_keys, encrypt


@pytest.fixture(scope="module")
def test_api_key() -> str:
    return secrets.token_hex(32)


@pytest.fixture(scope="module")
def app(test_api_key: str, tmp_path_factory):
    os.environ["API_KEY"] = test_api_key
    db_path = str(tmp_path_factory.mktemp("db") / "test.db")
    os.environ["DB_PATH"] = db_path
    from manager.manager.server import create_app
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


@pytest.fixture
def valid_envelope(test_api_key: str) -> dict:
    enc_key, mac_key = derive_keys(test_api_key)
    payload = {
        "section":      "metrics",
        "agent_id":     "test-agent",
        "agent_name":   "Integration Test Mac",
        "collected_at": int(time.time()),
        "data":         {"cpu": "8% user, 2% sys"},
    }
    envelope = encrypt(payload, enc_key, mac_key, "test-agent", int(time.time()))
    envelope["section"] = "metrics"   # plaintext routing hint
    return envelope


# ── Ingest endpoint ───────────────────────────────────────────────────────────

def test_valid_payload_returns_ok(client, valid_envelope):
    resp = client.post("/api/v1/ingest", json=valid_envelope)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_invalid_json_returns_400(client):
    resp = client.post(
        "/api/v1/ingest",
        content=b"not-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_missing_hmac_returns_401(client, valid_envelope):
    bad = dict(valid_envelope)
    del bad["hmac"]
    resp = client.post("/api/v1/ingest", json=bad)
    assert resp.status_code == 401


def test_tampered_hmac_returns_401(client, valid_envelope):
    bad = dict(valid_envelope)
    bad["hmac"] = "00" * 32
    resp = client.post("/api/v1/ingest", json=bad)
    assert resp.status_code == 401


def test_replay_returns_401(client, valid_envelope):
    """Second POST with the same nonce must be rejected."""
    client.post("/api/v1/ingest", json=valid_envelope)   # first: OK
    resp = client.post("/api/v1/ingest", json=valid_envelope)
    assert resp.status_code == 401


# ── Agents endpoint ───────────────────────────────────────────────────────────

def test_agent_appears_after_ingest(client, valid_envelope):
    client.post("/api/v1/ingest", json=valid_envelope)
    resp = client.get("/api/v1/agents")
    assert resp.status_code == 200
    ids = [a["agent_id"] for a in resp.json()]
    assert "test-agent" in ids


def test_invalid_section_name_returns_400(client):
    resp = client.get("/api/v1/agents/test-agent/notasection")
    assert resp.status_code == 400


# ── Health endpoint ───────────────────────────────────────────────────────────

def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"
