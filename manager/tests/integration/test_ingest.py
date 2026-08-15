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


def _run(coro):
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    # Without MANAGER_DATABASE_URL/INTEL_DATABASE_URL, create_app() falls back
    # to the default shared postgresql://.../manager + /intel databases
    # (server.py) — every run of this file would then accumulate "test-agent"
    # state across every pytest invocation, forever. Isolated per-run
    # databases instead (see test_attacklens_pipeline.py for the same fix).
    from manager.tests.conftest import _create_test_db, _drop_test_db
    dsn_m, name_m = _run(_create_test_db())
    dsn_i, name_i = _run(_create_test_db())

    os.environ["DATA_DIR"]             = str(tmp_path_factory.mktemp("db"))
    os.environ["ENROLLMENT_TOKENS"]    = _ENROLL_TOKEN
    os.environ["MANAGER_DATABASE_URL"] = dsn_m
    os.environ["INTEL_DATABASE_URL"]   = dsn_i
    os.environ.pop("API_KEY", None)
    from manager.manager.server import create_app
    try:
        yield create_app()
    finally:
        _run(_drop_test_db(name_m))
        _run(_drop_test_db(name_i))


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


def _envelope(
    section: str = "metrics",
    data: object | None = None,
    *,
    collected_at: object | None = None,
) -> dict:
    enc_key, mac_key = derive_keys(_AGENT_KEY)
    payload = {
        "section":      section,
        "agent_id":     _AGENT_ID,
        "agent_name":   "Integration Test Mac",
        "collected_at": int(time.time()) if collected_at is None else collected_at,
        "os":           "macos",
        "os_version":   "15.0",
        "arch":         platform.machine(),
        "hostname":     socket.gethostname(),
        "data":         data if data is not None else {"cpu_pct": 8.0, "mem_pct": 42.0},
    }
    env = encrypt(payload, enc_key, mac_key, _AGENT_ID, int(time.time()))
    env["section"] = section
    return env


# ── Ingest endpoint ───────────────────────────────────────────────────────────

def test_valid_payload_returns_ok(client):
    r = client.post("/api/v1/ingest", json=_envelope())
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_developer_security_payload_is_received_and_queryable(client):
    """Pin the new hourly snapshot's complete encrypted agent→manager path."""
    snapshot = {
        "schema_version": 1,
        "collector_version": "macos-developer-security/2",
        "platform": "macos",
        "privacy": {"credential_values_collected": False},
        "capabilities": {"mcp_servers": {"servers": []}},
        "collection": {"state": "complete", "partial": False, "errors": []},
    }
    sent = client.post(
        "/api/v1/ingest", json=_envelope("developer_security", snapshot)
    )
    assert sent.status_code == 200
    assert sent.json()["status"] == "ok"

    received = client.get(
        f"/api/v1/agents/{_AGENT_ID}/developer_security", params={"window": "1h"}
    )
    assert received.status_code == 200
    rows = received.json()
    assert rows
    assert rows[0]["data"]["schema_version"] == 1
    assert rows[0]["data"]["capabilities"]["mcp_servers"]["servers"] == []


def test_partial_developer_security_payload_is_preserved(client):
    """A bounded collector timeout is degraded telemetry, not data loss."""
    snapshot = {
        "schema_version": 1,
        "collector_version": "macos-developer-security/partial-acceptance",
        "platform": "macos",
        "scope": {"users": 1},
        "privacy": {"credential_values_collected": False},
        "capabilities": {"mcp_servers": {"servers": []}},
        "collection": {
            "state": "partial",
            "partial": True,
            "errors": [{"capability": "containers", "error": "timeout"}],
        },
    }

    sent = client.post(
        "/api/v1/ingest", json=_envelope("developer_security", snapshot)
    )
    assert sent.status_code == 200

    raw = client.get(
        "/api/v1/raw/query",
        params={
            "agent_id": _AGENT_ID,
            "section": "developer_security",
            "search": "partial-acceptance",
        },
    )
    assert raw.status_code == 200
    rows = raw.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["data"]["collection"]["partial"] is True
    assert rows[0]["data"]["collection"]["errors"][0]["capability"] == "containers"


def test_invalid_json_returns_400(client):
    r = client.post("/api/v1/ingest",
                    content=b"not-json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_non_object_json_returns_400(client):
    r = client.post("/api/v1/ingest", json=["not", "an", "envelope"])
    assert r.status_code == 400


def test_malformed_timestamp_returns_400_not_500(client):
    env = _envelope()
    env["timestamp"] = {"unexpected": "object"}
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 400


def test_malformed_collected_at_returns_422_not_retryable_503(client):
    r = client.post(
        "/api/v1/ingest",
        json=_envelope(collected_at="not-an-event-time"),
    )
    assert r.status_code == 422
    assert "collected_at" in r.json().get("detail", "")


def test_non_finite_collected_at_returns_422(client):
    r = client.post(
        "/api/v1/ingest",
        json=_envelope(collected_at=float("nan")),
    )
    assert r.status_code == 422
    assert "collected_at" in r.json().get("detail", "")


def test_wrong_section_data_shape_is_rejected_in_strict_mode(client, monkeypatch):
    from manager.manager.api import ingest as ingest_module

    monkeypatch.setattr(ingest_module, "_STRICT_PAYLOAD", True)
    r = client.post(
        "/api/v1/ingest",
        json=_envelope("processes", {"pid": 42, "name": "not-a-list"}),
    )
    assert r.status_code == 422
    assert "processes: data must be a list" in r.json().get("detail", "")


def test_oversized_ingest_is_rejected_before_crypto(client, monkeypatch):
    from manager.manager.api import ingest as ingest_module
    monkeypatch.setattr(ingest_module, "_MAX_ENVELOPE_BYTES", 128)
    r = client.post(
        "/api/v1/ingest",
        content=b"{" + b"x" * 500 + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413


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


def test_authenticated_agent_cannot_attribute_payload_to_another_agent(client):
    enc_key, mac_key = derive_keys(_AGENT_KEY)
    payload = {
        "section": "metrics",
        "agent_id": "victim-agent",
        "collected_at": int(time.time()),
        "data": {"cpu_pct": 8.0, "mem_pct": 42.0},
    }
    env = encrypt(payload, enc_key, mac_key, _AGENT_ID, int(time.time()))
    env["section"] = "metrics"

    r = client.post("/api/v1/ingest", json=env)

    assert r.status_code == 403
    assert "does not match" in r.json()["detail"]


def test_replay_returns_duplicate_200(client):
    """Same nonce is acknowledged twice but stored exactly once."""
    marker = "duplicate-" + secrets.token_hex(8)
    env = _envelope(data={"cpu_pct": 8.0, "mem_pct": 42.0, "marker": marker})
    before = client.get(
        "/api/v1/raw/count", params={"agent_id": _AGENT_ID, "search": marker}
    ).json()["count"]

    first = client.post("/api/v1/ingest", json=env)
    assert first.status_code == 200
    r = client.post("/api/v1/ingest", json=env) # second: replay
    assert r.status_code == 200
    assert r.json()["status"] == "duplicate"

    after = client.get(
        "/api/v1/raw/count", params={"agent_id": _AGENT_ID, "search": marker}
    ).json()["count"]
    assert after == before + 1


def test_delayed_collection_uses_event_time_and_remains_queryable(client):
    """A fresh transmission may legitimately carry telemetry collected earlier."""
    marker = "delayed-" + secrets.token_hex(8)
    collected_at = int(time.time()) - 3600
    r = client.post(
        "/api/v1/ingest",
        json=_envelope(
            data={"cpu_pct": 8.0, "mem_pct": 42.0, "marker": marker},
            collected_at=collected_at,
        ),
    )
    assert r.status_code == 200

    raw = client.get(
        "/api/v1/raw/query",
        params={
            "agent_id": _AGENT_ID,
            "section": "metrics",
            "start": collected_at - 1,
            "end": collected_at + 1,
            "search": marker,
        },
    )
    assert raw.status_code == 200
    rows = raw.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["collected_at"] == collected_at


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
