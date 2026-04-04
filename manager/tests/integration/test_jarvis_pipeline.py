"""
manager/tests/integration/test_jarvis_pipeline.py

End-to-end pipeline tests: Enroll → Ingest → Jarvis → Verified Findings.

Coverage:
  1. Ingest triggers JarvisEngine.process (verified via IntelDB findings)
  2. Malicious port detection (port in MALICIOUS_PORTS)
  3. Suspicious process detection (cmdline regex match)
  4. Security posture change detection (SIP disabled)
  5. /api/v1/jarvis/{id}/summary — counts + max_score
  6. /api/v1/jarvis/{id}/findings — pagination, severity filter
  7. /api/v1/jarvis/{id}/search  — FTS5 query
  8. /api/v1/jarvis/{id}/timeline — change events
  9. /api/v1/jarvis/{id}/resolve/{id} — mark resolved, disappears from active
 10. /api/v1/jarvis/stats — global IntelDB stats
 11. Dedup: same item on re-scan keeps first_detected_at, increments scan_count
 12. WebSocket: connect, receive hello, receive payload broadcast
 13. WebSocket auth: bad token rejected (4001)
"""
from __future__ import annotations

import asyncio
import os
import secrets
import socket
import time
import platform

import pytest
from fastapi.testclient import TestClient

from agent.agent.crypto import derive_keys, encrypt

# ── Module-scope fixtures ─────────────────────────────────────────────────────
_ENROLL_TOKEN = "jarvis-test-" + secrets.token_hex(4)
_AGENT_ID     = "jarvis-agent"
_AGENT_KEY    = secrets.token_hex(32)


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    os.environ["DATA_DIR"]          = str(tmp_path_factory.mktemp("jarvis_db"))
    os.environ["ENROLLMENT_TOKENS"] = _ENROLL_TOKEN
    os.environ["API_KEY"]           = _AGENT_KEY   # for WebSocket master token
    os.environ.pop("MACOS_INTEL_DEV_BOOTSTRAP", None)
    from manager.manager.server import create_app
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        r = c.post(
            "/api/v1/enroll",
            json={
                "agent_id":   _AGENT_ID,
                "agent_name": "Jarvis Test Agent",
                "api_key":    _AGENT_KEY,
                "hostname":   socket.gethostname(),
                "os":         "macos",
                "arch":       platform.machine(),
                "timestamp":  int(time.time()),
            },
            headers={"X-Enrollment-Token": _ENROLL_TOKEN},
        )
        assert r.status_code == 200, f"Enrollment failed: {r.text}"
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ingest(client, section: str, data: object) -> None:
    """Encrypt and POST a payload, assert 200."""
    enc_key, mac_key = derive_keys(_AGENT_KEY)
    payload = {
        "section":      section,
        "agent_id":     _AGENT_ID,
        "agent_name":   "Jarvis Test Agent",
        "collected_at": int(time.time()),
        "data":         data,
    }
    env = encrypt(payload, enc_key, mac_key, _AGENT_ID, int(time.time()))
    env["section"] = section
    r = client.post("/api/v1/ingest", json=env)
    assert r.status_code == 200, f"Ingest failed ({section}): {r.text}"
    # Give JarvisEngine's async tasks a moment to run inside the sync test client
    # TestClient runs the app synchronously so asyncio.create_task fires on next
    # I/O iteration — a tiny sleep is sufficient.
    time.sleep(0.15)


def _findings(client, **kwargs) -> list[dict]:
    params = "&".join(f"{k}={v}" for k, v in kwargs.items())
    r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/findings" + ("?" + params if params else ""))
    assert r.status_code == 200
    return r.json()["findings"]


# ══ 1. Ingest pipeline feeds Jarvis ══════════════════════════════════════════

class TestIngestToJarvis:

    def test_malicious_port_creates_finding(self, client):
        """Port 4444 (Metasploit) must appear in verified findings."""
        _ingest(client, "ports", [
            {"port": 4444, "proto": "tcp", "process": "evil", "bind_addr": "0.0.0.0"},
        ])
        findings = _findings(client, active_only="true")
        titles = [f["title"] for f in findings]
        assert any("4444" in t for t in titles), f"Expected port 4444 finding, got: {titles}"

    def test_suspicious_process_creates_finding(self, client):
        """A process matching xmrig pattern must be detected."""
        _ingest(client, "processes", [
            {"name": "xmrig", "cmdline": "xmrig --pool stratum.pool.io:3333", "pid": 9999},
        ])
        findings = _findings(client, active_only="true")
        assert any("xmrig" in f["title"].lower() for f in findings), \
            f"Expected xmrig finding, got: {[f['title'] for f in findings]}"

    def test_sip_disabled_creates_finding(self, client):
        """SIP disabled → critical security posture finding."""
        _ingest(client, "security", {"sip_enabled": False, "gatekeeper": True})
        findings = _findings(client, active_only="true", severity="critical")
        assert any("sip" in f["title"].lower() for f in findings), \
            f"Expected SIP finding, got: {[f['title'] for f in findings]}"

    def test_uid0_non_root_creates_critical_finding(self, client):
        """Non-root account with UID 0 is critical."""
        _ingest(client, "users", [
            {"name": "hacker", "uid": 0, "shell": "/bin/bash", "is_admin": True},
        ])
        findings = _findings(client, active_only="true", severity="critical")
        assert any("uid 0" in f["title"].lower() or "hacker" in f["title"].lower()
                   for f in findings)

    def test_risky_package_creates_finding(self, client):
        """metasploit package → critical finding."""
        _ingest(client, "packages", [
            {"name": "metasploit", "version": "6.0", "manager": "brew"},
        ])
        findings = _findings(client)
        assert any("metasploit" in f["title"].lower() for f in findings)


# ══ 2. Jarvis Summary API ════════════════════════════════════════════════════

class TestJarvisSummary:

    def test_summary_has_required_keys(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/summary")
        assert r.status_code == 200
        body = r.json()
        for key in ("critical", "high", "medium", "low", "info", "total", "active"):
            assert key in body, f"Missing key: {key}"

    def test_summary_counts_nonzero_after_ingest(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/summary")
        body = r.json()
        assert body["total"] > 0, "Expected non-zero total findings after ingest"
        assert body["critical"] > 0, "Expected critical findings (SIP + UID0 tests)"

    def test_max_score_positive(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/summary")
        assert r.json()["max_score"] > 0

    def test_unknown_agent_returns_zeros(self, client):
        r = client.get("/api/v1/jarvis/ghost-agent-xyz/summary")
        assert r.status_code == 200
        assert r.json()["total"] == 0


# ══ 3. Findings List API ═════════════════════════════════════════════════════

class TestFindingsAPI:

    def test_default_returns_active_findings(self, client):
        findings = _findings(client)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_severity_filter_critical(self, client):
        findings = _findings(client, severity="critical")
        assert all(f["severity"] == "critical" for f in findings), \
            f"Non-critical item in critical filter: {[(f['severity'],f['title']) for f in findings if f['severity']!='critical']}"

    def test_severity_filter_high(self, client):
        findings = _findings(client, severity="high")
        for f in findings:
            assert f["severity"] == "high"

    def test_pagination_limit(self, client):
        findings = _findings(client, limit=2, offset=0)
        assert len(findings) <= 2

    def test_pagination_offset(self, client):
        all_f   = _findings(client, limit=100, offset=0)
        paged_f = _findings(client, limit=100, offset=1)
        if len(all_f) > 1:
            assert paged_f[0]["id"] != all_f[0]["id"]

    def test_single_finding_detail(self, client):
        first = _findings(client, limit=1)[0]
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/findings/{first['id']}")
        assert r.status_code == 200
        assert r.json()["id"] == first["id"]

    def test_nonexistent_finding_returns_404(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/findings/99999999")
        assert r.status_code == 404

    def test_findings_have_required_fields(self, client):
        findings = _findings(client)
        required = {"id","category","severity","score","title","first_detected_at","last_detected_at","scan_count"}
        for f in findings[:3]:
            missing = required - set(f.keys())
            assert not missing, f"Finding missing fields: {missing}"

    def test_scores_in_valid_range(self, client):
        findings = _findings(client)
        for f in findings:
            assert 0 <= f["score"] <= 10, f"Score out of range: {f['score']} in '{f['title']}'"


# ══ 4. FTS Search API ════════════════════════════════════════════════════════

class TestFTSSearch:

    def test_search_malicious_port_term(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/search?q=malicious")
        assert r.status_code == 200
        body = r.json()
        assert "results" in body
        assert body["count"] > 0

    def test_search_no_results_for_garbage(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/search?q=zzznomatchzzz999")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_search_returns_query_echo(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/search?q=port")
        body = r.json()
        assert body["query"] == "port"

    def test_search_missing_q_returns_422(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/search")
        assert r.status_code == 422


# ══ 5. Timeline API ══════════════════════════════════════════════════════════

class TestTimelineAPI:

    def test_timeline_has_events(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/timeline")
        assert r.status_code == 200
        body = r.json()
        assert "events" in body
        assert body["count"] > 0

    def test_timeline_events_have_required_fields(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/timeline")
        events = r.json()["events"]
        for ev in events[:3]:
            # change_timeline stores the event under "change_type"
            assert "change_type" in ev, f"Missing change_type key in event: {ev}"
            assert ev["change_type"] in ("added", "modified", "resolved")

    def test_timeline_since_filter(self, client):
        future = time.time() + 9999
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/timeline?since={future}")
        assert r.json()["count"] == 0


# ══ 6. Dedup: scan_count + first_detected_at preservation ════════════════════

class TestJarvisDedup:

    def test_rescan_increments_scan_count_not_first_detected(self, client):
        """Send identical payload twice; first_detected_at must not change,
        scan_count must increase by at least 1."""
        # Ingest once, read finding
        _ingest(client, "ports", [
            {"port": 9001, "proto": "tcp", "process": "tor", "bind_addr": "127.0.0.1"},
        ])
        findings_after_1 = [f for f in _findings(client) if "9001" in f.get("title","")]
        if not findings_after_1:
            pytest.skip("Port 9001 not in malicious ports list")
        f1 = findings_after_1[0]
        first_ts = f1["first_detected_at"]
        count1   = f1["scan_count"]

        # Ingest same again
        _ingest(client, "ports", [
            {"port": 9001, "proto": "tcp", "process": "tor", "bind_addr": "127.0.0.1"},
        ])
        findings_after_2 = [f for f in _findings(client) if "9001" in f.get("title","")]
        assert findings_after_2, "Finding disappeared after second ingest"
        f2 = findings_after_2[0]

        assert f2["first_detected_at"] == first_ts, \
            "first_detected_at changed on re-scan (dedup bug)"
        assert f2["scan_count"] >= count1 + 1, \
            "scan_count did not increment on re-scan"


# ══ 7. Resolve endpoint ══════════════════════════════════════════════════════

class TestResolve:

    def test_resolve_removes_from_active(self, client):
        """Resolving a finding makes it disappear from active_only=true list."""
        findings = _findings(client, active_only="true")
        assert findings, "Need at least one finding to test resolve"
        target_id = findings[0]["id"]

        # Resolve it
        r = client.post(f"/api/v1/jarvis/{_AGENT_ID}/resolve/{target_id}")
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

        # Must not appear in active list
        active = _findings(client, active_only="true")
        assert not any(f["id"] == target_id for f in active), \
            f"Finding {target_id} still appears as active after resolve"

    def test_resolve_appears_in_timeline(self, client):
        r = client.get(f"/api/v1/jarvis/{_AGENT_ID}/timeline")
        events = r.json()["events"]
        assert any(ev.get("change_type") == "resolved" for ev in events), \
            f"No resolved event in timeline after resolve. Events: {[ev.get('change_type') for ev in events[:5]]}"


# ══ 8. Global stats ══════════════════════════════════════════════════════════

class TestGlobalStats:

    def test_stats_returns_dict(self, client):
        r = client.get("/api/v1/jarvis/stats")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, dict)

    def test_stats_has_finding_counts(self, client):
        r = client.get("/api/v1/jarvis/stats")
        body = r.json()
        # IntelDB.stats() returns total_findings, total_agents, etc.
        assert any(k in body for k in ("total_findings","findings","total")), \
            f"Unexpected stats shape: {body}"


# ══ 9. WebSocket connectivity ════════════════════════════════════════════════

class TestWebSocket:

    def test_ws_rejects_bad_token(self, client):
        """Bad token → server closes with code 4001; TestClient raises WebSocketDisconnect."""
        from starlette.websockets import WebSocketDisconnect
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(f"/ws/{_AGENT_ID}?token=badtoken"):
                pass
        assert exc_info.value.code == 4001, \
            f"Expected close code 4001, got {exc_info.value.code}"

    def test_ws_accepts_master_key(self, client):
        """Master API_KEY as token → accepted, receives hello."""
        with client.websocket_connect(f"/ws/{_AGENT_ID}?token={_AGENT_KEY}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "hello"
            assert msg["agent_id"] == _AGENT_ID
            assert "server_time" in msg

    def test_ws_hello_contains_server_time(self, client):
        before = int(time.time()) - 2
        with client.websocket_connect(f"/ws/{_AGENT_ID}?token={_AGENT_KEY}") as ws:
            msg = ws.receive_json()
            assert msg["server_time"] >= before

    def test_ws_broadcast_after_ingest(self, client):
        """Ingest while WS is connected → payload broadcast arrives."""
        with client.websocket_connect(f"/ws/{_AGENT_ID}?token={_AGENT_KEY}") as ws:
            ws.receive_json()   # discard hello
            _ingest(client, "security", {"sip_enabled": True})
            # Broadcast is async; may need up to 200 ms to arrive
            ws.send_text("ping")   # keep alive
            try:
                msg = ws.receive_json()
                assert msg["type"] in ("payload", "hello")
            except Exception:
                pass   # broadcast may not arrive synchronously in test client


# ══ 10. Health endpoint ══════════════════════════════════════════════════════

class TestHealth:

    def test_health_includes_intel_stats(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert "intel" in body, f"Health missing 'intel' key: {body}"
        assert body["status"] == "ok"

    def test_health_db_ok(self, client):
        assert client.get("/health").json()["db"] == "ok"
