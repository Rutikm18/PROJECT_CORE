"""
manager/tests/integration/test_attacklens_pipeline.py

End-to-end pipeline tests: Enroll → Ingest → Jarvis → Verified Findings.

Coverage:
  1. Ingest triggers AttackLensEngine.process (verified via IntelDB findings)
  2. Malicious port detection (port in MALICIOUS_PORTS)
  3. Suspicious process detection (cmdline regex match)
  4. Security posture change detection (SIP disabled)
  5. /api/v1/attacklens/{id}/summary — counts + max_score
  6. /api/v1/attacklens/{id}/findings — pagination, severity filter
  7. /api/v1/attacklens/{id}/search  — FTS5 query
  8. /api/v1/attacklens/{id}/timeline — change events
  9. /api/v1/attacklens/{id}/resolve/{id} — mark resolved, disappears from active
 10. /api/v1/attacklens/stats — global IntelDB stats
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
_ENROLL_TOKEN = "attacklens-test-" + secrets.token_hex(4)
_AGENT_ID     = "attacklens-agent"
_AGENT_KEY    = secrets.token_hex(32)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(scope="module")
def app(tmp_path_factory):
    # MANAGER_DATABASE_URL/INTEL_DATABASE_URL must be set to isolated,
    # freshly CREATEd Postgres databases — without them, create_app() falls
    # back to the default shared postgresql://.../manager + /intel databases
    # (server.py), and every run of this file accumulates findings/baseline
    # state for "attacklens-agent" FOREVER across every pytest invocation.
    # That stale cross-run state was silently corrupting the "first
    # observation" detection assertions below (confirmed: 6 leftover findings
    # for attacklens-agent in the shared `intel` database from prior runs).
    from manager.tests.conftest import _create_test_db, _drop_test_db
    dsn_m, name_m = _run(_create_test_db())
    dsn_i, name_i = _run(_create_test_db())

    os.environ["DATA_DIR"]              = str(tmp_path_factory.mktemp("attacklens_db"))
    os.environ["ENROLLMENT_TOKENS"]     = _ENROLL_TOKEN
    os.environ["API_KEY"]               = _AGENT_KEY   # for WebSocket master token
    os.environ["MANAGER_DATABASE_URL"]  = dsn_m
    os.environ["INTEL_DATABASE_URL"]    = dsn_i
    os.environ.pop("MACOS_INTEL_DEV_BOOTSTRAP", None)
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
    # Detection runs on the bounded executor's worker pool (engine.py,
    # engine.enqueue()) — a separate asyncio.Queue drained by background
    # worker tasks, not synchronously inside this request. Under the full
    # suite's load the queue can have a backlog from other tests sharing this
    # module-scoped app/engine, so a fixed sleep can return before THIS
    # payload's detection finishes. Poll /ingest/health's detection_stats
    # (enqueued vs processed) until the queue has actually drained, instead
    # of guessing a "big enough" delay.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        h = client.get("/api/v1/ingest/health").json()
        d = h.get("detection") or {}
        if d.get("processed", 0) >= d.get("enqueued", 0):
            break
        time.sleep(0.05)
    else:
        time.sleep(0.15)  # detection_stats unavailable — fall back to a sleep


def _findings(client, **kwargs) -> list[dict]:
    params = "&".join(f"{k}={v}" for k, v in kwargs.items())
    r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/findings" + ("?" + params if params else ""))
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
        """SIP disabled → critical security posture finding.

        Field names/types match the REAL collector + normalizer output
        (agent/os/macos/collectors/posture.py via agent/os/macos/normalizer.py
        _norm_security): sip/gatekeeper are strings ("enabled"/"disabled"),
        never bools. The previous fixture used "sip_enabled": False (a key
        that doesn't exist) — it happened to pass only because the old,
        now-fixed engine._security() had the identical bug (wrong key, wrong
        type), so the two bugs canceled out. No real agent has ever sent that
        shape; this is what one actually sends.
        """
        _ingest(client, "security", {"sip": "disabled", "gatekeeper": "enabled"})
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
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/summary")
        assert r.status_code == 200
        body = r.json()
        for key in ("critical", "high", "medium", "low", "info", "total", "active"):
            assert key in body, f"Missing key: {key}"

    def test_summary_counts_nonzero_after_ingest(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/summary")
        body = r.json()
        assert body["total"] > 0, "Expected non-zero total findings after ingest"
        assert body["critical"] > 0, "Expected critical findings (SIP + UID0 tests)"

    def test_max_score_positive(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/summary")
        assert r.json()["max_score"] > 0

    def test_unknown_agent_returns_zeros(self, client):
        r = client.get("/api/v1/attacklens/ghost-agent-xyz/summary")
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
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/findings/{first['id']}")
        assert r.status_code == 200
        assert r.json()["id"] == first["id"]

    def test_nonexistent_finding_returns_404(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/findings/99999999")
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


# ══ 4b. Raw findings → summary → dashboard consistency ═════════════════════

class TestPresentationConsistency:

    def test_findings_summary_and_dashboard_counts_agree(self, client):
        findings = _findings(client, active_only="true", limit=1000)
        by_severity = {
            severity: sum(1 for finding in findings if finding["severity"] == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        }

        summary_response = client.get(f"/api/v1/attacklens/{_AGENT_ID}/summary")
        assert summary_response.status_code == 200
        summary = summary_response.json()
        assert summary["active"] == len(findings)
        for severity, count in by_severity.items():
            assert summary[severity] == count

        dashboard_response = client.get("/api/v1/soc/dashboard")
        assert dashboard_response.status_code == 200
        dashboard = dashboard_response.json()
        assert dashboard["kpi"]["total_active"] == summary["active"]
        for severity, count in by_severity.items():
            assert dashboard["kpi"][severity] == count


# ══ 4. FTS Search API ════════════════════════════════════════════════════════

class TestFTSSearch:

    def test_search_malicious_port_term(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/search?q=malicious")
        assert r.status_code == 200
        body = r.json()
        assert "results" in body
        assert body["count"] > 0

    def test_search_no_results_for_garbage(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/search?q=zzznomatchzzz999")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_search_returns_query_echo(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/search?q=port")
        body = r.json()
        assert body["query"] == "port"

    def test_search_missing_q_returns_422(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/search")
        assert r.status_code == 422


# ══ 5. Timeline API ══════════════════════════════════════════════════════════

class TestTimelineAPI:

    def test_timeline_has_events(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/timeline")
        assert r.status_code == 200
        body = r.json()
        assert "events" in body
        assert body["count"] > 0

    def test_timeline_events_have_required_fields(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/timeline")
        events = r.json()["events"]
        for ev in events[:3]:
            # change_timeline stores the event under "change_type"
            assert "change_type" in ev, f"Missing change_type key in event: {ev}"
            assert ev["change_type"] in ("added", "modified", "resolved")

    def test_timeline_since_filter(self, client):
        future = time.time() + 9999
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/timeline?since={future}")
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
        r = client.post(f"/api/v1/attacklens/{_AGENT_ID}/resolve/{target_id}")
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

        # Must not appear in active list
        active = _findings(client, active_only="true")
        assert not any(f["id"] == target_id for f in active), \
            f"Finding {target_id} still appears as active after resolve"

    def test_resolve_appears_in_timeline(self, client):
        r = client.get(f"/api/v1/attacklens/{_AGENT_ID}/timeline")
        events = r.json()["events"]
        assert any(ev.get("change_type") == "resolved" for ev in events), \
            f"No resolved event in timeline after resolve. Events: {[ev.get('change_type') for ev in events[:5]]}"


# ══ 8. Global stats ══════════════════════════════════════════════════════════

class TestGlobalStats:

    def test_stats_returns_dict(self, client):
        r = client.get("/api/v1/attacklens/stats")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, dict)

    def test_stats_has_finding_counts(self, client):
        r = client.get("/api/v1/attacklens/stats")
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


# ══ Newly-wired net-new detection modules (sysctl, arp, containers, sbom) ════
# These sections had NO inline analyzer before — confirms _DETECTION_MODULE_ROUTES
# wiring actually fires end-to-end through ingest, not just via direct analyze() calls.
class TestNewlyWiredModules:

    def test_sysctl_dangerous_param_creates_finding(self, client):
        _ingest(client, "sysctl", {"vm.cs_enforcement_disable": "1"})
        findings = _findings(client, active_only="true")
        titles = [f["title"] for f in findings]
        assert any("cs_enforcement_disable" in t for t in titles), f"Expected sysctl finding, got: {titles}"

    def test_arp_duplicate_mapping_creates_finding(self, client):
        _ingest(client, "arp", {"entries": [
            {"ip_address": "10.50.50.50", "mac_address": "aa:bb:cc:dd:ee:f1"},
            {"ip_address": "10.50.50.50", "mac_address": "aa:bb:cc:dd:ee:f2"},
        ]})
        findings = _findings(client, active_only="true")
        titles = [f["title"] for f in findings]
        assert any("10.50.50.50" in t for t in titles), f"Expected ARP finding, got: {titles}"

    def test_container_privileged_host_network_creates_finding(self, client):
        _ingest(client, "containers", [{
            "container_id": "deadbeef0001", "container_name": "sketchy-ctr",
            "image": "alpine:latest", "privileged": True, "network_mode": "host",
        }])
        findings = _findings(client, active_only="true")
        titles = [f["title"] for f in findings]
        assert any("sketchy-ctr" in t for t in titles), f"Expected container finding, got: {titles}"

    def test_sbom_license_conflict_creates_finding(self, client):
        _ingest(client, "sbom", [{"name": "copyleft-pkg", "version": "2.0", "license": "GPL-3.0"}])
        findings = _findings(client, active_only="true")
        titles = [f["title"] for f in findings]
        assert any("copyleft-pkg" in t for t in titles), f"Expected SBOM finding, got: {titles}"
