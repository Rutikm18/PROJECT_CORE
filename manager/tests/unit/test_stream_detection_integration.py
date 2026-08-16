from __future__ import annotations

import asyncio

import pytest

from manager.manager.attacklens import engine as engine_module
from manager.manager.attacklens.engine import AttackLensEngine
from manager.manager.attacklens.feeds import FeedManager, FeedRefreshError, _parse_ip_ioc
from manager.manager.attacklens.nvd import CVELookup
from manager.manager.attacklens.detections.developer_security import analyze as analyze_developer_security
from shared.sections import canonical_section
from manager.manager.workers.attacklens import AttackLensWorker
from manager.manager.workers.telemetry import TelemetryWorker


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize(
    ("incoming", "expected"),
    [
        ("LISTENING-PORTS", "ports"),
        ("network_sessions", "connections"),
        ("scheduled_tasks", "tasks"),
        ("pip_packages", "packages"),
        ("endpoint_posture", "security"),
        ("container_security", "containers"),
        ("open_files", "openfiles"),
    ],
)
def test_section_aliases_are_canonical(incoming, expected):
    assert canonical_section(incoming) == expected


class _Rulepack:
    async def analyze(self, *_args):
        return []


def test_rich_module_is_additive_to_existing_inline_analyzer(monkeypatch):
    async def module_analyze(agent_id, section, data, db, hostname):
        return [{
            "rule_id": "module:process", "severity": "high", "confidence": 0.9,
            "title": "module hit", "evidence": {"process": "bad"},
        }]

    async def inline_analyze(agent_id, data):
        return [{
            "rule_id": "inline:process", "source": "inline:process",
            "category": "process", "item_key": "inline:bad", "severity": "high",
            "score": 8.0, "title": "inline hit", "evidence": {"process": "bad"},
        }]

    eng = object.__new__(AttackLensEngine)
    eng._idb = object()
    eng._feeds = None
    eng._rulepack = _Rulepack()
    eng._processes = inline_analyze
    monkeypatch.setitem(engine_module._DETECTION_MODULE_ROUTES, "processes", [module_analyze])
    monkeypatch.setitem(engine_module.ENGINE_CONFIG, "use_detection_modules", True)

    findings = _run(eng._dispatch("agent-1", "processes", [{"name": "bad"}]))
    assert {finding["rule_id"] for finding in findings} == {
        "module:process", "inline:process",
    }


def test_dispatch_does_not_clear_other_agents_rate_history(monkeypatch):
    async def module_analyze(*_args):
        return []

    module_analyze.__module__ = engine_module.__name__
    monkeypatch.setattr(engine_module, "_dedup_cache", {"old": 1.0}, raising=False)
    monkeypatch.setattr(
        engine_module, "_rate_counter", {"other-agent": [1.0]}, raising=False,
    )
    monkeypatch.setitem(engine_module._DETECTION_MODULE_ROUTES, "sca", [module_analyze])
    monkeypatch.setitem(engine_module.ENGINE_CONFIG, "use_detection_modules", True)

    eng = object.__new__(AttackLensEngine)
    eng._idb = object()
    eng._feeds = None
    eng._rulepack = _Rulepack()
    _run(eng._dispatch("agent-1", "sca", {}))

    assert engine_module._dedup_cache == {}
    assert engine_module._rate_counter == {"other-agent": [1.0]}


class _WorkerEngine:
    def __init__(self):
        self.processed = []
        self.marked = []
        self.correlated = []

    async def process(self, agent_id, section, data, **kwargs):
        self.processed.append((agent_id, section, data, kwargs))
        return True

    async def run_correlations(self, agent_id):
        self.correlated.append(agent_id)

    async def mark_payload_processed(self, agent_id, section, collected_at):
        self.marked.append((agent_id, section, collected_at))


class _Tracker:
    async def register(self, chunk_set_id, chunk_total):
        return None

    async def mark_done(self, chunk_set_id, chunk_index):
        return True


def test_attacklens_worker_passes_event_and_chunk_identity_to_engine():
    eng = _WorkerEngine()
    worker = AttackLensWorker("amqp://unused", eng, _Tracker())
    _run(worker._process({
        "agent_id": "agent-1", "section": "processes", "data": [{"pid": 1}],
        "collected_at": 1_700_000_123.0, "event_id": "event-1", "chunk_set_id": "set-1",
        "chunk_index": 1, "chunk_total": 2,
    }))

    assert eng.processed[0][3]["collected_at"] == 1_700_000_123.0
    assert eng.processed[0][3]["skip_correlation"] is True
    assert eng.processed[0][3]["event_id"] == "event-1"
    assert eng.processed[0][3]["chunk_index"] == 1
    assert eng.processed[0][3]["chunk_total"] == 2
    assert eng.marked == []
    assert eng.correlated == []


def test_queue_workers_close_active_connection_on_stop():
    class Connection:
        def __init__(self):
            self.closed = False

        async def close(self):
            self.closed = True

    attacklens = AttackLensWorker("amqp://unused", _WorkerEngine())
    telemetry = TelemetryWorker(
        "amqp://unused", object(), object(), object(), object(),
    )
    attacklens._connection = Connection()
    telemetry._connection = Connection()

    _run(attacklens.stop())
    _run(telemetry.stop())

    assert attacklens._connection.closed is True
    assert telemetry._connection.closed is True


class _IntelDB:
    def __init__(self):
        self.iocs = []

    async def get_all_iocs(self, _kind):
        return []

    async def list_kev(self, limit=10000):
        return []

    async def get_threat_actors(self, **_kwargs):
        return []

    async def get_recent_news(self, **_kwargs):
        return []

    async def upsert_ioc(self, **record):
        self.iocs.append(record)


def _snapshot():
    return {
        "generated_at": 1_700_000_000.0,
        "ips": [{"value": "8.8.8.8", "source": "feed", "confidence": 90}],
        "domains": [{"value": "EVIL.EXAMPLE", "source": "feed", "confidence": 90}],
        "hashes": [{"value": "a" * 64, "source": "threatfox", "confidence": 95}],
        "kev_ids": ["CVE-2025-0001"],
        "spamhaus_cidrs": ["203.0.113.0/24"],
    }


def test_central_snapshot_hydrates_all_detector_ioc_types():
    feeds = FeedManager(_IntelDB(), central_url="http://intel")

    async def central_json(*_args, **_kwargs):
        return _snapshot()

    feeds._central_json = central_json
    _run(feeds._load_from_central())

    assert feeds.is_malicious_ip("8.8.8.8")
    assert feeds.is_malicious_domain("evil.example")
    assert feeds.is_malicious_hash("A" * 64)
    assert feeds.is_kev_cve("cve-2025-0001")


def test_invalid_central_snapshot_does_not_replace_last_good_data():
    feeds = FeedManager(_IntelDB(), central_url="http://intel")
    feeds._ip_set = {"8.8.8.8"}
    feeds._ip_meta = {"8.8.8.8": {"source": "old"}}

    async def central_json(*_args, **_kwargs):
        return {"generated_at": 1.0, "ips": []}

    feeds._central_json = central_json
    with pytest.raises(FeedRefreshError):
        _run(feeds._load_from_central())
    assert feeds.is_malicious_ip("8.8.8.8")


def test_threatfox_hash_is_validated_and_persisted():
    db = _IntelDB()
    feeds = FeedManager(db)
    _run(feeds._add_hash("B" * 64, "threatfox", "critical", 95, "malware"))
    _run(feeds._add_hash("not-a-hash", "threatfox", "critical", 95, "bad"))

    assert feeds.is_malicious_hash("b" * 64)
    assert len(db.iocs) == 1
    assert db.iocs[0]["ioc_type"] == "hash"


def test_feed_values_are_canonical_and_malformed_iocs_are_rejected():
    db = _IntelDB()
    feeds = FeedManager(db)

    assert _run(feeds._add_ip("999.1.1.1", "feed", "high", 80, "bad")) is False
    assert _run(feeds._add_domain("https://evil.example/a", "feed", "high", 80, "bad")) is False
    assert _run(feeds._add_domain("EVIL.EXAMPLE.", "feed", "high", 80, "ok")) is True
    assert _parse_ip_ioc("[2606:4700:4700::1111]:443") == "2606:4700:4700::1111"
    assert len(db.iocs) == 1


def test_developer_security_stream_runs_dedicated_detection_logic():
    payload = {
        "capabilities": {
            "editor_extensions": {"items": [{
                "user": "alice", "editor": "vscode", "id": "unknown.agent",
                "auto_activates": True, "unknown_publisher": True,
                "entrypoint_indicators": ["child_process"],
            }]},
            "mcp_servers": {"servers": [{
                "name": "mutable", "config_path": "/Users/alice/.cursor/mcp.json",
                "command": "npx", "uses_latest": True,
                "uses_unpinned_ephemeral_runner": True, "env_keys": ["API_TOKEN"],
            }]},
            "agent_cli_tools": {"path": [{"path": "/tmp/tools", "world_writable": True}]},
            "browser_extensions": {"items": [{
                "user": "alice", "browser": "chrome", "id": "a" * 32,
                "native_messaging": True, "dangerous_permissions": ["webRequest"],
            }]},
            "native_messaging": {"items": [{
                "name": "unsafe.host", "path": "/Users/alice/host.json",
                "executable": "/tmp/host", "executable_meta": {"mode": "-rwxr-xr-x"},
            }]},
            "git": {"users": [{"settings": [{"key": "core.sshCommand", "value": "ssh-wrapper"}]}]},
            "credential_locations": {"locations": [{
                "user": "alice", "path": "/Users/alice/.npmrc", "mode": "-rw-r--r--",
            }]},
            "listening_ports": {"items": [{
                "process": "ollama", "pid": 42, "endpoint": "*:11434",
                "port": 11434, "wildcard": True, "interesting": True,
            }]},
            "docker": {"risk_posture": [{
                "id": "container-1", "privileged": True, "high_risk": True,
            }]},
        }
    }

    findings = _run(analyze_developer_security(
        "agent-1", "developer_security", payload, object(), "mac-1"
    ))

    assert {finding["rule_id"] for finding in findings} == {
        "AL-DEV-001", "AL-DEV-002", "AL-DEV-003", "AL-DEV-004", "AL-DEV-005",
        "AL-DEV-006", "AL-DEV-007", "AL-DEV-008", "AL-DEV-009",
        # AL-DEV-012 (AIAPP-0001): the ollama listener on *:11434 is a known
        # inference server on a wildcard bind — new, correct coverage.
        "AL-DEV-012",
    }
    assert all(finding["affected_asset"] == "mac-1" for finding in findings)
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert by_rule["AL-DEV-001"]["evidence"]["unknown_publisher"] is True
    assert by_rule["AL-DEV-001"]["evidence"]["side_loaded"] is True
    assert by_rule["AL-DEV-004"]["evidence"]["native_messaging"] is True
    assert by_rule["AL-DEV-009"]["evidence"]["high_risk"] is True


class _NVDMirrorDB:
    def __init__(self):
        self.cached = None

    async def get_cve_cache(self, _key):
        return None

    async def search_nvd_local(self, _package, limit=10):
        return [{
            "cve_id": "CVE-2026-1000", "description": "Acme issue",
            "cvss_score": 8.1, "severity": "high", "cwe_ids": "[]",
            "cpe_uris": '["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"]',
            "cpe_matches": '[{"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",'
                           '"vulnerable":true,"versionStartIncluding":"2.0",'
                           '"versionEndExcluding":"3.0"}]',
        }]

    async def set_cve_cache(self, key, cves, ttl):
        self.cached = (key, cves, ttl)

    async def get_cve_by_id(self, _cve_id):
        return None

    async def get_nvd_local_by_id(self, _cve_id):
        return (await self.search_nvd_local("widget"))[0]


def test_nvd_lookup_uses_local_mirror_and_applies_version_ranges():
    db = _NVDMirrorDB()
    lookup = CVELookup(db)

    affected = _run(lookup.lookup("widget", "2.5"))
    unaffected = _run(lookup.lookup("widget", "3.1"))

    assert [row["cve_id"] for row in affected] == ["CVE-2026-1000"]
    assert affected[0]["affected_cpe_matches"][0]["versionEndExcluding"] == "3.0"
    assert unaffected == []


def test_nvd_cve_by_id_uses_same_local_mirror_contract():
    cve = _run(CVELookup(_NVDMirrorDB()).get_cve("CVE-2026-1000"))

    assert cve["cve_id"] == "CVE-2026-1000"
    assert cve["affected_cpe_matches"][0]["versionStartIncluding"] == "2.0"
