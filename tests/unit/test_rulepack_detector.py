from __future__ import annotations

import asyncio

from manager.manager.attacklens.rulepack import RulePackDetector


def _run(coro):
    return asyncio.run(coro)


def test_rulepack_loads_yaml_categories() -> None:
    detector = RulePackDetector.load()

    assert len(detector.rules_for("processes")) == 6
    assert len(detector.rules_for("security")) == 5
    assert len(detector.rules_for("open_files")) == 5
    assert len(detector.rules_for("openfiles")) == 5


def test_process_obfuscation_rule_emits_finding() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "processes", [{
        "name": "powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc " + "A" * 80,
        "path": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:PROCESSES-002"]
    assert findings[0]["category"] == "process"
    assert "command_line matches" in findings[0]["evidence"]["_rulepack"]["matched_conditions"][0]
    assert findings[0]["evidence"]["_rulepack"]["evidence_strength"] == "strong"
    assert findings[0]["precision_factors"]["rule_confidence"] >= 0.80


def test_config_secret_rule_handles_dict_payload() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "configs", {
        "/etc/example.conf": "api_key = sk-test\n",
    }))

    assert [f["rule_id"] for f in findings] == ["rulepack:CONFIGS-003"]
    assert findings[0]["category"] == "config"
    assert findings[0]["evidence"]["path"] == "/etc/example.conf"


def test_openfiles_agent_section_alias_reaches_open_files_rules() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "openfiles", [{
        "pid": 42,
        "process": "python3",
        "file_path": "/Users/alice/.ssh/id_rsa",
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:OPEN_FILES-001"]
    assert findings[0]["category"] == "open_file"


def test_mount_rule_accepts_live_agent_mountpoint_alias() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "mounts", [{
        "device": "tmpfs",
        "mountpoint": "/etc",
        "fstype": "apfs",
        "options": "rw,o+w",
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:MOUNTS-003"]


def test_storage_rule_accepts_live_agent_storage_aliases() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "storage", [{
        "device": "disk9",
        "mountpoint": "",
        "fstype": "unknown",
        "total_gb": 2.5,
        "pct": 0,
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:STORAGE-005"]


def test_hardware_mass_storage_rule_infers_live_usb_schema(monkeypatch) -> None:
    monkeypatch.setenv("ATTACKLENS_APPROVED_USB_IDS", "0x1234:0xabcd:approved")
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "hardware", [{
        "bus": "usb",
        "name": "SanDisk Ultra USB Flash Drive",
        "vendor_id": "0x0781",
        "product_id": "0x5581",
        "serial": "A1B2C3",
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:HARDWARE-001"]


def test_container_privileged_and_socket_mount_rules_emit_findings() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "containers", [{
        "id": "abc",
        "image": "unknown/app:latest",
        "privileged": True,
        "mounts": [{"source": "/var/run/docker.sock", "target": "/docker.sock"}],
    }]))

    assert {f["rule_id"] for f in findings} == {
        "rulepack:CONTAINERS-001",
        "rulepack:CONTAINERS-002",
    }


class _Feeds:
    def is_malicious_ip(self, ip: str) -> bool:
        return ip == "8.8.8.8"


def test_connection_rule_uses_existing_feed_manager() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze(
        "agent-1",
        "connections",
        [{"remote_addr": "8.8.8.8:443", "process": "curl"}],
        _Feeds(),
    ))

    assert [f["rule_id"] for f in findings] == ["rulepack:CONNECTIONS-002"]
    assert findings[0]["category"] == "connection"
    assert findings[0]["confidence"] >= 0.96
    assert findings[0]["precision_factors"]["authoritative_corroboration"] == 1.0
    integration_state = findings[0]["evidence"]["_rulepack"]["integration_state"]
    assert integration_state["available"]["threat_intel"] is True


def test_connection_rule_marks_missing_threat_intel_integration() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze(
        "agent-1",
        "connections",
        [{"remote_addr": "8.8.8.8:443", "process": "curl", "malicious_ip": True}],
    ))

    assert [f["rule_id"] for f in findings] == ["rulepack:CONNECTIONS-002"]
    integration_state = findings[0]["evidence"]["_rulepack"]["integration_state"]
    assert "threat_intel" in integration_state["missing"]
    assert findings[0]["confidence"] < 0.90


def test_connection_rule_accepts_trusted_platform_corroboration() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze(
        "agent-1",
        "connections",
        [{
            "remote_addr": "8.8.8.8:443",
            "process": "curl",
            "malicious_ip": True,
            "threat_source": "abuseipdb",
        }],
    ))

    assert [f["rule_id"] for f in findings] == ["rulepack:CONNECTIONS-002"]
    integration_state = findings[0]["evidence"]["_rulepack"]["integration_state"]
    assert integration_state["missing"] == []
    assert "abuseipdb" in integration_state["trusted_sources"]
    assert findings[0]["evidence"]["_rulepack"]["evidence_strength"] == "authoritative"


def test_multi_condition_process_injection_is_authoritative() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "processes", [{
        "name": "unknown.exe",
        "remote_memory_allocation": True,
        "remote_thread_created": True,
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:PROCESSES-003"]
    assert findings[0]["evidence"]["_rulepack"]["evidence_strength"] == "authoritative"
    assert findings[0]["confidence"] >= 0.96
    assert findings[0]["precision_factors"]["condition_coverage"] > 0


def test_single_suspicious_path_heuristic_is_calibrated_below_authoritative() -> None:
    detector = RulePackDetector.load()

    findings = _run(detector.analyze("agent-1", "processes", [{
        "name": "helper",
        "path": "/tmp/helper",
    }]))

    assert [f["rule_id"] for f in findings] == ["rulepack:PROCESSES-004"]
    assert findings[0]["evidence"]["_rulepack"]["evidence_strength"] == "moderate"
    assert findings[0]["confidence"] < 0.84
    assert findings[0]["precision_factors"]["single_heuristic_penalty"] == 0.0
