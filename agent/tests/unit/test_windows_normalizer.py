"""
agent/tests/unit/test_windows_normalizer.py

Tests for the Windows normalizer.  Runs on any OS — no Windows dependencies.

Strategy
────────
Each test passes synthetic raw collector output through the normalizer and
asserts that:
  1. The returned data matches the canonical schema types (no type mismatches).
  2. Optional fields are None rather than missing keys.
  3. Type coercion works (strings → int/float, None passthrough, bad values → default).
  4. Unknown sections are passed through unchanged.
  5. List sections return lists; dict sections return dicts.
"""
from __future__ import annotations

import sys
import os
import pytest

# Ensure project root is importable regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

from agent.os.windows.normalizer import normalize


# ── helpers ───────────────────────────────────────────────────────────────────

def assert_fields(record: dict, required: list[str], optional: list[str] = None) -> None:
    for f in required:
        assert f in record, f"Required field missing: {f!r}"
    for f in (optional or []):
        assert f in record, f"Optional field missing: {f!r}"


# ── metrics ───────────────────────────────────────────────────────────────────

class TestMetrics:
    def test_canonical_fields_present(self):
        raw = {"cpu_pct": 42.5, "mem_pct": 60.0, "mem_used_mb": 8192,
               "mem_total_mb": 16384, "uptime_sec": 3600}
        out = normalize("metrics", raw)
        assert isinstance(out, dict)
        assert out["cpu_pct"] == 42.5
        assert out["mem_pct"] == 60.0
        assert out["mem_used_mb"] == 8192
        assert out["mem_total_mb"] == 16384
        assert out["load_1m"] is None   # Windows — always None

    def test_string_coercion(self):
        raw = {"cpu_pct": "55.2", "mem_pct": "70", "mem_used_mb": "4000",
               "mem_total_mb": "8000"}
        out = normalize("metrics", raw)
        assert out["cpu_pct"] == 55.2
        assert isinstance(out["cpu_pct"], float)
        assert out["mem_used_mb"] == 4000
        assert isinstance(out["mem_used_mb"], int)

    def test_missing_optional_fields_are_none(self):
        raw = {"cpu_pct": 10.0, "mem_pct": 20.0, "mem_used_mb": 100, "mem_total_mb": 200}
        out = normalize("metrics", raw)
        for field in ("swap_pct", "swap_used_mb", "swap_total_mb", "cpu_cores", "uptime_sec"):
            assert field in out
            assert out[field] is None, f"{field} should be None when missing"

    def test_bad_values_get_default(self):
        raw = {"cpu_pct": "bad", "mem_pct": None, "mem_used_mb": "x", "mem_total_mb": "y"}
        out = normalize("metrics", raw)
        assert out["cpu_pct"] == 0.0
        assert out["mem_pct"] == 0.0
        assert out["mem_used_mb"] == 0


# ── connections ───────────────────────────────────────────────────────────────

class TestConnections:
    def test_basic_connection(self):
        raw = [{"proto": "tcp", "local_addr": "10.0.0.1", "local_port": 52000,
                "remote_addr": "8.8.8.8", "remote_port": 443,
                "state": "ESTABLISHED", "pid": 1234, "process": "chrome.exe"}]
        out = normalize("connections", raw)
        assert isinstance(out, list)
        assert len(out) == 1
        c = out[0]
        assert c["proto"] == "tcp"
        assert c["local_port"] == 52000
        assert c["remote_addr"] == "8.8.8.8"

    def test_invalid_records_skipped(self):
        out = normalize("connections", [None, "bad", 42])
        assert out == []

    def test_non_list_passthrough(self):
        raw = {"not": "a list"}
        assert normalize("connections", raw) == raw


# ── processes ─────────────────────────────────────────────────────────────────

class TestProcesses:
    def test_process_fields(self):
        raw = [{"pid": 100, "ppid": 4, "name": "svchost.exe",
                "user": "NT AUTHORITY\\SYSTEM", "cpu_pct": 0.5,
                "mem_pct": 0.1, "mem_rss_mb": 32, "status": "running",
                "started_at": 1700000000, "cmdline": "svchost -k netsvcs"}]
        out = normalize("processes", raw)
        assert len(out) == 1
        p = out[0]
        assert p["pid"] == 100
        assert p["name"] == "svchost.exe"
        assert p["cpu_pct"] == 0.5

    def test_float_coercion_on_cpu_pct(self):
        raw = [{"pid": 1, "ppid": None, "name": "test", "user": None,
                "cpu_pct": "12.3", "mem_pct": "4.5", "mem_rss_mb": None,
                "status": None, "started_at": None, "cmdline": None}]
        out = normalize("processes", raw)
        assert out[0]["cpu_pct"] == 12.3


# ── ports ─────────────────────────────────────────────────────────────────────

class TestPorts:
    def test_port_record(self):
        raw = [{"proto": "tcp", "port": 445, "bind_addr": "0.0.0.0",
                "state": "LISTEN", "pid": 4, "process": "System"}]
        out = normalize("ports", raw)
        assert out[0]["port"] == 445
        assert out[0]["proto"] == "tcp"

    def test_missing_bind_addr_defaults(self):
        raw = [{"proto": "udp", "port": 53, "pid": 100, "process": "dns.exe"}]
        out = normalize("ports", raw)
        assert out[0]["bind_addr"] == "0.0.0.0"


# ── network ───────────────────────────────────────────────────────────────────

class TestNetwork:
    def test_network_dict(self):
        raw = {
            "interfaces": [{"name": "Ethernet", "mac": "aa:bb:cc:dd:ee:ff",
                             "ipv4": "10.0.0.5", "ipv6": None, "status": "up", "mtu": 1500}],
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "default_gw": "10.0.0.1",
            "hostname": "DESKTOP-XYZ",
            "domain": None,
            "wifi_ssid": "CorpWiFi",
            "wifi_rssi": -55,
        }
        out = normalize("network", raw)
        assert out["hostname"] == "DESKTOP-XYZ"
        assert out["wifi_ssid"] == "CorpWiFi"
        assert len(out["interfaces"]) == 1
        assert out["interfaces"][0]["name"] == "Ethernet"


# ── security ──────────────────────────────────────────────────────────────────

class TestSecurity:
    def test_windows_fields_populated(self):
        raw = {"defender": "enabled", "uac": "enabled", "bitlocker": "on",
               "firewall": "on", "secure_boot": "full",
               "av_installed": True, "av_product": "Windows Defender",
               "os_patched": True, "auto_update": True}
        out = normalize("security", raw)
        # macOS fields always None
        assert out["sip"] is None
        assert out["gatekeeper"] is None
        assert out["filevault"] is None
        # Windows fields present
        assert out["defender"] == "enabled"
        assert out["uac"] == "enabled"
        assert out["bitlocker"] == "on"

    def test_linux_fields_none(self):
        out = normalize("security", {})
        assert out["selinux"] is None
        assert out["apparmor"] is None
        assert out["ufw"] is None


# ── sysctl ────────────────────────────────────────────────────────────────────

class TestSysctl:
    def test_registry_records(self):
        raw = [
            {"key": r"HKLM\SYSTEM\...\TCPMaxConnectRetransmissions", "value": "3", "security_relevant": True},
            {"key": r"HKLM\...\EnableLUA", "value": "1", "security_relevant": True},
        ]
        out = normalize("sysctl", raw)
        assert len(out) == 2
        assert out[0]["security_relevant"] is True
        assert isinstance(out[0]["key"], str)

    def test_empty_keys_skipped(self):
        raw = [{"key": "", "value": "x", "security_relevant": False}]
        out = normalize("sysctl", raw)
        assert out == []


# ── services ──────────────────────────────────────────────────────────────────

class TestServices:
    def test_status_mapping(self):
        raw = [
            {"name": "Spooler", "status": "running", "enabled": True, "pid": 1234,
             "type": "winsvc", "description": "Print Spooler"},
            {"name": "WSearch", "status": "stopped", "enabled": False, "pid": None,
             "type": "winsvc", "description": "Windows Search"},
            {"name": "BadSvc", "status": "paused", "enabled": None, "pid": None,
             "type": "winsvc", "description": None},
        ]
        out = normalize("services", raw)
        assert out[0]["status"] == "running"
        assert out[1]["status"] == "stopped"
        assert out[2]["status"] == "stopped"   # paused → stopped


# ── users ─────────────────────────────────────────────────────────────────────

class TestUsers:
    def test_uid_gid_always_none(self):
        raw = [{"name": "Administrator", "admin": True, "locked": False,
                "home": r"C:\Users\Administrator", "last_login": 1700000000}]
        out = normalize("users", raw)
        assert out[0]["uid"] is None
        assert out[0]["gid"] is None
        assert out[0]["admin"] is True


# ── apps ──────────────────────────────────────────────────────────────────────

class TestApps:
    def test_app_record(self):
        raw = [{"name": "Google Chrome", "version": "123.0.0.0",
                "vendor": "Google LLC", "path": r"C:\Program Files\Google\Chrome",
                "installed_at": 1700000000}]
        out = normalize("apps", raw)
        assert out[0]["name"] == "Google Chrome"
        assert out[0]["bundle_id"] is None   # macOS concept
        assert out[0]["notarized"] is None   # macOS only

    def test_empty_name_skipped(self):
        raw = [{"name": "", "version": "1.0"}]
        out = normalize("apps", raw)
        assert out == []


# ── packages ──────────────────────────────────────────────────────────────────

class TestPackages:
    def test_winget_package(self):
        raw = [{"manager": "winget", "name": "Microsoft.PowerShell",
                "version": "7.4.0", "latest": None, "outdated": None}]
        out = normalize("packages", raw)
        assert out[0]["manager"] == "winget"
        assert out[0]["version"] == "7.4.0"


# ── tasks ─────────────────────────────────────────────────────────────────────

class TestTasks:
    def test_scheduled_task(self):
        raw = [{"name": r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
                "type": "schtasks", "schedule": "Daily", "command": "UsoClient.exe ScanInstallWait",
                "user": "SYSTEM", "enabled": True, "last_run": None, "next_run": None}]
        out = normalize("tasks", raw)
        assert out[0]["type"] == "schtasks"
        assert out[0]["enabled"] is True


# ── storage ───────────────────────────────────────────────────────────────────

class TestStorage:
    def test_storage_record(self):
        raw = [{"device": "C:\\", "mountpoint": "C:\\", "fstype": "NTFS",
                "total_gb": 237.5, "used_gb": 120.3, "free_gb": 117.2, "pct": 50.6}]
        out = normalize("storage", raw)
        assert out[0]["fstype"] == "NTFS"
        assert isinstance(out[0]["total_gb"], float)


# ── sbom ──────────────────────────────────────────────────────────────────────

class TestSbom:
    def test_pip_component(self):
        raw = [{"type": "library", "name": "requests", "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0", "license": "Apache-2.0",
                "source": "pip", "cpe": None}]
        out = normalize("sbom", raw)
        assert out[0]["purl"] == "pkg:pypi/requests@2.31.0"
        assert out[0]["source"] == "pip"


# ── unknown section passthrough ───────────────────────────────────────────────

class TestPassthrough:
    def test_unknown_section_returns_raw(self):
        raw = {"anything": "goes"}
        assert normalize("nonexistent_section", raw) == raw

    def test_non_dict_input_for_dict_section_returned_unchanged(self):
        assert normalize("metrics", "not-a-dict") == "not-a-dict"

    def test_non_list_input_for_list_section_returned_unchanged(self):
        assert normalize("processes", {"oops": True}) == {"oops": True}
