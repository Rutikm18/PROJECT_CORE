"""
agent/tests/unit/test_macos_normalizer.py

Tests for agent/os/macos/normalizer.py

Strategy
────────
Each test passes synthetic raw collector output through the normalizer and
asserts that:
  1. The returned data matches canonical schema types (no type mismatches).
  2. Optional fields are None rather than missing keys.
  3. Type coercion works (strings → int/float, None passthrough, bad → default).
  4. Unknown sections are passed through unchanged.
  5. List sections return lists; dict sections return dicts.
  6. CLI text path (legacy) and psutil structured path both normalise correctly.

Runs on any OS — no macOS dependencies.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

import pytest
from agent.os.macos.normalizer import normalize


# ── metrics ───────────────────────────────────────────────────────────────────

class TestMetrics:
    def test_psutil_path(self):
        raw = {
            "cpu_pct": 42.5, "mem_pct": 60.0,
            "mem_used_mb": 8192, "mem_total_mb": 16384,
            "swap_pct": 25.0, "swap_used_mb": 512, "swap_total_mb": 2048,
            "load_1m": 1.2, "load_5m": 0.9, "load_15m": 0.7,
            "cpu_cores": 10, "uptime_sec": 3600,
        }
        out = normalize("metrics", raw)
        assert isinstance(out, dict)
        assert out["cpu_pct"] == 42.5
        assert out["mem_pct"] == 60.0
        assert out["mem_used_mb"] == 8192
        assert out["load_1m"] == 1.2
        assert out["cpu_cores"] == 10
        assert out["uptime_sec"] == 3600

    def test_psutil_string_coercion(self):
        raw = {
            "cpu_pct": "55.2", "mem_pct": "70", "mem_used_mb": "4000",
            "mem_total_mb": "8000", "load_1m": "1.5", "load_5m": "1.2", "load_15m": "0.8",
        }
        out = normalize("metrics", raw)
        assert out["cpu_pct"] == 55.2
        assert isinstance(out["cpu_pct"], float)
        assert out["mem_used_mb"] == 4000
        assert isinstance(out["mem_used_mb"], int)
        assert out["load_1m"] == 1.5

    def test_cli_text_path(self):
        raw = {
            "cpu":    "CPU usage: 12.3% user, 5.6% sys, 82.1% idle",
            "load":   "{ 1.23 0.98 0.74 }",
            "vmstat": "Pages free:         12345.\nPages wired down:    5678.\nPages active:        3456.\npage size of 16384 bytes",
            "swap":   "vm.swapusage: total = 2048.00M  used = 512.00M  free = 1536.00M",
        }
        out = normalize("metrics", raw)
        assert isinstance(out, dict)
        assert abs(out["cpu_pct"] - 17.9) < 0.01   # 12.3 + 5.6
        assert out["load_1m"] == 1.23
        assert out["load_5m"] == 0.98
        assert out["swap_total_mb"] == 2048
        assert out["swap_used_mb"] == 512

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

    def test_non_dict_returned_unchanged(self):
        assert normalize("metrics", "not-a-dict") == "not-a-dict"


# ── connections ───────────────────────────────────────────────────────────────

class TestConnections:
    def test_psutil_structured_path(self):
        raw = [{"proto": "tcp", "local_addr": "10.0.0.1", "local_port": 52000,
                "remote_addr": "8.8.8.8", "remote_port": 443,
                "state": "ESTABLISHED", "pid": 1234, "process": "chrome"}]
        out = normalize("connections", raw)
        assert isinstance(out, list)
        assert len(out) == 1
        c = out[0]
        assert c["proto"] == "tcp"
        assert c["local_port"] == 52000
        assert c["remote_addr"] == "8.8.8.8"
        assert c["process"] == "chrome"

    def test_lsof_text_path(self):
        raw = [{"proc": "chrome", "pid": "1234",
                "addr": "10.0.0.1:52000->8.8.8.8:443"}]
        out = normalize("connections", raw)
        assert len(out) == 1
        c = out[0]
        assert c["local_addr"] == "10.0.0.1"
        assert c["local_port"] == 52000
        assert c["remote_addr"] == "8.8.8.8"
        assert c["remote_port"] == 443
        assert c["process"] == "chrome"

    def test_invalid_records_skipped(self):
        out = normalize("connections", [None, "bad", 42])
        assert out == []

    def test_non_list_passthrough(self):
        raw = {"not": "a list"}
        assert normalize("connections", raw) == raw


# ── processes ─────────────────────────────────────────────────────────────────

class TestProcesses:
    def test_psutil_path(self):
        raw = [{"pid": 100, "ppid": 1, "name": "Finder",
                "user": "alice", "cpu_pct": 0.5, "mem_pct": 0.1,
                "mem_rss_mb": 64, "status": "running",
                "started_at": 1700000000, "cmdline": "/System/Library/CoreServices/Finder.app"}]
        out = normalize("processes", raw)
        assert len(out) == 1
        p = out[0]
        assert p["pid"] == 100
        assert p["name"] == "Finder"
        assert p["cpu_pct"] == 0.5

    def test_ps_text_path(self):
        raw = [{"pid": "42", "ppid": "1", "user": "root",
                "cpu_pct": "12.3", "mem_pct": "4.5", "mem_rss_mb": "32",
                "status": "R", "name": "python3", "cmdline": None}]
        out = normalize("processes", raw)
        assert out[0]["cpu_pct"] == 12.3
        assert out[0]["pid"] == 42


# ── ports ─────────────────────────────────────────────────────────────────────

class TestPorts:
    def test_psutil_path(self):
        raw = [{"proto": "tcp", "port": 443, "bind_addr": "0.0.0.0",
                "state": "LISTEN", "pid": 4, "process": "nginx"}]
        out = normalize("ports", raw)
        assert out[0]["port"] == 443
        assert out[0]["bind_addr"] == "0.0.0.0"

    def test_lsof_path(self):
        raw = [{"proc": "sshd", "pid": "88", "proto": "TCP", "addr": "*:22"}]
        out = normalize("ports", raw)
        assert out[0]["port"] == 22
        assert out[0]["proto"] == "tcp"

    def test_missing_bind_addr_defaults(self):
        raw = [{"proto": "udp", "port": 53, "pid": 100, "process": "mDNSResponder"}]
        out = normalize("ports", raw)
        assert out[0]["bind_addr"] == "0.0.0.0"


# ── network ───────────────────────────────────────────────────────────────────

class TestNetwork:
    def test_full_dict(self):
        raw = {
            "interfaces": [{"name": "en0", "mac": "aa:bb:cc:dd:ee:ff",
                             "ipv4": "192.168.1.10", "ipv6": "fe80::1",
                             "status": "up", "mtu": 1500, "speed": 1000}],
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "default_gw": "192.168.1.1",
            "hostname": "macbook-pro.local",
            "domain": None,
            "wifi_ssid": "CorpWiFi",
            "wifi_bssid": "aa:bb:cc:dd:ee:ff",
            "wifi_rssi": -65,
            "wifi_channel": "6",
        }
        out = normalize("network", raw)
        assert out["hostname"] == "macbook-pro.local"
        assert out["wifi_ssid"] == "CorpWiFi"
        assert out["wifi_rssi"] == -65
        assert len(out["interfaces"]) == 1
        assert out["interfaces"][0]["name"] == "en0"
        assert out["interfaces"][0]["speed"] == 1000


# ── battery ───────────────────────────────────────────────────────────────────

class TestBattery:
    def test_present_charging(self):
        raw = {"present": True, "charging": True, "charge_pct": 87.5,
               "cycle_count": 342, "condition": "Good",
               "capacity_mah": 5000, "design_mah": 5100, "voltage_mv": 12000}
        out = normalize("battery", raw)
        assert out["present"] is True
        assert out["charging"] is True
        assert out["charge_pct"] == 87.5
        assert out["cycle_count"] == 342
        assert out["condition"] == "Good"

    def test_not_present(self):
        out = normalize("battery", {"present": False})
        assert out["present"] is False
        assert out["charging"] is None
        assert out["charge_pct"] is None


# ── security ──────────────────────────────────────────────────────────────────

class TestSecurity:
    def test_macos_fields_populated(self):
        raw = {"sip": "enabled", "gatekeeper": "enabled",
               "filevault": "on", "firewall": "on",
               "xprotect": "5271", "secure_boot": "full",
               "auto_update": True, "lockdown_mode": False}
        out = normalize("security", raw)
        assert out["sip"] == "enabled"
        assert out["gatekeeper"] == "enabled"
        assert out["filevault"] == "on"
        assert out["secure_boot"] == "full"
        # Windows/Linux fields always None on macOS
        assert out["uac"] is None
        assert out["bitlocker"] is None
        assert out["defender"] is None
        assert out["selinux"] is None
        assert out["apparmor"] is None

    def test_lockdown_mode_coercion(self):
        out = normalize("security", {"lockdown_mode": "1"})
        assert out["lockdown_mode"] is True
        out2 = normalize("security", {"lockdown_mode": False})
        assert out2["lockdown_mode"] is False


# ── sysctl ────────────────────────────────────────────────────────────────────

class TestSysctl:
    def test_list_of_records(self):
        raw = [
            {"key": "kern.hostname", "value": "macbook", "security_relevant": True},
            {"key": "net.inet.ip.forwarding", "value": "0", "security_relevant": True},
        ]
        out = normalize("sysctl", raw)
        assert len(out) == 2
        assert out[0]["key"] == "kern.hostname"
        assert out[0]["security_relevant"] is True

    def test_legacy_dict_form(self):
        raw = {"kern.hostname": "macbook", "net.inet.ip.forwarding": "0"}
        out = normalize("sysctl", raw)
        assert isinstance(out, list)
        assert len(out) == 2
        assert all("key" in r for r in out)

    def test_empty_key_skipped(self):
        raw = [{"key": "", "value": "x", "security_relevant": False}]
        out = normalize("sysctl", raw)
        assert out == []


# ── configs ───────────────────────────────────────────────────────────────────

class TestConfigs:
    def test_list_form(self):
        raw = [{"path": "/etc/hosts", "content": "127.0.0.1 localhost",
                "suspicious": False}]
        out = normalize("configs", raw)
        assert out[0]["path"] == "/etc/hosts"
        assert out[0]["suspicious"] is False

    def test_legacy_dict_form(self):
        raw = {"/etc/hosts": "127.0.0.1 localhost", "/etc/zshrc": ""}
        out = normalize("configs", raw)
        assert isinstance(out, list)
        assert len(out) == 2
        paths = {r["path"] for r in out}
        assert "/etc/hosts" in paths


# ── services ──────────────────────────────────────────────────────────────────

class TestServices:
    def test_status_normalisation(self):
        raw = [
            {"name": "com.macintel.agent", "status": "running", "enabled": True,
             "pid": 1234, "type": "launchd", "description": None},
            {"name": "com.apple.Spotlight", "status": "stopped", "enabled": True,
             "pid": None, "type": "launchd", "description": "Spotlight"},
            {"name": "legacy.svc", "status": "paused", "enabled": None,
             "pid": None, "type": "launchd", "description": None},
        ]
        out = normalize("services", raw)
        assert out[0]["status"] == "running"
        assert out[1]["status"] == "stopped"
        assert out[2]["status"] == "stopped"   # paused → stopped


# ── users ─────────────────────────────────────────────────────────────────────

class TestUsers:
    def test_uid_gid_present(self):
        raw = [{"name": "alice", "uid": 501, "gid": 20,
                "admin": True, "locked": False,
                "home": "/Users/alice", "last_login": 1700000000}]
        out = normalize("users", raw)
        assert out[0]["uid"] == 501
        assert out[0]["gid"] == 20
        assert out[0]["admin"] is True

    def test_uid_gid_coercion(self):
        raw = [{"name": "bob", "uid": "502", "gid": "20"}]
        out = normalize("users", raw)
        assert out[0]["uid"] == 502
        assert isinstance(out[0]["uid"], int)


# ── apps ──────────────────────────────────────────────────────────────────────

class TestApps:
    def test_full_app_record(self):
        raw = [{"name": "Google Chrome", "version": "123.0.0.0",
                "bundle_id": "com.google.Chrome",
                "path": "/Applications/Google Chrome.app",
                "vendor": "Google LLC", "signed": True, "notarized": True,
                "installed_at": 1700000000}]
        out = normalize("apps", raw)
        assert out[0]["name"] == "Google Chrome"
        assert out[0]["bundle_id"] == "com.google.Chrome"
        assert out[0]["signed"] is True
        assert out[0]["notarized"] is True

    def test_empty_name_skipped(self):
        raw = [{"name": "", "version": "1.0"}]
        out = normalize("apps", raw)
        assert out == []


# ── packages ──────────────────────────────────────────────────────────────────

class TestPackages:
    def test_brew_package(self):
        raw = [{"manager": "brew", "name": "git", "version": "2.44.0",
                "latest": "2.44.0", "outdated": False, "installed_at": None}]
        out = normalize("packages", raw)
        assert out[0]["manager"] == "brew"
        assert out[0]["version"] == "2.44.0"
        assert out[0]["outdated"] is False

    def test_pip3_package(self):
        raw = [{"manager": "pip3", "name": "requests", "version": "2.31.0",
                "latest": None, "outdated": None, "installed_at": None}]
        out = normalize("packages", raw)
        assert out[0]["manager"] == "pip3"


# ── storage ───────────────────────────────────────────────────────────────────

class TestStorage:
    def test_storage_record(self):
        raw = [{"device": "/dev/disk3s1", "mountpoint": "/",
                "fstype": "apfs",
                "total_gb": 460.4, "used_gb": 210.8, "free_gb": 249.6, "pct": 45.8}]
        out = normalize("storage", raw)
        assert out[0]["fstype"] == "apfs"
        assert isinstance(out[0]["total_gb"], float)
        assert out[0]["pct"] == 45.8


# ── tasks ─────────────────────────────────────────────────────────────────────

class TestTasks:
    def test_cron_entry(self):
        raw = [{"name": "backup.sh", "type": "cron",
                "schedule": "0 2 * * *", "command": "/usr/local/bin/backup.sh",
                "user": "root", "enabled": True, "last_run": None, "next_run": None}]
        out = normalize("tasks", raw)
        assert out[0]["type"] == "cron"
        assert out[0]["enabled"] is True

    def test_launchd_entry(self):
        raw = [{"name": "com.apple.MRT", "type": "launchd",
                "schedule": "daily", "command": "/usr/libexec/MRT",
                "user": "root", "enabled": True}]
        out = normalize("tasks", raw)
        assert out[0]["type"] == "launchd"


# ── sbom ──────────────────────────────────────────────────────────────────────

class TestSbom:
    def test_pip_component(self):
        raw = [{"type": "library", "name": "requests", "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0", "license": "Apache-2.0",
                "source": "pip3", "cpe": None}]
        out = normalize("sbom", raw)
        assert out[0]["purl"] == "pkg:pypi/requests@2.31.0"
        assert out[0]["source"] == "pip3"

    def test_brew_component(self):
        raw = [{"type": "library", "name": "openssl", "version": "3.2.1",
                "purl": "pkg:brew/openssl@3.2.1", "license": "OpenSSL",
                "source": "brew", "cpe": None}]
        out = normalize("sbom", raw)
        assert out[0]["source"] == "brew"


# ── passthrough ───────────────────────────────────────────────────────────────

class TestPassthrough:
    def test_unknown_section(self):
        raw = {"anything": "goes"}
        assert normalize("nonexistent_section", raw) == raw

    def test_wrong_type_for_dict_section(self):
        assert normalize("metrics", "not-a-dict") == "not-a-dict"

    def test_wrong_type_for_list_section(self):
        assert normalize("processes", {"oops": True}) == {"oops": True}

    def test_none_raw_for_list_section(self):
        assert normalize("connections", None) is None

    def test_hardware_list(self):
        raw = [{"bus": "usb", "name": "Magic Mouse",
                "vendor": "Apple", "product_id": "0x030d",
                "vendor_id": "0x05ac", "serial": None, "revision": "9.0"}]
        out = normalize("hardware", raw)
        assert out[0]["bus"] == "usb"
        assert out[0]["vendor"] == "Apple"
