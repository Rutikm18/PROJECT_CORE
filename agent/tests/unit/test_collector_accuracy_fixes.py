"""
agent/tests/unit/test_collector_accuracy_fixes.py — data-accuracy regressions
for the macOS collectors.

Each test pins a confirmed bug that made the agent ship missing or wrong data
on a real macOS 26 machine:

  1. WiFi was read via the `airport` CLI, which Apple REMOVED in macOS 15 →
     every wifi_* field was null on modern Macs. Fixed via system_profiler.
  2. codesign trust treated ad-hoc-signed binaries (the shape most macOS
     malware ships in) as "signed". Fixed to require a real authority chain.
  3. ProcessesCollector advertised a `signed` field but hard-coded it None.
  4. ServicesCollector hard-coded `enabled=True` for every service.
  5. ConfigsCollector scanned only os.path.expanduser('~') — under the root
     LaunchDaemon that's /var/root, blinding it to every real user's shell rc
     and ~/.ssh/authorized_keys.
  6. SecurityCollector._screen_sharing matched `"0"` anywhere in the plist
     output (e.g. LastExitStatus = 0) → false-positive "on".
"""
from __future__ import annotations

import agent.os.macos.collectors.base as base
import agent.os.macos.collectors.network as network
import agent.os.macos.collectors.system as system
import agent.os.macos.collectors.posture as posture
from agent.os.macos.collectors.base import codesign_trust
from agent.os.macos.collectors.network import NetworkCollector
from agent.os.macos.collectors.system import ServicesCollector
from agent.os.macos.collectors.posture import ConfigsCollector, SecurityCollector


# ── 1. WiFi via system_profiler, not the removed `airport` CLI ───────────────

_SP_AIRPORT = {
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [{
            "spairport_current_network_information": {
                "_name": "CorpWiFi",
                "spairport_network_channel": "44 (5GHz, 80MHz)",
                "spairport_signal_noise": "-53 dBm / -90 dBm",
                "spairport_security_mode": "spairport_security_mode_wpa3_personal",
            },
            "spairport_status_information": "spairport_status_connected",
        }],
    }],
}


def test_wifi_parsed_from_system_profiler(monkeypatch):
    monkeypatch.setattr(network, "_sp_json", lambda *a, **k: _SP_AIRPORT)
    info = NetworkCollector()._wifi_system_profiler()
    assert info["ssid"] == "CorpWiFi"
    assert info["channel"] == "44"        # parsed out of "44 (5GHz, 80MHz)"
    assert info["rssi"] == -53            # signal half of "-53 dBm / -90 dBm"


def test_wifi_falls_back_to_legacy_only_when_system_profiler_empty(monkeypatch):
    monkeypatch.setattr(network, "_sp_json", lambda *a, **k: None)
    # Legacy airport binary absent on modern macOS → empty, never crashes.
    monkeypatch.setattr(network.os.path, "exists", lambda p: False)
    info = NetworkCollector()._wifi()
    assert info == {}


def test_wifi_redacted_ssid_still_returns_signal(monkeypatch):
    """OS may redact SSID without Location consent — RSSI/channel must still flow."""
    sp = {"SPAirPortDataType": [{"spairport_airport_interfaces": [{
        "spairport_current_network_information": {
            "spairport_network_channel": "6 (2GHz, 20MHz)",
            "spairport_signal_noise": "-61 dBm / -92 dBm",
        }}]}]}
    monkeypatch.setattr(network, "_sp_json", lambda *a, **k: sp)
    info = NetworkCollector()._wifi_system_profiler()
    assert "ssid" not in info or info.get("ssid") is None
    assert info["rssi"] == -61
    assert info["channel"] == "6"


# ── 2. codesign trust must reject ad-hoc / unsigned ──────────────────────────

def test_codesign_trust_true_with_authority(monkeypatch):
    out = ("Identifier=com.apple.ls\n"
           "Authority=Software Signing\n"
           "Authority=Apple Code Signing Certification Authority\n")
    monkeypatch.setattr(base, "_run", lambda *a, **k: out)
    assert codesign_trust("/bin/ls") is True


def test_codesign_trust_false_for_adhoc(monkeypatch):
    # Ad-hoc: has an Identifier but Signature=adhoc and NO authority chain.
    out = "Identifier=sketchy\nSignature=adhoc\n"
    monkeypatch.setattr(base, "_run", lambda *a, **k: out)
    assert codesign_trust("/tmp/sketchy") is False


def test_codesign_trust_false_for_unsigned(monkeypatch):
    monkeypatch.setattr(base, "_run", lambda *a, **k: "code object is not signed at all")
    assert codesign_trust("/tmp/unsigned") is False


def test_codesign_trust_none_when_undeterminable(monkeypatch):
    monkeypatch.setattr(base, "_run", lambda *a, **k: "")
    assert codesign_trust("/does/not/exist") is None


# ── 3. ProcessesCollector signing cache ──────────────────────────────────────

def test_process_signing_status_is_cached(monkeypatch, tmp_path):
    from agent.os.macos.collectors.volatile import ProcessesCollector
    ProcessesCollector._sign_cache.clear()
    exe = tmp_path / "bin"
    exe.write_text("x")

    calls = []
    monkeypatch.setattr("agent.os.macos.collectors.volatile.codesign_trust",
                        lambda p: (calls.append(p), True)[1])

    c = ProcessesCollector()
    assert c._signing_status(str(exe)) is True
    assert c._signing_status(str(exe)) is True   # second call: cache hit
    assert len(calls) == 1, "signing verdict must be cached by (path, mtime)"


def test_process_signing_status_none_for_missing_exe():
    from agent.os.macos.collectors.volatile import ProcessesCollector
    assert ProcessesCollector()._signing_status("") is None
    assert ProcessesCollector()._signing_status("/no/such/binary/xyz") is None


# ── 4. ServicesCollector real enabled-state ──────────────────────────────────

def test_services_enabled_reflects_disabled_list(monkeypatch):
    disabled_out = ('disabled services = {\n'
                    '\t"com.evil.daemon" => disabled\n'
                    '\t"com.apple.good" => enabled\n'
                    '}\n')
    list_out = ("PID\tStatus\tLabel\n"
                "123\t0\tcom.apple.good\n"
                "-\t0\tcom.evil.daemon\n")

    def fake_run(cmd, *a, **k):
        if "print-disabled" in cmd:
            return disabled_out
        if cmd[:2] == ["launchctl", "list"]:
            return list_out
        return ""
    monkeypatch.setattr(system, "_run", fake_run)

    rows = {r["name"]: r for r in ServicesCollector().collect()}
    assert rows["com.apple.good"]["enabled"] is True
    assert rows["com.apple.good"]["status"] == "running"   # has a PID
    assert rows["com.evil.daemon"]["enabled"] is False     # was always True before
    assert rows["com.evil.daemon"]["status"] == "stopped"  # no PID


def test_services_enabled_none_when_disabled_list_unavailable(monkeypatch):
    list_out = "PID\tStatus\tLabel\n123\t0\tcom.apple.good\n"

    def fake_run(cmd, *a, **k):
        if "print-disabled" in cmd:
            return ""          # unavailable (e.g. unprivileged)
        if cmd[:2] == ["launchctl", "list"]:
            return list_out
        return ""
    monkeypatch.setattr(system, "_run", fake_run)

    rows = ServicesCollector().collect()
    assert rows[0]["enabled"] is None, "honest unknown, not a confident wrong True"


# ── 5. ConfigsCollector scans every real user home ───────────────────────────

def test_configs_scans_all_user_homes(monkeypatch, tmp_path):
    # Two fake users, each with a shell rc + authorized_keys.
    users = tmp_path / "Users"
    for u in ("alice", "bob"):
        ssh = users / u / ".ssh"
        ssh.mkdir(parents=True)
        (users / u / ".zshrc").write_text("export PATH=$PATH")
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAA... attacker@evil")

    monkeypatch.setattr(posture.os, "listdir",
                        lambda p: ["alice", "bob", "Shared"] if p == "/Users" else [])
    monkeypatch.setattr(posture.os.path, "isdir",
                        lambda p: str(p).startswith(str(users)) or p == "/var/root")
    monkeypatch.setattr(ConfigsCollector, "_SYSTEM_PATHS", ())
    # Redirect /Users/<u> to our tmp tree.
    real_join = posture.os.path.join
    monkeypatch.setattr(posture.os.path, "join",
                        lambda a, *b: real_join(str(users), *b) if a == "/Users"
                        else real_join(a, *b))

    rows = ConfigsCollector().collect()
    paths = {r["path"] for r in rows}
    # Both users' authorized_keys must be present — the whole point of the fix.
    assert any("alice" in p and "authorized_keys" in p for p in paths)
    assert any("bob" in p and "authorized_keys" in p for p in paths)


def test_configs_home_dirs_excludes_shared(monkeypatch):
    monkeypatch.setattr(posture.os, "listdir",
                        lambda p: ["alice", "Shared", ".localized"] if p == "/Users" else [])
    monkeypatch.setattr(posture.os.path, "isdir", lambda p: True)
    homes = ConfigsCollector()._home_dirs()
    assert not any("Shared" in h for h in homes)
    assert not any(h.endswith(".localized") for h in homes)


# ── 6. Screen sharing no longer false-positives on "0" ───────────────────────

def test_screen_sharing_uses_svc_loaded(monkeypatch):
    sec = SecurityCollector()
    monkeypatch.setattr(sec, "_svc_loaded", lambda label: False)
    assert sec._screen_sharing() is False     # off, not a false "on"
    monkeypatch.setattr(sec, "_svc_loaded", lambda label: True)
    assert sec._screen_sharing() is True
