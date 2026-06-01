"""
manager/manager/attacklens/detections/service_monitor.py
Detection of service stoppages, unauthorized daemon creation, and suspicious
service binary path changes.

Covers defense evasion via security service suppression, attacker persistence
via new daemon registration, and ransomware preparation via EDR killing.

Telemetry sections handled:
  services, launchd_services, systemd_services, windows_services

COMPLIANCE MAPPING:
  NIST CSF:    DE.CM-7 (Unauthorized activity monitored), PR.PT-1
  CIS Control: 4 (Secure Configuration), 10 (Malware Defenses)
  SOC 2:       CC7.2, A1.2 (Availability commitments)
  ISO 27001:   A.12.1.2 (Change management), A.16.1.5

MITRE ATT&CK:
  T1543.004  (Launch Daemon — macOS)
  T1543.003  (Windows Service)
  T1562.001  (Disable or Modify Tools)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.detections.service_monitor")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Services that must never be stopped. Any transition to stopped/disabled is CRITICAL.
CRITICAL_SERVICES: frozenset[str] = frozenset({
    # EDR / AV agents
    "falcond", "falcon-sensor", "csagent", "csfalconservice",
    "sentinelone", "s1agent", "sentinelagent",
    "cbdaemon", "carbonblack", "cb",
    "windowsdefender", "windefend", "mssense",
    "cylancesvc", "cylanceprotect",
    "amppolicyservice", "clamav",
    # Logging / SIEM shippers
    "auditd", "syslog", "syslogd", "rsyslog", "syslog-ng",
    "osqueryd", "osquery",
    "filebeat", "metricbeat", "heartbeat",
    "splunkd", "splunkforwarder",
    "elastic-agent", "elasticagent",
    # Integrity
    "aide", "tripwire", "samhain",
    # macOS system integrity
    "com.apple.security.syspolicyd",
    "com.apple.mrt",
    "com.apple.xprotect",
    "com.apple.trustd",
    # Linux audit
    "systemd-journald",
})

# Approved binary path prefixes — services whose binaries live here are trusted
TRUSTED_BINARY_PREFIXES: tuple[str, ...] = (
    "/System/Library/",
    "/Library/Apple/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/sbin/",
    "/bin/",
    "/opt/homebrew/",
    "C:\\Windows\\system32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
)

# Binary paths that indicate a service running from a suspicious location
SUSPICIOUS_PATH_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p, re.I) for p in [
    r"^/tmp/",
    r"^/var/tmp/",
    r"/Users/[^/]+/Downloads/",
    r"/Users/[^/]+/Desktop/",
    r"^/private/tmp/",
    r"%TEMP%",
    r"%APPDATA%",
    r"\\Temp\\",
    r"\\AppData\\Local\\Temp\\",
    r"\\AppData\\Roaming\\",
    r"\.exe$.*--[a-z]",      # executable with suspicious flags
])

# macOS LaunchAgent paths — services registered here by non-user processes are suspicious
LAUNCHAGENT_USER_PATHS: tuple[str, ...] = (
    "/Library/LaunchAgents/",
    "LaunchAgents/",       # ~/Library/LaunchAgents
)

# States considered "stopped"
STOPPED_STATES: frozenset[str] = frozenset({
    "stopped", "inactive", "dead", "disabled",
    "0",  # launchctl exit code 0 with no pid = stopped
    "failed", "not-found", "masked",
})

DEDUP_WINDOW_SECS: int       = 3600   # 1-hour dedup for service events
RATE_LIMIT_MAX_PER_HOUR: int = 40

SERVICE_SECTIONS: frozenset[str] = frozenset({
    "services", "launchd_services", "systemd_services", "windows_services",
})

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}

# ─────────────────────────────────────────────────────────────────────────────
# DEDUP / RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _should_suppress(agent_id: str, rule_id: str, item: str) -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit: agent=%s module=service_monitor", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_name(name: str) -> str:
    return re.split(r"[./\\]", name.lower().strip())[-1]


def ingest_services(data: Any) -> list[dict]:
    """
    Normalize service telemetry from any OS format into:
      [{name, binary_path, state, signature_valid, plist_path,
        run_as_user, stopped_by_pid, stopped_by_user, command_used}]
    """
    services: list[dict] = []

    if isinstance(data, dict):
        if "services" in data:
            data = data["services"]
        elif "Name" in data or "Status" in data:
            data = [data]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name  = str(item.get("name") or item.get("Name") or item.get("label") or "")
            state = str(item.get("state") or item.get("Status") or item.get("status") or "").lower()
            services.append({
                "name":             name,
                "binary_path":      str(item.get("binary_path") or item.get("BinaryPathName") or
                                        item.get("exe") or item.get("ProgramArguments", [""])[0]
                                        if isinstance(item.get("ProgramArguments"), list) else
                                        item.get("binary_path", "")),
                "state":            state,
                "signature_valid":  bool(item.get("signature_valid", True)),
                "plist_path":       str(item.get("plist_path") or item.get("plist") or ""),
                "run_as_user":      str(item.get("run_as_user") or item.get("user") or item.get("StartName") or ""),
                "stopped_by_pid":   int(item.get("stopped_by_pid") or 0),
                "stopped_by_user":  str(item.get("stopped_by_user") or ""),
                "command_used":     str(item.get("command_used") or ""),
            })
        return services

    if isinstance(data, str):
        # Loose parsing of `launchctl list` output:
        # PID   Status   Label
        # -     0        com.apple.something
        for line in data.splitlines():
            parts = line.strip().split()
            if len(parts) < 3 or parts[0] == "PID":
                continue
            pid_str, status_str, label = parts[0], parts[1], parts[2]
            state = "running" if pid_str not in ("-", "0") else "stopped"
            services.append({
                "name": label, "binary_path": "",
                "state": state, "signature_valid": True,
                "plist_path": "", "run_as_user": "",
                "stopped_by_pid": 0, "stopped_by_user": "", "command_used": "",
            })

    return services

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str, hostname: str, severity: str, rule_id: str,
    title: str, description: str, mitre_technique: str,
    evidence: dict, raw_svc: dict,
) -> dict:
    tactic = "Defense Evasion" if "T1562" in mitre_technique else "Persistence"
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        tactic,
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw_svc,
        "compliance_controls": [
            "NIST CSF DE.CM-7", "NIST CSF PR.PT-1",
            "CIS Control 4", "CIS Control 10",
            "SOC 2 CC7.2", "SOC 2 A1.2",
            "ISO 27001 A.12.1.2", "ISO 27001 A.16.1.5",
        ],
        "recommended_action":  _rec_action(rule_id),
        "false_positive_notes": _fp_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "service_monitor",
        "rule_id":             rule_id,
    }


def _rec_action(rule_id: str) -> str:
    m = {
        "critical_svc_stopped":   "Restart the security service immediately. Investigate who/what stopped it and hunt for malware.",
        "new_daemon":             "Investigate the new daemon. Remove it if unauthorized and scan for persistence mechanisms.",
        "binary_path_changed":    "Compare the new binary against a trusted hash. Quarantine if integrity check fails.",
        "unsigned_service":       "Quarantine the unsigned service binary and investigate its origin.",
        "suspicious_path":        "Remove the service and delete the binary from the temp/user-writable path.",
    }
    return m.get(rule_id, "Investigate the flagged service event.")


def _fp_note(rule_id: str) -> str:
    m = {
        "critical_svc_stopped":   "Planned maintenance or OS updates may stop security services. Verify timing.",
        "new_daemon":             "Legitimate software installs create new services. Verify the installer source.",
        "binary_path_changed":    "OS or software updates change binary paths. Verify update history.",
        "unsigned_service":       "Developer tools and brew packages may be unsigned. Verify with asset inventory.",
        "suspicious_path":        "Some installers temporarily extract to /tmp. Verify the service moves to a permanent path.",
    }
    return m.get(rule_id, "Review context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

def detect_critical_service_stopped(agent_id: str, services: list[dict]) -> list[dict]:
    """CRITICAL — Any service in the never-stop list is stopped/disabled."""
    findings: list[dict] = []
    for svc in services:
        raw_name   = svc["name"].lower().strip()
        name       = _normalize_name(raw_name)
        state      = svc["state"]
        # Match against full label OR normalized basename
        if raw_name not in CRITICAL_SERVICES and name not in CRITICAL_SERVICES:
            continue
        if state not in STOPPED_STATES:
            continue
        if _should_suppress(agent_id, "critical_svc_stopped", name):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical",
            rule_id="critical_svc_stopped",
            title=f"Critical security service stopped: {svc['name']}",
            description=(
                f"Security-critical service '{svc['name']}' has transitioned to '{state}'. "
                "Attackers commonly disable EDR agents, logging services, and integrity monitors "
                "before deploying payloads to evade detection."
            ),
            mitre_technique="T1562.001",
            evidence={
                "service_name":    svc["name"],
                "state":           state,
                "stopped_by_pid":  svc["stopped_by_pid"],
                "stopped_by_user": svc["stopped_by_user"],
                "command_used":    svc["command_used"],
            },
            raw_svc=svc,
        ))
    return findings


async def detect_new_daemon(
    agent_id: str,
    services: list[dict],
    db: Any,
) -> list[dict]:
    """CRITICAL — New service/daemon not in the approved baseline."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "service_monitor", "service_baseline")
    baseline: dict[str, str] = {}
    if raw_state:
        try:
            baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            baseline = {}

    updated = dict(baseline)
    for svc in services:
        name = svc["name"]
        fp   = hashlib.sha256(f"{name}:{svc['binary_path']}".encode()).hexdigest()[:20]
        updated[name] = fp

        if name in baseline:
            continue  # known service

        if _should_suppress(agent_id, "new_daemon", name):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical",
            rule_id="new_daemon",
            title=f"New unauthorized daemon registered: {name}",
            description=(
                f"Service '{name}' has been registered and is not in the approved service baseline. "
                "Attackers register new daemons to achieve persistence across reboots. "
                f"Binary path: {svc['binary_path'] or 'unknown'}"
            ),
            mitre_technique="T1543.004",
            evidence={
                "service_name": name,
                "binary_path":  svc["binary_path"],
                "plist_path":   svc["plist_path"],
                "state":        svc["state"],
                "run_as_user":  svc["run_as_user"],
                "fingerprint":  fp,
            },
            raw_svc=svc,
        ))

    try:
        await db.set_entity_state(
            agent_id, "service_monitor", "service_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist service baseline agent=%s: %s", agent_id, exc)

    return findings


async def detect_binary_path_changed(
    agent_id: str,
    services: list[dict],
    db: Any,
) -> list[dict]:
    """HIGH — BinaryPathName for an existing service changed."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "service_monitor", "service_binary_baseline")
    binary_baseline: dict[str, str] = {}
    if raw_state:
        try:
            binary_baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            binary_baseline = {}

    updated = dict(binary_baseline)
    for svc in services:
        name    = svc["name"]
        binpath = svc["binary_path"]
        if not binpath:
            continue
        updated[name] = binpath
        prev = binary_baseline.get(name)
        if prev is None or prev == binpath:
            continue
        if _should_suppress(agent_id, "binary_path_changed", f"{name}:{binpath}"):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high",
            rule_id="binary_path_changed",
            title=f"Service binary path changed: {name}",
            description=(
                f"Service '{name}' binary path changed from '{prev}' to '{binpath}'. "
                "Attackers replace service binaries with malicious ones to achieve persistent "
                "code execution with service-level privileges."
            ),
            mitre_technique="T1543.003",
            evidence={
                "service_name": name,
                "old_path":     prev,
                "new_path":     binpath,
                "state":        svc["state"],
            },
            raw_svc=svc,
        ))

    try:
        await db.set_entity_state(
            agent_id, "service_monitor", "service_binary_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist binary baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_unsigned_service(agent_id: str, services: list[dict]) -> list[dict]:
    """HIGH — New service binary lacks valid code signature."""
    findings: list[dict] = []
    for svc in services:
        if svc["signature_valid"]:
            continue
        if not svc["binary_path"]:
            continue
        name = svc["name"]
        if _should_suppress(agent_id, "unsigned_service", name):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high",
            rule_id="unsigned_service",
            title=f"Unsigned service binary: {name}",
            description=(
                f"Service '{name}' has a binary at '{svc['binary_path']}' "
                "with an invalid or missing code signature. "
                "Unsigned service binaries are a strong indicator of a persistence implant."
            ),
            mitre_technique="T1543.003",
            evidence={
                "service_name":      name,
                "binary_path":       svc["binary_path"],
                "signature_valid":   False,
                "state":             svc["state"],
                "plist_path":        svc["plist_path"],
            },
            raw_svc=svc,
        ))
    return findings


def detect_suspicious_path(agent_id: str, services: list[dict]) -> list[dict]:
    """MEDIUM — Service binary running from a temp or user-writable path."""
    findings: list[dict] = []
    for svc in services:
        binpath = svc["binary_path"]
        if not binpath:
            continue
        matched = next((p.pattern for p in SUSPICIOUS_PATH_PATTERNS if p.search(binpath)), None)
        if matched is None:
            continue
        name = svc["name"]
        if _should_suppress(agent_id, "suspicious_path", f"{name}:{binpath}"):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="medium",
            rule_id="suspicious_path",
            title=f"Service running from suspicious path: {name}",
            description=(
                f"Service '{name}' binary is located at '{binpath}', "
                "which is a temp or user-writable directory. "
                "Legitimate system services should not run from these locations."
            ),
            mitre_technique="T1543.004",
            evidence={
                "service_name":    name,
                "binary_path":     binpath,
                "matched_pattern": matched,
                "state":           svc["state"],
            },
            raw_svc=svc,
        ))
    return findings

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

async def analyze(
    agent_id: str,
    section:  str,
    data:     Any,
    db:       Any,
    hostname: str = "",
) -> list[dict]:
    if section not in SERVICE_SECTIONS:
        return []

    services = ingest_services(data)
    if not services:
        return []

    findings: list[dict] = []

    for f in detect_critical_service_stopped(agent_id, services):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_new_daemon(agent_id, services, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_binary_path_changed(agent_id, services, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_unsigned_service(agent_id, services):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_suspicious_path(agent_id, services):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio
    import sys

    PASS = "\033[92mPASS\033[0m"
    FAIL = "\033[91mFAIL\033[0m"
    passed = failed = 0

    def check(label: str, cond: bool) -> None:
        global passed, failed
        if cond:
            print(f"  {PASS}  {label}")
            passed += 1
        else:
            print(f"  {FAIL}  {label}")
            failed += 1

    class MockDB:
        def __init__(self):
            self._store: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._store.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, value, ts):
            self._store[f"{agent_id}:{ns}:{key}"] = value

    def fresh():
        _dedup_cache.clear()
        _rate_counter.clear()

    def make_svc(**kw) -> dict:
        d = {
            "name": "mysvc", "binary_path": "/usr/sbin/mysvc",
            "state": "running", "signature_valid": True,
            "plist_path": "", "run_as_user": "root",
            "stopped_by_pid": 0, "stopped_by_user": "", "command_used": "",
        }
        d.update(kw)
        return d

    async def run_tests():
        global passed, failed

        # ── 1. Critical service stopped: falcond ──────────────────────────────
        print("\nTest 1: EDR service falcond stopped → CRITICAL")
        fresh()
        svcs = [make_svc(name="falcond", state="stopped", stopped_by_user="root")]
        findings = detect_critical_service_stopped("agentA", svcs)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule critical_svc_stopped", findings[0]["rule_id"] == "critical_svc_stopped")
        check("stopped_by_user in evidence", findings[0]["evidence"]["stopped_by_user"] == "root")

        # ── 2. auditd stopped → CRITICAL ─────────────────────────────────────
        print("\nTest 2: auditd stopped → CRITICAL")
        fresh()
        svcs = [make_svc(name="auditd", state="inactive")]
        findings = detect_critical_service_stopped("agentB", svcs)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 3. Non-critical service stopped → no alert ───────────────────────
        print("\nTest 3: Non-critical service stopped — no alert")
        fresh()
        svcs = [make_svc(name="crond", state="stopped")]
        findings = detect_critical_service_stopped("agentC", svcs)
        check("no findings", len(findings) == 0)

        # ── 4. Critical service running → no alert ────────────────────────────
        print("\nTest 4: falcond running — no alert")
        fresh()
        svcs = [make_svc(name="falcond", state="running")]
        findings = detect_critical_service_stopped("agentD", svcs)
        check("no findings", len(findings) == 0)

        # ── 5. New daemon: first scan → CRITICAL ──────────────────────────────
        print("\nTest 5: New daemon triggers CRITICAL")
        fresh()
        db5 = MockDB()
        svcs = [make_svc(name="evil_daemon", binary_path="/tmp/evil")]
        findings = await detect_new_daemon("agentE", svcs, db5)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule new_daemon", findings[0]["rule_id"] == "new_daemon")

        # ── 6. New daemon: second scan → suppressed ───────────────────────────
        print("\nTest 6: Known daemon — no re-alert")
        fresh()
        db6 = MockDB()
        svcs = [make_svc(name="legitimate_svc")]
        await detect_new_daemon("agentF", svcs, db6)
        findings = await detect_new_daemon("agentF", svcs, db6)
        check("no findings on second scan", len(findings) == 0)

        # ── 7. Binary path changed → HIGH ────────────────────────────────────
        print("\nTest 7: Service binary path changed → HIGH")
        fresh()
        db7 = MockDB()
        svcs_old = [make_svc(name="httpd", binary_path="/usr/sbin/httpd")]
        await detect_binary_path_changed("agentG", svcs_old, db7)
        svcs_new = [make_svc(name="httpd", binary_path="/tmp/httpd_evil")]
        findings = await detect_binary_path_changed("agentG", svcs_new, db7)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("old_path in evidence", findings[0]["evidence"]["old_path"] == "/usr/sbin/httpd")
        check("new_path in evidence", findings[0]["evidence"]["new_path"] == "/tmp/httpd_evil")

        # ── 8. Binary path unchanged → no alert ──────────────────────────────
        print("\nTest 8: Binary path unchanged — no alert")
        fresh()
        db8 = MockDB()
        svcs = [make_svc(name="sshd", binary_path="/usr/sbin/sshd")]
        await detect_binary_path_changed("agentH", svcs, db8)
        findings = await detect_binary_path_changed("agentH", svcs, db8)
        check("no findings", len(findings) == 0)

        # ── 9. Unsigned service → HIGH ────────────────────────────────────────
        print("\nTest 9: Unsigned service binary → HIGH")
        fresh()
        svcs = [make_svc(name="backdoor_svc", binary_path="/usr/local/bin/back",
                         signature_valid=False)]
        findings = detect_unsigned_service("agentI", svcs)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("rule unsigned_service", findings[0]["rule_id"] == "unsigned_service")

        # ── 10. Signed service → no alert ────────────────────────────────────
        print("\nTest 10: Signed service — no alert")
        fresh()
        svcs = [make_svc(name="nginx", binary_path="/usr/sbin/nginx", signature_valid=True)]
        findings = detect_unsigned_service("agentJ", svcs)
        check("no findings", len(findings) == 0)

        # ── 11. Suspicious path /tmp → MEDIUM ────────────────────────────────
        print("\nTest 11: Service binary in /tmp → MEDIUM")
        fresh()
        svcs = [make_svc(name="malware_svc", binary_path="/tmp/malware.sh")]
        findings = detect_suspicious_path("agentK", svcs)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("rule suspicious_path", findings[0]["rule_id"] == "suspicious_path")

        # ── 12. Suspicious Downloads path → MEDIUM ────────────────────────────
        print("\nTest 12: Service in ~/Downloads → MEDIUM")
        fresh()
        svcs = [make_svc(name="suspect", binary_path="/Users/bob/Downloads/app.sh")]
        findings = detect_suspicious_path("agentL", svcs)
        check("1 finding", len(findings) == 1)

        # ── 13. Trusted path → no alert ───────────────────────────────────────
        print("\nTest 13: Trusted binary path — no alert")
        fresh()
        svcs = [make_svc(name="sshd", binary_path="/usr/sbin/sshd")]
        findings = detect_suspicious_path("agentM", svcs)
        check("no findings", len(findings) == 0)

        # ── 14. launchctl list text ingestion ─────────────────────────────────
        print("\nTest 14: launchctl list text ingestion")
        fresh()
        raw = (
            "PID   Status  Label\n"
            "1234  0       com.apple.security.syspolicyd\n"
            "-     0       com.apple.mrt\n"
        )
        svcs = ingest_services(raw)
        check("2 services parsed", len(svcs) == 2)
        check("first is running", svcs[0]["state"] == "running")
        check("second is stopped", svcs[1]["state"] == "stopped")

        # ── 15. Dict list ingestion ───────────────────────────────────────────
        print("\nTest 15: Dict list ingestion")
        fresh()
        raw = [
            {"name": "nginx", "state": "running", "binary_path": "/usr/sbin/nginx",
             "signature_valid": True, "run_as_user": "www-data"},
        ]
        svcs = ingest_services(raw)
        check("1 service", len(svcs) == 1)
        check("name nginx", svcs[0]["name"] == "nginx")

        # ── 16. com.apple.MRT stopped → CRITICAL (case normalization) ────────
        print("\nTest 16: com.apple.MRT stopped via label normalization")
        fresh()
        svcs = [make_svc(name="com.apple.mrt", state="disabled")]
        findings = detect_critical_service_stopped("agentN", svcs)
        check("1 finding (com.apple.mrt)", len(findings) == 1)

        # ── 17. SentinelOne stopped via alias ─────────────────────────────────
        print("\nTest 17: SentinelOne s1agent stopped")
        fresh()
        svcs = [make_svc(name="s1agent", state="dead")]
        findings = detect_critical_service_stopped("agentO", svcs)
        check("1 finding", len(findings) == 1)

        # ── 18. Dedup: same critical service stop suppressed ──────────────────
        print("\nTest 18: Dedup — same stop not re-alerted")
        fresh()
        svcs = [make_svc(name="auditd", state="stopped")]
        f1 = detect_critical_service_stopped("agentP", svcs)
        f2 = detect_critical_service_stopped("agentP", svcs)
        check("first fires", len(f1) == 1)
        check("second suppressed", len(f2) == 0)

        # ── 19. Full analyze() pipeline ───────────────────────────────────────
        print("\nTest 19: Full analyze() pipeline")
        fresh()
        db19 = MockDB()
        raw = [
            {"name": "osqueryd", "state": "stopped", "binary_path": "/usr/bin/osqueryd",
             "signature_valid": True, "run_as_user": "root",
             "stopped_by_pid": 0, "stopped_by_user": "", "command_used": "",
             "plist_path": ""},
            {"name": "new_evil_daemon", "state": "running", "binary_path": "/tmp/evil",
             "signature_valid": False, "run_as_user": "root",
             "stopped_by_pid": 0, "stopped_by_user": "", "command_used": "",
             "plist_path": ""},
        ]
        findings = await analyze("agentQ", "services", raw, db19, hostname="host-q")
        rule_ids = {f["rule_id"] for f in findings}
        check("critical_svc_stopped fired", "critical_svc_stopped" in rule_ids)
        check("new_daemon fired", "new_daemon" in rule_ids)
        check("unsigned_service fired", "unsigned_service" in rule_ids)
        check("suspicious_path fired", "suspicious_path" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-q" for f in findings))

        # ── 20. Non-service section → empty ───────────────────────────────────
        print("\nTest 20: Non-service section → empty")
        fresh()
        db20 = MockDB()
        findings = await analyze("agentR", "processes", [], db20)
        check("empty", len(findings) == 0)

        # ── 21. Empty service list → empty ────────────────────────────────────
        print("\nTest 21: Empty service list → empty")
        fresh()
        db21 = MockDB()
        findings = await analyze("agentS", "services", [], db21)
        check("empty", len(findings) == 0)

        print(f"\n{'─'*50}")
        total = passed + failed
        print(f"Results: {passed}/{total} passed", end="")
        if failed:
            print(f"  ({failed} FAILED)")
            sys.exit(1)
        else:
            print("  — all OK")

    asyncio.run(run_tests())
