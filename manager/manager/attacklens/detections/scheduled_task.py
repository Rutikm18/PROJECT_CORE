"""
manager/manager/attacklens/detections/scheduled_task.py
Detection of unauthorized scheduled tasks, hidden persistence jobs, and
suspicious auto-start entries.

Covers malware persistence, stealth execution, and ransomware staging via
cron, launchd, systemd timers, Windows Task Scheduler, and registry Run keys.

Telemetry sections handled:
  scheduled_tasks, cron_jobs, launchd_tasks, systemd_timers, tasks

COMPLIANCE MAPPING:
  NIST CSF:    DE.CM-7 (Unauthorized activity monitored), PR.PT-1
  CIS Control: 4.7 (Manage default accounts)
  SOC 2:       CC6.8 (Unauthorized software prevented)
  ISO 27001:   A.12.4.1 (Event logging)

MITRE ATT&CK:
  T1053.003  (Cron — Linux/macOS)
  T1053.004  (Launchd — macOS)
  T1053.005  (Scheduled Task — Windows)
  T1547.011  (Plist Modification)
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

log = logging.getLogger("manager.attacklens.detections.scheduled_task")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Paths under which tasks are considered root-accessible and suspicious
ROOT_WRITABLE_SUSPICIOUS_PATHS: tuple[str, ...] = (
    "/tmp/", "/var/tmp/", "/private/tmp/",
    "/Users/", "~/Downloads/", "~/Desktop/",
    "%TEMP%", "%APPDATA%", "\\Temp\\", "\\AppData\\",
)

# Executables that combined with network capability form a suspicious task
NETWORK_CAPABLE_INTERPRETERS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "python", "python3", "ruby", "perl", "node",
    "curl", "wget", "nc", "netcat", "socat", "php",
})

# High-frequency creation: > N new tasks in BURST_WINDOW_SECS is suspicious
NEW_TASK_BURST_THRESHOLD: int  = 3
BURST_WINDOW_SECS: int         = 600   # 10 minutes

# Dedup window: 4-hour window per task_name, resets on binary change
DEDUP_WINDOW_SECS: int       = 14400
RATE_LIMIT_MAX_PER_HOUR: int = 40

TASK_SECTIONS: frozenset[str] = frozenset({
    "scheduled_tasks", "cron_jobs", "launchd_tasks",
    "systemd_timers", "tasks",
})

# ─────────────────────────────────────────────────────────────────────────────
# UNICODE HOMOGLYPH / HIDDEN NAME DETECTION
# ─────────────────────────────────────────────────────────────────────────────

# Ranges of Unicode characters that visually resemble ASCII or are invisible
_HOMOGLYPH_RE = re.compile(
    r"[а-я"       # Cyrillic lowercase (look like Latin)
    r"Ѐ-Я"        # Cyrillic uppercase
    r"Ͱ-Ͽ"        # Greek
    r"​-‏"        # Zero-width characters
    r" -⁯"        # General punctuation (includes invisible)
    r"﻿"               # BOM / ZWNBSP
    r"­"               # Soft hyphen
    r"]"
)

def _has_homoglyph(name: str) -> bool:
    return bool(_HOMOGLYPH_RE.search(name))


def _is_hidden_name(name: str) -> bool:
    """Task name starting with '.' or containing homoglyphs/invisible chars."""
    return name.startswith(".") or _has_homoglyph(name)

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}
_new_task_times: dict[str, list[float]] = {}  # agent_id → [timestamps of new tasks]

# ─────────────────────────────────────────────────────────────────────────────
# DEDUP / RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _should_suppress(agent_id: str, rule_id: str, item: str,
                     binary_changed: bool = False) -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if binary_changed:
        _dedup_cache.pop(key, None)
    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit: agent=%s module=scheduled_task", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def _extract_exe(exe_path: str) -> str:
    """Return the bare executable name from a full path."""
    return re.split(r"[/\\ ]", exe_path.strip())[-1].lower().replace(".exe", "")


def ingest_tasks(data: Any) -> list[dict]:
    """
    Normalize scheduled task telemetry into:
      [{task_name, executable_path, schedule, run_as_user,
        signature_valid, sha256, plist_path, has_network, raw}]
    """
    tasks: list[dict] = []

    if isinstance(data, dict):
        if "tasks" in data:
            data = data["tasks"]
        elif "TaskName" in data or "task_name" in data:
            data = [data]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            name     = str(item.get("task_name") or item.get("TaskName") or
                           item.get("name") or item.get("label") or "")
            exe_path = str(item.get("executable_path") or item.get("exe") or
                           item.get("BinaryPathName") or item.get("program") or
                           (item.get("ProgramArguments", [""])[0]
                            if isinstance(item.get("ProgramArguments"), list) else "") or "")
            tasks.append({
                "task_name":       name,
                "executable_path": exe_path,
                "schedule":        str(item.get("schedule") or item.get("Triggers") or ""),
                "run_as_user":     str(item.get("run_as_user") or item.get("RunAsUser") or
                                       item.get("user") or item.get("StartName") or ""),
                "signature_valid": bool(item.get("signature_valid", True)),
                "sha256":          str(item.get("sha256") or ""),
                "plist_path":      str(item.get("plist_path") or item.get("plist") or ""),
                "has_network":     bool(item.get("has_network") or item.get("network", False)),
                "raw":             item,
            })
        return tasks

    if isinstance(data, str):
        # crontab -l style: "*/5 * * * * /usr/bin/curl http://..."
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                schedule = " ".join(parts[:5])
                cmd      = parts[5]
                tasks.append({
                    "task_name":       cmd.split()[0],
                    "executable_path": cmd.split()[0],
                    "schedule":        schedule,
                    "run_as_user":     "",
                    "signature_valid": True,
                    "sha256":          "",
                    "plist_path":      "",
                    "has_network":     False,
                    "raw":             {"cron_line": line},
                })

    return tasks

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str, hostname: str, severity: str, rule_id: str,
    title: str, description: str, mitre_technique: str,
    evidence: dict, raw_task: dict,
) -> dict:
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        "Persistence",
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw_task,
        "compliance_controls": [
            "NIST CSF DE.CM-7", "NIST CSF PR.PT-1",
            "CIS Control 4.7", "SOC 2 CC6.8",
            "ISO 27001 A.12.4.1",
        ],
        "recommended_action":  _rec_action(rule_id),
        "false_positive_notes": _fp_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "scheduled_task",
        "rule_id":             rule_id,
    }


def _rec_action(rule_id: str) -> str:
    m = {
        "new_task":           "Remove the unauthorized task and investigate the binary for malware.",
        "root_task_tmp":      "Remove the task immediately and delete the binary. Scan for persistence.",
        "unsigned_task":      "Quarantine the task binary and investigate its origin.",
        "high_freq_tasks":    "Investigate what process is creating tasks so rapidly. Possible automated installer.",
        "binary_hash_changed": "Verify the binary against a trusted hash. Quarantine if integrity check fails.",
        "hidden_task":        "Remove the task. Investigate for a persistence rootkit.",
        "network_interpreter": "Review the task's purpose. Remove if not authorized.",
    }
    return m.get(rule_id, "Investigate and remove the flagged scheduled task.")


def _fp_note(rule_id: str) -> str:
    m = {
        "new_task":           "Software installers create legitimate scheduled tasks. Verify the installer.",
        "root_task_tmp":      "Some installers temporarily use /tmp. Verify the task moves to a permanent path.",
        "unsigned_task":      "Open-source tools and homebrew packages may be unsigned.",
        "high_freq_tasks":    "Batch software deployments can create many tasks simultaneously.",
        "binary_hash_changed": "OS or software updates change binary hashes. Verify update history.",
        "hidden_task":        "Some system tasks use dot-prefix names on macOS.",
        "network_interpreter": "Many legitimate admin tasks use curl or wget for health checks.",
    }
    return m.get(rule_id, "Review context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

async def detect_new_task(
    agent_id: str,
    tasks: list[dict],
    db: Any,
) -> list[dict]:
    """CRITICAL — New scheduled task not in the approved baseline."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "scheduled_task", "task_baseline")
    baseline: dict[str, str] = {}
    if raw_state:
        try:
            baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            baseline = {}

    updated = dict(baseline)
    now = time.time()

    for task in tasks:
        name     = task["task_name"]
        sha256   = task["sha256"]
        fp       = hashlib.sha256(f"{name}:{task['executable_path']}".encode()).hexdigest()[:20]
        updated[name] = fp

        if name in baseline:
            continue

        # Track burst
        times = [t for t in _new_task_times.get(agent_id, []) if now - t < BURST_WINDOW_SECS]
        times.append(now)
        _new_task_times[agent_id] = times

        if _should_suppress(agent_id, "new_task", name):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical", rule_id="new_task",
            title=f"New unauthorized scheduled task: {name}",
            description=(
                f"Scheduled task '{name}' appeared and is not in the approved baseline. "
                f"Executable: {task['executable_path'] or 'unknown'}. "
                "Attackers register new tasks to survive reboots and achieve persistence."
            ),
            mitre_technique="T1053.003",
            evidence={
                "task_name":       name,
                "executable_path": task["executable_path"],
                "schedule":        task["schedule"],
                "run_as_user":     task["run_as_user"],
                "signature_valid": task["signature_valid"],
                "sha256":          sha256,
                "fingerprint":     fp,
            },
            raw_task=task["raw"],
        ))

    try:
        await db.set_entity_state(
            agent_id, "scheduled_task", "task_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist task baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_root_task_in_tmp(agent_id: str, tasks: list[dict]) -> list[dict]:
    """CRITICAL — Task executing as root from a user-writable or temp path."""
    findings: list[dict] = []
    for task in tasks:
        user    = task["run_as_user"].lower()
        exe     = task["executable_path"]
        is_root = user in ("root", "0", "system", "nt authority\\system")
        if not is_root:
            continue
        in_tmp  = any(exe.lower().startswith(p.lower()) or p.lower() in exe.lower()
                      for p in ROOT_WRITABLE_SUSPICIOUS_PATHS)
        if not in_tmp:
            continue
        name = task["task_name"]
        if _should_suppress(agent_id, "root_task_tmp", name):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical", rule_id="root_task_tmp",
            title=f"Root-privilege task executing from suspicious path: {name}",
            description=(
                f"Scheduled task '{name}' runs as '{task['run_as_user']}' "
                f"with executable at '{exe}', which is a user-writable or temp directory. "
                "Root tasks in temp paths are a strong ransomware staging or malware indicator."
            ),
            mitre_technique="T1053.004",
            evidence={
                "task_name":       name,
                "run_as_user":     task["run_as_user"],
                "executable_path": exe,
                "schedule":        task["schedule"],
            },
            raw_task=task["raw"],
        ))
    return findings


def detect_unsigned_task(agent_id: str, tasks: list[dict]) -> list[dict]:
    """HIGH — Task executable has invalid code signature and is not in approved list."""
    findings: list[dict] = []
    for task in tasks:
        if task["signature_valid"]:
            continue
        name = task["task_name"]
        if _should_suppress(agent_id, "unsigned_task", name):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="unsigned_task",
            title=f"Unsigned scheduled task executable: {name}",
            description=(
                f"Scheduled task '{name}' references an executable '{task['executable_path']}' "
                "with an invalid or missing code signature. "
                "This is a strong indicator of a persistence implant."
            ),
            mitre_technique="T1053.005",
            evidence={
                "task_name":       name,
                "executable_path": task["executable_path"],
                "signature_valid": False,
                "sha256":          task["sha256"],
                "run_as_user":     task["run_as_user"],
                "schedule":        task["schedule"],
            },
            raw_task=task["raw"],
        ))
    return findings


def detect_task_burst(agent_id: str) -> list[dict]:
    """HIGH — More than NEW_TASK_BURST_THRESHOLD new tasks created within BURST_WINDOW_SECS."""
    findings: list[dict] = []
    now   = time.time()
    times = [t for t in _new_task_times.get(agent_id, []) if now - t < BURST_WINDOW_SECS]
    if len(times) <= NEW_TASK_BURST_THRESHOLD:
        return findings
    item_key = f"burst:{int(now // BURST_WINDOW_SECS)}"
    if _should_suppress(agent_id, "high_freq_tasks", item_key):
        return findings
    findings.append({
        "alert_id":            str(uuid.uuid4()),
        "severity":            "high",
        "title":               f"High-frequency task creation: {len(times)} new tasks in {BURST_WINDOW_SECS}s",
        "description":         (
            f"{len(times)} new scheduled tasks were created within {BURST_WINDOW_SECS} seconds. "
            "This rate is consistent with an automated malware installer or ransomware staging."
        ),
        "affected_asset":      agent_id,
        "mitre_tactic":        "Persistence",
        "mitre_technique":     "T1053.003",
        "evidence":            {"new_task_count": len(times), "window_secs": BURST_WINDOW_SECS},
        "raw_telemetry":       {},
        "compliance_controls": ["NIST CSF DE.CM-7", "SOC 2 CC6.8"],
        "recommended_action":  "Investigate what process is creating tasks at this rate.",
        "false_positive_notes": "Batch deployments can create many tasks simultaneously.",
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "scheduled_task",
        "rule_id":             "high_freq_tasks",
    })
    return findings


async def detect_binary_hash_changed(
    agent_id: str,
    tasks: list[dict],
    db: Any,
) -> list[dict]:
    """HIGH — SHA256 of the executable referenced by an approved task changed."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "scheduled_task", "task_hash_baseline")
    hash_baseline: dict[str, str] = {}
    if raw_state:
        try:
            hash_baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            hash_baseline = {}

    updated = dict(hash_baseline)
    for task in tasks:
        name   = task["task_name"]
        sha256 = task["sha256"]
        if not sha256:
            continue
        updated[name] = sha256
        prev_hash = hash_baseline.get(name)
        if prev_hash is None or prev_hash == sha256:
            continue
        binary_changed = True
        if _should_suppress(agent_id, "binary_hash_changed", f"{name}:{sha256}",
                            binary_changed=binary_changed):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="binary_hash_changed",
            title=f"Task binary hash changed: {name}",
            description=(
                f"Scheduled task '{name}' executable hash changed "
                f"from {prev_hash[:16]}… to {sha256[:16]}…. "
                "This may indicate a trojanized update or binary replacement attack."
            ),
            mitre_technique="T1053.005",
            evidence={
                "task_name":    name,
                "exe_path":     task["executable_path"],
                "old_hash":     prev_hash,
                "new_hash":     sha256,
            },
            raw_task=task["raw"],
        ))

    try:
        await db.set_entity_state(
            agent_id, "scheduled_task", "task_hash_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist hash baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_hidden_task(agent_id: str, tasks: list[dict]) -> list[dict]:
    """HIGH — Task name starts with '.' or contains Unicode homoglyphs."""
    findings: list[dict] = []
    for task in tasks:
        name = task["task_name"]
        if not _is_hidden_name(name):
            continue
        if _should_suppress(agent_id, "hidden_task", name):
            continue
        reason = "dot-prefix" if name.startswith(".") else "unicode-homoglyph"
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="hidden_task",
            title=f"Hidden scheduled task detected: {repr(name)}",
            description=(
                f"Scheduled task '{repr(name)}' uses a hidden naming convention ({reason}). "
                "Attackers use dot-prefixed or homoglyph names to hide persistence entries "
                "from casual inspection."
            ),
            mitre_technique="T1547.011",
            evidence={
                "task_name":  name,
                "reason":     reason,
                "exe_path":   task["executable_path"],
            },
            raw_task=task["raw"],
        ))
    return findings


def detect_network_interpreter_task(agent_id: str, tasks: list[dict]) -> list[dict]:
    """MEDIUM — Task executable is a network-capable interpreter."""
    findings: list[dict] = []
    for task in tasks:
        exe  = _extract_exe(task["executable_path"])
        if exe not in NETWORK_CAPABLE_INTERPRETERS:
            continue
        if not task["has_network"]:
            continue
        name = task["task_name"]
        if _should_suppress(agent_id, "network_interpreter", name):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="medium", rule_id="network_interpreter",
            title=f"Scheduled task uses network-capable interpreter: {name} ({exe})",
            description=(
                f"Task '{name}' executes '{exe}' and has network access enabled. "
                "Shell scripts and interpreters running as scheduled tasks with network "
                "capability are frequently used for C2 beaconing and data exfiltration."
            ),
            mitre_technique="T1053.003",
            evidence={
                "task_name":   name,
                "interpreter": exe,
                "exe_path":    task["executable_path"],
                "schedule":    task["schedule"],
                "has_network": True,
            },
            raw_task=task["raw"],
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
    if section not in TASK_SECTIONS:
        return []

    tasks = ingest_tasks(data)
    if not tasks:
        return []

    findings: list[dict] = []

    for f in await detect_new_task(agent_id, tasks, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_root_task_in_tmp(agent_id, tasks):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_unsigned_task(agent_id, tasks):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_task_burst(agent_id):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_binary_hash_changed(agent_id, tasks, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_hidden_task(agent_id, tasks):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_network_interpreter_task(agent_id, tasks):
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
        _new_task_times.clear()

    def make_task(**kw) -> dict:
        d = {
            "task_name": "legit_task", "executable_path": "/usr/bin/python3",
            "schedule": "*/5 * * * *", "run_as_user": "nobody",
            "signature_valid": True, "sha256": "abc123",
            "plist_path": "", "has_network": False,
            "raw": {},
        }
        d.update(kw)
        return d

    async def run_tests():
        global passed, failed

        # ── 1. New task: first scan → CRITICAL ───────────────────────────────
        print("\nTest 1: New unauthorized task → CRITICAL")
        fresh()
        db1 = MockDB()
        tasks = [make_task(task_name="evil_task", executable_path="/tmp/evil.sh")]
        findings = await detect_new_task("agentA", tasks, db1)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule new_task", findings[0]["rule_id"] == "new_task")

        # ── 2. Known task: second scan → suppressed ───────────────────────────
        print("\nTest 2: Known task — no re-alert")
        fresh()
        db2 = MockDB()
        tasks = [make_task(task_name="backup_job", executable_path="/usr/bin/rsync")]
        await detect_new_task("agentB", tasks, db2)
        findings = await detect_new_task("agentB", tasks, db2)
        check("no findings on second scan", len(findings) == 0)

        # ── 3. Root task in /tmp → CRITICAL ──────────────────────────────────
        print("\nTest 3: Root task in /tmp → CRITICAL")
        fresh()
        tasks = [make_task(task_name="ransomware", executable_path="/tmp/ransom.sh",
                           run_as_user="root")]
        findings = detect_root_task_in_tmp("agentC", tasks)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule root_task_tmp", findings[0]["rule_id"] == "root_task_tmp")

        # ── 4. Root task in safe path → no alert ─────────────────────────────
        print("\nTest 4: Root task in /usr/bin — no alert")
        fresh()
        tasks = [make_task(task_name="backup", executable_path="/usr/bin/rsync",
                           run_as_user="root")]
        findings = detect_root_task_in_tmp("agentD", tasks)
        check("no findings", len(findings) == 0)

        # ── 5. Non-root task in /tmp → no alert ──────────────────────────────
        print("\nTest 5: Non-root task in /tmp — no alert")
        fresh()
        tasks = [make_task(task_name="user_task", executable_path="/tmp/user.sh",
                           run_as_user="alice")]
        findings = detect_root_task_in_tmp("agentE", tasks)
        check("no findings (non-root)", len(findings) == 0)

        # ── 6. Unsigned task → HIGH ───────────────────────────────────────────
        print("\nTest 6: Unsigned task → HIGH")
        fresh()
        tasks = [make_task(task_name="malware_task", signature_valid=False,
                           executable_path="/usr/local/bin/malware")]
        findings = detect_unsigned_task("agentF", tasks)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")

        # ── 7. Signed task → no alert ─────────────────────────────────────────
        print("\nTest 7: Signed task — no alert")
        fresh()
        tasks = [make_task(task_name="legitimate", signature_valid=True)]
        findings = detect_unsigned_task("agentG", tasks)
        check("no findings", len(findings) == 0)

        # ── 8. Task burst: > 3 new tasks in 10 min → HIGH ────────────────────
        print("\nTest 8: Task burst → HIGH")
        fresh()
        db8 = MockDB()
        for i in range(4):
            t = [make_task(task_name=f"burst_task_{i}")]
            await detect_new_task("agentH", t, db8)
        findings = detect_task_burst("agentH")
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("rule high_freq_tasks", findings[0]["rule_id"] == "high_freq_tasks")

        # ── 9. No burst: < 4 tasks → no alert ────────────────────────────────
        print("\nTest 9: No burst — < 4 tasks")
        fresh()
        db9 = MockDB()
        for i in range(2):
            t = [make_task(task_name=f"few_task_{i}")]
            await detect_new_task("agentI", t, db9)
        findings = detect_task_burst("agentI")
        check("no findings", len(findings) == 0)

        # ── 10. Binary hash changed → HIGH ───────────────────────────────────
        print("\nTest 10: Binary hash changed → HIGH")
        fresh()
        db10 = MockDB()
        tasks_old = [make_task(task_name="cron_backup", sha256="aabbccdd")]
        await detect_binary_hash_changed("agentJ", tasks_old, db10)
        tasks_new = [make_task(task_name="cron_backup", sha256="eeff0011")]
        findings = await detect_binary_hash_changed("agentJ", tasks_new, db10)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("old_hash in evidence", "aabbccdd" in findings[0]["evidence"]["old_hash"])

        # ── 11. Hash unchanged → no alert ─────────────────────────────────────
        print("\nTest 11: Hash unchanged — no alert")
        fresh()
        db11 = MockDB()
        tasks = [make_task(task_name="stable_task", sha256="deadbeef")]
        await detect_binary_hash_changed("agentK", tasks, db11)
        findings = await detect_binary_hash_changed("agentK", tasks, db11)
        check("no findings", len(findings) == 0)

        # ── 12. Hidden task: dot-prefix → HIGH ───────────────────────────────
        print("\nTest 12: Dot-prefix task name → HIGH")
        fresh()
        tasks = [make_task(task_name=".hidden_backdoor")]
        findings = detect_hidden_task("agentL", tasks)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("reason dot-prefix", findings[0]["evidence"]["reason"] == "dot-prefix")

        # ── 13. Hidden task: homoglyph → HIGH ────────────────────────────────
        print("\nTest 13: Homoglyph task name → HIGH")
        fresh()
        # "system" with Cyrillic 's' (с = с)
        homoglyph_name = "сystem_task"
        tasks = [make_task(task_name=homoglyph_name)]
        findings = detect_hidden_task("agentM", tasks)
        check("1 finding", len(findings) == 1)
        check("reason unicode-homoglyph", findings[0]["evidence"]["reason"] == "unicode-homoglyph")

        # ── 14. Normal task name → no alert ──────────────────────────────────
        print("\nTest 14: Normal task name — no alert")
        fresh()
        tasks = [make_task(task_name="com.apple.periodic-weekly")]
        findings = detect_hidden_task("agentN", tasks)
        check("no findings", len(findings) == 0)

        # ── 15. Network interpreter task → MEDIUM ─────────────────────────────
        print("\nTest 15: curl task with network → MEDIUM")
        fresh()
        tasks = [make_task(task_name="health_check", executable_path="/usr/bin/curl",
                           has_network=True)]
        findings = detect_network_interpreter_task("agentO", tasks)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("rule network_interpreter", findings[0]["rule_id"] == "network_interpreter")

        # ── 16. Interpreter without network flag → no alert ───────────────────
        print("\nTest 16: curl task without network flag — no alert")
        fresh()
        tasks = [make_task(task_name="no_net", executable_path="/usr/bin/curl",
                           has_network=False)]
        findings = detect_network_interpreter_task("agentP", tasks)
        check("no findings (no network flag)", len(findings) == 0)

        # ── 17. Crontab text ingestion ────────────────────────────────────────
        print("\nTest 17: Crontab text ingestion")
        fresh()
        raw = "*/5 * * * * /usr/bin/curl http://example.com/update\n0 2 * * * /usr/sbin/logrotate\n"
        tasks = ingest_tasks(raw)
        check("2 tasks", len(tasks) == 2)
        check("schedule correct", "*/5 * * * *" in tasks[0]["schedule"])

        # ── 18. Dict list ingestion ────────────────────────────────────────────
        print("\nTest 18: Dict list ingestion")
        fresh()
        raw = [
            {"task_name": "MyTask", "executable_path": "/usr/bin/python3",
             "schedule": "daily", "run_as_user": "root", "signature_valid": True,
             "sha256": "aa", "has_network": False, "plist_path": ""},
        ]
        tasks = ingest_tasks(raw)
        check("1 task", len(tasks) == 1)
        check("run_as_user root", tasks[0]["run_as_user"] == "root")

        # ── 19. Root task in Downloads → CRITICAL ─────────────────────────────
        print("\nTest 19: Root task in ~/Downloads → CRITICAL")
        fresh()
        tasks = [make_task(task_name="deploy", run_as_user="root",
                           executable_path="/Users/alice/Downloads/deploy.sh")]
        findings = detect_root_task_in_tmp("agentQ", tasks)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 20. Full analyze() pipeline ───────────────────────────────────────
        print("\nTest 20: Full analyze() pipeline")
        fresh()
        db20 = MockDB()
        # Two tasks: one unsigned root task in /tmp, one curl task with network
        raw = [
            {"task_name": "new_persist", "executable_path": "/tmp/evil.sh",
             "run_as_user": "root", "signature_valid": False,
             "sha256": "deadbeef", "has_network": False,
             "schedule": "*/1 * * * *", "plist_path": ""},
            {"task_name": "c2_beacon", "executable_path": "/usr/bin/curl",
             "run_as_user": "nobody", "signature_valid": True,
             "sha256": "beefdead", "has_network": True,
             "schedule": "*/5 * * * *", "plist_path": ""},
        ]
        findings = await analyze("agentR", "scheduled_tasks", raw, db20, hostname="host-r")
        rule_ids = {f["rule_id"] for f in findings}
        check("new_task fired", "new_task" in rule_ids)
        check("root_task_tmp fired", "root_task_tmp" in rule_ids)
        check("unsigned_task fired", "unsigned_task" in rule_ids)
        check("network_interpreter fired", "network_interpreter" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-r" for f in findings))

        # ── 21. Non-task section → empty ─────────────────────────────────────
        print("\nTest 21: Non-task section → empty")
        fresh()
        db21 = MockDB()
        findings = await analyze("agentS", "processes", [], db21)
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
