"""
manager/manager/attacklens/detections/binary_integrity.py
Production-grade trusted binary integrity monitoring.

Detects unauthorized modification, replacement, or abuse of system binaries
under /usr/bin, /usr/sbin, /bin, /sbin, C:\\Windows\\System32 to identify
rootkit activity, privilege escalation tools, and living-off-the-land abuse.

Section handled: binaries

COMPLIANCE MAPPING:
  NIST CSF:    PR.DS-6 (Integrity checking), DE.CM-7 (Unauthorized activity)
  CIS Control 10: Malware Defenses
  SOC 2:       CC7.2 (Security incidents evaluated)
  ISO 27001:   A.12.2.1 (Controls against malware)

MITRE ATT&CK:
  T1036.005 (Match Legitimate Name or Location)
  T1548.001 (Setuid/Setgid)
  T1218     (System Binary Proxy Execution — LOLBin family)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.detections.binary_integrity")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — all thresholds configurable here
# ─────────────────────────────────────────────────────────────────────────────

# Suppress hash-change alerts for this many seconds after an OS update event
PATCH_WINDOW_SECS: int = 14400   # 4 hours

# Dedup and rate-limiting
DEDUP_WINDOW_SECS: int       = 3600
RATE_LIMIT_MAX_PER_HOUR: int = 40

# Approved SUID whitelist config path
SUID_WHITELIST_PATH: str = os.environ.get(
    "SUID_WHITELIST_PATH", "config/suid_whitelist.json"
)

# Monitored system binary paths (agent enumerates these)
MONITORED_PATHS: tuple[str, ...] = (
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
)

# Binaries that are expected to have SUID/SGID set on well-configured systems.
# Anything OUTSIDE this list that has SUID/SGID set is suspicious.
APPROVED_SUID_BINARIES: frozenset[str] = frozenset({
    "sudo", "su", "passwd", "newgrp", "sg", "chsh", "chfn",
    "gpasswd", "mount", "umount", "ping", "ping6", "traceroute",
    "at", "crontab", "write", "wall", "ssh-agent",
    "pkexec", "polkit",          # Linux privilege escalation tools — expected SUID
    "Xorg", "xterm",             # X11 display server
    "fusermount", "fusermount3", # FUSE filesystem mounts
    "newuidmap", "newgidmap",    # user namespace mapping
})

# LOLBin list — living-off-the-land binaries abused for execution/evasion.
# Map: binary_name_pattern → MITRE technique + description
LOLBINS: dict[str, dict] = {
    # macOS/Linux
    "bash":       {"mitre": "T1059.004", "desc": "Unix shell spawned outside normal parent"},
    "sh":         {"mitre": "T1059.004", "desc": "Unix shell spawned outside normal parent"},
    "zsh":        {"mitre": "T1059.004", "desc": "Unix shell spawned outside normal parent"},
    "python":     {"mitre": "T1059.006", "desc": "Python interpreter spawned outside normal parent"},
    "python3":    {"mitre": "T1059.006", "desc": "Python interpreter spawned outside normal parent"},
    "perl":       {"mitre": "T1059.006", "desc": "Perl interpreter spawned outside normal parent"},
    "ruby":       {"mitre": "T1059.004", "desc": "Ruby interpreter spawned outside normal parent"},
    "curl":       {"mitre": "T1105",     "desc": "curl spawned outside normal parent — possible C2 download"},
    "wget":       {"mitre": "T1105",     "desc": "wget spawned outside normal parent — possible C2 download"},
    "nc":         {"mitre": "T1059.004", "desc": "Netcat spawned — possible reverse shell"},
    "ncat":       {"mitre": "T1059.004", "desc": "Ncat spawned — possible reverse shell"},
    "socat":      {"mitre": "T1059.004", "desc": "socat spawned — tunneling / reverse shell"},
    "osascript":  {"mitre": "T1059.002", "desc": "AppleScript executor — possible bypass or automation"},
    # Windows
    "mshta.exe":    {"mitre": "T1218.005", "desc": "MSHTA proxy execution — HTA file runner"},
    "certutil.exe": {"mitre": "T1140",     "desc": "certutil — file download or base64 decode"},
    "regsvr32.exe": {"mitre": "T1218.010", "desc": "regsvr32 proxy execution — possible COM bypass"},
    "rundll32.exe": {"mitre": "T1218.011", "desc": "rundll32 proxy execution"},
    "wscript.exe":  {"mitre": "T1059.005", "desc": "Windows Script Host — VBScript/JScript runner"},
    "cscript.exe":  {"mitre": "T1059.005", "desc": "Windows Script Host — VBScript/JScript runner"},
    "msiexec.exe":  {"mitre": "T1218.007", "desc": "msiexec proxy execution — MSI-based payload drop"},
    "installutil.exe": {"mitre": "T1218.004", "desc": "InstallUtil proxy execution"},
    "regasm.exe":   {"mitre": "T1218.009", "desc": "RegAsm proxy execution"},
    "regsvcs.exe":  {"mitre": "T1218.009", "desc": "RegSvcs proxy execution"},
}

# Parents that make a LOLBin spawn suspicious: office apps, browsers, email clients
SUSPICIOUS_LOLBin_PARENTS: frozenset[str] = frozenset({
    "microsoft word", "winword", "excel", "powerpnt", "outlook",
    "teams", "slack", "zoom", "chrome", "safari", "firefox", "edge",
    "adobe acrobat", "acrord32", "acrobat",
    "thunderbird", "eudora",
    "java", "javaw",
})

# Parents that are explicitly benign for LOLBin spawns (suppress FP)
BENIGN_LOLBin_PARENTS: frozenset[str] = frozenset({
    "terminal", "iterm2", "iterm", "konsole", "gnome-terminal", "xterm",
    "bash", "sh", "zsh", "fish", "tmux", "screen",
    "code", "code-helper", "idea", "pycharm", "vim", "nvim", "emacs",
    "makefile", "make", "cmake", "gradle", "maven", "xcode",
    "launchd", "systemd", "init", "cron", "crond",
    "ansible", "puppet", "chef", "salt", "terraform",
    "jenkins", "gitlab-runner", "github-actions-runner",
    "sudo", "su",
})

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}
_suid_whitelist_cache: dict           = {}
_suid_whitelist_loaded_at: float      = 0.0
_patch_window: dict[str, float]       = {}   # agent_id → patch_window_until_ts

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _binary_name(path: str) -> str:
    """Return lowercase basename without extension (handles both / and \\ paths)."""
    name = re.split(r"[/\\]", str(path or ""))[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _normalize_path(p: str) -> str:
    """Lowercase path with forward slashes."""
    return str(p or "").replace("\\", "/").lower().strip()


def _is_system_path(path: str) -> bool:
    """Return True if path is under a monitored system binary directory."""
    norm = _normalize_path(path)
    system_roots = (
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/local/bin/", "/usr/local/sbin/",
        "c:/windows/system32/", "c:/windows/syswow64/",
    )
    return any(norm.startswith(r) for r in system_roots)


def _load_suid_whitelist() -> dict:
    """
    Load SUID whitelist config.  Reloads every 5 minutes.

    Format:
      {
        "paths": {
          "/usr/lib/openssh/ssh-keysign": {"reason": "SSH host-key signing"},
          "/usr/bin/pkexec": {"reason": "PolicyKit frontend", "expires": "2027-01-01"}
        }
      }
    """
    global _suid_whitelist_cache, _suid_whitelist_loaded_at
    now = time.time()
    if now - _suid_whitelist_loaded_at < 300 and _suid_whitelist_cache:
        return _suid_whitelist_cache
    try:
        p = Path(SUID_WHITELIST_PATH)
        _suid_whitelist_cache = json.loads(p.read_text()) if p.exists() else {"paths": {}}
    except Exception as exc:
        log.debug("SUID whitelist load failed (%s): %s", SUID_WHITELIST_PATH, exc)
        _suid_whitelist_cache = {"paths": {}}
    _suid_whitelist_loaded_at = now
    return _suid_whitelist_cache


def _is_whitelisted_suid(path: str) -> bool:
    """Return True if this path is in the SUID whitelist (name or full path)."""
    wl      = _load_suid_whitelist()
    paths   = wl.get("paths", {})
    name    = _binary_name(path)
    norm_p  = _normalize_path(path)

    # Check by name in APPROVED_SUID_BINARIES constant
    if name in APPROVED_SUID_BINARIES:
        return True

    # Check by full path in config file whitelist
    for wl_path, cfg in paths.items():
        if _normalize_path(wl_path) == norm_p:
            expires = cfg.get("expires", "")
            if expires:
                try:
                    if datetime.fromisoformat(expires).date() < datetime.now().date():
                        return False  # expired
                except ValueError:
                    pass
            return True

    return False


def _register_patch_window(agent_id: str, ts: Optional[float] = None) -> None:
    """Mark this agent as in a patch window for PATCH_WINDOW_SECS seconds."""
    _patch_window[agent_id] = (ts or time.time()) + PATCH_WINDOW_SECS


def _in_patch_window(agent_id: str) -> bool:
    return time.time() < _patch_window.get(agent_id, 0)


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
        log.debug("Rate limit: agent=%s module=binary_integrity", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

_BASELINE_NS = "binary_integrity"


async def _load_baseline(agent_id: str, key: str, db: Any) -> Optional[dict]:
    try:
        row = await db.get_entity_state(agent_id, _BASELINE_NS, key)
        if row and row.get("fingerprint"):
            return json.loads(row["fingerprint"])
    except Exception as exc:
        log.debug("Baseline load error agent=%s key=%s: %s", agent_id, key, exc)
    return None


async def _save_baseline(agent_id: str, key: str, data: dict, db: Any) -> None:
    try:
        await db.set_entity_state(
            agent_id, _BASELINE_NS, key,
            json.dumps(data, default=str),
            time.time(),
        )
    except Exception as exc:
        log.debug("Baseline save error agent=%s key=%s: %s", agent_id, key, exc)


def _path_key(path: str) -> str:
    """Stable entity-state key for a binary path."""
    return hashlib.sha256(_normalize_path(path).encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION — normalize raw section payload
# ─────────────────────────────────────────────────────────────────────────────

def ingest_binaries(raw: Any) -> dict:
    """
    Normalize the 'binaries' section payload from agent.

    Accepts:
      • dict with keys: binaries (or files), processes (optional, for LOLBin),
                        os_update_events (optional, for patch-window suppression)
      • list of binary dicts (flat format)

    Each normalized binary entry:
      {path, sha256, permissions_octal, owner, group, is_suid, is_sgid,
       is_signed, signature_valid, size_bytes, modified_ts, raw}

    Each process entry (for LOLBin detection):
      {name, exe, cmdline, pid, ppid, parent_name, raw}
    """
    result: dict[str, list] = {
        "binaries": [], "processes": [], "os_update_events": [],
    }

    if isinstance(raw, dict):
        bins_raw   = raw.get("binaries") or raw.get("files") or []
        procs_raw  = raw.get("processes") or raw.get("process_events") or []
        events_raw = raw.get("os_update_events") or raw.get("update_events") or []
    elif isinstance(raw, list):
        bins_raw, procs_raw, events_raw = raw, [], []
    else:
        return result

    for b in bins_raw:
        if not isinstance(b, dict):
            continue
        path = str(b.get("path") or b.get("file") or "").strip()
        if not path:
            continue
        result["binaries"].append({
            "path":             path,
            "sha256":           str(b.get("sha256") or b.get("hash") or "").lower().strip(),
            "permissions_octal": str(b.get("permissions_octal") or b.get("perms") or ""),
            "owner":            str(b.get("owner") or b.get("user") or ""),
            "group":            str(b.get("group") or ""),
            "is_suid":          bool(b.get("is_suid") or b.get("suid")),
            "is_sgid":          bool(b.get("is_sgid") or b.get("sgid")),
            "is_signed":        b.get("is_signed"),        # None = unknown
            "signature_valid":  b.get("signature_valid"),  # None = unknown
            "size_bytes":       int(b.get("size_bytes") or b.get("size") or 0),
            "modified_ts":      float(b.get("modified_ts") or b.get("mtime") or 0),
            "raw":              b,
        })

    for p in procs_raw:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or p.get("exe") or "").strip()
        if not name:
            continue
        result["processes"].append({
            "name":        name,
            "exe":         str(p.get("exe") or p.get("path") or ""),
            "cmdline":     str(p.get("cmdline") or p.get("cmd") or ""),
            "pid":         p.get("pid", ""),
            "ppid":        p.get("ppid") or p.get("parent_pid"),
            "parent_name": str(p.get("parent_name") or p.get("parent") or "").lower(),
            "raw":         p,
        })

    for ev in events_raw:
        if not isinstance(ev, dict):
            continue
        ts = float(ev.get("timestamp") or ev.get("ts") or time.time())
        result["os_update_events"].append({
            "event_type": str(ev.get("event_type") or ev.get("type") or "update"),
            "timestamp":  ts,
            "package":    str(ev.get("package") or ev.get("pkg") or ""),
        })

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def detect_hash_change(
    agent_id:  str,
    binaries:  list[dict],
    db:        Any,
) -> list[dict]:
    """
    CRITICAL: SHA256 of a monitored binary changed outside a known patch window.

    Baseline is set at first observation. Changes within PATCH_WINDOW_SECS of
    an OS update event are suppressed.  Baseline is updated only on explicit
    operator rebaseline command or after a confirmed patch.
    """
    hits = []
    now  = time.time()
    in_patch = _in_patch_window(agent_id)

    for binary in binaries:
        path   = binary["path"]
        sha256 = binary["sha256"]
        if not sha256 or not _is_system_path(path):
            continue

        key      = f"hash:{_path_key(path)}"
        baseline = await _load_baseline(agent_id, key, db)

        if not baseline:
            await _save_baseline(agent_id, key, {
                "path":        path,
                "sha256":      sha256,
                "permissions_octal": binary["permissions_octal"],
                "owner":       binary["owner"],
                "first_seen":  now,
                "last_seen":   now,
            }, db)
            log.debug("Binary baseline set: agent=%s path=%s", agent_id, path)
            continue

        baseline_sha = baseline.get("sha256", "")
        if not baseline_sha or sha256 == baseline_sha:
            # Update last_seen timestamp
            baseline["last_seen"] = now
            await _save_baseline(agent_id, key, baseline, db)
            continue

        # Suppress during active patch window
        if in_patch:
            log.debug("Hash change suppressed by patch window: agent=%s path=%s", agent_id, path)
            baseline["sha256"]   = sha256  # update baseline to new post-patch hash
            baseline["last_seen"] = now
            await _save_baseline(agent_id, key, baseline, db)
            continue

        first_seen_str = ""
        try:
            first_seen_str = datetime.fromtimestamp(
                float(baseline.get("first_seen", 0))
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass

        hits.append({
            "rule_id":    "binint:hash_changed",
            "severity":   "critical",
            "title":      f"System binary modified: {path}",
            "description": (
                f"SHA256 of '{path}' changed from {baseline_sha[:16]}… "
                f"to {sha256[:16]}… "
                f"(baseline established {first_seen_str}, no active patch window). "
                f"Unexpected binary modifications outside patch events are a strong "
                f"indicator of rootkit installation, binary replacement, or trojanization."
            ),
            "evidence": {
                "path":            path,
                "current_sha256":  sha256,
                "baseline_sha256": baseline_sha,
                "baseline_set":    baseline.get("first_seen", ""),
                "size_bytes":      binary.get("size_bytes", 0),
                "modified_ts":     binary.get("modified_ts", 0),
                "owner":           binary.get("owner", ""),
                "permissions":     binary.get("permissions_octal", ""),
            },
            "raw_telemetry": [binary["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1036.005",
            "compliance_controls": {
                "NIST": ["PR.DS-6", "DE.CM-7"],  "CIS": ["10.2"],
                "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Do NOT execute '{path}' until verified. "
                f"2. macOS: `codesign -dv --verbose=4 {path}`. "
                f"3. Linux: `dpkg -V $(dpkg -S {path} | cut -d: -f1)` or `rpm -V $(rpm -qf {path})`. "
                f"4. Windows: `Get-AuthenticodeSignature '{path}'`. "
                f"5. Compare SHA256 {sha256} against vendor package checksum. "
                f"6. If tampered: treat as active incident — isolate, preserve memory dump, "
                f"   restore from known-good backup."
            ),
            "false_positive_notes": (
                "Legitimate OS and package manager updates change binary hashes — "
                f"changes within {PATCH_WINDOW_SECS//3600}h of an OS update event are suppressed. "
                "Manually trigger a rebaseline after confirming a legitimate update: "
                "`POST /api/attacklens/rebaseline/{agent_id}/binaries`."
            ),
            "item_key":   f"binint:hash:{_path_key(path)}",
            "category":   "binary",
            "source":     "rule:binary_integrity",
            "score":      SEVERITY_SCORES["critical"],
            "tags":       ["binary_integrity", "hash_changed", "rootkit", "T1036.005"],
        })

    return hits


async def detect_new_suid(
    agent_id: str,
    binaries: list[dict],
    db:       Any,
) -> list[dict]:
    """
    CRITICAL: A binary in a monitored path has SUID/SGID that was not in the
    baseline AND is not in the approved whitelist.

    ALL system-path binaries are tracked (even those without SUID) so that when
    SUID is later added the baseline already exists and the change is detected.
    """
    hits = []
    now  = time.time()

    for binary in binaries:
        path    = binary["path"]
        is_suid = binary["is_suid"]
        is_sgid = binary["is_sgid"]

        if not _is_system_path(path):
            continue

        key      = f"suid:{_path_key(path)}"
        baseline = await _load_baseline(agent_id, key, db)

        if not baseline:
            # First observation — record current SUID state for all system binaries
            await _save_baseline(agent_id, key, {
                "path":       path,
                "is_suid":    is_suid,
                "is_sgid":    is_sgid,
                "sha256":     binary["sha256"],
                "first_seen": now,
            }, db)
            # Alert if first-seen binary already has SUID and is NOT whitelisted
            if (is_suid or is_sgid) and not _is_whitelisted_suid(path):
                bit = "SUID" if is_suid else "SGID"
                hits.append({
                    "rule_id":    "binint:new_suid",
                    "severity":   "critical",
                    "title":      f"New {bit} binary outside whitelist: {path}",
                    "description": (
                        f"'{path}' has the {bit} bit set and was not present in the "
                        f"baseline for this agent. New SUID/SGID binaries in system paths "
                        f"not in the approved whitelist are a privilege escalation vector — "
                        f"they allow any user to execute the binary as root (T1548.001)."
                    ),
                    "evidence": {
                        "path":        path,
                        "is_suid":     is_suid,
                        "is_sgid":     is_sgid,
                        "sha256":      binary["sha256"],
                        "owner":       binary["owner"],
                        "permissions": binary["permissions_octal"],
                        "size_bytes":  binary["size_bytes"],
                    },
                    "raw_telemetry": [binary["raw"]],
                    "mitre_tactic":     "Privilege Escalation",
                    "mitre_technique":  "T1548.001",
                    "compliance_controls": {
                        "NIST": ["PR.DS-6", "DE.CM-7"],  "CIS": ["10.2"],
                        "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
                    },
                    "recommended_action": (
                        f"1. Verify purpose of '{path}': `ls -la {path}`. "
                        f"2. Check when created/modified: `stat {path}`. "
                        f"3. Identify responsible package: `dpkg -S {path}` / `rpm -qf {path}`. "
                        f"4. If not from a known package: `chmod u-s {path}`. "
                        f"5. Add to config/suid_whitelist.json only after confirming legitimacy."
                    ),
                    "false_positive_notes": (
                        "Package manager installs may add SUID binaries (e.g., pkexec, sudo). "
                        "Add known-safe paths to config/suid_whitelist.json or the "
                        "APPROVED_SUID_BINARIES constant."
                    ),
                    "item_key":   f"binint:suid:{_path_key(path)}",
                    "category":   "binary",
                    "source":     "rule:binary_integrity",
                    "score":      SEVERITY_SCORES["critical"],
                    "tags":       ["binary_integrity", "suid", "privilege_escalation", "T1548.001"],
                })
            continue

        # Existing baseline — check if SUID bit was ADDED since last scan
        was_suid = baseline.get("is_suid", False)
        was_sgid = baseline.get("is_sgid", False)
        new_suid = is_suid and not was_suid
        new_sgid = is_sgid and not was_sgid

        if (new_suid or new_sgid) and not _is_whitelisted_suid(path):
            bit = "SUID" if new_suid else "SGID"
            hits.append({
                "rule_id":    "binint:suid_bit_added",
                "severity":   "critical",
                "title":      f"{bit} bit added to existing binary: {path}",
                "description": (
                    f"The {bit} bit was added to '{path}' since the baseline was established. "
                    f"An attacker with temporary write access to a system path may add SUID "
                    f"as a privilege escalation backdoor. "
                    f"The binary now executes as root for any user."
                ),
                "evidence": {
                    "path":        path,
                    "is_suid":     is_suid,
                    "is_sgid":     is_sgid,
                    "was_suid":    was_suid,
                    "was_sgid":    was_sgid,
                    "sha256":      binary["sha256"],
                    "owner":       binary["owner"],
                    "permissions": binary["permissions_octal"],
                },
                "raw_telemetry": [binary["raw"]],
                "mitre_tactic":     "Privilege Escalation",
                "mitre_technique":  "T1548.001",
                "compliance_controls": {
                    "NIST": ["PR.DS-6", "DE.CM-7"],  "CIS": ["10.2"],
                    "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
                },
                "recommended_action": (
                    f"Remove the {bit} bit: `chmod u-s {path}` (SUID) / `chmod g-s {path}` (SGID). "
                    f"Audit who changed permissions: `ausearch -f {path}` (auditd). "
                    f"Check if binary content also changed (compare hash against package manager)."
                ),
                "false_positive_notes": (
                    "Package manager updates may legitimately add SUID bits. "
                    "Run `dpkg -V` / `rpm -V` to verify the change came from an authorized update."
                ),
                "item_key":   f"binint:suid_added:{_path_key(path)}",
                "category":   "binary",
                "source":     "rule:binary_integrity",
                "score":      SEVERITY_SCORES["critical"],
                "tags":       ["binary_integrity", "suid_added", "privilege_escalation", "T1548.001"],
            })

        # Always update SUID state in baseline
        baseline.update({"is_suid": is_suid, "is_sgid": is_sgid, "last_seen": now})
        await _save_baseline(agent_id, key, baseline, db)

    return hits


def detect_unsigned_system_binary(
    agent_id:  str,
    binaries:  list[dict],
) -> list[dict]:
    """
    HIGH: A binary in a system path executed with invalid or absent code signature.

    Only fires when signature_valid is explicitly False (not None/unknown), to
    avoid false positives from agents that do not report signatures.
    """
    hits = []
    for binary in binaries:
        path = binary["path"]
        if not _is_system_path(path):
            continue
        # signature_valid=False means the agent checked and the check failed.
        # None means the agent did not check — do not alert on None.
        if binary.get("signature_valid") is not False:
            continue

        hits.append({
            "rule_id":    "binint:unsigned_system_binary",
            "severity":   "high",
            "title":      f"Unsigned/invalid signature in system path: {path}",
            "description": (
                f"Binary '{path}' is in a monitored system path but has an "
                f"invalid or absent code signature. "
                f"Attackers replace system binaries with unsigned versions to avoid "
                f"signature-based detection (T1036.005). "
                f"On macOS: SIP normally prevents this — the presence of an unsigned "
                f"system binary may indicate SIP was disabled."
            ),
            "evidence": {
                "path":            path,
                "sha256":          binary.get("sha256", ""),
                "signature_valid": binary.get("signature_valid"),
                "is_signed":       binary.get("is_signed"),
                "owner":           binary.get("owner", ""),
                "permissions":     binary.get("permissions_octal", ""),
            },
            "raw_telemetry": [binary["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1036.005",
            "compliance_controls": {
                "NIST": ["PR.DS-6", "DE.CM-7"],  "CIS": ["10.2"],
                "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. macOS: `codesign --verify --deep --strict {path}` — "
                f"check the specific error code. "
                f"2. Linux: `rpm -V $(rpm -qf {path})` or `dpkg -V <pkg>`. "
                f"3. Windows: `Get-AuthenticodeSignature '{path}'`. "
                f"4. Compare SHA256 against vendor distribution. "
                f"5. If tampered: restore from package manager or OS media. "
                f"6. macOS: verify SIP status with `csrutil status`."
            ),
            "false_positive_notes": (
                "Self-compiled or locally modified binaries (e.g., custom builds of "
                "nginx, OpenSSH in development environments) are unsigned. "
                "Third-party packages on macOS that are not notarized may also fail. "
                "Suppress by ensuring the binary's path is not under monitored system paths."
            ),
            "item_key":   f"binint:unsigned:{_path_key(path)}",
            "category":   "binary",
            "source":     "rule:binary_integrity",
            "score":      SEVERITY_SCORES["high"],
            "tags":       ["binary_integrity", "unsigned", "T1036.005"],
        })

    return hits


def detect_lolbin_abuse(
    agent_id:  str,
    processes: list[dict],
) -> list[dict]:
    """
    HIGH: A LOLBin is spawned by a suspicious parent (Office, browser, email).

    The parent-child chain is included in evidence.  Spawns from terminal
    emulators and CI/CD frameworks are suppressed as benign.
    """
    hits = []

    for proc in processes:
        name        = _binary_name(proc.get("name", "") or proc.get("exe", ""))
        parent_name = proc.get("parent_name", "").lower()
        exe         = proc.get("exe", "")
        cmdline     = proc.get("cmdline", "")

        lolbin_info = LOLBINS.get(name)
        if not lolbin_info:
            continue

        # Suppress spawns from benign parents (terminal, IDE, CI/CD)
        if parent_name and any(b in parent_name for b in BENIGN_LOLBin_PARENTS):
            continue

        # Only alert if parent is in the suspicious list, or is absent/unknown
        parent_suspicious = (
            not parent_name or
            any(s in parent_name for s in SUSPICIOUS_LOLBin_PARENTS)
        )
        if not parent_suspicious:
            continue

        severity = "high"
        # CRITICAL if Office/email spawned shell — very high TP rate
        if any(s in parent_name for s in (
            "winword", "excel", "powerpnt", "outlook", "word", "teams", "slack"
        )):
            severity = "critical"

        hits.append({
            "rule_id":    "binint:lolbin_abuse",
            "severity":   severity,
            "title":      f"LOLBin abuse: {name} spawned by {parent_name or 'unknown'}",
            "description": (
                f"{lolbin_info['desc']}. "
                f"'{name}' (PID {proc.get('pid', '?')}) was spawned by "
                f"'{parent_name or 'unknown'}' (PPID {proc.get('ppid', '?')}). "
                f"This parent-child combination is a well-known indicator of "
                f"macro malware, phishing payload execution, or browser exploit."
            ),
            "evidence": {
                "binary":       name,
                "exe_path":     exe,
                "cmdline":      cmdline[:300],
                "pid":          proc.get("pid", ""),
                "parent_name":  parent_name,
                "ppid":         proc.get("ppid", ""),
            },
            "raw_telemetry": [proc["raw"]],
            "mitre_tactic":     "Execution",
            "mitre_technique":  lolbin_info["mitre"],
            "compliance_controls": {
                "NIST": ["DE.CM-7", "PR.DS-6"],  "CIS": ["10.2"],
                "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Investigate what '{parent_name}' document/URL triggered this spawn. "
                f"2. Kill PID {proc.get('pid', '?')} and quarantine any downloaded files. "
                f"3. Check for follow-on network connections from PID {proc.get('pid', '?')}. "
                f"4. Collect memory artifacts: `sudo osqueryi 'select * from process_open_files "
                f"where pid={proc.get('pid', 0)}'`. "
                f"5. Isolate the endpoint if C2 traffic is detected."
            ),
            "false_positive_notes": (
                "Authorized automation (Ansible, scripts invoking curl via Teams webhooks) "
                "can produce similar parent-child chains. Validate with the user and add "
                "the specific parent process to BENIGN_LOLBin_PARENTS if genuinely safe."
            ),
            "item_key":   f"binint:lolbin:{name}:{proc.get('pid', '')}",
            "category":   "process",
            "source":     "rule:binary_integrity",
            "score":      SEVERITY_SCORES[severity],
            "tags":       ["binary_integrity", "lolbin", name, lolbin_info["mitre"]],
        })

    return hits


async def detect_permission_change(
    agent_id: str,
    binaries: list[dict],
    db:       Any,
) -> list[dict]:
    """
    MEDIUM: File permissions changed on a system binary outside a patch window.

    Compares current permissions_octal against the baseline. Suppressed during
    active patch windows.
    """
    hits = []
    now  = time.time()
    in_patch = _in_patch_window(agent_id)

    for binary in binaries:
        path  = binary["path"]
        perms = binary["permissions_octal"]
        if not perms or not _is_system_path(path):
            continue

        key      = f"perms:{_path_key(path)}"
        baseline = await _load_baseline(agent_id, key, db)

        if not baseline:
            await _save_baseline(agent_id, key, {
                "path": path, "permissions_octal": perms, "first_seen": now,
            }, db)
            continue

        base_perms = baseline.get("permissions_octal", "")
        if not base_perms or perms == base_perms:
            continue

        if in_patch:
            baseline["permissions_octal"] = perms
            baseline["last_seen"] = now
            await _save_baseline(agent_id, key, baseline, db)
            continue

        hits.append({
            "rule_id":    "binint:permission_changed",
            "severity":   "medium",
            "title":      f"Permission change on system binary: {path} ({base_perms} → {perms})",
            "description": (
                f"Permissions of '{path}' changed from {base_perms} to {perms} "
                f"outside a known patch window. "
                f"Unexpected permission changes on system binaries may indicate "
                f"an attacker making a binary world-writable for replacement, or "
                f"adding SUID/SGID as a persistence/escalation mechanism."
            ),
            "evidence": {
                "path":                  path,
                "current_permissions":   perms,
                "baseline_permissions":  base_perms,
                "owner":                 binary.get("owner", ""),
                "sha256":                binary.get("sha256", ""),
                "baseline_set":          baseline.get("first_seen", ""),
            },
            "raw_telemetry": [binary["raw"]],
            "mitre_tactic":     "Defense Evasion",
            "mitre_technique":  "T1222",
            "compliance_controls": {
                "NIST": ["PR.DS-6", "DE.CM-7"],  "CIS": ["10.2"],
                "ISO":  ["A.12.2.1"],              "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Check who changed permissions: `ausearch -f {path} -ts recent` "
                f"(auditd) or `log show --predicate 'eventMessage contains \"{path}\"'` "
                f"(macOS). "
                f"2. Verify the binary hash against its package: `rpm -V`/`dpkg -V`. "
                f"3. If world-writable was set (`chmod o+w`): restore correct permissions "
                f"immediately and investigate who had write access."
            ),
            "false_positive_notes": (
                "Package manager updates legitimately change permissions. "
                f"Changes within {PATCH_WINDOW_SECS//3600}h of an OS update event are "
                "suppressed automatically."
            ),
            "item_key":   f"binint:perms:{_path_key(path)}",
            "category":   "binary",
            "source":     "rule:binary_integrity",
            "score":      SEVERITY_SCORES["medium"],
            "tags":       ["binary_integrity", "permission_change", "T1222"],
        })

    return hits


# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER — raw hit → full structured alert
# ─────────────────────────────────────────────────────────────────────────────

def build_alert(hit: dict, agent_id: str, hostname: str = "") -> dict:
    sev = hit.get("severity", "high")
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
        # Engine / IntelDB fields
        "category":    hit.get("category", "binary"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:binary_integrity"),
        "tags":        hit.get("tags", ["binary_integrity"]),
        "cve_ids":     hit.get("cve_ids", []),
        "cvss_score":  hit.get("cvss_score"),
        "cvss_vector": hit.get("cvss_vector", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT — called per section by AttackLensEngine
# ─────────────────────────────────────────────────────────────────────────────

async def analyze(
    agent_id: str,
    section:  str,
    data:     Any,
    db:       Any,
    hostname: str = "",
) -> list[dict]:
    """
    Main entry point.  Called by AttackLensEngine._dispatch() for 'binaries'
    section.  Returns list of structured alert dicts ready for
    IntelDB.upsert_finding().
    """
    if section != "binaries":
        return []

    ingested  = ingest_binaries(data)
    binaries  = ingested["binaries"]
    processes = ingested["processes"]
    os_events = ingested["os_update_events"]

    if not binaries and not processes:
        return []

    # Register OS update events — opens patch suppression window
    now = time.time()
    for ev in os_events:
        ts = float(ev.get("timestamp") or now)
        if abs(now - ts) < PATCH_WINDOW_SECS:
            _register_patch_window(agent_id, ts)
            log.debug("Patch window registered for agent=%s until %s",
                      agent_id, _patch_window.get(agent_id))

    raw_hits: list[dict] = []

    try:
        raw_hits.extend(await detect_hash_change(agent_id, binaries, db))
    except Exception as exc:
        log.debug("detect_hash_change error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(await detect_new_suid(agent_id, binaries, db))
    except Exception as exc:
        log.debug("detect_new_suid error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(detect_unsigned_system_binary(agent_id, binaries))
    except Exception as exc:
        log.debug("detect_unsigned_system_binary error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(detect_lolbin_abuse(agent_id, processes))
    except Exception as exc:
        log.debug("detect_lolbin_abuse error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(await detect_permission_change(agent_id, binaries, db))
    except Exception as exc:
        log.debug("detect_permission_change error agent=%s: %s", agent_id, exc)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Suppressed dedup: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))

    if alerts:
        log.info("BinaryIntegrity: agent=%s binaries=%d processes=%d alerts=%d",
                 agent_id, len(binaries), len(processes), len(alerts))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS — TP + FP per detection condition
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    print("=== binary_integrity.py — Test Harness ===\n")

    class MockDB:
        def __init__(self):
            self._state: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._state.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, fingerprint, ts):
            self._state[f"{agent_id}:{ns}:{key}"] = {"fingerprint": fingerprint, "ts": ts}

    def _bin(path, sha256="abc123", perms="0755", owner="root",
             is_suid=False, is_sgid=False, sig_valid=True, size=12345):
        return {
            "path":              path,
            "sha256":            sha256,
            "permissions_octal": perms,
            "owner":             owner,
            "group":             "root",
            "is_suid":           is_suid,
            "is_sgid":           is_sgid,
            "is_signed":         sig_valid,
            "signature_valid":   sig_valid,
            "size_bytes":        size,
            "modified_ts":       time.time(),
            "raw":               {"path": path, "sha256": sha256},
        }

    def _proc(name, parent_name="", exe="", cmdline="", pid=100, ppid=50):
        return {
            "name":        name,
            "exe":         exe or f"/usr/bin/{name}",
            "cmdline":     cmdline,
            "pid":         pid,
            "ppid":        ppid,
            "parent_name": parent_name.lower(),
            "raw":         {"name": name, "parent": parent_name},
        }

    async def run_tests():
        # ── Helpers ───────────────────────────────────────────────────────────
        assert _binary_name("/usr/bin/python3") == "python3"
        assert _binary_name(r"C:\Windows\System32\cmd.exe") == "cmd"
        assert _is_system_path("/usr/bin/bash") is True
        assert _is_system_path("/home/user/bash") is False
        assert _is_system_path(r"C:\Windows\System32\cmd.exe") is True
        assert _is_whitelisted_suid("/usr/bin/sudo") is True
        assert _is_whitelisted_suid("/usr/bin/curl") is False
        print("[PASS] Path/name helpers and SUID whitelist")

        # ── TP: Hash changed ──────────────────────────────────────────────────
        db_hash = MockDB()
        b1  = _bin("/usr/bin/bash", sha256="aaaaaa1111111111111111111111111111111111111111111111111111111111")
        b1b = _bin("/usr/bin/bash", sha256="bbbbbb2222222222222222222222222222222222222222222222222222222222")
        # First call: establish baseline
        h1 = await detect_hash_change("agent-hash", [b1], db_hash)
        assert h1 == []
        print("[PASS] Hash baseline set: no alert on first observation")
        # Second call: hash changed → CRITICAL
        h2 = await detect_hash_change("agent-hash", [b1b], db_hash)
        assert len(h2) == 1 and h2[0]["severity"] == "critical"
        assert "bbbbbb22" in h2[0]["evidence"]["current_sha256"]
        assert "aaaaaa11" in h2[0]["evidence"]["baseline_sha256"]
        print(f"[PASS] TP hash changed: {h2[0]['title']}")

        # ── FP: Hash changed within patch window ─────────────────────────────
        db_patch = MockDB()
        b_pre  = _bin("/usr/bin/curl", sha256="cccccc3333333333333333333333333333333333333333333333333333333333")
        b_post = _bin("/usr/bin/curl", sha256="dddddd4444444444444444444444444444444444444444444444444444444444")
        await detect_hash_change("agent-patch", [b_pre], db_patch)
        _register_patch_window("agent-patch")  # simulate OS update
        h_patch = await detect_hash_change("agent-patch", [b_post], db_patch)
        assert h_patch == []
        print("[PASS] FP hash change during patch window: suppressed")

        # ── FP: Hash unchanged ────────────────────────────────────────────────
        db_same = MockDB()
        b_same = _bin("/usr/bin/ls", sha256="eeeeee5555555555555555555555555555555555555555555555555555555555")
        await detect_hash_change("agent-same", [b_same], db_same)
        h_same = await detect_hash_change("agent-same", [b_same], db_same)
        assert h_same == []
        print("[PASS] FP hash unchanged: suppressed")

        # ── TP: New SUID binary outside whitelist ─────────────────────────────
        db_suid = MockDB()
        suid_b  = _bin("/usr/bin/hacktool", is_suid=True, sha256="ff" * 32)
        suid_h  = await detect_new_suid("agent-suid", [suid_b], db_suid)
        assert len(suid_h) == 1 and suid_h[0]["severity"] == "critical"
        assert "T1548.001" in suid_h[0]["mitre_technique"]
        print(f"[PASS] TP new SUID binary: {suid_h[0]['title']}")

        # ── TP: SUID bit ADDED to existing binary ─────────────────────────────
        db_suid2  = MockDB()
        normal_b  = _bin("/usr/bin/cp", is_suid=False, sha256="11" * 32)
        suid_now  = _bin("/usr/bin/cp", is_suid=True,  sha256="11" * 32)
        # First call: baseline with no SUID
        await detect_new_suid("agent-suid2", [normal_b], db_suid2)
        # Second call: SUID added → CRITICAL
        suid_h2 = await detect_new_suid("agent-suid2", [suid_now], db_suid2)
        assert len(suid_h2) == 1 and "added" in suid_h2[0]["rule_id"]
        print(f"[PASS] TP SUID bit added: {suid_h2[0]['title']}")

        # ── FP: SUID on whitelisted binary ────────────────────────────────────
        db_suid3 = MockDB()
        sudo_b   = _bin("/usr/bin/sudo", is_suid=True, sha256="aa" * 32)
        assert await detect_new_suid("agent-suid3", [sudo_b], db_suid3) == []
        print("[PASS] FP SUID on whitelisted binary (sudo): suppressed")

        # ── FP: SUID on non-system path ───────────────────────────────────────
        db_suid4 = MockDB()
        home_b   = _bin("/home/user/mytool", is_suid=True, sha256="bb" * 32)
        assert await detect_new_suid("agent-suid4", [home_b], db_suid4) == []
        print("[PASS] FP SUID on non-system path: suppressed")

        # ── TP: Unsigned system binary ────────────────────────────────────────
        unsigned_b = _bin("/usr/bin/netcat", sig_valid=False)
        unsigned_b["signature_valid"] = False
        unsigned_h = detect_unsigned_system_binary("agent-unsigned", [unsigned_b])
        assert len(unsigned_h) == 1 and unsigned_h[0]["severity"] == "high"
        assert "T1036.005" in unsigned_h[0]["mitre_technique"]
        print(f"[PASS] TP unsigned system binary: {unsigned_h[0]['title']}")

        # ── FP: signature_valid=None (agent didn't check) ─────────────────────
        unk_sig = _bin("/usr/bin/grep")
        unk_sig["signature_valid"] = None
        assert detect_unsigned_system_binary("agent-unk", [unk_sig]) == []
        print("[PASS] FP signature_valid=None (unknown): suppressed")

        # ── FP: Unsigned binary NOT in system path ────────────────────────────
        home_unsigned = _bin("/home/dev/myapp")
        home_unsigned["signature_valid"] = False
        assert detect_unsigned_system_binary("agent-home-un", [home_unsigned]) == []
        print("[PASS] FP unsigned binary outside system path: suppressed")

        # ── TP: LOLBin spawned by Office app ─────────────────────────────────
        lolbin_proc = _proc("bash", parent_name="Microsoft Word", pid=555, ppid=444)
        lolbin_hits = detect_lolbin_abuse("agent-lol", [lolbin_proc])
        assert len(lolbin_hits) == 1 and lolbin_hits[0]["severity"] == "critical"
        assert lolbin_hits[0]["evidence"]["binary"] == "bash"
        print(f"[PASS] TP LOLBin (Office → bash): {lolbin_hits[0]['title']}")

        # ── TP: LOLBin curl spawned by Teams ──────────────────────────────────
        curl_proc = _proc("curl", parent_name="teams", pid=666, ppid=333)
        curl_hits = detect_lolbin_abuse("agent-lol2", [curl_proc])
        assert len(curl_hits) == 1 and "T1105" in curl_hits[0]["mitre_technique"]
        print(f"[PASS] TP LOLBin (Teams → curl): {curl_hits[0]['title']}")

        # ── FP: LOLBin spawned by terminal (benign) ───────────────────────────
        term_proc = _proc("curl", parent_name="terminal")
        assert detect_lolbin_abuse("agent-term", [term_proc]) == []
        print("[PASS] FP LOLBin spawned from terminal: suppressed")

        # ── FP: LOLBin spawned by benign parent (CI/CD) ───────────────────────
        ci_proc = _proc("python3", parent_name="jenkins")
        assert detect_lolbin_abuse("agent-ci", [ci_proc]) == []
        print("[PASS] FP LOLBin spawned by Jenkins: suppressed")

        # ── FP: Normal binary name (not a LOLBin) ─────────────────────────────
        normal_proc = _proc("nginx", parent_name="Microsoft Word")
        assert detect_lolbin_abuse("agent-normal", [normal_proc]) == []
        print("[PASS] FP non-LOLBin spawned by Office: suppressed (not a LOLBin)")

        # ── TP: Permission change outside patch window ────────────────────────
        db_perms  = MockDB()
        p1 = _bin("/usr/bin/find", perms="0755")
        p2 = _bin("/usr/bin/find", perms="0777")
        await detect_permission_change("agent-perms", [p1], db_perms)
        perms_hits = await detect_permission_change("agent-perms", [p2], db_perms)
        assert len(perms_hits) == 1 and perms_hits[0]["severity"] == "medium"
        assert perms_hits[0]["evidence"]["current_permissions"] == "0777"
        print(f"[PASS] TP permission change: {perms_hits[0]['title']}")

        # ── FP: Permission change during patch window ─────────────────────────
        db_perms2 = MockDB()
        pp1 = _bin("/usr/bin/id", perms="0755")
        pp2 = _bin("/usr/bin/id", perms="0750")
        await detect_permission_change("agent-perms2", [pp1], db_perms2)
        _register_patch_window("agent-perms2")
        fp_perms = await detect_permission_change("agent-perms2", [pp2], db_perms2)
        assert fp_perms == []
        print("[PASS] FP permission change during patch window: suppressed")

        # ── Alert builder: all mandatory fields ───────────────────────────────
        alert = build_alert(lolbin_hits[0], "agent-001", "workstation-05")
        required = {"alert_id", "severity", "title", "description", "affected_asset",
                    "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                    "compliance_controls", "recommended_action", "false_positive_notes",
                    "timestamp_utc"}
        missing = required - set(alert.keys())
        assert not missing, f"Missing mandatory fields: {missing}"
        assert alert["affected_asset"] == "workstation-05"
        print("[PASS] Alert builder: all mandatory fields present")

        # ── Dedup ─────────────────────────────────────────────────────────────
        _dedup_cache.clear()
        _rate_counter.clear()
        assert _should_suppress("agent-dd", "binint:test", "k1") is False
        assert _should_suppress("agent-dd", "binint:test", "k1") is True    # deduped
        assert _should_suppress("agent-dd", "binint:test", "k2") is False   # different key
        assert _should_suppress("agent-dd2", "binint:test", "k1") is False  # different agent
        print("[PASS] Dedup: first=pass, second=suppress, diff_key=pass, diff_agent=pass")

        print("\n=== All tests passed ===")

    asyncio.run(run_tests())
