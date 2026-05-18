"""
manager/api/posture.py — Security Posture endpoints.

GET /api/v1/posture/agents          summary scores for every enrolled agent
GET /api/v1/posture/{agent_id}      full CIS benchmark report for one agent

Architecture for large data:
  • Uses db.get_latest_section_per_agent() (O(1) batch query) for the
    all-agents summary so cost is always 3 queries, not 3 × N agents.
  • Per-agent detail fetches only the 3 relevant sections (security, sysctl,
    configs) — payloads are small (<50 KB each) so no streaming needed.
  • Check evaluation is pure Python, O(n_checks) ≈ O(1) per agent.
  • Results are computed on demand; a future optimisation would store the
    score in the asset_registry table on every new payload via the Jarvis
    worker, giving sub-millisecond reads for the summary view.

CIS Controls mapped to real agent data fields:
  SIP, Gatekeeper, FileVault, Firewall, XProtect, Secure Boot,
  Auto Update, Screensaver lock + timeout, SSH password auth,
  SSH root login, Remote Login (SSH), Screen Sharing, Remote Management,
  Suspicious shell configs, Lockdown Mode.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, TYPE_CHECKING

from fastapi import APIRouter, HTTPException

if TYPE_CHECKING:
    from ..db      import Database
    from ..indexer import IntelDB

log = logging.getLogger("manager.api.posture")

# ── CIS Check definitions ─────────────────────────────────────────────────────
# Each entry drives both evaluation and display.
# Fields: id, name, cis_control (int), severity, mitre, remediation
# The `check` callable receives (security_dict, sysctl_list, configs_list)
# and returns ("pass"|"fail"|"warn"|"unknown", actual_value_str)

_NA = "N/A — data not yet collected"


def _sip(sec, _s, _c):
    v = sec.get("sip")
    if v is None:           return "unknown", _NA
    return ("pass" if v == "enabled" else "fail"), str(v)


def _filevault(sec, _s, _c):
    v = sec.get("filevault")
    if v is None:           return "unknown", _NA
    return ("pass" if v == "on" else "fail"), str(v)


def _gatekeeper(sec, _s, _c):
    v = sec.get("gatekeeper")
    if v is None:           return "unknown", _NA
    return ("pass" if v == "enabled" else "fail"), str(v)


def _firewall(sec, _s, _c):
    v = sec.get("firewall")
    if v is None:           return "unknown", _NA
    return ("pass" if v == "on" else "fail"), str(v)


def _secure_boot(sec, _s, _c):
    v = sec.get("secure_boot")
    if v is None:           return "unknown", _NA
    if "full" in str(v).lower():  return "pass", v
    if v in ("off", "0x00"):      return "fail", v
    return "warn", v


def _auto_update(sec, _s, _c):
    v = sec.get("auto_update")
    if v is None:           return "unknown", _NA
    return ("pass" if v is True else "fail"), str(v)


def _screensaver_lock(sec, _s, _c):
    v = sec.get("screensaver_lock")
    if v is None:           return "unknown", _NA
    return ("pass" if v is True else "fail"), str(v)


def _screensaver_timeout(sec, _s, _c):
    v = sec.get("screensaver_idle_sec")
    if v is None:           return "unknown", _NA
    try:
        secs = int(v)
        if secs == 0:       return "fail", "Never"
        if secs <= 300:     return "pass", f"{secs}s"
        return "warn", f"{secs}s (>5 min)"
    except (TypeError, ValueError):
        return "unknown", str(v)


def _ssh_disabled_or_no_pw(sec, _s, _c):
    ssh_on = sec.get("remote_login")
    pw     = sec.get("ssh_password_auth")
    if ssh_on is False:                    return "pass", "SSH off"
    if ssh_on is True and pw == "no":      return "pass", "SSH on, password auth off"
    if ssh_on is True and pw == "yes":     return "fail", "SSH on + password auth enabled"
    if ssh_on is True:                     return "warn", "SSH on, password auth unknown"
    return "unknown", _NA


def _ssh_root_login(sec, _s, _c):
    v = sec.get("ssh_permit_root_login")
    if v is None:           return "unknown", _NA
    if v in ("no", "prohibit-password", "forced-commands-only"):
        return "pass", v
    return "fail", v


def _screen_sharing(sec, _s, _c):
    v = sec.get("screen_sharing")
    if v is None:           return "unknown", _NA
    return ("fail" if v is True else "pass"), ("enabled" if v else "disabled")


def _remote_management(sec, _s, _c):
    v = sec.get("remote_management")
    if v is None:           return "unknown", _NA
    return ("fail" if v is True else "pass"), ("enabled" if v else "disabled")


def _xprotect(sec, _s, _c):
    v = sec.get("xprotect_version")
    if v is None:           return "unknown", _NA
    try:
        if int(str(v).replace(".", "")) > 0:
            return "pass", f"v{v}"
    except (ValueError, TypeError):
        pass
    return "warn", str(v)


def _lockdown_mode(sec, _s, _c):
    v = sec.get("lockdown_mode")
    if v is None:           return "unknown", _NA
    return ("pass" if v is True else "warn"), ("on" if v else "off")


def _suspicious_configs(_sec, _s, configs):
    if not configs:         return "unknown", _NA
    hits = [c.get("path", "") for c in configs if c.get("suspicious")]
    if hits:
        return "fail", f"{len(hits)} suspicious file(s): {', '.join(hits[:3])}"
    return "pass", f"{len(configs)} config(s) clean"


def _dev_tools(sec, _s, _c):
    v = sec.get("dev_tools")
    if v is None:           return "unknown", _NA
    if "enabled" in str(v).lower():
        return "warn", v
    return "pass", v


# Master check registry
_CHECKS = [
    # id, name, cis_control, severity, mitre, remediation, fn
    ("SIP",  "System Integrity Protection",       4, "critical",
     "T1553.001",
     "Run: `csrutil enable` from macOS Recovery (Cmd+R at boot). SIP prevents rootkit persistence.",
     _sip),

    ("FV2",  "FileVault Full-Disk Encryption",    3, "critical",
     "T1486",
     "System Settings → Privacy & Security → FileVault → Turn On. Protects data if device is stolen.",
     _filevault),

    ("GK",   "Gatekeeper Code Signing",           4, "high",
     "T1553.001",
     "Run: `sudo spctl --global-enable`. Prevents unsigned/unnotarised binaries from executing.",
     _gatekeeper),

    ("FW",   "Application Firewall",              12, "high",
     "T1562.004",
     "System Settings → Network → Firewall → Turn On. Blocks unsolicited inbound connections.",
     _firewall),

    ("SB",   "Secure Boot — Full Security",       4, "high",
     "T1542.001",
     "Set in macOS Recovery → Startup Security Utility → Full Security. Prevents unsigned kernels.",
     _secure_boot),

    ("AU",   "Automatic Security Updates",        7, "high",
     "T1195",
     "System Settings → General → Software Update → enable Automatic Updates (all options).",
     _auto_update),

    ("SCR",  "Screensaver Require Password",      4, "high",
     "T1078",
     "System Settings → Lock Screen → Require password immediately. Prevents physical access.",
     _screensaver_lock),

    ("STO",  "Screensaver Idle Timeout ≤5 min",  4, "medium",
     "T1078",
     "System Settings → Lock Screen → Start Screen Saver after: set to 5 minutes or less.",
     _screensaver_timeout),

    ("SSH",  "SSH — Password Auth Disabled",      5, "high",
     "T1021.004",
     "Disable SSH entirely (System Settings → Sharing) or set `PasswordAuthentication no` in /etc/ssh/sshd_config.",
     _ssh_disabled_or_no_pw),

    ("SRL",  "SSH Root Login Prohibited",         5, "medium",
     "T1021.004",
     "Add `PermitRootLogin no` to /etc/ssh/sshd_config then restart SSH.",
     _ssh_root_login),

    ("SCN",  "Screen Sharing (VNC) Disabled",     4, "medium",
     "T1021.005",
     "System Settings → Sharing → Screen Sharing → Off.",
     _screen_sharing),

    ("ARD",  "Apple Remote Desktop Disabled",     4, "medium",
     "T1021.002",
     "System Settings → Sharing → Remote Management → Off.",
     _remote_management),

    ("XP",   "XProtect Malware Definitions",      10, "medium",
     "T1204",
     "XProtect updates automatically. Ensure `AutomaticCheckEnabled=1` in com.apple.SoftwareUpdate.",
     _xprotect),

    ("CFG",  "No Suspicious Shell Configs",       4, "high",
     "T1546.004",
     "Review flagged config files for download-cradle patterns (curl|sh, eval base64, etc).",
     _suspicious_configs),

    ("DT",   "Developer Tools Security",          4, "low",
     "T1055",
     "Restrict Developer Tools to specific users: `sudo DevToolsSecurity -disable`.",
     _dev_tools),

    ("LM",   "Lockdown Mode (High-Risk Users)",   4, "low",
     "T1203",
     "Enable for high-risk users: System Settings → Privacy & Security → Lockdown Mode. Limits attack surface significantly.",
     _lockdown_mode),
]

# CIS Control groups — maps control number to label
_CIS_GROUPS = {
    3:  "Data Protection",
    4:  "Secure Configuration",
    5:  "Account Management",
    7:  "Vulnerability Management",
    10: "Malware Defenses",
    12: "Network Infrastructure",
}

# Severity weights for score calculation
_SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


def _run_checks(security: dict, sysctl: list, configs: list) -> list[dict]:
    results = []
    for check_id, name, cis, sev, mitre, remed, fn in _CHECKS:
        try:
            status, actual = fn(security, sysctl, configs)
        except Exception:
            status, actual = "unknown", "error"
        results.append({
            "id":          check_id,
            "name":        name,
            "cis_control": cis,
            "cis_label":   _CIS_GROUPS.get(cis, f"CIS-{cis}"),
            "severity":    sev,
            "status":      status,
            "actual":      actual,
            "mitre":       mitre,
            "remediation": remed,
        })
    return results


def _compute_score(checks: list[dict]) -> dict:
    """
    Weighted posture score 0–100.
    Only PASS/FAIL/WARN are counted (unknown checks are excluded from denominator).
    WARN counts as half a FAIL.
    """
    total_weight = 0
    pass_weight  = 0
    for c in checks:
        if c["status"] == "unknown":
            continue
        w = _SEV_WEIGHT.get(c["severity"], 1)
        total_weight += w
        if c["status"] == "pass":
            pass_weight += w
        elif c["status"] == "warn":
            pass_weight += w * 0.5

    score = round((pass_weight / total_weight) * 100) if total_weight else 0
    grade = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 60 else
        "D" if score >= 40 else
        "F"
    )
    return {
        "score":        score,
        "grade":        grade,
        "pass_weight":  round(pass_weight, 1),
        "total_weight": total_weight,
    }


def _group_summary(checks: list[dict]) -> list[dict]:
    groups: dict[int, dict] = {}
    for c in checks:
        cis = c["cis_control"]
        if cis not in groups:
            groups[cis] = {
                "cis_control": cis,
                "label":       _CIS_GROUPS.get(cis, f"CIS-{cis}"),
                "pass": 0, "fail": 0, "warn": 0, "unknown": 0, "total": 0,
            }
        groups[cis][c["status"]] += 1
        groups[cis]["total"] += 1

    result = []
    for g in sorted(groups.values(), key=lambda x: x["cis_control"]):
        known = g["pass"] + g["fail"] + g["warn"]
        g["pass_rate"] = round((g["pass"] / known) * 100) if known else 0
        result.append(g)
    return result


def make_posture_router(db: "Database", intel_db: "IntelDB") -> APIRouter:
    router = APIRouter()

    # ── All-agents summary (3 batch queries, not 3×N) ─────────────────────────
    @router.get("/agents")
    async def posture_summary():
        """
        Posture score for every enrolled agent.
        Uses batch queries: 3 SQL calls total regardless of agent count.
        """
        now = int(time.time())
        agents, sec_map, cfg_map = await asyncio.gather(
            db.get_all_agents(),
            db.get_latest_section_per_agent("security"),
            db.get_latest_section_per_agent("configs"),
        )
        sysctl_map = await db.get_latest_section_per_agent("sysctl")

        result = []
        for agent in agents:
            aid       = agent["agent_id"]
            security  = sec_map.get(aid, {})
            sysctl    = sysctl_map.get(aid, [])
            configs   = cfg_map.get(aid, [])

            if not isinstance(sysctl, list):   sysctl = []
            if not isinstance(configs, list):  configs = []

            checks = _run_checks(security, sysctl, configs)
            score  = _compute_score(checks)

            last_seen = int(agent.get("last_seen") or 0)
            elapsed   = now - last_seen if last_seen else 9999

            result.append({
                "agent_id": aid,
                "hostname": agent.get("name") or aid,
                "status":   "online" if elapsed < 90 else "stale" if elapsed < 300 else "offline",
                "last_seen": last_seen,
                "score":    score["score"],
                "grade":    score["grade"],
                "fail":     sum(1 for c in checks if c["status"] == "fail"),
                "warn":     sum(1 for c in checks if c["status"] == "warn"),
                "pass":     sum(1 for c in checks if c["status"] == "pass"),
                "total":    len(checks),
                "has_data": bool(security),
            })

        return sorted(result, key=lambda x: x["score"])  # worst first

    # ── Single-agent full posture report ──────────────────────────────────────
    @router.get("/{agent_id}")
    async def posture_detail(agent_id: str):
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")

        sec_map, sysctl_map, cfg_map = await asyncio.gather(
            db.get_latest_section_per_agent("security"),
            db.get_latest_section_per_agent("sysctl"),
            db.get_latest_section_per_agent("configs"),
        )

        security = sec_map.get(agent_id, {})
        sysctl   = sysctl_map.get(agent_id, [])
        configs  = cfg_map.get(agent_id, [])

        if not isinstance(sysctl, list):  sysctl = []
        if not isinstance(configs, list): configs = []

        checks  = _run_checks(security, sysctl, configs)
        score   = _compute_score(checks)
        groups  = _group_summary(checks)

        # Suspicious config files for display
        suspicious = [c for c in configs if c.get("suspicious")]

        # Notable sysctl security values
        sysctl_security = [
            r for r in sysctl
            if isinstance(r, dict) and any(
                r.get("key", "").startswith(p)
                for p in ("kern.codesign", "kern.secure_kernel", "security.", "kern.bootargs")
            )
        ][:10]

        return {
            "agent_id":       agent_id,
            "hostname":       agent.get("name") or agent_id,
            "last_seen":      int(agent.get("last_seen") or 0),
            "score":          score,
            "checks":         checks,
            "groups":         groups,
            "has_data":       bool(security),
            "suspicious_configs": suspicious,
            "sysctl_security":    sysctl_security,
            "raw_security":       security,
        }

    return router
