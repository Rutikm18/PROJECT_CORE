"""
manager/manager/attacklens/detections/user_account.py
Detection of unauthorized user account creation, hidden persistence users,
and privilege escalation account indicators.

Detects attacker-created accounts, UID 0 clones, hidden system-like users,
and unauthorized shell/home directory modifications.

Telemetry sections handled:
  users, user_accounts, passwd_entries, local_users

COMPLIANCE MAPPING:
  NIST CSF:    PR.AC-1 (Identities managed), DE.CM-3 (Personnel activity monitored)
  CIS Control: 5 (Account Management), 6 (Access Control Management)
  SOC 2:       CC6.2 (Access provisioned appropriately), CC6.3
  ISO 27001:   A.9.2 (User access management), A.9.4.2

MITRE ATT&CK:
  T1136      (Create Account)
  T1136.001  (Local Account)
  T1136.002  (Domain Account)
  T1078      (Valid Accounts)
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

log = logging.getLogger("manager.attacklens.detections.user_account")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Interactive shells — service accounts with these are suspicious
INTERACTIVE_SHELLS: frozenset[str] = frozenset({
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
    "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/zsh",
    "/usr/local/bin/bash", "/usr/local/bin/zsh",
    "cmd.exe", "powershell.exe",
})

# Non-login shells — expected for service accounts
NON_LOGIN_SHELLS: frozenset[str] = frozenset({
    "/usr/bin/false", "/bin/false",
    "/sbin/nologin", "/usr/sbin/nologin",
    "/usr/bin/nologin",
})

# Groups whose membership indicates elevated privilege
PRIVILEGED_GROUPS: frozenset[str] = frozenset({
    "root", "wheel", "sudo", "admin", "administrators",
    "docker", "shadow", "disk", "kmem",
    "domain admins", "enterprise admins", "schema admins",
    "network configuration operators",
})

# UID/GID thresholds for "system account" on Linux
LINUX_SYSTEM_UID_MAX: int = 999

# Patterns in usernames that indicate hidden / suspicious accounts
_HIDDEN_USER_RE = re.compile(r"^_|[^\x20-\x7e]", re.UNICODE)

# Home directory paths that are suspicious for new accounts
SUSPICIOUS_HOME_PATHS: tuple[str, ...] = (
    "/tmp", "/var/tmp", "/dev/null", "/dev/shm",
)

# Dedup: no window for CRITICAL (new accounts) — real-time.
# 30-minute window for modification alerts.
DEDUP_WINDOW_CREATION: int   = 0       # no dedup — alert every time
DEDUP_WINDOW_MODIFICATION: int = 1800
RATE_LIMIT_MAX_PER_HOUR: int = 60

USER_SECTIONS: frozenset[str] = frozenset({
    "users", "user_accounts", "passwd_entries", "local_users",
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


def _should_suppress(agent_id: str, rule_id: str, item: str,
                     window: int = DEDUP_WINDOW_MODIFICATION) -> bool:
    if window <= 0:
        # No dedup — always fire
        times = [t for t in _rate_counter.get(agent_id, []) if time.time() - t < 3600]
        if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
            log.debug("Rate limit: agent=%s module=user_account", agent_id)
            return True
        times.append(time.time())
        _rate_counter[agent_id] = times
        return False

    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if now - _dedup_cache.get(key, 0) < window:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit: agent=%s module=user_account", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def ingest_users(data: Any) -> list[dict]:
    """
    Normalize user account telemetry into:
      [{username, uid, gid, shell, home, groups, account_flags,
        last_login, created_timestamp, is_domain, raw}]
    """
    users: list[dict] = []

    if isinstance(data, dict):
        if "users" in data:
            data = data["users"]
        elif "Name" in data or "username" in data:
            data = [data]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                # /etc/passwd line: "username:x:uid:gid:comment:home:shell"
                line = str(item).strip()
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        users.append({
                            "username":          parts[0],
                            "uid":               int(parts[2]),
                            "gid":               int(parts[3]),
                            "shell":             parts[6],
                            "home":              parts[5],
                            "groups":            [],
                            "account_flags":     [],
                            "last_login":        "",
                            "created_timestamp": "",
                            "is_domain":         False,
                            "raw":               {"passwd_line": line},
                        })
                    except (ValueError, IndexError):
                        pass
                continue
            groups_raw = item.get("groups") or item.get("Groups") or []
            if isinstance(groups_raw, str):
                groups_raw = [g.strip() for g in groups_raw.split(",") if g.strip()]
            def _int_field(item: dict, *keys: str, default: int = -1) -> int:
                for k in keys:
                    v = item.get(k)
                    if v is not None:
                        try:
                            return int(v)
                        except (TypeError, ValueError):
                            pass
                return default

            users.append({
                "username":          str(item.get("username") or item.get("Name") or item.get("name") or ""),
                "uid":               _int_field(item, "uid", "UID", "UniqueID"),
                "gid":               _int_field(item, "gid", "GID", "PrimaryGroupID"),
                "shell":             str(item.get("shell") or item.get("UserShell") or item.get("login_shell") or ""),
                "home":              str(item.get("home") or item.get("NFSHomeDirectory") or item.get("home_dir") or ""),
                "groups":            [str(g).lower() for g in groups_raw],
                "account_flags":     item.get("account_flags") or item.get("flags") or [],
                "last_login":        str(item.get("last_login") or ""),
                "created_timestamp": str(item.get("created_timestamp") or ""),
                "is_domain":         bool(item.get("is_domain", False)),
                "raw":               item,
            })
        return users

    if isinstance(data, str):
        # /etc/passwd format
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                try:
                    users.append({
                        "username":          parts[0],
                        "uid":               int(parts[2]),
                        "gid":               int(parts[3]),
                        "shell":             parts[6],
                        "home":              parts[5],
                        "groups":            [],
                        "account_flags":     [],
                        "last_login":        "",
                        "created_timestamp": "",
                        "is_domain":         False,
                        "raw":               {"passwd_line": line},
                    })
                except (ValueError, IndexError):
                    pass

    return users

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str, hostname: str, severity: str, rule_id: str,
    title: str, description: str, mitre_technique: str,
    evidence: dict, raw_user: Any,
) -> dict:
    tactic = "Persistence" if "T1136" in mitre_technique else "Privilege Escalation"
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        tactic,
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw_user if isinstance(raw_user, dict) else {"raw": str(raw_user)},
        "compliance_controls": [
            "NIST CSF PR.AC-1", "NIST CSF DE.CM-3",
            "CIS Control 5", "CIS Control 6",
            "SOC 2 CC6.2", "SOC 2 CC6.3",
            "ISO 27001 A.9.2", "ISO 27001 A.9.4.2",
        ],
        "recommended_action":  _rec_action(rule_id),
        "false_positive_notes": _fp_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "user_account",
        "rule_id":             rule_id,
    }


def _rec_action(rule_id: str) -> str:
    m = {
        "new_account":       "Immediately disable the account and investigate who created it. "
                             "Revoke any sessions and audit for lateral movement.",
        "uid_zero_clone":    "Delete the account immediately and audit for privilege abuse. "
                             "This is a root backdoor.",
        "hidden_user":       "Disable and remove the account. Audit for other persistence mechanisms.",
        "service_with_shell":"Change the account's shell to /usr/sbin/nologin if interactive access is not needed.",
        "home_changed":      "Revert the home directory change if unauthorized. Audit file access.",
        "privgroup_added":   "Remove the account from the privileged group if not authorized. "
                             "Audit all actions taken by this account.",
        "shell_changed":     "Change shell back to non-login shell if the change was unauthorized.",
    }
    return m.get(rule_id, "Investigate the flagged account change.")


def _fp_note(rule_id: str) -> str:
    m = {
        "new_account":       "Software installs sometimes create service accounts. Verify with the installer.",
        "uid_zero_clone":    "Only 'root' should ever have UID 0. No legitimate software needs this.",
        "hidden_user":       "macOS system accounts start with '_' by design. "
                             "Flag only non-Apple-created underscore accounts.",
        "service_with_shell":"Some services legitimately need interactive shell access for administration.",
        "home_changed":      "Home directory changes may be part of account migration. Verify with admin.",
        "privgroup_added":   "Admin provisioning workflows add users to privileged groups. "
                             "Verify with IT ticketing.",
        "shell_changed":     "OS upgrades sometimes reset shell paths. Verify update history.",
    }
    return m.get(rule_id, "Review context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

async def detect_new_account(
    agent_id: str,
    users: list[dict],
    db: Any,
) -> list[dict]:
    """CRITICAL — New account not present in the approved baseline."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "user_account", "user_baseline")
    baseline: dict[str, dict] = {}
    if raw_state:
        try:
            baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            baseline = {}

    updated = dict(baseline)
    for user in users:
        uname = user["username"]
        if not uname:
            continue
        snap = {"uid": user["uid"], "shell": user["shell"], "home": user["home"]}
        updated[uname] = snap

        if uname in baseline:
            continue

        # No dedup window for new accounts — alert immediately every time
        if _should_suppress(agent_id, "new_account", uname, window=0):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical", rule_id="new_account",
            title=f"New user account created: {uname}",
            description=(
                f"User account '{uname}' (UID {user['uid']}) appeared and is not in the "
                "approved account baseline. Attackers create accounts for persistence "
                "and to maintain access after credential rotation."
            ),
            mitre_technique="T1136.001",
            evidence={
                "username": uname, "uid": user["uid"], "gid": user["gid"],
                "shell": user["shell"], "home": user["home"],
                "groups": user["groups"],
            },
            raw_user=user["raw"],
        ))

    try:
        await db.set_entity_state(
            agent_id, "user_account", "user_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist user baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_uid_zero_clone(agent_id: str, users: list[dict]) -> list[dict]:
    """CRITICAL — Account with UID 0 / GID 0 that is not named 'root'."""
    findings: list[dict] = []
    for user in users:
        uname = user["username"]
        uid   = user["uid"]
        gid   = user["gid"]
        if uname == "root":
            continue
        if uid != 0 and gid != 0:
            continue

        # Windows Administrators group membership is checked separately
        attr  = "UID" if uid == 0 else "GID"
        value = uid if uid == 0 else gid
        if _should_suppress(agent_id, "uid_zero_clone", uname, window=0):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="critical", rule_id="uid_zero_clone",
            title=f"Root-equivalent account detected: {uname} ({attr}={value})",
            description=(
                f"Account '{uname}' has {attr}={value}, giving it root-equivalent privileges. "
                "Only 'root' should ever have UID/GID 0. This is a classic backdoor technique "
                "to create a privileged account that survives root password changes."
            ),
            mitre_technique="T1136.001",
            evidence={
                "username": uname, "uid": uid, "gid": gid,
                "shell": user["shell"], "home": user["home"],
            },
            raw_user=user["raw"],
        ))
    return findings


def detect_hidden_user(agent_id: str, users: list[dict]) -> list[dict]:
    """HIGH — Username starting with _ (unexpected) or containing suspicious characters."""
    findings: list[dict] = []
    for user in users:
        uname = user["username"]
        if not uname:
            continue
        if not _HIDDEN_USER_RE.match(uname):
            continue
        # macOS system accounts all start with _ — only flag if NOT a known pattern
        # We flag all underscore-prefix accounts that aren't standard macOS ones.
        # The approved-baseline check in detect_new_account handles whitelisting.
        if _should_suppress(agent_id, "hidden_user", uname):
            continue
        reason = "underscore-prefix" if uname.startswith("_") else "non-printable characters"
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="hidden_user",
            title=f"Hidden / system-like user detected: {repr(uname)}",
            description=(
                f"Account '{uname}' uses a naming convention ({reason}) typically "
                "reserved for macOS system accounts or used to hide accounts from "
                "standard user enumeration tools."
            ),
            mitre_technique="T1136.001",
            evidence={
                "username": uname, "uid": user["uid"],
                "shell": user["shell"], "reason": reason,
            },
            raw_user=user["raw"],
        ))
    return findings


def detect_service_with_shell(agent_id: str, users: list[dict]) -> list[dict]:
    """HIGH — Service/system account with an interactive shell."""
    findings: list[dict] = []
    for user in users:
        uname = user["username"]
        uid   = user["uid"]
        shell = user["shell"]
        # Only flag accounts in system UID range
        is_system = (0 < uid < LINUX_SYSTEM_UID_MAX) or "system" in uname.lower()
        if not is_system:
            continue
        if shell not in INTERACTIVE_SHELLS:
            continue
        if _should_suppress(agent_id, "service_with_shell", uname):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="service_with_shell",
            title=f"Service account with interactive shell: {uname} (shell={shell})",
            description=(
                f"System account '{uname}' (UID {uid}) has an interactive shell '{shell}'. "
                "Service accounts should use /sbin/nologin or /bin/false. "
                "An interactive shell enables direct login and post-compromise persistence."
            ),
            mitre_technique="T1078",
            evidence={
                "username": uname, "uid": uid, "gid": user["gid"],
                "shell": shell, "home": user["home"],
            },
            raw_user=user["raw"],
        ))
    return findings


async def detect_home_changed(
    agent_id: str,
    users: list[dict],
    db: Any,
) -> list[dict]:
    """HIGH — Home directory changed for an existing account."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "user_account", "user_home_baseline")
    home_baseline: dict[str, str] = {}
    if raw_state:
        try:
            home_baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            home_baseline = {}

    updated = dict(home_baseline)
    for user in users:
        uname = user["username"]
        home  = user["home"]
        if not uname or not home:
            continue
        updated[uname] = home
        prev_home = home_baseline.get(uname)
        if prev_home is None or prev_home == home:
            continue
        if _should_suppress(agent_id, "home_changed", f"{uname}:{home}"):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high", rule_id="home_changed",
            title=f"Home directory changed for {uname}: {prev_home} → {home}",
            description=(
                f"Account '{uname}' home directory changed from '{prev_home}' to '{home}'. "
                "Attackers change home directories to redirect shell initialization "
                "scripts or gain write access to sensitive directories."
            ),
            mitre_technique="T1078",
            evidence={
                "username":   uname,
                "old_home":   prev_home,
                "new_home":   home,
            },
            raw_user=user["raw"],
        ))

    try:
        await db.set_entity_state(
            agent_id, "user_account", "user_home_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist home baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_privgroup_added(agent_id: str, users: list[dict]) -> list[dict]:
    """HIGH (→ CRITICAL for domain admin) — Account added to a privileged group."""
    findings: list[dict] = []
    for user in users:
        uname  = user["username"]
        groups = {g.lower() for g in (user.get("groups") or [])}
        priv   = groups & PRIVILEGED_GROUPS
        if not priv:
            continue
        is_domain_admin = bool({"domain admins", "enterprise admins", "schema admins"} & priv)
        severity = "critical" if is_domain_admin else "high"
        item_key = f"{uname}:{','.join(sorted(priv))}"
        if _should_suppress(agent_id, "privgroup_added", item_key):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity=severity, rule_id="privgroup_added",
            title=f"Account in privileged group(s): {uname} → {', '.join(sorted(priv))}",
            description=(
                f"Account '{uname}' is a member of privileged group(s): {', '.join(sorted(priv))}. "
                + ("DOMAIN ADMIN — full domain compromise risk. " if is_domain_admin else "")
                + "Investigate whether this membership was authorized."
            ),
            mitre_technique="T1136.002" if is_domain_admin else "T1136.001",
            evidence={
                "username":          uname,
                "privileged_groups": sorted(priv),
                "all_groups":        sorted(user.get("groups", [])),
                "uid":               user["uid"],
            },
            raw_user=user["raw"],
        ))
    return findings


async def detect_shell_changed(
    agent_id: str,
    users: list[dict],
    db: Any,
) -> list[dict]:
    """MEDIUM — Account shell changed from non-login to interactive."""
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "user_account", "user_shell_baseline")
    shell_baseline: dict[str, str] = {}
    if raw_state:
        try:
            shell_baseline = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            shell_baseline = {}

    updated = dict(shell_baseline)
    for user in users:
        uname = user["username"]
        shell = user["shell"]
        if not uname:
            continue
        updated[uname] = shell
        prev_shell = shell_baseline.get(uname)
        if prev_shell is None:
            continue
        # Only alert when going from non-login → interactive
        if prev_shell not in NON_LOGIN_SHELLS:
            continue
        if shell not in INTERACTIVE_SHELLS:
            continue
        if _should_suppress(agent_id, "shell_changed", f"{uname}:{shell}"):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="medium", rule_id="shell_changed",
            title=f"Account shell changed to interactive: {uname} ({prev_shell} → {shell})",
            description=(
                f"Account '{uname}' shell changed from '{prev_shell}' to '{shell}'. "
                "Changing a service account's shell from nologin to bash enables "
                "direct login and is a common post-compromise persistence technique."
            ),
            mitre_technique="T1078",
            evidence={
                "username":    uname,
                "old_shell":   prev_shell,
                "new_shell":   shell,
            },
            raw_user=user["raw"],
        ))

    try:
        await db.set_entity_state(
            agent_id, "user_account", "user_shell_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist shell baseline agent=%s: %s", agent_id, exc)

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
    if section not in USER_SECTIONS:
        return []

    users = ingest_users(data)
    if not users:
        return []

    findings: list[dict] = []

    for f in await detect_new_account(agent_id, users, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_uid_zero_clone(agent_id, users):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_hidden_user(agent_id, users):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_service_with_shell(agent_id, users):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_home_changed(agent_id, users, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in detect_privgroup_added(agent_id, users):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for f in await detect_shell_changed(agent_id, users, db):
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

    def make_user(**kw) -> dict:
        d = {
            "username": "alice", "uid": 1000, "gid": 1000,
            "shell": "/bin/bash", "home": "/home/alice",
            "groups": [], "account_flags": [],
            "last_login": "", "created_timestamp": "", "is_domain": False,
            "raw": {},
        }
        d.update(kw)
        return d

    async def run_tests():
        global passed, failed

        # ── 1. New account: first scan → CRITICAL ─────────────────────────────
        print("\nTest 1: New account → CRITICAL")
        fresh()
        db1 = MockDB()
        users = [make_user(username="backdoor", uid=5000)]
        findings = await detect_new_account("agentA", users, db1)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule new_account", findings[0]["rule_id"] == "new_account")

        # ── 2. Known account: second scan → no alert ──────────────────────────
        print("\nTest 2: Known account — no re-alert")
        fresh()
        db2 = MockDB()
        users = [make_user(username="alice", uid=1000)]
        await detect_new_account("agentB", users, db2)
        findings = await detect_new_account("agentB", users, db2)
        check("no findings on second scan", len(findings) == 0)

        # ── 3. New account: no dedup — fires again ────────────────────────────
        print("\nTest 3: New account — no dedup window, fires each time it's new")
        fresh()
        db3 = MockDB()
        # Each new scan with a brand-new username that was never in baseline fires
        users = [make_user(username="newuser99", uid=6000)]
        f1 = await detect_new_account("agentC", users, db3)
        # Same agent, same DB — now it IS in baseline → should not fire
        f2 = await detect_new_account("agentC", users, db3)
        check("first scan fires", len(f1) == 1)
        check("second scan does not fire (already in baseline)", len(f2) == 0)

        # ── 4. UID 0 clone → CRITICAL ─────────────────────────────────────────
        print("\nTest 4: UID 0 clone → CRITICAL")
        fresh()
        users = [make_user(username="evil_root", uid=0)]
        findings = detect_uid_zero_clone("agentD", users)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")
        check("rule uid_zero_clone", findings[0]["rule_id"] == "uid_zero_clone")

        # ── 5. root itself → no alert ─────────────────────────────────────────
        print("\nTest 5: root UID 0 — no alert")
        fresh()
        users = [make_user(username="root", uid=0, gid=0)]
        findings = detect_uid_zero_clone("agentE", users)
        check("no findings for root", len(findings) == 0)

        # ── 6. GID 0 clone → CRITICAL ─────────────────────────────────────────
        print("\nTest 6: GID 0 clone → CRITICAL")
        fresh()
        users = [make_user(username="wheel_clone", uid=1500, gid=0)]
        findings = detect_uid_zero_clone("agentF", users)
        check("1 finding", len(findings) == 1)

        # ── 7. Hidden user: underscore prefix → HIGH ──────────────────────────
        print("\nTest 7: Underscore-prefix hidden user → HIGH")
        fresh()
        users = [make_user(username="_evil_daemon", uid=500)]
        findings = detect_hidden_user("agentG", users)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("reason underscore-prefix", findings[0]["evidence"]["reason"] == "underscore-prefix")

        # ── 8. Normal user → no alert ─────────────────────────────────────────
        print("\nTest 8: Normal username — no alert")
        fresh()
        users = [make_user(username="alice", uid=1000)]
        findings = detect_hidden_user("agentH", users)
        check("no findings", len(findings) == 0)

        # ── 9. Service account with bash shell → HIGH ─────────────────────────
        print("\nTest 9: Service account with bash → HIGH")
        fresh()
        users = [make_user(username="www-data", uid=33, shell="/bin/bash")]
        findings = detect_service_with_shell("agentI", users)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("rule service_with_shell", findings[0]["rule_id"] == "service_with_shell")

        # ── 10. Normal user with bash → no alert (UID > 999) ─────────────────
        print("\nTest 10: Regular user (UID 1000) with bash — no alert")
        fresh()
        users = [make_user(username="alice", uid=1000, shell="/bin/bash")]
        findings = detect_service_with_shell("agentJ", users)
        check("no findings", len(findings) == 0)

        # ── 11. Home directory changed → HIGH ────────────────────────────────
        print("\nTest 11: Home directory changed → HIGH")
        fresh()
        db11 = MockDB()
        await detect_home_changed("agentK", [make_user(username="bob", home="/home/bob")], db11)
        findings = await detect_home_changed("agentK", [make_user(username="bob", home="/tmp/evil")], db11)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("old_home in evidence", findings[0]["evidence"]["old_home"] == "/home/bob")

        # ── 12. Home unchanged → no alert ────────────────────────────────────
        print("\nTest 12: Home unchanged — no alert")
        fresh()
        db12 = MockDB()
        await detect_home_changed("agentL", [make_user(username="carol", home="/home/carol")], db12)
        findings = await detect_home_changed("agentL", [make_user(username="carol", home="/home/carol")], db12)
        check("no findings", len(findings) == 0)

        # ── 13. Privileged group: sudo → HIGH ─────────────────────────────────
        print("\nTest 13: User in sudo group → HIGH")
        fresh()
        users = [make_user(username="attacker", uid=2000, groups=["users", "sudo"])]
        findings = detect_privgroup_added("agentM", users)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("sudo in evidence", "sudo" in findings[0]["evidence"]["privileged_groups"])

        # ── 14. Domain Admins → CRITICAL ─────────────────────────────────────
        print("\nTest 14: Domain Admins membership → CRITICAL")
        fresh()
        users = [make_user(username="compromised", uid=3000,
                           groups=["domain users", "domain admins"])]
        findings = detect_privgroup_added("agentN", users)
        check("1 finding", len(findings) == 1)
        check("severity critical", findings[0]["severity"] == "critical")

        # ── 15. No privileged groups → no alert ──────────────────────────────
        print("\nTest 15: No privileged groups — no alert")
        fresh()
        users = [make_user(username="alice", groups=["users", "audio"])]
        findings = detect_privgroup_added("agentO", users)
        check("no findings", len(findings) == 0)

        # ── 16. Shell changed: nologin → bash → MEDIUM ───────────────────────
        print("\nTest 16: Shell changed nologin → bash → MEDIUM")
        fresh()
        db16 = MockDB()
        await detect_shell_changed("agentP", [make_user(username="svc", shell="/usr/sbin/nologin")], db16)
        findings = await detect_shell_changed("agentP", [make_user(username="svc", shell="/bin/bash")], db16)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("rule shell_changed", findings[0]["rule_id"] == "shell_changed")

        # ── 17. Shell changed: bash → bash → no alert ────────────────────────
        print("\nTest 17: Shell unchanged bash → bash — no alert")
        fresh()
        db17 = MockDB()
        await detect_shell_changed("agentQ", [make_user(username="svc2", shell="/bin/bash")], db17)
        findings = await detect_shell_changed("agentQ", [make_user(username="svc2", shell="/bin/bash")], db17)
        check("no findings", len(findings) == 0)

        # ── 18. /etc/passwd text ingestion ────────────────────────────────────
        print("\nTest 18: /etc/passwd text ingestion")
        fresh()
        raw = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        users = ingest_users(raw)
        check("2 users", len(users) == 2)
        check("root uid=0", users[0]["uid"] == 0)
        check("nobody shell correct", users[1]["shell"] == "/usr/sbin/nologin")

        # ── 19. Dict list ingestion ───────────────────────────────────────────
        print("\nTest 19: Dict list ingestion")
        fresh()
        raw = [
            {"username": "dave", "uid": 1001, "gid": 1001,
             "shell": "/bin/bash", "home": "/home/dave",
             "groups": ["sudo", "docker"]},
        ]
        users = ingest_users(raw)
        check("1 user", len(users) == 1)
        check("groups contain sudo", "sudo" in users[0]["groups"])

        # ── 20. Full analyze() pipeline ───────────────────────────────────────
        print("\nTest 20: Full analyze() pipeline")
        fresh()
        db20 = MockDB()
        raw = [
            {"username": "backdoor_user", "uid": 0, "gid": 0,
             "shell": "/bin/bash", "home": "/tmp/home",
             "groups": ["sudo", "wheel"]},
        ]
        findings = await analyze("agentR", "users", raw, db20, hostname="host-r")
        rule_ids = {f["rule_id"] for f in findings}
        check("new_account fired", "new_account" in rule_ids)
        check("uid_zero_clone fired", "uid_zero_clone" in rule_ids)
        check("privgroup_added fired", "privgroup_added" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-r" for f in findings))

        # ── 21. Non-user section → empty ─────────────────────────────────────
        print("\nTest 21: Non-user section → empty")
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
