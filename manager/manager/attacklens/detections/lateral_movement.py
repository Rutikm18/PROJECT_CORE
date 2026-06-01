"""
manager/manager/attacklens/detections/lateral_movement.py
Production-grade lateral movement detection — macOS, Linux, Windows.

COMPLIANCE MAPPING:
  NIST SP 800-53:  AC-2, AC-3, AC-6, AC-17, AU-2, AU-6, AU-12, SI-4
  CIS Controls:    4.1 (Admin Privileges), 12.1 (Boundary Defense), 12.8 (Egress Filtering)
  ISO 27001:       A.9.1.2, A.9.2.3, A.9.4.4, A.13.1.1, A.13.1.3
  PCI-DSS v4:      Req 1.2, Req 7.2, Req 8.3, Req 10.2, Req 10.6
  SOC 2 CC:        CC6.1, CC6.2, CC6.3, CC6.6
  MITRE ATT&CK:    T1021 (Remote Services), T1046 (Network Service Discovery),
                   T1078 (Valid Accounts), T1136 (Create Account)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("manager.attacklens.detections.lateral_movement")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — all thresholds configurable here
# ─────────────────────────────────────────────────────────────────────────────

INTERNAL_CONN_SPIKE_THRESHOLD: int = 10     # unique internal IPs in one cycle → scanning
SSH_SPRAY_THRESHOLD: int           = 5      # unique SSH destinations → spray
RDP_FLAG_ANY_EXTERNAL: bool        = True   # ANY external RDP = suspicious
SMB_FLAG_ANY_EXTERNAL: bool        = True   # ANY external SMB = suspicious
WINRM_FLAG_ANY_EXTERNAL: bool      = True   # ANY external WinRM = suspicious

LATERAL_PORTS: frozenset[int] = frozenset({
    22, 23, 135, 137, 138, 139, 389, 445, 636,
    1433, 1521, 3268, 3269, 3389, 5900, 5901,
    5985, 5986, 6379, 27017,
})

INTERNAL_SUBNETS: tuple[str, ...] = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128",
)
_INTERNAL_NETS = [ipaddress.ip_network(c, strict=False) for c in INTERNAL_SUBNETS]

DEDUP_WINDOW_SECS: int      = 3600   # suppress repeat alert for same key within 1 hour
RATE_LIMIT_MAX_PER_HOUR: int = 20    # max alerts this module emits per agent per hour

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL DEDUP / RATE-LIMIT STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]       = {}
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
        log.debug("Rate limit: agent=%s module=lateral_movement", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION — validate + normalize raw section data
# ─────────────────────────────────────────────────────────────────────────────

def ingest_connections(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        raddr = str(item.get("remote_addr") or item.get("raddr") or "")
        out.append({
            "pid":         item.get("pid"),
            "name":        str(item.get("name") or item.get("process_name") or ""),
            "status":      str(item.get("status") or ""),
            "local_addr":  str(item.get("local_addr") or item.get("laddr") or ""),
            "remote_addr": raddr,
            "remote_ip":   _parse_ip(raddr),
            "remote_port": _parse_port(raddr),
            "raw":         item,
        })
    return out


def ingest_users(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append({
            "name":     str(item.get("name") or item.get("username") or ""),
            "uid":      item.get("uid"),
            "is_admin": bool(item.get("is_admin") or item.get("admin") or item.get("sudoer")),
            "shell":    str(item.get("shell") or ""),
            "raw":      item,
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_internal_scanning(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1046 — Network service scanning: too many unique internal IPs contacted."""
    internal_dest: dict[str, list[int]] = {}
    for c in conns:
        ip, port = c["remote_ip"], c["remote_port"]
        if ip and port and _is_internal(ip) and not _is_loopback(ip):
            internal_dest.setdefault(ip, []).append(port)
    if len(internal_dest) < INTERNAL_CONN_SPIKE_THRESHOLD:
        return []
    all_ports = sorted({p for ports in internal_dest.values() for p in ports})
    return [{
        "rule_id":    "lm:internal_scan",
        "severity":   "high",
        "title":      f"Internal network scanning: {len(internal_dest)} unique internal IPs",
        "description": (
            f"Connections to {len(internal_dest)} unique internal IPs in a single collection "
            f"cycle — consistent with network service discovery (T1046) or worm propagation. "
            f"Contacted ports: {all_ports[:20]}."
        ),
        "evidence": {
            "unique_internal_ips": len(internal_dest),
            "threshold":           INTERNAL_CONN_SPIKE_THRESHOLD,
            "destinations":        dict(list(internal_dest.items())[:15]),
            "unique_ports":        all_ports[:30],
        },
        "raw_telemetry": [c["raw"] for c in conns if _is_internal(c["remote_ip"])][:30],
        "mitre_tactic":     "Discovery",
        "mitre_technique":  "T1046",
        "compliance_controls": {
            "NIST": ["SI-4", "AC-17"], "CIS": ["12.1", "12.8"],
            "ISO":  ["A.13.1.1"],      "PCI": ["Req 1.3", "Req 10.6"], "SOC2": ["CC6.6"],
        },
        "recommended_action": (
            "Isolate the host. Run `ss -tunap` or `netstat -an` to capture live state. "
            "Identify the scanning process by PID. Check for nmap/masscan/zmap or worm activity. "
            "If a service account, verify automation scope."
        ),
        "false_positive_notes": (
            "Monitoring/backup agents (Zabbix, Prometheus, Ansible) legitimately contact many IPs. "
            "Verify connection process name — if a management tool, reduce threshold or whitelist "
            "the process name in allowlist.py."
        ),
        "item_key": f"internal_scan:{len(internal_dest)}ip",
        "category": "connection",
        "source":   "rule:lateral_movement",
        "score":    SEVERITY_SCORES["high"],
        "tags":     ["lateral_movement", "scanning", "T1046"],
    }]


def detect_ssh_spray(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1021.004 — SSH to many unique destinations in one collection cycle."""
    ssh_dests = {
        c["remote_ip"] for c in conns
        if c["remote_port"] == 22 and c["remote_ip"] and not _is_loopback(c["remote_ip"])
    }
    if len(ssh_dests) < SSH_SPRAY_THRESHOLD:
        return []
    ssh_raw = [c["raw"] for c in conns if c["remote_port"] == 22]
    return [{
        "rule_id":    "lm:ssh_spray",
        "severity":   "high",
        "title":      f"SSH lateral movement spray: {len(ssh_dests)} destinations",
        "description": (
            f"SSH connections to {len(ssh_dests)} unique hosts in one collection cycle — "
            f"consistent with credential-based lateral movement (T1021.004) or automated SSH spray."
        ),
        "evidence": {
            "unique_ssh_destinations": list(ssh_dests),
            "threshold":               SSH_SPRAY_THRESHOLD,
            "connection_count":        len(ssh_raw),
        },
        "raw_telemetry": ssh_raw[:20],
        "mitre_tactic":     "Lateral Movement",
        "mitre_technique":  "T1021.004",
        "compliance_controls": {
            "NIST": ["AC-2", "AC-17", "AU-2"], "CIS": ["4.1", "12.1"],
            "ISO":  ["A.9.1.2", "A.9.4.4"],   "PCI": ["Req 8.3", "Req 10.2"], "SOC2": ["CC6.1"],
        },
        "recommended_action": (
            "Rotate all SSH key material on this host. Audit `~/.ssh/known_hosts` for new entries. "
            "Check auth.log on target hosts for connection attempts. "
            "Restrict SSH outbound to jump hosts only via firewall rules."
        ),
        "false_positive_notes": (
            "Ansible, Capistrano, Fabric, and Puppet legitimately SSH to many hosts. "
            "Check the connection process name — if an automation tool, raise threshold "
            "or add process to BENIGN_PARENT_CHILD in allowlist.py."
        ),
        "item_key": f"ssh_spray:{len(ssh_dests)}",
        "category": "connection",
        "source":   "rule:lateral_movement",
        "score":    SEVERITY_SCORES["high"],
        "tags":     ["lateral_movement", "ssh", "T1021.004"],
    }]


def detect_rdp_external(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1021.001 — Any RDP connection to an external (non-RFC1918) IP."""
    if not RDP_FLAG_ANY_EXTERNAL:
        return []
    hits = []
    for c in conns:
        if c["remote_port"] == 3389 and c["remote_ip"] and not _is_internal(c["remote_ip"]):
            hits.append({
                "rule_id":    "lm:rdp_external",
                "severity":   "critical",
                "title":      f"External RDP: {c['remote_ip']}:3389",
                "description": (
                    f"RDP connection to external IP {c['remote_ip']} by process '{c['name']}'. "
                    f"External RDP is rarely legitimate — strong indicator of operator controlling "
                    f"a remote host post-compromise or stolen credential reuse."
                ),
                "evidence": {
                    "remote_ip": c["remote_ip"], "process": c["name"], "pid": c.get("pid"),
                },
                "raw_telemetry": [c["raw"]],
                "mitre_tactic":     "Lateral Movement",
                "mitre_technique":  "T1021.001",
                "compliance_controls": {
                    "NIST": ["AC-3", "AC-17", "SI-4"], "CIS": ["4.1", "12.8"],
                    "ISO":  ["A.9.1.2", "A.9.4.4"],   "PCI": ["Req 1.2", "Req 8.3"], "SOC2": ["CC6.6"],
                },
                "recommended_action": (
                    "Kill the RDP session. Block the destination IP at egress. "
                    "Rotate all credentials the account may have used. "
                    "Check if mstsc.exe / rdesktop / Remmina was recently installed."
                ),
                "false_positive_notes": (
                    "VPN split-tunnel or Azure Virtual Desktop routes RDP via public IPs. "
                    "Add known egress/VPN IPs to TRUSTED_CIDRS in allowlist.py before suppressing."
                ),
                "item_key": f"rdp_external:{c['remote_ip']}",
                "category": "connection",
                "source":   "rule:lateral_movement",
                "score":    SEVERITY_SCORES["critical"],
                "tags":     ["lateral_movement", "rdp", "T1021.001"],
            })
    return hits


def detect_smb_external(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1021.002 — SMB/CIFS to external IPs should never occur."""
    if not SMB_FLAG_ANY_EXTERNAL:
        return []
    hits = []
    for c in conns:
        if (c["remote_port"] in (139, 445) and c["remote_ip"]
                and not _is_internal(c["remote_ip"]) and not _is_loopback(c["remote_ip"])):
            hits.append({
                "rule_id":    "lm:smb_external",
                "severity":   "high",
                "title":      f"External SMB connection: {c['remote_ip']}:{c['remote_port']}",
                "description": (
                    f"SMB/CIFS to external IP {c['remote_ip']} — SMB must not cross network "
                    f"boundaries. Indicates data exfiltration, ransomware C2, or EternalBlue-style "
                    f"exploitation targeting an internet-facing host."
                ),
                "evidence": c["raw"],
                "raw_telemetry": [c["raw"]],
                "mitre_tactic":     "Lateral Movement",
                "mitre_technique":  "T1021.002",
                "compliance_controls": {
                    "NIST": ["AC-3", "SI-4", "SC-7"], "CIS": ["12.1", "12.8"],
                    "ISO":  ["A.13.1.1", "A.13.1.3"], "PCI": ["Req 1.2", "Req 1.3"], "SOC2": ["CC6.7"],
                },
                "recommended_action": (
                    "Block TCP 139/445 at egress firewall immediately. "
                    "Identify the process owning the connection (check by PID). "
                    "Capture traffic for forensics if possible. Treat as active incident."
                ),
                "false_positive_notes": (
                    "Azure Files mounted over SMB (*.file.core.windows.net) routes via public IPs. "
                    "Verify the destination belongs to Azure storage before suppressing."
                ),
                "item_key": f"smb_external:{c['remote_ip']}",
                "category": "connection",
                "source":   "rule:lateral_movement",
                "score":    SEVERITY_SCORES["high"],
                "tags":     ["lateral_movement", "smb", "T1021.002"],
            })
    return hits


def detect_winrm_external(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1021.006 — WinRM to external hosts is attacker-controlled remote execution."""
    if not WINRM_FLAG_ANY_EXTERNAL:
        return []
    hits = []
    for c in conns:
        if (c["remote_port"] in (5985, 5986) and c["remote_ip"]
                and not _is_internal(c["remote_ip"])):
            hits.append({
                "rule_id":    "lm:winrm_external",
                "severity":   "high",
                "title":      f"External WinRM: {c['remote_ip']}:{c['remote_port']}",
                "description": (
                    f"WinRM connection to external {c['remote_ip']}:{c['remote_port']} by '{c['name']}'. "
                    f"Attackers use WinRM for remote command execution and as a C2 transport."
                ),
                "evidence": c["raw"],
                "raw_telemetry": [c["raw"]],
                "mitre_tactic":     "Lateral Movement",
                "mitre_technique":  "T1021.006",
                "compliance_controls": {
                    "NIST": ["AC-17", "SI-4"], "CIS": ["4.1", "12.8"],
                    "ISO":  ["A.9.1.2"],        "PCI": ["Req 1.2", "Req 8.3"], "SOC2": ["CC6.1"],
                },
                "recommended_action": (
                    "Block WinRM ports (5985/5986) at perimeter. "
                    "If powershell.exe is the owner, treat as confirmed attacker activity. "
                    "Check for associated scheduled tasks using WinRM for persistence."
                ),
                "false_positive_notes": (
                    "Azure Arc, Ansible (WinRM transport), and SCCM use WinRM to managed endpoints. "
                    "Verify the destination belongs to your management plane before suppressing."
                ),
                "item_key": f"winrm_external:{c['remote_ip']}",
                "category": "connection",
                "source":   "rule:lateral_movement",
                "score":    SEVERITY_SCORES["high"],
                "tags":     ["lateral_movement", "winrm", "T1021.006"],
            })
    return hits


async def detect_new_admin(agent_id: str, users: list[dict], db: Any) -> list[dict]:
    """T1136 / T1078.003 — New admin account or unexpected privilege escalation."""
    hits = []
    now = time.time()
    for user in users:
        name = user.get("name", "")
        if not name:
            continue
        is_admin = user.get("is_admin", False)
        uid = user.get("uid")
        key = f"user:{name}"
        fingerprint = json.dumps({"admin": is_admin, "uid": uid}, sort_keys=True)
        prev = await db.get_entity_state(agent_id, "user_lm", key)

        if prev is None:
            await db.set_entity_state(agent_id, "user_lm", key, fingerprint, now)
            if is_admin:
                hits.append({
                    "rule_id":    "lm:new_admin_account",
                    "severity":   "high",
                    "title":      f"New admin account first seen: {name}",
                    "description": (
                        f"Account '{name}' (UID {uid}) observed for the first time with admin "
                        f"privileges. New admin accounts are a common attacker persistence mechanism."
                    ),
                    "evidence": user["raw"],
                    "raw_telemetry": [user["raw"]],
                    "mitre_tactic":     "Persistence",
                    "mitre_technique":  "T1136.001",
                    "compliance_controls": {
                        "NIST": ["AC-2", "AC-6", "AU-12"], "CIS": ["4.1", "4.3"],
                        "ISO":  ["A.9.2.1", "A.9.2.3"],   "PCI": ["Req 7.2", "Req 8.2"], "SOC2": ["CC6.2"],
                    },
                    "recommended_action": (
                        "Verify creation intent via change management ticket. "
                        "Run `dscl . -list /Users` (macOS) / `getent passwd` (Linux) / "
                        "`net user` (Windows) to audit all accounts. Disable if unauthorized."
                    ),
                    "false_positive_notes": (
                        "New employee onboarding, MDM provisioning, or imaging creates admin accounts. "
                        "Correlate with HR/IT tickets. Suppress known service accounts by adding "
                        "them to the user allowlist."
                    ),
                    "item_key": key,
                    "category": "user",
                    "source":   "rule:lateral_movement",
                    "score":    SEVERITY_SCORES["high"],
                    "tags":     ["lateral_movement", "account", "T1136"],
                })
        else:
            try:
                prev_data = json.loads(prev.get("fingerprint", "{}"))
            except Exception:
                prev_data = {}
            if not prev_data.get("admin") and is_admin:
                hits.append({
                    "rule_id":    "lm:privesc_admin_grant",
                    "severity":   "critical",
                    "title":      f"Privilege escalation: '{name}' granted admin rights",
                    "description": (
                        f"Account '{name}' was a standard user and now has admin/root privileges. "
                        f"Escalation of existing accounts is high-confidence attacker activity."
                    ),
                    "evidence": {"current": user["raw"], "was_admin": False},
                    "raw_telemetry": [user["raw"]],
                    "mitre_tactic":     "Privilege Escalation",
                    "mitre_technique":  "T1078.003",
                    "compliance_controls": {
                        "NIST": ["AC-2", "AC-6", "AU-2"], "CIS": ["4.1", "4.3", "5.4"],
                        "ISO":  ["A.9.2.3", "A.9.4.4"],   "PCI": ["Req 7.2", "Req 8.3"], "SOC2": ["CC6.3"],
                    },
                    "recommended_action": (
                        "Audit who granted admin (check auth.log / sudo log / event log). "
                        "If unauthorized, revoke immediately and rotate all passwords. "
                        "Investigate lateral movement from this account in the last 24h."
                    ),
                    "false_positive_notes": (
                        "MDM/GPO-driven privilege grants are legitimate. "
                        "Correlate with IT change tickets. Suppress for known managed privilege grants."
                    ),
                    "item_key": f"{key}:privesc",
                    "category": "user",
                    "source":   "rule:lateral_movement",
                    "score":    SEVERITY_SCORES["critical"],
                    "tags":     ["lateral_movement", "privesc", "T1078"],
                })
            await db.set_entity_state(agent_id, "user_lm", key, fingerprint, now)
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER — raw hit → full structured alert with all mandatory fields
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
        # Engine / IntelDB fields
        "category":   hit.get("category", "connection"),
        "item_key":   hit.get("item_key", ""),
        "rule_id":    hit.get("rule_id", ""),
        "score":      hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":     hit.get("source", "rule:lateral_movement"),
        "tags":       hit.get("tags", ["lateral_movement"]),
        "cve_ids":    [],
        "cvss_score": None,
        "cvss_vector": None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DEDUPLICATION / RATE-LIMITING WRAPPER — main entry point
# ─────────────────────────────────────────────────────────────────────────────

async def analyze(
    agent_id: str,
    section:  str,
    data:     Any,
    db:       Any,
    hostname: str = "",
) -> list[dict]:
    """Called per section by AttackLensEngine. Returns structured alert dicts."""
    raw_hits: list[dict] = []

    if section == "connections":
        conns = ingest_connections(data)
        raw_hits += detect_internal_scanning(agent_id, conns)
        raw_hits += detect_ssh_spray(agent_id, conns)
        raw_hits += detect_rdp_external(agent_id, conns)
        raw_hits += detect_smb_external(agent_id, conns)
        raw_hits += detect_winrm_external(agent_id, conns)
    elif section == "users":
        users = ingest_users(data)
        raw_hits += await detect_new_admin(agent_id, users, db)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Suppressed dedup: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ip(addr: str) -> str:
    if not addr or addr in ("-", "*:*", "0.0.0.0:0"):
        return ""
    try:
        if addr.startswith("["):
            return addr.split("]")[0][1:]
        return addr.rsplit(":", 1)[0]
    except Exception:
        return ""


def _parse_port(addr: str) -> int | None:
    try:
        return int(addr.rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return None


def _is_internal(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETS)
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== lateral_movement.py — Test Harness ===\n")

    # ── TP: Internal scanning ──────────────────────────────────────────────────
    tp_data = [
        {"remote_addr": f"10.0.1.{i}:445", "local_addr": "10.0.1.1:50000",
         "name": "nc", "pid": 1000 + i}
        for i in range(1, 20)
    ]
    conns = ingest_connections(tp_data)
    hits = detect_internal_scanning("agent-tp", conns)
    assert len(hits) == 1 and hits[0]["severity"] == "high" and "T1046" in hits[0]["mitre_technique"]
    print(f"[PASS] TP internal scan: {hits[0]['title']}")

    # ── FP: Monitoring agent (9 hosts < threshold=10) ─────────────────────────
    fp_data = [
        {"remote_addr": f"10.0.1.{i}:9100", "local_addr": "10.0.1.1:50001",
         "name": "prometheus", "pid": 2000 + i}
        for i in range(1, 9)
    ]
    fp_conns = ingest_connections(fp_data)
    fp_hits = detect_internal_scanning("agent-fp", fp_conns)
    assert len(fp_hits) == 0
    print("[PASS] FP monitoring agent: suppressed (below threshold)")

    # ── TP: SSH spray ─────────────────────────────────────────────────────────
    ssh_tp = [
        {"remote_addr": f"10.0.2.{i}:22", "local_addr": "10.0.1.1:54321",
         "name": "ssh", "pid": 3000 + i}
        for i in range(1, 8)
    ]
    ssh_conns = ingest_connections(ssh_tp)
    ssh_hits = detect_ssh_spray("agent-tp2", ssh_conns)
    assert len(ssh_hits) == 1 and "T1021.004" in ssh_hits[0]["mitre_technique"]
    print(f"[PASS] TP SSH spray: {ssh_hits[0]['title']}")

    # ── FP: Ansible (3 hosts, under threshold) ────────────────────────────────
    ssh_fp = [
        {"remote_addr": f"10.0.2.{i}:22", "local_addr": "10.0.1.1:54322",
         "name": "ansible", "pid": 4000 + i}
        for i in range(1, 4)
    ]
    fp_ssh_conns = ingest_connections(ssh_fp)
    assert detect_ssh_spray("agent-fp2", fp_ssh_conns) == []
    print("[PASS] FP Ansible: suppressed (3 hosts < threshold=5)")

    # ── TP: External RDP ──────────────────────────────────────────────────────
    rdp_tp = [{"remote_addr": "203.0.113.55:3389", "local_addr": "10.0.0.5:54000",
               "name": "mstsc.exe", "pid": 5000}]
    rdp_conns = ingest_connections(rdp_tp)
    rdp_hits = detect_rdp_external("agent-tp3", rdp_conns)
    assert len(rdp_hits) == 1 and rdp_hits[0]["severity"] == "critical"
    print(f"[PASS] TP external RDP: {rdp_hits[0]['title']}")

    # ── FP: Internal RDP ──────────────────────────────────────────────────────
    assert detect_rdp_external("agent-fp3", ingest_connections(
        [{"remote_addr": "192.168.1.10:3389", "name": "mstsc.exe", "pid": 5001}]
    )) == []
    print("[PASS] FP internal RDP: suppressed")

    # ── Alert builder: verify all mandatory fields present ────────────────────
    alert = build_alert(ssh_hits[0], "agent-tp2", "dev-box-01")
    required = {"alert_id", "severity", "title", "description", "affected_asset",
                "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                "compliance_controls", "recommended_action", "false_positive_notes", "timestamp_utc"}
    missing = required - set(alert.keys())
    assert not missing, f"Missing: {missing}"
    assert alert["affected_asset"] == "dev-box-01"
    print(f"[PASS] Alert builder: all mandatory fields present (alert_id={alert['alert_id'][:8]}…)")

    print("\n=== All tests passed ===")
