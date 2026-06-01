"""
manager/manager/attacklens/detections/covert_channel.py
Production-grade covert C2, beaconing, reverse shell, and tunneling detection.

Detects stealthy adversary communication using statistical and structural
analysis of network connection telemetry:
  • C2 beaconing    — Coefficient-of-Variation analysis on inter-connection
                      intervals (CoV < 0.15, ≥5 connections in 30 min)
  • Reverse shell   — Shell binary with ESTABLISHED outbound external connection
  • NAT64 abuse     — IPv4 C2 hidden in 64:ff9b::/96 to bypass IPv4 egress rules
  • Long session    — Non-browser process holding >1 h session on 443/80
  • Connection burst— Single PID connecting to >50 distinct external IPs
  • Suspicious domain — DGA domain (Shannon entropy > 3.5) or newly registered (<30 d)

Sections handled:
  processes        → populate cross-section process cache (no findings emitted)
  connections      → run all 6 detection passes
  network_sessions → run all 6 detection passes

COMPLIANCE MAPPING:
  NIST CSF:  DE.CM-1, DE.CM-7 (Continuous monitoring)
  CIS:       9.2, 13.6, 13.8 (DNS/Email/URL Filtering, Network Monitoring)
  ISO 27001: A.12.4.1 (Event logging), A.13.1.2 (Network security)
  SOC 2:     CC7.2, CC7.3 (Anomaly detection, Incident response)

MITRE ATT&CK:
  T1071.001  (Application Layer Protocol — Web Protocols)
  T1059.004  (Command and Scripting Interpreter — Unix Shell)
  T1572      (Protocol Tunneling)
  T1568.002  (Dynamic Resolution — Domain Generation Algorithms)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import statistics
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.detections.covert_channel")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — all thresholds configurable here
# ─────────────────────────────────────────────────────────────────────────────

# Beaconing: CoV-based analysis in a 30-minute sliding window
BEACON_MIN_CONNECTIONS: int   = 5
BEACON_WINDOW_SECS: int       = 1800   # 30-minute window
BEACON_COV_THRESHOLD: float   = 0.15   # CoV below this = highly regular = beaconing

# Long-lived session: non-browser/non-approved process on web port
LONG_SESSION_THRESHOLD_SECS: int = 3600  # 1 hour

# Connection burst: single PID → many distinct external IPs
CONN_BURST_THRESHOLD: int    = 50
CONN_BURST_WINDOW_SECS: int  = 60

# Suspicious domain: DGA entropy threshold and new-domain age window
DOMAIN_ENTROPY_THRESHOLD: float = 3.5   # Shannon bits on first label
DOMAIN_AGE_THRESHOLD_DAYS: int  = 30    # domain registered < 30 days ago

# Dedup / rate-limiting
DEDUP_WINDOW_SECS: int       = 3600
RATE_LIMIT_MAX_PER_HOUR: int = 30

APPROVED_VPN_PROCESSES: frozenset[str] = frozenset({
    "openvpn", "wireguard", "wg", "vpnagent", "globalprotect",
    "ciscoanyconnect", "tunnelblick", "expressvpn", "nordvpn",
    "mullvadvpn", "privateinternetaccess", "surfshark", "ipvanish",
})

APPROVED_LONG_SESSION_PROCESSES: frozenset[str] = frozenset({
    "chrome", "firefox", "safari", "msedge", "opera", "brave", "arc",
    "backblaze", "crashplan", "dropbox", "onedrive", "box",
    "zoom", "teams", "slack", "webex", "skype",
    "spotify", "appleid_ui", "systempreferences", "softwareupdated",
    "coreaudiod", "nsurlsessiond", "useractivityd",
})

BROWSER_PROCESSES: frozenset[str] = frozenset({
    "chrome", "chromium", "firefox", "safari", "msedge", "edge",
    "opera", "brave", "arc", "vivaldi", "webkit2webprocess",
})

SHELL_BINARIES: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "fish", "csh", "tcsh", "ksh",
    "cmd", "cmd.exe", "pwsh", "powershell", "powershell.exe",
    "wscript", "wscript.exe", "cscript", "cscript.exe",
})

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# CDN CIDR SUPPRESSION — pre-compiled at module load
# ─────────────────────────────────────────────────────────────────────────────

_CDN_CIDR_STRINGS: list[str] = [
    # Cloudflare
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
    "131.0.72.0/22", "162.158.0.0/15", "198.41.128.0/17",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "188.114.96.0/20", "197.234.240.0/22",
    # Akamai
    "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
    "2.16.0.0/13", "92.122.0.0/15", "184.24.0.0/13",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15",
    "52.222.128.0/17", "54.182.0.0/16", "54.192.0.0/12",
    # Google / GCP
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
    "34.0.0.0/15", "34.64.0.0/10",
]

_CDN_NETWORKS: list = []


def _init_cdn_networks() -> None:
    for cidr in _CDN_CIDR_STRINGS:
        try:
            _CDN_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass


_init_cdn_networks()

_NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]          = {}
_rate_counter: dict[str, list[float]]   = {}
_beacon_windows: dict[str, list[float]] = {}  # "agent:pid:remote_ip" → [timestamps]
_process_cache: dict[str, list[dict]]   = {}  # agent_id → ingested processes

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_ip(ip: str) -> str:
    """Lowercase canonical IP string. Returns '' on invalid input."""
    try:
        return str(ipaddress.ip_address(ip.strip().strip("[]")))
    except ValueError:
        return ""


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def _is_cdn_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


def _is_nat64(ip: str) -> bool:
    """Return True if ip falls inside the NAT64 translation prefix 64:ff9b::/96."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr in _NAT64_NETWORK
    except ValueError:
        return False


def _extract_nat64_ipv4(ip: str) -> str:
    """Return the IPv4 address embedded in the last 4 bytes of a NAT64 address."""
    try:
        packed = ipaddress.ip_address(ip).packed  # 16 bytes
        return str(ipaddress.ip_address(packed[12:16]))
    except Exception:
        return ""


def _binary_name(name: str) -> str:
    """Extract binary name from a path, lowercase, without .exe suffix."""
    n = re.split(r"[/\\]", str(name or ""))[-1].lower()
    return n[:-4] if n.endswith(".exe") else n


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits for string s."""
    if not s:
        return 0.0
    n = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _coefficient_of_variation(values: list[float]) -> float:
    """stdev(values) / mean(values). Returns inf when fewer than 2 values or mean is 0."""
    if len(values) < 2:
        return float("inf")
    mean = statistics.mean(values)
    if mean == 0:
        return float("inf")
    return statistics.stdev(values) / mean


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
        log.debug("Rate limit reached: agent=%s module=covert_channel", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

_BASELINE_NS = "covert_channel"


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


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION — normalize raw section payload
# ─────────────────────────────────────────────────────────────────────────────

def ingest_connections(raw: Any) -> list[dict]:
    """
    Normalize connection/session section payload.

    Accepts:
      • list of connection dicts (flat)
      • dict with key: connections | sessions | network_sessions

    Each normalized session: {pid, process_name, remote_ip, remote_port,
                               local_port, state, session_start, duration_secs,
                               remote_hostname, domain_age_days, domain_entropy,
                               bytes_sent, bytes_recv, raw}
    """
    if isinstance(raw, dict):
        items = (raw.get("connections") or raw.get("sessions") or
                 raw.get("network_sessions") or [])
    elif isinstance(raw, list):
        items = raw
    else:
        return []

    result = []
    for item in items:
        if not isinstance(item, dict):
            continue

        # Prefer explicit remote_ip field; fall back to parsing remote_addr/raddr
        ip_raw = str(item.get("remote_ip") or "").strip()
        if not ip_raw:
            addr = str(item.get("remote_addr") or item.get("raddr") or "")
            if addr and addr not in ("-", "*:*", "0.0.0.0:0"):
                ip_raw = addr.rsplit(":", 1)[0].strip("[]")

        remote_ip = _normalize_ip(ip_raw) if ip_raw else ""
        if not remote_ip:
            continue

        remote_port = 0
        try:
            rp_raw = item.get("remote_port")
            if rp_raw is None:
                # Try to parse from remote_addr / raddr
                addr = str(item.get("remote_addr") or item.get("raddr") or "")
                rp_raw = addr.rsplit(":", 1)[-1] if ":" in addr else 0
            remote_port = int(rp_raw or 0)
        except (ValueError, TypeError):
            pass

        hostname = str(item.get("remote_hostname") or item.get("hostname") or "")
        domain_entropy = 0.0
        if hostname:
            label = hostname.split(".")[0] if "." in hostname else hostname
            domain_entropy = _shannon_entropy(label)

        result.append({
            "pid":             int(item.get("pid") or 0),
            "process_name":    str(item.get("process_name") or item.get("name") or
                                   item.get("process") or ""),
            "remote_ip":       remote_ip,
            "remote_port":     remote_port,
            "local_port":      int(item.get("local_port") or 0),
            "state":           str(item.get("state") or "ESTABLISHED"),
            "session_start":   float(item.get("session_start") or
                                     item.get("start_ts") or time.time()),
            "duration_secs":   float(item.get("duration_secs") or
                                     item.get("duration") or 0),
            "remote_hostname": hostname,
            "domain_age_days": item.get("domain_age_days"),   # None = unknown
            "domain_entropy":  domain_entropy,
            "bytes_sent":      int(item.get("bytes_sent") or 0),
            "bytes_recv":      int(item.get("bytes_recv") or 0),
            "raw":             item,
        })
    return result


def ingest_processes(raw: Any) -> list[dict]:
    """Normalize process list to {pid, name, ppid, parent_name, exe, cmdline}."""
    items = raw if isinstance(raw, list) else (
        raw.get("processes", []) if isinstance(raw, dict) else []
    )
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("pid") or 0)
        except (ValueError, TypeError):
            pid = 0
        try:
            ppid = int(item.get("ppid") or item.get("parent_pid") or 0)
        except (ValueError, TypeError):
            ppid = 0
        result.append({
            "pid":         pid,
            "name":        str(item.get("name") or item.get("process_name") or ""),
            "ppid":        ppid,
            "parent_name": str(item.get("parent_name") or ""),
            "exe":         str(item.get("exe") or item.get("path") or ""),
            "cmdline":     str(item.get("cmdline") or item.get("cmd") or ""),
            "raw":         item,
        })
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def detect_beaconing(
    agent_id: str,
    sessions: list[dict],
    db:       Any,
) -> list[dict]:
    """
    CRITICAL: Automated C2 beaconing via Coefficient-of-Variation (CoV) analysis.

    For each (pid, remote_ip) pair, a new connection event is registered each
    time session_start changes.  Timestamps are tracked in a module-level
    30-minute sliding window.  When >= 5 events accumulate, CoV of inter-event
    intervals is computed.  CoV < 0.15 indicates a highly regular (automated)
    connection pattern — the hallmark of C2 implants and RATs.

    Suppressions: CDN IPs, private IPs, browsers, approved VPN processes.
    """
    hits = []
    now  = time.time()

    for sess in sessions:
        pid       = sess.get("pid", 0)
        remote_ip = sess.get("remote_ip", "")
        proc_name = _binary_name(sess.get("process_name") or "")
        sess_start = sess.get("session_start", now)

        if not pid or not remote_ip:
            continue
        if _is_private_ip(remote_ip):
            continue
        if _is_cdn_ip(remote_ip):
            continue
        if proc_name in BROWSER_PROCESSES:
            continue
        if proc_name in APPROVED_VPN_PROCESSES:
            continue

        baseline_key = f"beacon_start:{pid}:{remote_ip}"
        baseline     = await _load_baseline(agent_id, baseline_key, db)
        last_start   = (baseline or {}).get("session_start")

        is_new_session = (last_start is None) or (abs(sess_start - float(last_start)) > 5)
        if not is_new_session:
            continue

        await _save_baseline(agent_id, baseline_key, {
            "session_start": sess_start, "pid": pid, "remote_ip": remote_ip,
        }, db)

        window_key = f"{agent_id}:{pid}:{remote_ip}"
        window = [t for t in _beacon_windows.get(window_key, []) if now - t < BEACON_WINDOW_SECS]
        window.append(now)
        _beacon_windows[window_key] = window

        if len(window) < BEACON_MIN_CONNECTIONS:
            continue

        sorted_ts = sorted(window)
        intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
        if not intervals:
            continue

        cov = _coefficient_of_variation(intervals)
        if cov >= BEACON_COV_THRESHOLD:
            continue

        avg_interval = statistics.mean(intervals)
        remote_port  = sess.get("remote_port", 0)

        hits.append({
            "rule_id":   "cc:beaconing",
            "severity":  "critical",
            "title": (
                f"C2 beaconing: {proc_name} (PID {pid}) → {remote_ip} "
                f"[CoV={cov:.3f}, {len(window)} connections in {BEACON_WINDOW_SECS//60} min]"
            ),
            "description": (
                f"Process '{proc_name}' (PID {pid}) connected to {remote_ip}:{remote_port} "
                f"{len(window)} times within {BEACON_WINDOW_SECS // 60} minutes with a "
                f"Coefficient of Variation (CoV) of {cov:.3f} — well below the beaconing "
                f"threshold of {BEACON_COV_THRESHOLD}. Average inter-connection interval: "
                f"{avg_interval:.1f}s. "
                f"A CoV near zero indicates a clock-driven, automated process. "
                f"C2 implants, RATs, and backdoors call home on a fixed schedule; "
                f"legitimate applications have irregular connection patterns."
            ),
            "evidence": {
                "pid":               pid,
                "process_name":      proc_name,
                "remote_ip":         remote_ip,
                "remote_port":       remote_port,
                "remote_hostname":   sess.get("remote_hostname", ""),
                "connection_count":  len(window),
                "cov":               round(cov, 4),
                "avg_interval_secs": round(avg_interval, 1),
                "window_secs":       BEACON_WINDOW_SECS,
                "cov_threshold":     BEACON_COV_THRESHOLD,
                "intervals_sample":  [round(iv, 1) for iv in intervals[:10]],
            },
            "raw_telemetry": [sess.get("raw", sess)],
            "mitre_tactic":    "Command and Control",
            "mitre_technique": "T1071.001",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "DE.CM-7"],
                "CIS":  ["13.6", "13.8"],
                "ISO":  ["A.12.4.1"],
                "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Capture traffic: `tcpdump -i any 'host {remote_ip}' -w /tmp/beacon.pcap`. "
                f"2. Identify binary: `lsof -p {pid}` for the executable path. "
                f"3. Inspect process lineage: `pstree -p {pid}` — find the launch mechanism. "
                f"4. Block {remote_ip} at egress firewall and DNS if unauthorized. "
                f"5. Extract memory from PID {pid} for shellcode analysis if injection is suspected. "
                f"6. Preserve evidence, isolate endpoint, and escalate to IR."
            ),
            "false_positive_notes": (
                "Legitimate update agents (Sparkle, AutoUpdate, CrashReporter) check in on "
                "regular schedules. CDN and browser traffic is suppressed. "
                "Cloud sync tools with fixed polling intervals may appear — add to "
                "APPROVED_LONG_SESSION_PROCESSES or configure a per-agent allowlist."
            ),
            "item_key":  f"cc:beacon:{pid}:{remote_ip}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["critical"],
            "tags":      ["beaconing", "c2", "T1071.001"],
        })

    return hits


def detect_reverse_shell(
    agent_id:  str,
    sessions:  list[dict],
    processes: list[dict],
) -> list[dict]:
    """
    CRITICAL: Shell binary with ESTABLISHED outbound connection to an external IP.

    A shell process (bash, sh, zsh, powershell, etc.) that has an active
    outbound TCP connection to a non-private, non-CDN host is a definitive
    reverse shell indicator.

    Also triggers when a process with an external connection has spawned a shell
    subprocess (detected via parent–child process lineage cross-join).
    """
    pid_map: dict[int, dict] = {p["pid"]: p for p in processes if p.get("pid")}

    hits = []
    for sess in sessions:
        pid       = sess.get("pid", 0)
        proc_name = _binary_name(sess.get("process_name") or "")
        state     = str(sess.get("state") or "").upper()
        remote_ip = sess.get("remote_ip", "")

        if state and state not in ("ESTABLISHED",):
            continue
        if not remote_ip or _is_private_ip(remote_ip):
            continue
        if _is_cdn_ip(remote_ip):
            continue
        if proc_name in BROWSER_PROCESSES:
            continue

        is_shell = proc_name in SHELL_BINARIES

        # Cross-section: process with external conn has a shell child
        is_shell_parent = False
        if not is_shell and pid:
            for proc in processes:
                if (proc.get("ppid") == pid and
                        _binary_name(proc.get("name") or "") in SHELL_BINARIES):
                    is_shell_parent = True
                    break

        if not is_shell and not is_shell_parent:
            continue

        remote_port = sess.get("remote_port", 0)
        shell_child_name = ""
        if is_shell_parent:
            for proc in processes:
                if proc.get("ppid") == pid and _binary_name(proc.get("name") or "") in SHELL_BINARIES:
                    shell_child_name = _binary_name(proc.get("name") or "")
                    break

        hits.append({
            "rule_id":   "cc:reverse_shell",
            "severity":  "critical",
            "title": (
                f"Reverse shell: {proc_name} (PID {pid}) → {remote_ip}:{remote_port}"
                + (f" [spawned {shell_child_name}]" if is_shell_parent else "")
            ),
            "description": (
                f"Shell process '{proc_name}' (PID {pid}) has an ESTABLISHED outbound "
                f"TCP connection to external host {remote_ip}:{remote_port}. "
                f"A shell binary with an active external connection is the definitive "
                f"signature of a reverse shell — the adversary has interactive command "
                f"execution on this endpoint via {remote_ip}."
                + (f" Additionally, '{proc_name}' (PID {pid}) spawned a child shell "
                   f"'{shell_child_name}', indicating commands from the C2 channel are "
                   f"being piped into a local shell for execution."
                   if is_shell_parent else "")
            ),
            "evidence": {
                "pid":              pid,
                "process_name":     proc_name,
                "remote_ip":        remote_ip,
                "remote_port":      remote_port,
                "remote_hostname":  sess.get("remote_hostname", ""),
                "state":            state,
                "is_shell":         is_shell,
                "is_shell_parent":  is_shell_parent,
                "shell_child_name": shell_child_name,
                "duration_secs":    sess.get("duration_secs", 0),
            },
            "raw_telemetry": [sess.get("raw", sess)],
            "mitre_tactic":    "Execution",
            "mitre_technique": "T1059.004",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "RS.RP-1"],
                "CIS":  ["13.6", "10.2"],
                "ISO":  ["A.16.1.5"],
                "SOC2": ["CC7.3"],
            },
            "recommended_action": (
                f"CRITICAL — active reverse shell likely in progress. "
                f"1. IMMEDIATELY isolate the endpoint from the network. "
                f"2. Kill the shell process: `kill -9 {pid}`. "
                f"3. Block {remote_ip} at all egress controls. "
                f"4. Capture memory before process termination if possible. "
                f"5. Check persistence: LaunchAgents, LaunchDaemons, crontabs, ~/.bashrc. "
                f"6. Rotate all credentials accessible from this endpoint. "
                f"7. Escalate to IR and begin full forensic investigation."
            ),
            "false_positive_notes": (
                "SSH remote sessions show a shell with an external connection on port 22. "
                "Distinguish by remote_port: 22 = SSH (expected), any other port = suspicious. "
                "Remote dev tools (VS Code tunnels) may appear similarly — verify the remote "
                "hostname against known authorized remote development infrastructure."
            ),
            "item_key":  f"cc:revshell:{pid}:{remote_ip}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["critical"],
            "tags":      ["reverse_shell", "c2", "T1059.004"],
        })

    return hits


def detect_nat64_abuse(
    agent_id: str,
    sessions: list[dict],
) -> list[dict]:
    """
    HIGH: IPv4 C2 communication hidden inside NAT64 (64:ff9b::/96).

    The IANA NAT64 prefix 64:ff9b::/96 encodes IPv4 addresses into IPv6.
    Non-VPN processes sending traffic to this prefix are bypassing IPv4 egress
    controls by embedding the C2 IPv4 address inside an IPv6 packet (T1572).
    """
    hits = []
    for sess in sessions:
        remote_ip = sess.get("remote_ip", "")
        if not _is_nat64(remote_ip):
            continue

        proc_name = _binary_name(sess.get("process_name") or "")
        if proc_name in APPROVED_VPN_PROCESSES:
            continue

        pid           = sess.get("pid", 0)
        remote_port   = sess.get("remote_port", 0)
        embedded_ipv4 = _extract_nat64_ipv4(remote_ip)

        hits.append({
            "rule_id":   "cc:nat64_abuse",
            "severity":  "high",
            "title": (
                f"NAT64 C2 evasion: {proc_name} (PID {pid}) → {remote_ip} "
                f"[embedded IPv4: {embedded_ipv4}]"
            ),
            "description": (
                f"Process '{proc_name}' (PID {pid}) is communicating with "
                f"{remote_ip}:{remote_port} — an IPv6 address inside the IANA NAT64 "
                f"translation prefix 64:ff9b::/96. "
                f"This prefix maps IPv6 packets to IPv4 address {embedded_ipv4}. "
                f"Non-VPN processes using NAT64 are a strong indicator of an adversary "
                f"bypassing IPv4-only egress firewall rules by encoding a C2 IPv4 "
                f"address inside IPv6 traffic."
            ),
            "evidence": {
                "pid":             pid,
                "process_name":    proc_name,
                "nat64_address":   remote_ip,
                "embedded_ipv4":   embedded_ipv4,
                "remote_port":     remote_port,
                "remote_hostname": sess.get("remote_hostname", ""),
            },
            "raw_telemetry": [sess.get("raw", sess)],
            "mitre_tactic":    "Command and Control",
            "mitre_technique": "T1572",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "PR.AC-5"],
                "CIS":  ["13.6", "9.4"],
                "ISO":  ["A.13.1.2"],
                "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"1. Block all traffic from this endpoint to 64:ff9b::/96 at the firewall. "
                f"2. Also block {embedded_ipv4} at IPv4 egress controls. "
                f"3. Kill process {pid} and identify the binary: `lsof -p {pid}`. "
                f"4. Determine if NAT64 is a legitimate config on this network "
                f"   (rare in enterprise — if not deployed, this is deliberate evasion). "
                f"5. Review DNS AAAA query logs for 64:ff9b::/96 lookups from this endpoint."
            ),
            "false_positive_notes": (
                "NAT64 is legitimate in IPv6-only environments (iOS simulators, certain "
                "cloud networks). Approved VPN clients are suppressed. If the endpoint is "
                "on a validated IPv6-only network, add the process to APPROVED_VPN_PROCESSES "
                "or configure a network-level allowlist for this agent."
            ),
            "item_key":  f"cc:nat64:{pid}:{remote_ip}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["high"],
            "tags":      ["nat64", "tunneling", "c2_evasion", "T1572"],
        })

    return hits


def detect_long_lived_session(
    agent_id: str,
    sessions: list[dict],
) -> list[dict]:
    """
    HIGH: Non-browser, non-approved process holding a session >1 h on port 443/80.

    Legitimate long-lived HTTPS sessions come from browsers, backup clients, and
    cloud sync tools.  An unrecognized process maintaining a persistent connection
    on a web port to an external IP is a strong covert C2 indicator (T1071.001).
    """
    hits = []
    for sess in sessions:
        duration    = sess.get("duration_secs", 0)
        remote_port = sess.get("remote_port", 0)
        remote_ip   = sess.get("remote_ip", "")
        proc_name   = _binary_name(sess.get("process_name") or "")
        pid         = sess.get("pid", 0)

        if duration < LONG_SESSION_THRESHOLD_SECS:
            continue
        if remote_port not in (443, 80, 8443, 8080):
            continue
        if not remote_ip or _is_private_ip(remote_ip):
            continue
        if _is_cdn_ip(remote_ip):
            continue
        if proc_name in APPROVED_LONG_SESSION_PROCESSES:
            continue
        if proc_name in BROWSER_PROCESSES:
            continue

        duration_h = duration / 3600

        hits.append({
            "rule_id":   "cc:long_lived_session",
            "severity":  "high",
            "title": (
                f"Long-lived {remote_port}/TCP: {proc_name} (PID {pid}) → "
                f"{remote_ip} [{duration_h:.1f}h]"
            ),
            "description": (
                f"Process '{proc_name}' (PID {pid}) has held an ESTABLISHED TCP "
                f"connection to {remote_ip}:{remote_port} for {duration_h:.1f} hours "
                f"({duration:.0f}s). "
                f"Unrecognized processes maintaining persistent long-lived connections "
                f"on web ports (443, 80) are characteristic of covert C2 channels using "
                f"TLS to blend with normal web traffic."
            ),
            "evidence": {
                "pid":             pid,
                "process_name":    proc_name,
                "remote_ip":       remote_ip,
                "remote_port":     remote_port,
                "remote_hostname": sess.get("remote_hostname", ""),
                "duration_secs":   duration,
                "duration_hours":  round(duration_h, 2),
                "threshold_secs":  LONG_SESSION_THRESHOLD_SECS,
            },
            "raw_telemetry": [sess.get("raw", sess)],
            "mitre_tactic":    "Command and Control",
            "mitre_technique": "T1071.001",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "DE.CM-7"],
                "CIS":  ["13.6"],
                "ISO":  ["A.12.4.1"],
                "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Identify the binary: `lsof -p {pid}` or `ps -p {pid} -o comm,args`. "
                f"2. Inspect TLS certificate: "
                f"`openssl s_client -connect {remote_ip}:{remote_port}`. "
                f"3. Capture and analyze traffic pattern for C2 characteristics "
                f"   (beaconing, short keep-alive data, asymmetric bytes). "
                f"4. If not recognized business traffic: isolate endpoint and kill PID {pid}. "
                f"5. Check persistence mechanisms: crontabs, LaunchAgents, startup items."
            ),
            "false_positive_notes": (
                "Corporate VPN clients, cloud backup tools (Backblaze, Crashplan), "
                "and cloud sync tools (Dropbox, OneDrive) hold long-lived HTTPS connections — "
                "these are suppressed if listed in APPROVED_LONG_SESSION_PROCESSES. "
                "Browser and CDN traffic is suppressed. Add legitimate enterprise tools "
                "to the approved process list."
            ),
            "item_key":  f"cc:longsess:{pid}:{remote_ip}:{remote_port}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["high"],
            "tags":      ["long_session", "c2", "T1071.001"],
        })

    return hits


def detect_connection_burst(
    agent_id: str,
    sessions: list[dict],
) -> list[dict]:
    """
    HIGH: Single PID connects to >50 distinct external IPs in the current snapshot.

    Rapid multi-target connection bursts from one process indicate:
    – DGA malware attempting to reach any available C2 server
    – Network scanning for lateral movement (T1046)
    – Data exfiltration to distributed drop servers
    – Botnet propagation
    """
    pid_ips:   dict[int, set[str]]   = {}
    pid_procs: dict[int, str]        = {}
    pid_raw:   dict[int, list[dict]] = {}

    for sess in sessions:
        pid       = sess.get("pid", 0)
        remote_ip = sess.get("remote_ip", "")
        proc_name = _binary_name(sess.get("process_name") or "")

        if not pid or not remote_ip:
            continue
        if _is_private_ip(remote_ip):
            continue

        pid_ips.setdefault(pid, set()).add(remote_ip)
        pid_procs[pid] = proc_name
        pid_raw.setdefault(pid, []).append(sess.get("raw", sess))

    hits = []
    for pid, ips in pid_ips.items():
        if len(ips) < CONN_BURST_THRESHOLD:
            continue

        proc_name = pid_procs.get(pid, "")
        if proc_name in BROWSER_PROCESSES:
            continue

        hits.append({
            "rule_id":   "cc:connection_burst",
            "severity":  "high",
            "title": (
                f"Connection burst: {proc_name} (PID {pid}) → "
                f"{len(ips)} distinct IPs [threshold: {CONN_BURST_THRESHOLD}]"
            ),
            "description": (
                f"Process '{proc_name}' (PID {pid}) currently has active connections to "
                f"{len(ips)} distinct external IP addresses — {len(ips) - CONN_BURST_THRESHOLD} "
                f"above the threshold of {CONN_BURST_THRESHOLD}. "
                f"Single-process multi-target bursts are characteristic of DGA malware "
                f"trying to reach any available C2 server, network scanning for lateral "
                f"movement, or rapid data exfiltration to distributed drop sites."
            ),
            "evidence": {
                "pid":               pid,
                "process_name":      proc_name,
                "distinct_ip_count": len(ips),
                "threshold":         CONN_BURST_THRESHOLD,
                "sample_ips":        sorted(ips)[:10],
            },
            "raw_telemetry": pid_raw.get(pid, [])[:5],
            "mitre_tactic":    "Command and Control",
            "mitre_technique": "T1572",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "DE.CM-7"],
                "CIS":  ["13.6", "13.8"],
                "ISO":  ["A.12.4.1"],
                "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Identify and inspect the binary for PID {pid}: `lsof -p {pid}`. "
                f"2. Confirm whether this is an authorized scanner (Nessus, Qualys, etc.). "
                f"3. If unauthorized: isolate endpoint and kill process {pid}. "
                f"4. Inspect DNS queries for high-entropy names (DGA patterns). "
                f"5. Block all {len(ips)} destination IPs at the egress firewall."
            ),
            "false_positive_notes": (
                "Authorized network vulnerability scanners (Nessus, Qualys, Rapid7) "
                "produce legitimate large-scale connection bursts. Browser processes are "
                "excluded. Whitelist authorized scanner processes via the agent allowlist "
                "configuration or add to APPROVED_LONG_SESSION_PROCESSES."
            ),
            "item_key":  f"cc:burst:{pid}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["high"],
            "tags":      ["connection_burst", "scanning", "c2", "T1572"],
        })

    return hits


def detect_suspicious_domain(
    agent_id: str,
    sessions: list[dict],
) -> list[dict]:
    """
    MEDIUM: Connection to a DGA domain (Shannon entropy > 3.5) or recently
    registered domain (< 30 days old).

    High-entropy labels indicate Domain Generation Algorithm activity.
    Recently registered domains are disproportionately used for C2
    infrastructure before threat feeds can blocklist them.
    """
    hits         = []
    seen_domains: set[str] = set()

    for sess in sessions:
        hostname = sess.get("remote_hostname", "")
        if not hostname or hostname in seen_domains:
            continue

        remote_ip  = sess.get("remote_ip", "")
        proc_name  = _binary_name(sess.get("process_name") or "")
        pid        = sess.get("pid", 0)
        entropy    = sess.get("domain_entropy", 0.0)
        age_days   = sess.get("domain_age_days")   # None = unknown

        if not remote_ip or _is_private_ip(remote_ip):
            continue
        if _is_cdn_ip(remote_ip):
            continue
        if proc_name in BROWSER_PROCESSES:
            continue

        reasons = []
        if entropy > DOMAIN_ENTROPY_THRESHOLD:
            reasons.append(
                f"high-entropy label (entropy={entropy:.2f} > {DOMAIN_ENTROPY_THRESHOLD})"
            )
        if age_days is not None and age_days < DOMAIN_AGE_THRESHOLD_DAYS:
            reasons.append(
                f"recently registered ({age_days}d old < {DOMAIN_AGE_THRESHOLD_DAYS}d threshold)"
            )
        if not reasons:
            continue

        seen_domains.add(hostname)
        reason_str = " and ".join(reasons)
        first_label = hostname.split(".")[0] if "." in hostname else hostname

        hits.append({
            "rule_id":   "cc:suspicious_domain",
            "severity":  "medium",
            "title":     f"Suspicious domain: '{hostname}' ({reason_str})",
            "description": (
                f"Process '{proc_name}' (PID {pid}) connected to '{hostname}' ({remote_ip}), "
                f"which is flagged as suspicious: {reason_str}. "
                + (
                    f"The first label '{first_label}' has a Shannon entropy of {entropy:.2f} bits, "
                    f"above the DGA threshold of {DOMAIN_ENTROPY_THRESHOLD}. "
                    f"High-entropy labels are generated algorithmically (DGA) to create domains "
                    f"that rotate faster than threat feeds can blocklist them. "
                    if entropy > DOMAIN_ENTROPY_THRESHOLD else ""
                )
                + (
                    f"Domains registered within the last {DOMAIN_AGE_THRESHOLD_DAYS} days "
                    f"are disproportionately abused for C2 infrastructure. "
                    if age_days is not None and age_days < DOMAIN_AGE_THRESHOLD_DAYS else ""
                )
            ),
            "evidence": {
                "pid":                 pid,
                "process_name":        proc_name,
                "remote_ip":           remote_ip,
                "remote_port":         sess.get("remote_port", 0),
                "hostname":            hostname,
                "first_label":         first_label,
                "domain_entropy":      round(entropy, 4),
                "domain_age_days":     age_days,
                "reasons":             reasons,
                "entropy_threshold":   DOMAIN_ENTROPY_THRESHOLD,
                "age_threshold_days":  DOMAIN_AGE_THRESHOLD_DAYS,
            },
            "raw_telemetry": [sess.get("raw", sess)],
            "mitre_tactic":    "Command and Control",
            "mitre_technique": "T1568.002",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "DE.CM-7"],
                "CIS":  ["9.2", "13.6"],
                "ISO":  ["A.12.4.1"],
                "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. WHOIS lookup: `whois {hostname}`. "
                f"2. Check VirusTotal, Shodan, and Cisco Talos for '{hostname}'. "
                f"3. Analyze all DNS queries from this endpoint for DGA patterns. "
                f"4. If confirmed malicious: block '{hostname}' at DNS/proxy and "
                f"   {remote_ip} at egress firewall. "
                f"5. Trace the connection back to PID {pid}: check launch mechanism "
                f"   and parent chain."
            ),
            "false_positive_notes": (
                "Legitimate new services may use recently registered domains. "
                "Some CDNs and URL shorteners use high-entropy subdomains. "
                "CDN IPs and browser traffic are suppressed. "
                "If the domain is a known business service, add to the domain allowlist."
            ),
            "item_key":  f"cc:susp_domain:{hostname}",
            "category":  "network",
            "source":    "rule:covert_channel",
            "score":     SEVERITY_SCORES["medium"],
            "tags":      ["suspicious_domain", "dga", "c2", "T1568.002"],
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
        "category":    hit.get("category", "network"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:covert_channel"),
        "tags":        hit.get("tags", ["covert_channel"]),
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
    Main entry point. Called by AttackLensEngine._dispatch() per payload.

    'processes'        → populate cross-section process cache, no findings
    'connections'      → run all 6 covert channel detection passes
    'network_sessions' → same as connections
    """
    if section == "processes":
        _process_cache[agent_id] = ingest_processes(data)
        return []

    if section not in ("connections", "network_sessions"):
        return []

    sessions  = ingest_connections(data)
    processes = _process_cache.get(agent_id, [])

    if not sessions:
        return []

    raw_hits: list[dict] = []

    for det_fn, det_args in [
        (detect_beaconing,        (agent_id, sessions, db)),
        (detect_nat64_abuse,      (agent_id, sessions)),
        (detect_long_lived_session,(agent_id, sessions)),
        (detect_connection_burst, (agent_id, sessions)),
        (detect_suspicious_domain,(agent_id, sessions)),
    ]:
        try:
            result = det_fn(*det_args)
            # detect_beaconing is async; others are sync
            if hasattr(result, "__await__"):
                result = await result
            raw_hits.extend(result)
        except Exception as exc:
            log.debug("%s error agent=%s: %s", det_fn.__name__, agent_id, exc)

    try:
        raw_hits.extend(detect_reverse_shell(agent_id, sessions, processes))
    except Exception as exc:
        log.debug("detect_reverse_shell error agent=%s: %s", agent_id, exc)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Dedup suppressed: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))

    if alerts:
        log.info("CovertChannel: agent=%s section=%s sessions=%d alerts=%d",
                 agent_id, section, len(sessions), len(alerts))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS — 21 TP + FP tests across all detection conditions
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    print("=== covert_channel.py — Test Harness ===\n")

    class MockDB:
        def __init__(self):
            self._state: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._state.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, fingerprint, ts):
            self._state[f"{agent_id}:{ns}:{key}"] = {"fingerprint": fingerprint, "ts": ts}

    def _sess(pid, proc, remote_ip, port=443, state="ESTABLISHED",
              duration=0, session_start=None, hostname="", age=None):
        s = {
            "pid": pid, "process_name": proc, "remote_ip": remote_ip,
            "remote_port": port, "state": state, "duration_secs": duration,
            "session_start": session_start or time.time(),
            "remote_hostname": hostname,
            "domain_age_days": age,
            "raw": {"pid": pid, "proc": proc, "remote_ip": remote_ip},
        }
        if hostname:
            label = hostname.split(".")[0] if "." in hostname else hostname
            s["domain_entropy"] = _shannon_entropy(label)
        else:
            s["domain_entropy"] = 0.0
        return s

    async def run_tests():
        # ── 1. _normalize_ip ──────────────────────────────────────────────────
        assert _normalize_ip("192.168.1.1")      == "192.168.1.1"
        assert _normalize_ip("  8.8.8.8  ")      == "8.8.8.8"
        assert _normalize_ip("[::1]")             == "::1"
        assert _normalize_ip("not-an-ip")         == ""
        assert _normalize_ip("")                  == ""
        print("[PASS] 1. _normalize_ip")

        # ── 2. _is_private_ip / _is_cdn_ip ───────────────────────────────────
        assert _is_private_ip("10.0.0.1")        is True
        assert _is_private_ip("192.168.1.100")   is True
        assert _is_private_ip("127.0.0.1")       is True
        assert _is_private_ip("8.8.8.8")         is False
        assert _is_cdn_ip("104.16.0.1")          is True    # Cloudflare
        assert _is_cdn_ip("151.101.0.1")         is True    # Fastly
        assert _is_cdn_ip("1.2.3.4")             is False
        print("[PASS] 2. _is_private_ip / _is_cdn_ip")

        # ── 3. _is_nat64 / _extract_nat64_ipv4 ───────────────────────────────
        nat64_addr = "64:ff9b::192.0.2.1"
        assert _is_nat64(nat64_addr)              is True
        assert _is_nat64("2001:db8::1")           is False
        assert _is_nat64("8.8.8.8")               is False
        extracted = _extract_nat64_ipv4(nat64_addr)
        assert extracted == "192.0.2.1", f"Got: {extracted}"
        print("[PASS] 3. _is_nat64 / _extract_nat64_ipv4")

        # ── 4. _binary_name ───────────────────────────────────────────────────
        assert _binary_name("/usr/bin/bash")          == "bash"
        assert _binary_name("C:\\Windows\\cmd.exe")   == "cmd"
        assert _binary_name("powershell.exe")         == "powershell"
        assert _binary_name("")                       == ""
        assert _binary_name("/usr/bin/python3")       == "python3"
        print("[PASS] 4. _binary_name")

        # ── 5. _shannon_entropy ───────────────────────────────────────────────
        assert abs(_shannon_entropy("aaaa") - 0.0) < 0.001   # uniform = 0
        assert abs(_shannon_entropy("ab") - 1.0)   < 0.001   # 2 equal = 1 bit
        assert _shannon_entropy("0123456789abcdef")  > 3.5    # 16 unique = 4.0 bits
        assert _shannon_entropy("")                  == 0.0
        print("[PASS] 5. _shannon_entropy")

        # ── 6. _coefficient_of_variation ─────────────────────────────────────
        assert _coefficient_of_variation([10.0, 10.0, 10.0]) == 0.0
        assert _coefficient_of_variation([10.0])              == float("inf")
        assert _coefficient_of_variation([1.0, 100.0, 50.0])  > 0.5
        print("[PASS] 6. _coefficient_of_variation")

        # ── 7. TP: Beaconing — regular intervals, CoV < threshold ─────────────
        db_b   = MockDB()
        b_agent, b_pid, b_ip = "agent-beacon", 5555, "5.6.7.8"
        t_base = time.time() - 240
        # Pre-populate 4 evenly-spaced timestamps (60s apart, last one 60s ago)
        wk = f"{b_agent}:{b_pid}:{b_ip}"
        _beacon_windows[wk] = [t_base + i * 60 for i in range(4)]  # t, t+60, t+120, t+180
        # Set baseline so session_start t_base+240 is treated as a new session
        await _save_baseline(b_agent, f"beacon_start:{b_pid}:{b_ip}",
                             {"session_start": t_base, "pid": b_pid, "remote_ip": b_ip}, db_b)
        beacon_sess = _sess(b_pid, "updater", b_ip, port=4444, session_start=t_base + 240.0)
        beacon_hits = await detect_beaconing(b_agent, [beacon_sess], db_b)
        assert len(beacon_hits) == 1, f"Expected 1, got {len(beacon_hits)}"
        assert beacon_hits[0]["severity"] == "critical"
        assert beacon_hits[0]["evidence"]["cov"] < BEACON_COV_THRESHOLD
        assert beacon_hits[0]["evidence"]["connection_count"] == 5
        print(f"[PASS] 7. TP beaconing: {beacon_hits[0]['title'][:70]}")

        # ── 8. FP: Beaconing — CDN IP suppressed ─────────────────────────────
        db_cdn  = MockDB()
        cdn_wk  = "agent-cdn:1111:104.16.0.1"
        _beacon_windows[cdn_wk] = [time.time() - i * 60 for i in range(4)]
        cdn_hits = await detect_beaconing("agent-cdn", [_sess(1111, "spyware", "104.16.0.1")], db_cdn)
        assert cdn_hits == [], f"CDN IP should be suppressed, got {len(cdn_hits)}"
        print("[PASS] 8. FP beaconing CDN IP suppressed")

        # ── 9. FP: Beaconing — irregular intervals, CoV above threshold ───────
        db_irr   = MockDB()
        irr_agent, irr_pid, irr_ip = "agent-irr", 9999, "9.9.9.9"
        irr_wk   = f"{irr_agent}:{irr_pid}:{irr_ip}"
        t_irr    = time.time() - 600
        # Very uneven intervals: 5s, 400s, 10s, 300s
        _beacon_windows[irr_wk] = [t_irr, t_irr+5, t_irr+405, t_irr+415]
        await _save_baseline(irr_agent, f"beacon_start:{irr_pid}:{irr_ip}",
                             {"session_start": t_irr, "pid": irr_pid, "remote_ip": irr_ip}, db_irr)
        irr_hits = await detect_beaconing(irr_agent, [_sess(irr_pid, "someapp", irr_ip, session_start=t_irr + 715)], db_irr)
        assert irr_hits == [], f"Irregular CoV should not alert, got {len(irr_hits)}"
        print("[PASS] 9. FP beaconing irregular intervals (high CoV): suppressed")

        # ── 10. FP: Beaconing — browser process suppressed ───────────────────
        db_br = MockDB()
        br_wk = "agent-br:2222:7.7.7.7"
        _beacon_windows[br_wk] = [time.time() - i * 60 for i in range(4)]
        br_hits = await detect_beaconing("agent-br", [_sess(2222, "chrome", "7.7.7.7")], db_br)
        assert br_hits == [], "Browser process should be suppressed"
        print("[PASS] 10. FP beaconing browser process suppressed")

        # ── 11. TP: Reverse shell — shell binary + external connection ─────────
        # 45.33.32.x is Linode (ARIN-registered public range, not private/doc)
        revsh_sess = _sess(3333, "bash", "45.33.32.156", port=4444)
        revsh_hits = detect_reverse_shell("agent-revsh", [revsh_sess], [])
        assert len(revsh_hits) == 1, f"Expected 1 hit, got {len(revsh_hits)}"
        assert revsh_hits[0]["severity"] == "critical"
        assert revsh_hits[0]["evidence"]["is_shell"] is True
        assert "T1059.004" in revsh_hits[0]["mitre_technique"]
        print(f"[PASS] 11. TP reverse shell: {revsh_hits[0]['title'][:70]}")

        # ── 12. FP: Reverse shell — private IP suppressed ────────────────────
        priv_sess = _sess(3334, "bash", "192.168.1.10", port=4444)
        assert detect_reverse_shell("agent-priv", [priv_sess], []) == []
        print("[PASS] 12. FP reverse shell private IP suppressed")

        # ── 13. FP: Reverse shell — non-shell process, no child shell ─────────
        py_sess = _sess(3335, "python3", "45.33.32.157", port=8080)
        assert detect_reverse_shell("agent-py", [py_sess], []) == []
        print("[PASS] 13. FP reverse shell non-shell process (python3): suppressed")

        # ── 14. TP: NAT64 abuse — non-VPN process ─────────────────────────────
        # 64:ff9b::2d21:2001 encodes 45.33.32.1 (0x2d=45, 0x21=33, 0x20=32, 0x01=1)
        nat64_sess = _sess(4444, "malware", "64:ff9b::2d21:2001", port=443)
        nat64_hits = detect_nat64_abuse("agent-nat64", [nat64_sess])
        assert len(nat64_hits) == 1, f"Expected 1 hit, got {len(nat64_hits)}"
        assert nat64_hits[0]["severity"] == "high"
        assert nat64_hits[0]["evidence"]["embedded_ipv4"] == "45.33.32.1"
        assert "T1572" in nat64_hits[0]["mitre_technique"]
        print(f"[PASS] 14. TP NAT64 abuse: {nat64_hits[0]['title'][:70]}")

        # ── 15. FP: NAT64 — VPN process suppressed ───────────────────────────
        vpn_nat64 = _sess(4445, "openvpn", "64:ff9b::2d21:2002", port=1194)
        assert detect_nat64_abuse("agent-vpn", [vpn_nat64]) == []
        print("[PASS] 15. FP NAT64 VPN process suppressed")

        # ── 16. TP: Long-lived session — unexpected process ────────────────────
        long_sess = _sess(5555, "malbeacon", "45.33.32.158", port=443, duration=7200)
        long_hits = detect_long_lived_session("agent-long", [long_sess])
        assert len(long_hits) == 1, f"Expected 1 hit, got {len(long_hits)}"
        assert long_hits[0]["severity"] == "high"
        assert long_hits[0]["evidence"]["duration_hours"] == 2.0
        print(f"[PASS] 16. TP long-lived session: {long_hits[0]['title'][:70]}")

        # ── 17. FP: Long-lived session — approved process (zoom) ──────────────
        zoom_sess = _sess(5556, "zoom", "45.33.32.159", port=443, duration=7200)
        assert detect_long_lived_session("agent-zoom", [zoom_sess]) == []
        print("[PASS] 17. FP long-lived session approved process (zoom): suppressed")

        # ── 18. TP: Connection burst — >50 distinct IPs ───────────────────────
        # Build 60 sessions to distinct IPs in 45.x.x.x public range
        burst_sessions = [
            _sess(6666, "scanner", f"45.{(i // 200) + 1}.{i % 200}.1", port=80)
            for i in range(CONN_BURST_THRESHOLD + 10)
        ]
        burst_hits = detect_connection_burst("agent-burst", burst_sessions)
        assert len(burst_hits) == 1, f"Expected 1 hit, got {len(burst_hits)}"
        assert burst_hits[0]["severity"] == "high"
        assert burst_hits[0]["evidence"]["distinct_ip_count"] >= CONN_BURST_THRESHOLD
        print(f"[PASS] 18. TP connection burst: {burst_hits[0]['title'][:70]}")

        # ── 19. FP: Connection burst — below threshold ────────────────────────
        small_burst = [_sess(6667, "legit", f"46.{i}.1.1", port=80) for i in range(10)]
        assert detect_connection_burst("agent-small", small_burst) == []
        print("[PASS] 19. FP connection burst below threshold: suppressed")

        # ── 20. TP: Suspicious domain — high entropy (DGA) ───────────────────
        dga_hostname = "0123456789abcdef.evil.com"   # first label = 16 unique chars → 4.0 bits
        dga_sess = _sess(7777, "malware", "45.33.32.160", port=80, hostname=dga_hostname)
        dga_hits = detect_suspicious_domain("agent-dga", [dga_sess])
        assert len(dga_hits) == 1, f"Expected 1 hit, got {len(dga_hits)}"
        assert dga_hits[0]["severity"] == "medium"
        assert dga_hits[0]["evidence"]["domain_entropy"] > DOMAIN_ENTROPY_THRESHOLD
        assert "T1568.002" in dga_hits[0]["mitre_technique"]
        print(f"[PASS] 20. TP suspicious domain (DGA entropy): {dga_hits[0]['title'][:70]}")

        # ── 21. TP: Suspicious domain — new registration ──────────────────────
        new_domain_sess = _sess(7778, "malware", "45.33.32.161", port=80,
                                hostname="legit-looking.com", age=5)
        new_d_hits = detect_suspicious_domain("agent-newdom", [new_domain_sess])
        assert len(new_d_hits) == 1, f"Expected 1 hit, got {len(new_d_hits)}"
        assert "recently registered" in new_d_hits[0]["evidence"]["reasons"][0]
        print(f"[PASS] 21. TP suspicious domain (new registration): {new_d_hits[0]['title'][:70]}")

        # ── Alert builder: all mandatory fields ───────────────────────────────
        sample_hit = revsh_hits[0]
        alert = build_alert(sample_hit, "agent-001", "corp-laptop-01")
        required = {
            "alert_id", "severity", "title", "description", "affected_asset",
            "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
            "compliance_controls", "recommended_action", "false_positive_notes",
            "timestamp_utc",
        }
        missing = required - set(alert.keys())
        assert not missing, f"Missing mandatory fields: {missing}"
        assert alert["affected_asset"] == "corp-laptop-01"
        assert alert["alert_id"]   # non-empty UUID
        print("[PASS] Alert builder: all mandatory fields present")

        # ── Dedup ─────────────────────────────────────────────────────────────
        _dedup_cache.clear()
        _rate_counter.clear()
        assert _should_suppress("ag1", "cc:test", "k1") is False   # first → pass
        assert _should_suppress("ag1", "cc:test", "k1") is True    # repeat → suppress
        assert _should_suppress("ag1", "cc:test", "k2") is False   # diff key → pass
        assert _should_suppress("ag2", "cc:test", "k1") is False   # diff agent → pass
        print("[PASS] Dedup: first=pass, repeat=suppress, diff_key=pass, diff_agent=pass")

        print("\n=== All 21 tests passed ===")

    asyncio.run(run_tests())
