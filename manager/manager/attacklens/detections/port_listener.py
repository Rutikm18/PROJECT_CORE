"""
manager/manager/attacklens/detections/port_listener.py
Production-grade unauthorized port listener and backdoor detection.

Detects new, unexpected, or high-risk network listeners that indicate malware
persistence, reverse shells, or unauthorized remote-access services.

Telemetry sections handled:
  ports, listening_ports, netstat, ss_output, net_tcp_connection

COMPLIANCE MAPPING:
  NIST CSF:    PR.AC-3 (Remote access managed), DE.CM-1 (Network monitored),
               DE.CM-7 (Monitoring for unauthorized personnel / connections)
  CIS Control: 4.8 (Uninstall or disable unnecessary services)
  SOC 2:       CC6.6
  ISO 27001:   A.13.1.1 (Network controls), A.9.4.2 (Secure log-on)

MITRE ATT&CK:
  T1049   (System Network Connections Discovery)
  T1571   (Non-Standard Port)
  T1543   (Create or Modify System Process)
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

log = logging.getLogger("manager.attacklens.detections.port_listener")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Ports that are dangerous when exposed on non-loopback addresses.
HIGH_RISK_PORTS: frozenset[int] = frozenset({
    22,     # SSH (if unexpected)
    23,     # Telnet
    445,    # SMB
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    8080,   # Generic HTTP alt (often used by C2 frameworks)
    4444,   # Metasploit default
    4445,   # Metasploit alt
    1080,   # SOCKS proxy
    31337,  # Back Orifice / "elite" port
    12345,  # NetBus / many RATs
    65535,  # Commonly used by malware (max port)
    2375,   # Docker daemon API (unencrypted)
    15672,  # RabbitMQ management UI
    6666,   # IRC / many RATs
    6667,   # IRC
    1234,   # Generic RAT
    5554,   # Sasser worm
    9999,   # Common backdoor
    54321,  # Back Orifice 2000
})

# Processes that are permitted to open wildcard (0.0.0.0 / ::) listeners.
# This is the global fallback; per-agent approved baselines override it.
#
# ALL ENTRIES MUST BE lowercase: the agent's port collector emits process names
# lowercased, and _is_approved_wildcard() compares against name.lower(). The
# previous mixed-case entries (e.g. "mDNSResponder", "ControlCenter") therefore
# NEVER matched — a latent bug that let stock-macOS daemons keep generating
# wildcard-bind alerts. Verified against real agent data.
APPROVED_WILDCARD_BIND_PROCS: frozenset[str] = frozenset({
    # Web / app servers
    "nginx", "apache", "apache2", "httpd", "lighttpd", "caddy", "traefik",
    # Database servers
    "postgres", "postgresql", "mysqld", "mongod", "redis-server", "memcached",
    # System services
    "sshd", "slapd", "named", "bind", "ntpd", "chronyd",
    # Container / orchestration
    "dockerd", "containerd", "kubelet", "kube-apiserver",
    # Message brokers
    "rabbitmq", "beam.smp", "kafka",
    # Java app servers
    "java",
    # Windows services
    "system", "lsass.exe", "services.exe", "svchost.exe", "spoolsv.exe",
    # macOS system daemons that legitimately wildcard-bind. Without these,
    # `wildcard_bind` fired CRITICAL on stock macOS — verified against real
    # agent data, these processes alone produced ~16k false positives:
    #   netbiosd          → SMB/NetBIOS name service on 137/138
    #   rapportd          → Continuity / Handoff
    #   sharingd          → AirDrop / screen & file sharing
    #   mdnsresponder     → Bonjour (5353)
    #   controlcenter     → AirPlay receiver
    #   identityservicesd → iMessage / FaceTime relay
    "launchd", "mdnsresponder", "mdnsresponderhelper", "configd",
    "netbiosd", "rapportd", "sharingd", "identityservicesd", "remoted",
    "apsd", "nehelper", "controlcenter", "airplayxpchelper", "rapport",
    # Found by REMOVING the ephemeral-port blind spot below and replaying real
    # agent data: these macOS daemons wildcard-bind on high/ephemeral ports
    # doing normal OS work, not exposure. The fix is naming the specific
    # process — not exempting a port range, which would have hidden a real
    # backdoor choosing the same range on purpose.
    #   airportd         → WiFi interface management
    #   replicatord       → Continuity/Handoff state replication
    #   symptomsd         → diagnostics/symptom framework
    #   syslogd           → BSD syslog relay
    #   wifip2pd          → WiFi Direct/AirDrop peer-to-peer
    #   wifivelocityd     → WiFi performance telemetry
    "airportd", "replicatord", "symptomsd", "syslogd",
    "wifip2pd", "wifivelocityd",
    # Consumer browsers — bind ephemeral ports on 0.0.0.0 for IPC / Spotify Connect /
    # browser remote-debugging. Not server exposure; suppress port noise for these.
    # "zen" is a Firefox fork. "arc" / "brave" / "vivaldi" / "opera" are Chromium.
    "zen", "arc", "brave", "vivaldi", "opera",
    "firefox", "waterfox", "librewolf",
    # Media & communication apps
    "spotify", "vlc", "handbrake", "plexmediaplayer", "plexamp",
    "discord", "slack", "zoom", "msteams", "teams", "webex",
    "skype", "telegram", "signal", "whatsapp",
    # Cloud storage daemons
    "dropbox", "onedrive", "googledrivefs", "box",
    # macOS built-in media apps (may bind ephemeral for AirPlay)
    "music", "tv", "podcasts",
})

# Vendor/process-name PREFIXES whose subprocesses legitimately wildcard-bind.
# Exact-name matching alone missed these — e.g. Docker's listener process is
# `com.docker.backend`, not `dockerd`; macOS daemons are reverse-DNS named.
APPROVED_WILDCARD_PREFIXES: tuple[str, ...] = (
    "com.apple.",     # any first-party Apple daemon (reverse-DNS named)
    "com.docker.",    # Docker Desktop proxy/backend processes
    "com.microsoft.", # VS Code / Edge background services
    "org.mozilla.",
)

# macOS app subprocesses follow the "<App> Helper [(role)]" convention
# (Electron, Chromium, VS Code, Slack, …). They bind localhost/ephemeral ports
# for IPC. Treated as approved for wildcard-bind specifically.
APPROVED_WILDCARD_NAME_SUBSTRINGS: tuple[str, ...] = (
    " helper",        # "Code Helper (Plugin)", "Google Chrome Helper", …
)

# Processes considered "known services" — not flagged as unknown.
# Lowercase for the same reason as APPROVED_WILDCARD_BIND_PROCS — the agent
# emits lowercased process names and detect_unknown_process matches by name.
KNOWN_SERVICE_PROCS: frozenset[str] = frozenset(APPROVED_WILDCARD_BIND_PROCS) | frozenset({
    "python", "python3", "ruby", "node", "nodejs", "perl", "php",
    "gunicorn", "uvicorn", "puma", "unicorn", "thin", "passenger",
    "haproxy", "envoy", "istio-proxy", "varnishd",
    "elasticsearch", "kibana", "logstash", "opensearch",
    "zookeeper", "etcd", "consul", "vault",
    "syncthing", "tailscaled", "openvpn", "wireguard",
    "smbd", "nmbd", "winbindd",
    "com.apple.webkit.networking", "com.apple.webkit.webcontent",
})

# Expected port ranges per process name.
# If a process opens a port outside its allowed ranges: HIGH alert.
PROCESS_PORT_MAP: dict[str, list[tuple[int, int]]] = {
    "sshd":         [(22, 22)],
    "nginx":        [(80, 80), (443, 443), (8000, 9000)],
    "apache":       [(80, 80), (443, 443)],
    "apache2":      [(80, 80), (443, 443)],
    "httpd":        [(80, 80), (443, 443)],
    "postgres":     [(5432, 5432)],
    "mysqld":       [(3306, 3306), (33060, 33060)],  # 33060 = MySQL X Protocol
    "mongod":       [(27017, 27019)],
    "redis-server": [(6379, 6379)],
    "memcached":    [(11211, 11211)],
    "named":        [(53, 53)],
    "ntpd":         [(123, 123)],
    "chronyd":      [(123, 123)],
    "rabbitmq":     [(5672, 5672), (15672, 15672), (25672, 25672)],
    "beam.smp":     [(5672, 5672), (15672, 15672), (25672, 25672)],
    "dockerd":      [(2375, 2376)],
    "mDNSResponder": [(5353, 5353)],
    "elasticsearch": [(9200, 9200), (9300, 9300)],
}

# Bind addresses that are "external" (not loopback)
_LOOPBACK_ADDRS: frozenset[str] = frozenset({
    "127.0.0.1", "::1", "localhost",
})

# Approved baseline config path — optional, loaded from disk
BASELINE_CONFIG_PATH: str = os.environ.get(
    "PORT_LISTENER_BASELINE", "config/port_listener_baseline.json"
)

# Dedup: 60-minute window; key resets if process_name or path changes
DEDUP_WINDOW_SECS: int       = 3600
RATE_LIMIT_MAX_PER_HOUR: int = 60

# Sections that carry port/listener telemetry
PORT_SECTIONS: frozenset[str] = frozenset({
    "ports", "listening_ports", "netstat", "ss_output",
    "net_tcp_connection", "open_ports",
})

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}

# Maps "agent_id:port:pid" → {"process_name": str, "process_path": str}
# Used to detect process identity changes that reset suppression.
_listener_identity: dict[str, dict] = {}

# Per-agent port→pid map for duplicate-listener detection
_port_pid_map: dict[str, dict[int, list[int]]] = {}

# Approved baseline cache
_baseline_cache: dict                = {}
_baseline_loaded_at: float           = 0.0

# ─────────────────────────────────────────────────────────────────────────────
# DEDUP / RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _listener_changed(agent_id: str, port: int, pid: int,
                       proc_name: str, proc_path: str) -> bool:
    """Return True if the process identity for this port:pid has changed."""
    key = f"{agent_id}:{port}:{pid}"
    prev = _listener_identity.get(key, {})
    changed = (prev.get("process_name") != proc_name or
               prev.get("process_path") != proc_path)
    _listener_identity[key] = {"process_name": proc_name, "process_path": proc_path}
    return changed


def _should_suppress(agent_id: str, rule_id: str, item: str,
                     port: int = 0, pid: int = 0,
                     proc_name: str = "", proc_path: str = "") -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)

    # Identity change resets suppression for this key
    identity_changed = (port > 0 and pid > 0 and
                        _listener_changed(agent_id, port, pid, proc_name, proc_path))
    if identity_changed:
        _dedup_cache.pop(key, None)

    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit: agent=%s module=port_listener", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False

# ─────────────────────────────────────────────────────────────────────────────
# BASELINE LOADING
# ─────────────────────────────────────────────────────────────────────────────

def _load_baseline() -> dict:
    """
    Load the approved listener baseline. Reloads every 5 minutes.

    Format:
      {
        "approved_listeners": [
          {"port": 22, "proto": "tcp", "process_name": "sshd", "bind_ip": "0.0.0.0"}
        ],
        "approved_wildcard_procs": ["nginx", "postgres"]
      }
    """
    global _baseline_cache, _baseline_loaded_at
    now = time.time()
    if now - _baseline_loaded_at < 300 and _baseline_cache:
        return _baseline_cache
    try:
        p = Path(BASELINE_CONFIG_PATH)
        if p.exists():
            with open(p) as f:
                _baseline_cache = json.load(f)
        else:
            _baseline_cache = {"approved_listeners": [], "approved_wildcard_procs": []}
        _baseline_loaded_at = now
    except Exception as exc:
        log.debug("Port listener baseline load failed: %s", exc)
        _baseline_cache = {"approved_listeners": [], "approved_wildcard_procs": []}
    return _baseline_cache


def _is_approved_listener(port: int, proto: str, proc_name: str, bind_ip: str) -> bool:
    baseline = _load_baseline()
    for entry in baseline.get("approved_listeners", []):
        if (entry.get("port") == port
                and entry.get("proto", "tcp") == proto
                and entry.get("process_name", "").lower() == proc_name.lower()
                and entry.get("bind_ip", "0.0.0.0") == bind_ip):
            return True
    return False


def _is_approved_wildcard(proc_name: str) -> bool:
    """True if this process is allowed to bind a wildcard (0.0.0.0/::) listener.

    Matches by, in order: per-agent baseline, exact name, vendor reverse-DNS
    prefix (com.apple./com.docker./…), or the macOS "<App> Helper" subprocess
    convention. Exact-name-only matching previously missed `com.docker.backend`
    and editor/Electron helpers, which dominated the false-positive volume.
    """
    name = (proc_name or "").lower().strip()
    if not name:
        return False
    baseline = _load_baseline()
    extra = {p.lower() for p in baseline.get("approved_wildcard_procs", [])}
    if name in APPROVED_WILDCARD_BIND_PROCS or name in extra:
        return True
    if name.startswith(APPROVED_WILDCARD_PREFIXES):
        return True
    if any(sub in name for sub in APPROVED_WILDCARD_NAME_SUBSTRINGS):
        return True
    return False


# Port 0 is not a real, connectable network surface (you cannot dial "port
# 0" as a client) — collectors emit it as a sentinel when no actual listening
# port could be resolved. Excluded as a data-validity guard, not a coverage
# decision.
#
# Earlier this rule ALSO blanket-exempted the whole ephemeral range
# (>=49152), reasoning that high ports are "overwhelmingly transient IPC
# churn". Replaying real agent data after removing that exemption surfaced
# only legitimate macOS daemons (airportd, syslogd, wifip2pd, ...) — now
# named explicitly in APPROVED_WILDCARD_BIND_PROCS above — not a return of
# the false-positive volume. Keeping the port-range exemption would have
# created exactly the blind spot a real backdoor could exploit on purpose:
# detection must cover every port, and unapproved processes are now flagged
# regardless of which port they choose.
def _is_invalid_port(port: int) -> bool:
    return port == 0

# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION — normalize across all platform formats
# ─────────────────────────────────────────────────────────────────────────────

def _is_external(bind_ip: str) -> bool:
    return bind_ip not in _LOOPBACK_ADDRS and bind_ip not in ("", "none")


def _is_wildcard(bind_ip: str) -> bool:
    return bind_ip in ("0.0.0.0", "::", "*", "")


def _new_listener_severity(bind_ip: str) -> str:
    """Risk-tier a genuinely new listener instead of blanket CRITICAL.

    A new listener is noteworthy, but severity should track reachability. Known
    C2 / high-risk ports are separately flagged CRITICAL by detect_high_risk_port,
    so new_listener tiers by exposure to avoid critical-spamming every new
    service (e.g. nginx on 443):
      external / wildcard bind → high   (reachable off-host)
      loopback bind            → low    (local only — low blast radius)
      otherwise                → medium
    """
    if bind_ip in _LOOPBACK_ADDRS:
        return "low"
    if _is_external(bind_ip) or _is_wildcard(bind_ip):
        return "high"
    return "medium"


_SS_RE = re.compile(
    r"(?P<proto>tcp\S*)\s+\S+\s+\S+\s+(?P<local>\S+)\s+",
)
_NETSTAT_RE = re.compile(
    r"(?P<proto>tcp\S*)\s+\d+\s+\d+\s+(?P<local>\S+)\s+\S+\s+LISTEN\s+(?P<pid>\d+)/(?P<proc>\S+)",
)


def _parse_addr(addr: str) -> tuple[str, int]:
    """Split 'ip:port' or '[::]:port' into (ip, port)."""
    addr = addr.strip()
    if addr.startswith("["):
        # IPv6: [::]:22 or [::1]:22
        bracket_end = addr.rfind("]")
        ip = addr[1:bracket_end]
        try:
            port = int(addr[bracket_end + 2:])
        except (ValueError, IndexError):
            port = 0
        return ip, port
    if addr.count(":") == 1:
        parts = addr.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return parts[0], 0
    # bare port (Windows Get-NetTCPConnection style)
    try:
        return "0.0.0.0", int(addr)
    except ValueError:
        return addr, 0


def ingest_listeners(section: str, data: Any) -> list[dict]:
    """
    Normalize raw listener telemetry into:
      [{port, proto, bind_ip, pid, process_name, process_path,
        process_signature_valid, parent_pid, cmdline, interface}]
    """
    listeners: list[dict] = []

    if isinstance(data, dict):
        if "listeners" in data:
            data = data["listeners"]
        elif "ports" in data:
            data = data["ports"]
        elif "Value" in data or "LocalPort" in data:
            # Single Windows Get-NetTCPConnection record
            data = [data]

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            # Try generic normalized format first.
            # "bind_addr" is the ACTUAL field both macOS and Windows PortsCollector
            # emit (agent/os/macos/collectors/network.py, os/windows/collectors/
            # network.py) — it was missing from this chain entirely, so every real
            # agent listener fell through to the "0.0.0.0" default regardless of
            # its true bind address. That fed detect_wildcard_bind() a false
            # "world-accessible" verdict for every single listener, including ones
            # bound to 127.0.0.1 only — a fleet-wide false-positive generator.
            bind_ip = str(
                item.get("bind_addr") or item.get("bind_ip") or item.get("bind_address") or
                item.get("local_address") or item.get("LocalAddress") or
                item.get("address") or "0.0.0.0"
            )
            port_val = (item.get("port") or item.get("local_port") or
                        item.get("LocalPort") or 0)
            try:
                port = int(port_val)
            except (TypeError, ValueError):
                # Try parsing from "address:port" string
                _, port = _parse_addr(str(port_val))

            proc_name = str(
                item.get("process_name") or item.get("proc_name") or
                item.get("process") or item.get("OwningProcess") or ""
            ).lower().strip()
            # Strip full path to basename for comparison
            if "/" in proc_name or "\\" in proc_name:
                proc_name = re.split(r"[/\\]", proc_name)[-1]

            listeners.append({
                "port":                    port,
                "proto":                   str(item.get("proto") or item.get("protocol") or "tcp").lower(),
                "bind_ip":                 bind_ip,
                "pid":                     int(item.get("pid") or item.get("PID") or item.get("OwningProcessId") or 0),
                "process_name":            proc_name,
                "process_path":            str(item.get("process_path") or item.get("exe") or item.get("Path") or ""),
                "process_signature_valid": bool(item.get("process_signature_valid", True)),
                "parent_pid":              int(item.get("parent_pid") or item.get("ppid") or 0),
                "cmdline":                 str(item.get("cmdline") or item.get("command_line") or ""),
                "interface":               str(item.get("interface") or ""),
            })
        return listeners

    if isinstance(data, str):
        # Parse `ss -tlnp` or `netstat -tlnp` raw output
        for line in data.splitlines():
            line = line.strip()
            if not line or "LISTEN" not in line.upper():
                continue
            # netstat -tlnp format: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd"
            m = _NETSTAT_RE.search(line)
            if m:
                ip, port = _parse_addr(m.group("local"))
                try:
                    pid = int(m.group("pid"))
                except ValueError:
                    pid = 0
                listeners.append({
                    "port": port, "proto": "tcp",
                    "bind_ip": ip, "pid": pid,
                    "process_name": m.group("proc").lower().strip(),
                    "process_path": "", "process_signature_valid": True,
                    "parent_pid": 0, "cmdline": "", "interface": "",
                })
                continue
            # ss -tlnp format: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))"
            parts = line.split()
            if len(parts) >= 5:
                ip, port = _parse_addr(parts[4])
                proc_m = re.search(r'"([^"]+)",pid=(\d+)', line)
                proc_name = proc_m.group(1).lower() if proc_m else ""
                pid = int(proc_m.group(2)) if proc_m else 0
                listeners.append({
                    "port": port, "proto": parts[0].lower(),
                    "bind_ip": ip, "pid": pid,
                    "process_name": proc_name,
                    "process_path": "", "process_signature_valid": True,
                    "parent_pid": 0, "cmdline": "", "interface": "",
                })

    return listeners

# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _make_alert(
    agent_id: str,
    hostname: str,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    mitre_technique: str,
    evidence: dict,
    raw_listener: dict,
) -> dict:
    tactic_map = {
        "T1049":  "Discovery",
        "T1571":  "Command and Control",
        "T1543":  "Persistence",
    }
    return {
        "alert_id":            str(uuid.uuid4()),
        "severity":            severity,
        "title":               title,
        "description":         description,
        "affected_asset":      hostname or agent_id,
        "mitre_tactic":        tactic_map.get(mitre_technique, "Defense Evasion"),
        "mitre_technique":     mitre_technique,
        "evidence":            evidence,
        "raw_telemetry":       raw_listener,
        "compliance_controls": [
            "NIST CSF PR.AC-3", "NIST CSF DE.CM-1", "NIST CSF DE.CM-7",
            "CIS Control 4.8", "SOC 2 CC6.6",
            "ISO 27001 A.13.1.1", "ISO 27001 A.9.4.2",
        ],
        "recommended_action":  _recommended_action(rule_id, raw_listener),
        "false_positive_notes": _false_positive_note(rule_id),
        "timestamp_utc":       datetime.now(timezone.utc).isoformat(),
        "agent_id":            agent_id,
        "detection_module":    "port_listener",
        "rule_id":             rule_id,
    }


def _recommended_action(rule_id: str, lst: dict) -> str:
    port = lst.get("port", 0)
    proc = lst.get("process_name", "unknown")
    actions = {
        "new_listener":     f"Investigate process '{proc}' on port {port}. "
                            "Kill if unauthorized and audit for persistence mechanisms.",
        "wildcard_bind":    f"Process '{proc}' should not bind to 0.0.0.0/::. "
                            "Restrict binding to loopback or specific interface.",
        "high_risk_port":   f"Port {port} is high-risk. Firewall the port if not required, "
                            "or verify the service is authorized and patched.",
        "unknown_process":  f"Unknown/unsigned process '{proc}' opened a listener. "
                            "Terminate, quarantine, and scan for malware.",
        "port_mismatch":    f"Process '{proc}' opened an unexpected port {port}. "
                            "Verify if this is an authorized configuration change.",
        "duplicate_listener": f"Two processes share port {port}. One may be masquerading. "
                              "Kill the unexpected process and review.",
    }
    return actions.get(rule_id, "Investigate the flagged network listener.")


def _false_positive_note(rule_id: str) -> str:
    notes = {
        "new_listener":      "Newly deployed services may not yet be in the approved baseline. "
                             "Update baseline after verifying the service is authorized.",
        "wildcard_bind":     "Some legitimate services require 0.0.0.0 binding. "
                             "Add to approved_wildcard_procs in baseline if authorized.",
        "high_risk_port":    "Port 22 is expected on SSH servers. "
                             "Confirm the service identity before escalating.",
        "unknown_process":   "Developer tools (python, ruby) may open listeners during testing. "
                             "Check process context and parent before escalating.",
        "port_mismatch":     "Custom configurations may legitimately use non-standard ports. "
                             "Verify with the application owner.",
        "duplicate_listener": "Port reuse is possible during service restarts. "
                              "Verify both PIDs are from the same authorized process.",
    }
    return notes.get(rule_id, "Review process context before escalating.")

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION PASSES
# ─────────────────────────────────────────────────────────────────────────────

async def detect_new_listener(
    agent_id: str,
    listeners: list[dict],
    db: Any,
) -> list[dict]:
    """
    CRITICAL — Listener not present in the per-agent approved baseline.
    Baseline is persisted in entity state as a set of fingerprints.
    """
    findings: list[dict] = []

    raw_state = await db.get_entity_state(agent_id, "port_listener", "listener_baseline")
    stored: dict[str, dict] = {}
    if raw_state:
        try:
            stored = json.loads(raw_state) if isinstance(raw_state, str) else raw_state
        except Exception:
            stored = {}

    # First-run seeding: with no prior baseline we are seeing the host's
    # EXISTING listeners for the first time — they are not "newly appeared".
    # Record them as baseline and emit nothing; alert only on listeners that
    # show up in LATER snapshots. Removes the enrollment FP storm where every
    # listening service fired a CRITICAL new-listener alert.
    first_run = not stored

    updated = dict(stored)
    for lst in listeners:
        port      = lst["port"]
        proto     = lst["proto"]
        proc_name = lst["process_name"]
        bind_ip   = lst["bind_ip"]
        if not port:
            continue

        fp = hashlib.sha256(
            f"{port}:{proto}:{proc_name}:{bind_ip}".encode()
        ).hexdigest()[:20]

        # Known from config baseline → skip
        if _is_approved_listener(port, proto, proc_name, bind_ip):
            updated[fp] = {"port": port, "proto": proto,
                           "process_name": proc_name, "bind_ip": bind_ip}
            continue

        if fp in stored:
            # Already seen — not new
            continue

        updated[fp] = {"port": port, "proto": proto,
                       "process_name": proc_name, "bind_ip": bind_ip}

        if first_run:
            continue   # pre-existing listener at first observation — not new

        item_key = f"{port}:{lst['pid']}"
        if _should_suppress(agent_id, "new_listener", item_key,
                            port=port, pid=lst["pid"],
                            proc_name=proc_name, proc_path=lst["process_path"]):
            continue

        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity=_new_listener_severity(bind_ip),
            rule_id="new_listener",
            title=f"New unauthorized listener: {proc_name} on port {port}/{proto}",
            description=(
                f"Process '{proc_name}' (PID {lst['pid']}) opened a new listening port "
                f"{port}/{proto} on {bind_ip} that is not in the approved baseline. "
                "This may indicate malware, a reverse shell, or an unauthorized service."
            ),
            mitre_technique="T1543",
            evidence={
                "port": port, "proto": proto, "bind_ip": bind_ip,
                "pid": lst["pid"], "process_name": proc_name,
                "process_path": lst["process_path"],
                "parent_pid": lst["parent_pid"],
                "cmdline": lst["cmdline"],
                "fingerprint": fp,
            },
            raw_listener=lst,
        ))

    try:
        await db.set_entity_state(
            agent_id, "port_listener", "listener_baseline",
            updated, datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        log.debug("Failed to persist listener baseline agent=%s: %s", agent_id, exc)

    return findings


def detect_wildcard_bind(agent_id: str, listeners: list[dict]) -> list[dict]:
    """MEDIUM — A non-approved process exposes a *service* port to all interfaces,
    on ANY port — including the high/ephemeral range. There is no port-based
    exemption: a real backdoor can choose any port it likes, so detection must
    cover all of them. See _is_invalid_port for the one narrow, data-validity
    exception (port 0 — not a real connectable surface).

    Wildcard binding alone is a weak exposure signal, not a confirmed compromise,
    so it is MEDIUM (was CRITICAL — which, combined with no vendor-prefix
    filtering and a since-removed blanket ephemeral-port exemption, made this
    the single largest false-positive source in the system: ~16k critical
    alerts on stock macOS/Docker/VS Code). The genuinely-dangerous variants are
    escalated by dedicated rules:
      - known-bad / RAT ports        → detect_high_risk_port (HIGH)
      - unsigned / unknown binaries  → detect_unknown_process (HIGH)

    Suppressed only for approved processes (system/vendor/dev helpers — see
    APPROVED_WILDCARD_BIND_PROCS). The item_key is keyed on (process, port) —
    NOT the volatile pid — so the same exposed service dedups across snapshots
    instead of minting a new finding each cycle.
    """
    findings: list[dict] = []
    for lst in listeners:
        if not _is_wildcard(lst["bind_ip"]):
            continue
        proc_name = lst["process_name"]
        port      = lst["port"]
        if _is_approved_wildcard(proc_name):
            continue
        # Empty process name = port scanner couldn't resolve the PID to a name.
        # Without a name we can't evaluate risk — skip rather than false-alerting.
        # The high-risk-port rule (which fires on port NUMBER alone) still covers
        # genuinely-dangerous ports even when the process name is unknown.
        if not proc_name:
            continue
        if _is_invalid_port(port):
            continue
        # Stable dedup identity: process + port, never the churning pid. Keeps
        # one finding per genuinely-exposed service across re-scans.
        item_key = f"{proc_name or 'unknown'}:{port}"
        if _should_suppress(agent_id, "wildcard_bind", item_key,
                            port=port, pid=lst["pid"],
                            proc_name=proc_name, proc_path=lst["process_path"]):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="medium",
            rule_id="wildcard_bind",
            title=f"Service exposed on all interfaces: {proc_name} on {lst['bind_ip']}:{port}",
            description=(
                f"Process '{proc_name}' (PID {lst['pid']}) is listening on {lst['bind_ip']}:{port}, "
                "exposing the port to every network interface rather than loopback only. "
                "Review whether this service needs to be externally reachable."
            ),
            mitre_technique="T1571",
            evidence={
                "port": lst["port"], "proto": lst["proto"],
                "bind_ip": lst["bind_ip"], "pid": lst["pid"],
                "process_name": proc_name,
                "process_path": lst["process_path"],
                "parent_pid": lst["parent_pid"],
                "cmdline": lst["cmdline"],
            },
            raw_listener=lst,
        ))
    return findings


def detect_high_risk_port(agent_id: str, listeners: list[dict]) -> list[dict]:
    """HIGH — High-risk port exposed on a non-loopback address."""
    findings: list[dict] = []
    for lst in listeners:
        port = lst["port"]
        if port not in HIGH_RISK_PORTS:
            continue
        if not _is_external(lst["bind_ip"]) and not _is_wildcard(lst["bind_ip"]):
            continue
        # Approved services (e.g. com.docker.backend exposing 8080 / 15672 for
        # Docker Desktop's built-in HTTP/RabbitMQ) are not threats.
        if _is_approved_wildcard(lst["process_name"]):
            continue
        # Empty name means the port scanner couldn't resolve the PID.
        # Without an identity we can't assess risk — skip rather than false-alert.
        if not lst["process_name"]:
            continue
        item_key = f"{port}:{lst['pid']}"
        if _should_suppress(agent_id, "high_risk_port", item_key,
                            port=port, pid=lst["pid"],
                            proc_name=lst["process_name"], proc_path=lst["process_path"]):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high",
            rule_id="high_risk_port",
            title=f"High-risk port {port} externally exposed by {lst['process_name']}",
            description=(
                f"Port {port} is known to be associated with malicious activity or remote access tools. "
                f"Process '{lst['process_name']}' (PID {lst['pid']}) is listening on "
                f"{lst['bind_ip']}:{port}, which is externally reachable."
            ),
            mitre_technique="T1571",
            evidence={
                "port": port, "proto": lst["proto"],
                "bind_ip": lst["bind_ip"], "pid": lst["pid"],
                "process_name": lst["process_name"],
                "process_path": lst["process_path"],
            },
            raw_listener=lst,
        ))
    return findings


def detect_unknown_process(agent_id: str, listeners: list[dict]) -> list[dict]:
    """HIGH — Unknown/unsigned process opened a listener port."""
    findings: list[dict] = []
    for lst in listeners:
        proc_name = lst["process_name"]
        sig_valid = lst["process_signature_valid"]
        if proc_name in KNOWN_SERVICE_PROCS:
            continue
        if sig_valid:
            continue
        item_key = f"{lst['port']}:{lst['pid']}"
        if _should_suppress(agent_id, "unknown_process", item_key,
                            port=lst["port"], pid=lst["pid"],
                            proc_name=proc_name, proc_path=lst["process_path"]):
            continue
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high",
            rule_id="unknown_process",
            title=f"Unknown unsigned process listening: {proc_name} on port {lst['port']}",
            description=(
                f"Process '{proc_name}' (PID {lst['pid']}) has an invalid or missing "
                f"code signature and opened listening port {lst['port']}/{lst['proto']}. "
                "Unknown unsigned listeners are a strong indicator of malware or a backdoor."
            ),
            mitre_technique="T1543",
            evidence={
                "port": lst["port"], "proto": lst["proto"],
                "bind_ip": lst["bind_ip"], "pid": lst["pid"],
                "process_name": proc_name,
                "process_path": lst["process_path"],
                "process_signature_valid": sig_valid,
                "parent_pid": lst["parent_pid"],
                "cmdline": lst["cmdline"],
            },
            raw_listener=lst,
        ))
    return findings


def detect_port_mismatch(agent_id: str, listeners: list[dict]) -> list[dict]:
    """HIGH — Process opened a port outside its expected range."""
    findings: list[dict] = []
    for lst in listeners:
        proc_name = lst["process_name"]
        port      = lst["port"]
        expected  = PROCESS_PORT_MAP.get(proc_name)
        if expected is None:
            continue
        in_range = any(lo <= port <= hi for lo, hi in expected)
        if in_range:
            continue
        item_key = f"{port}:{lst['pid']}"
        if _should_suppress(agent_id, "port_mismatch", item_key,
                            port=port, pid=lst["pid"],
                            proc_name=proc_name, proc_path=lst["process_path"]):
            continue
        allowed_ranges = ", ".join(f"{lo}-{hi}" for lo, hi in expected)
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="high",
            rule_id="port_mismatch",
            title=f"Process-port mismatch: {proc_name} on unexpected port {port}",
            description=(
                f"Process '{proc_name}' (PID {lst['pid']}) is listening on port {port}, "
                f"but its expected port range is [{allowed_ranges}]. "
                "This may indicate a misconfiguration, compromise, or a masquerading process."
            ),
            mitre_technique="T1571",
            evidence={
                "port": port, "proto": lst["proto"],
                "bind_ip": lst["bind_ip"], "pid": lst["pid"],
                "process_name": proc_name,
                "process_path": lst["process_path"],
                "allowed_ranges": [{"lo": lo, "hi": hi} for lo, hi in expected],
                "cmdline": lst["cmdline"],
            },
            raw_listener=lst,
        ))
    return findings


def detect_duplicate_listener(agent_id: str, listeners: list[dict]) -> list[dict]:
    """MEDIUM — Two distinct PIDs are both listening on the same port."""
    findings: list[dict] = []

    # Build port → [(pid, proc_name)] map
    port_map: dict[int, list[tuple[int, str]]] = {}
    for lst in listeners:
        port = lst["port"]
        pid  = lst["pid"]
        if not port or not pid:
            continue
        port_map.setdefault(port, []).append((pid, lst["process_name"], lst))

    for port, entries in port_map.items():
        # Deduplicate by pid
        seen_pids: dict[int, tuple[str, dict]] = {}
        for pid, proc_name, lst in entries:
            if pid not in seen_pids:
                seen_pids[pid] = (proc_name, lst)
        if len(seen_pids) < 2:
            continue

        # If every process on this port is an approved service (or a browser
        # helper IPC process), the "masquerading" interpretation doesn't apply.
        # Also suppress when one of the entries has an empty process name and the
        # other is an approved service — the empty name is a data-quality artifact
        # from the port scanner failing to resolve the PID's process name (common
        # for Docker Desktop's internal network namespace listeners).
        all_approved = all(
            not name or _is_approved_wildcard(name) or " helper" in name.lower()
            for _, (name, _) in seen_pids.items()
        )
        any_approved = any(
            _is_approved_wildcard(name)
            for _, (name, _) in seen_pids.items()
        )
        # Suppress fully-approved sets OR sets where one process is approved and
        # the other is unnamed (which is the same service seen twice under the OS).
        has_unnamed = any(not name for _, (name, _) in seen_pids.items())
        if all_approved or (any_approved and has_unnamed):
            continue

        pids = list(seen_pids.keys())
        item_key = f"{port}:{':'.join(str(p) for p in sorted(pids))}"
        if _should_suppress(agent_id, "duplicate_listener", item_key):
            continue

        proc_list = [{"pid": pid, "process_name": name}
                     for pid, (name, _) in seen_pids.items()]
        # Use the first listener's raw dict as representative
        _, rep_lst = list(seen_pids.values())[0]
        findings.append(_make_alert(
            agent_id=agent_id, hostname="",
            severity="medium",
            rule_id="duplicate_listener",
            title=f"Duplicate listener on port {port} from {len(seen_pids)} processes",
            description=(
                f"Port {port} has active LISTEN sockets from {len(seen_pids)} distinct "
                f"processes: {', '.join(e['process_name'] for e in proc_list)}. "
                "One process may be masquerading as the legitimate service."
            ),
            mitre_technique="T1049",
            evidence={
                "port": port,
                "processes": proc_list,
                "pid_count": len(seen_pids),
            },
            raw_listener=rep_lst,
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
    if section not in PORT_SECTIONS:
        return []

    listeners = ingest_listeners(section, data)
    if not listeners:
        return []

    findings: list[dict] = []

    for f in await detect_new_listener(agent_id, listeners, db):
        f["affected_asset"] = hostname or agent_id
        findings.append(f)

    for det_fn in (
        detect_wildcard_bind,
        detect_high_risk_port,
        detect_unknown_process,
        detect_port_mismatch,
        detect_duplicate_listener,
    ):
        for f in det_fn(agent_id, listeners):
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
        _listener_identity.clear()
        _port_pid_map.clear()
        _baseline_cache.clear()
        global _baseline_loaded_at
        _baseline_loaded_at = 0.0

    def make_listener(**kw) -> dict:
        defaults = {
            "port": 4444, "proto": "tcp", "bind_ip": "0.0.0.0",
            "pid": 1234, "process_name": "nc",
            "process_path": "/usr/bin/nc",
            "process_signature_valid": False,
            "parent_pid": 999, "cmdline": "nc -lvp 4444",
            "interface": "eth0",
        }
        defaults.update(kw)
        return defaults

    async def run_tests():
        global passed, failed

        db = MockDB()

        # ── 1. New listener appearing AFTER baseline seeding → alert ──────────
        # detect_new_listener seeds silently on the first (empty-baseline) scan
        # and only alerts on listeners that appear in LATER snapshots — that's
        # the enrollment-FP-storm fix. So prime the baseline, THEN introduce a
        # genuinely-new listener. Severity is reachability-tiered (0.0.0.0 →
        # high), not blanket critical.
        print("\nTest 1: New listener (post-seed) triggers alert")
        fresh()
        db1 = MockDB()
        seed = [make_listener(port=22, pid=1, process_name="sshd",
                              bind_ip="0.0.0.0", process_signature_valid=True)]
        await detect_new_listener("agentA", seed, db1)   # seed baseline (no alerts)
        lst = seed + [make_listener(port=9999, pid=100, process_name="malware",
                                    bind_ip="0.0.0.0", process_signature_valid=False)]
        findings = await detect_new_listener("agentA", lst, db1)
        check("1 finding", len(findings) == 1)
        check("severity high (wildcard exposure)", findings[0]["severity"] == "high")
        check("rule_id new_listener", findings[0]["rule_id"] == "new_listener")

        # ── 2. Known listener: no alert on repeat ────────────────────────────
        print("\nTest 2: Same listener not re-alerted once in baseline")
        fresh()
        db2 = MockDB()
        await detect_new_listener("agentB",
            [make_listener(port=22, pid=1, process_name="sshd")], db2)  # seed
        newl = [make_listener(port=22, pid=1, process_name="sshd"),
                make_listener(port=7878, pid=200, process_name="backdoor",
                              bind_ip="127.0.0.1")]
        f1 = await detect_new_listener("agentB", newl, db2)   # 7878 is new → alert
        f2 = await detect_new_listener("agentB", newl, db2)   # now baselined → none
        check("first scan: 1 finding", len(f1) == 1)
        check("second scan: suppressed", len(f2) == 0)

        # ── 3. Dedup reset on process identity change ─────────────────────────
        print("\nTest 3: Re-alerts when a port's process identity changes")
        fresh()
        db3 = MockDB()
        await detect_new_listener("agentC",
            [make_listener(port=22, pid=1, process_name="sshd")], db3)  # seed
        lst_a = [make_listener(port=5555, pid=300, process_name="sshd",
                               bind_ip="10.0.0.1", process_signature_valid=True)]
        lst_b = [make_listener(port=5555, pid=300, process_name="malware",
                               bind_ip="10.0.0.1", process_signature_valid=False)]
        await detect_new_listener("agentC", lst_a, db3)   # sshd:5555 new → alert + baselined
        _dedup_cache.clear()
        f = await detect_new_listener("agentC", lst_b, db3)  # malware:5555 → different fp → new
        check("re-alerts after name change", len(f) == 1)

        # ── 4. Wildcard bind: approved process → no alert ────────────────────
        print("\nTest 4: Approved wildcard process suppressed")
        fresh()
        lst = [make_listener(port=80, pid=10, process_name="nginx",
                             bind_ip="0.0.0.0", process_signature_valid=True)]
        findings = detect_wildcard_bind("agentD", lst)
        check("no findings for nginx", len(findings) == 0)

        # ── 5. Wildcard bind: unknown process on a service port → MEDIUM ──────
        print("\nTest 5: Unknown wildcard bind → MEDIUM")
        fresh()
        lst = [make_listener(port=8888, pid=20, process_name="mystery_app",
                             bind_ip="0.0.0.0")]
        findings = detect_wildcard_bind("agentE", lst)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("bind_ip in evidence", findings[0]["evidence"]["bind_ip"] == "0.0.0.0")

        # ── 5b. Wildcard bind: unapproved process on a HIGH/ephemeral port still
        #        fires — no port-based blind spot. Only port 0 (not a real
        #        connectable surface) is exempt.
        print("\nTest 5b: Unapproved process on ephemeral port still fires")
        fresh()
        lst = [make_listener(port=53782, pid=21, process_name="mystery_app",
                             bind_ip="0.0.0.0")]
        findings = detect_wildcard_bind("agentE2", lst)
        check("fires on ephemeral port", len(findings) == 1)

        print("\nTest 5b2: Port 0 (no real port resolved) suppressed")
        fresh()
        lst = [make_listener(port=0, pid=22, process_name="mystery_app",
                             bind_ip="0.0.0.0")]
        check("no findings (invalid port)", len(detect_wildcard_bind("agentE2b", lst)) == 0)

        # ── 5c. FP regression: real stock-macOS / dev processes suppressed ────
        # These exact (process, port) pairs produced ~16k false positives on
        # live agent data before the allowlist/prefix/helper fixes.
        print("\nTest 5c: Known system/dev wildcard binders suppressed")
        for proc, port in [("netbiosd", 137), ("netbiosd", 138),
                            ("com.docker.backend", 6443),
                            ("com.docker.backend", 8080),
                            ("Code Helper (Plugin)", 18620),
                            ("com.apple.WebKit.Networking", 443),
                            # Found by removing the ephemeral-port exemption
                            # and replaying real data — see APPROVED_WILDCARD_
                            # BIND_PROCS for why each is legitimate.
                            ("airportd", 0), ("replicatord", 59995),
                            ("symptomsd", 52138), ("syslogd", 50194),
                            ("wifip2pd", 0), ("wifivelocityd", 0)]:
            fresh()
            lst = [make_listener(port=port, pid=22, process_name=proc, bind_ip="0.0.0.0")]
            check(f"suppressed: {proc}:{port}", len(detect_wildcard_bind("agentE3", lst)) == 0)

        # ── 6. Wildcard bind: IPv6 :: service port → fires ──────────────────
        print("\nTest 6: IPv6 wildcard :: on service port")
        fresh()
        lst = [make_listener(port=7777, pid=30, process_name="unknown_srv",
                             bind_ip="::")]
        findings = detect_wildcard_bind("agentF", lst)
        check("1 finding", len(findings) == 1)

        # ── 7. High-risk port 4444 on external IP → HIGH ─────────────────────
        print("\nTest 7: High-risk port 4444 externally exposed")
        fresh()
        lst = [make_listener(port=4444, pid=40, process_name="nc",
                             bind_ip="192.168.1.50")]
        findings = detect_high_risk_port("agentG", lst)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("port 4444", findings[0]["evidence"]["port"] == 4444)

        # ── 8. High-risk port on loopback → no alert ─────────────────────────
        print("\nTest 8: High-risk port on loopback suppressed")
        fresh()
        lst = [make_listener(port=4444, pid=50, process_name="nc",
                             bind_ip="127.0.0.1")]
        findings = detect_high_risk_port("agentH", lst)
        check("no findings (loopback)", len(findings) == 0)

        # ── 9. High-risk port 31337 → HIGH ───────────────────────────────────
        print("\nTest 9: Back Orifice port 31337")
        fresh()
        lst = [make_listener(port=31337, pid=60, process_name="xterm",
                             bind_ip="0.0.0.0")]
        findings = detect_high_risk_port("agentI", lst)
        check("1 finding", len(findings) == 1)
        check("rule_id high_risk_port", findings[0]["rule_id"] == "high_risk_port")

        # ── 10. Unknown unsigned process → HIGH ───────────────────────────────
        print("\nTest 10: Unknown unsigned process listener")
        fresh()
        lst = [make_listener(port=3333, pid=70, process_name="evil_daemon",
                             process_signature_valid=False)]
        findings = detect_unknown_process("agentJ", lst)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("sig_valid false", findings[0]["evidence"]["process_signature_valid"] is False)

        # ── 11. Known process with valid sig → no alert ───────────────────────
        print("\nTest 11: Known service with valid signature suppressed")
        fresh()
        lst = [make_listener(port=80, pid=80, process_name="nginx",
                             process_signature_valid=True)]
        findings = detect_unknown_process("agentK", lst)
        check("no findings", len(findings) == 0)

        # ── 12. Port mismatch: sshd on port 8080 → HIGH ───────────────────────
        print("\nTest 12: sshd on unexpected port 8080")
        fresh()
        lst = [make_listener(port=8080, pid=90, process_name="sshd",
                             bind_ip="0.0.0.0", process_signature_valid=True)]
        findings = detect_port_mismatch("agentL", lst)
        check("1 finding", len(findings) == 1)
        check("severity high", findings[0]["severity"] == "high")
        check("allowed_ranges in evidence", "allowed_ranges" in findings[0]["evidence"])

        # ── 13. Port mismatch: sshd on port 22 → no alert ────────────────────
        print("\nTest 13: sshd on correct port 22")
        fresh()
        lst = [make_listener(port=22, pid=100, process_name="sshd",
                             bind_ip="0.0.0.0", process_signature_valid=True)]
        findings = detect_port_mismatch("agentM", lst)
        check("no findings", len(findings) == 0)

        # ── 14. Port mismatch: nginx on port 9200 → HIGH ─────────────────────
        print("\nTest 14: nginx on port 9200 (out of range)")
        fresh()
        lst = [make_listener(port=9200, pid=110, process_name="nginx",
                             bind_ip="0.0.0.0", process_signature_valid=True)]
        findings = detect_port_mismatch("agentN", lst)
        check("1 finding", len(findings) == 1)

        # ── 15. Duplicate listener: two PIDs on same port → MEDIUM ────────────
        print("\nTest 15: Duplicate listener on port 443")
        fresh()
        lst = [
            make_listener(port=443, pid=200, process_name="nginx", bind_ip="0.0.0.0"),
            make_listener(port=443, pid=201, process_name="malware", bind_ip="0.0.0.0"),
        ]
        findings = detect_duplicate_listener("agentO", lst)
        check("1 finding", len(findings) == 1)
        check("severity medium", findings[0]["severity"] == "medium")
        check("pid_count = 2", findings[0]["evidence"]["pid_count"] == 2)

        # ── 16. Duplicate listener: same PID → no alert ───────────────────────
        print("\nTest 16: Same PID on same port — no duplicate alert")
        fresh()
        lst = [
            make_listener(port=443, pid=300, process_name="nginx", bind_ip="0.0.0.0"),
            make_listener(port=443, pid=300, process_name="nginx", bind_ip="::"),
        ]
        findings = detect_duplicate_listener("agentP", lst)
        check("no findings (same PID)", len(findings) == 0)

        # ── 17. Netstat text ingestion ────────────────────────────────────────
        print("\nTest 17: netstat -tlnp text parsing")
        fresh()
        raw = (
            "tcp  0  0  0.0.0.0:22  0.0.0.0:*  LISTEN  1001/sshd\n"
            "tcp  0  0  127.0.0.1:5432  0.0.0.0:*  LISTEN  2002/postgres\n"
        )
        parsed = ingest_listeners("ports", raw)
        check("2 listeners parsed", len(parsed) == 2)
        check("port 22 correct", parsed[0]["port"] == 22)
        check("process sshd", parsed[0]["process_name"] == "sshd")
        check("port 5432 correct", parsed[1]["port"] == 5432)

        # ── 18. Dict list ingestion ───────────────────────────────────────────
        print("\nTest 18: Dict list ingestion")
        fresh()
        raw = [
            {"port": 6379, "bind_ip": "0.0.0.0", "process_name": "redis-server",
             "pid": 500, "proto": "tcp", "process_signature_valid": True,
             "process_path": "/usr/bin/redis-server", "parent_pid": 1,
             "cmdline": "redis-server", "interface": "lo"},
        ]
        parsed = ingest_listeners("ports", raw)
        check("1 listener", len(parsed) == 1)
        check("port 6379", parsed[0]["port"] == 6379)

        # ── 19. Loopback listener: not flagged as high-risk ───────────────────
        print("\nTest 19: High-risk port on loopback not flagged")
        fresh()
        lst = [make_listener(port=23, pid=600, process_name="telnetd",
                             bind_ip="127.0.0.1")]
        findings = detect_high_risk_port("agentQ", lst)
        check("no findings (loopback)", len(findings) == 0)

        # ── 20. Full analyze() pipeline ───────────────────────────────────────
        print("\nTest 20: Full analyze() pipeline")
        fresh()
        db20 = MockDB()
        raw = [
            # New unknown listener: should trigger new_listener + wildcard + unknown
            {"port": 6666, "bind_ip": "0.0.0.0", "process_name": "strange_proc",
             "pid": 700, "proto": "tcp", "process_signature_valid": False,
             "process_path": "/tmp/strange", "parent_pid": 1,
             "cmdline": "/tmp/strange -l", "interface": "eth0"},
        ]
        # First scan seeds the new-listener baseline with a benign pre-existing
        # listener (no new_listener alert yet); the genuinely-new strange_proc
        # then appears in the second snapshot and fires new_listener, alongside
        # the exposure rules (wildcard/high-risk/unknown).
        seed_raw = [{"port": 5000, "bind_ip": "127.0.0.1", "process_name": "seedproc",
                     "pid": 1, "proto": "tcp", "process_signature_valid": True,
                     "process_path": "/usr/bin/seedproc", "parent_pid": 1,
                     "cmdline": "seedproc", "interface": "lo0"}]
        await analyze("agentR", "ports", seed_raw, db20, hostname="host-r")
        _dedup_cache.clear()
        findings = await analyze("agentR", "ports", seed_raw + raw, db20, hostname="host-r")
        rule_ids = {f["rule_id"] for f in findings}
        check("new_listener fired", "new_listener" in rule_ids)
        check("wildcard_bind fired", "wildcard_bind" in rule_ids)
        check("high_risk_port fired", "high_risk_port" in rule_ids)
        check("unknown_process fired", "unknown_process" in rule_ids)
        check("affected_asset set", all(f["affected_asset"] == "host-r" for f in findings))

        # ── 21. Non-port section → empty ─────────────────────────────────────
        print("\nTest 21: Non-port section returns empty")
        fresh()
        db21 = MockDB()
        findings = await analyze("agentS", "processes", [], db21)
        check("empty for non-port section", len(findings) == 0)

        # ── Summary ────────────────────────────────────────────────────────────
        print(f"\n{'─'*50}")
        total = passed + failed
        print(f"Results: {passed}/{total} passed", end="")
        if failed:
            print(f"  ({failed} FAILED)")
            sys.exit(1)
        else:
            print("  — all OK")

    asyncio.run(run_tests())
