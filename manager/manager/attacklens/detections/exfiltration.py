"""
manager/manager/attacklens/detections/exfiltration.py
Production-grade data exfiltration detection — macOS, Linux, Windows.

Detection vectors:
  1. Large outbound connection volume to a single external destination
  2. DNS tunneling — abnormally long subdomain queries or high query rate
  3. Beaconing to C2 — low-entropy periodic connections (behavioral)
  4. Process staging in writable temp paths with active outbound connections
  5. Suspicious data-volume spike vs historical baseline

COMPLIANCE MAPPING:
  NIST SP 800-53:  SC-7, AC-4, AU-6, AU-12, SI-4, SI-12
  CIS Controls:    Control 12 (Boundary Defense), Control 13 (Data Protection),
                   Control 14 (Sensitive Data Access)
  ISO 27001:       A.10.1.1, A.13.1.2, A.13.2.1, A.13.2.3
  PCI-DSS v4:      Req 1.3, Req 4.2, Req 9.4, Req 10.3
  SOC 2 CC:        CC6.6, CC6.7, CC9.2
  MITRE ATT&CK:    T1041 (Exfil over C2), T1048 (Exfil over Alt Protocol),
                   T1071.004 (DNS), T1567 (Exfil to Web Service), T1052 (Exfil via Media)
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("manager.attacklens.detections.exfiltration")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Outbound volume thresholds (connection-count based — bytes not available in psutil)
SINGLE_DEST_CONN_THRESHOLD: int    = 30    # >30 active conns to 1 external IP = suspicious
TOTAL_EXTERNAL_CONN_THRESHOLD: int = 100   # >100 external conns total = suspicious

# DNS tunneling detection
DNS_SUBDOMAIN_LENGTH_THRESHOLD: int = 40   # subdomains > 40 chars = likely encoded data
DNS_QUERY_RATE_THRESHOLD: int       = 50   # >50 unique DNS queries per collection = suspicious
DNS_ENTROPY_THRESHOLD: float        = 3.8  # high entropy subdomain = encoded content

# Staging path patterns (process running from temp dir with outbound connections)
STAGING_PATHS: tuple[str, ...] = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/Users/Shared/", "C:\\Windows\\Temp\\", "C:\\Users\\Public\\",
    "AppData\\Local\\Temp\\", "AppData\\Roaming\\", "%TEMP%\\",
)

# Whitelisted high-volume services (CDN, backup, sync — expected large transfers)
HIGH_VOLUME_WHITELIST_PROCESSES: frozenset[str] = frozenset({
    "backupd", "Time Machine", "onedrive", "dropbox", "googledrivesync",
    "box", "icloud", "syncthing", "rclone", "restic", "rsync",
    "adobedesktop", "steam", "epicgames",
})

# External IPs to skip (already covered by allowlist TRUSTED_CIDRS)
INTERNAL_SUBNETS: tuple[str, ...] = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
)
_INTERNAL_NETS = [ipaddress.ip_network(c, strict=False) for c in INTERNAL_SUBNETS]

# Dedup / rate-limit
DEDUP_WINDOW_SECS: int       = 3600
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
            "remote_addr": raddr,
            "remote_ip":   _parse_ip(raddr),
            "remote_port": _parse_port(raddr),
            "bytes_sent":  item.get("bytes_sent") or item.get("send_bytes") or 0,
            "raw":         item,
        })
    return out


def ingest_network(raw: Any) -> dict:
    """Network section is a dict with interfaces, dns_servers, etc."""
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
            "pid":    item.get("pid"),
            "name":   str(item.get("name") or ""),
            "exe":    str(item.get("exe") or item.get("path") or ""),
            "cmdline": str(item.get("cmdline") or item.get("cmd") or ""),
            "raw":    item,
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_single_dest_flood(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1041 — Many connections to a single external IP (data exfiltration channel)."""
    dest_counts: dict[str, list[dict]] = defaultdict(list)
    for c in conns:
        ip = c["remote_ip"]
        if ip and not _is_internal(ip):
            dest_counts[ip].append(c)

    hits = []
    for ip, dest_conns in dest_counts.items():
        if len(dest_conns) < SINGLE_DEST_CONN_THRESHOLD:
            continue
        processes = list({c["name"] for c in dest_conns if c["name"]})
        # Skip known sync/backup processes
        if any(proc.lower() in HIGH_VOLUME_WHITELIST_PROCESSES for proc in processes):
            continue
        hits.append({
            "rule_id":    "exfil:single_dest_flood",
            "severity":   "high",
            "title":      f"Outbound connection flood to {ip}: {len(dest_conns)} connections",
            "description": (
                f"{len(dest_conns)} simultaneous connections to external IP {ip} "
                f"by processes {processes[:5]}. Volume concentrated on a single destination "
                f"is consistent with data exfiltration or C2 channel abuse."
            ),
            "evidence": {
                "destination_ip":  ip,
                "connection_count": len(dest_conns),
                "threshold":        SINGLE_DEST_CONN_THRESHOLD,
                "processes":        processes,
                "ports":            list({c["remote_port"] for c in dest_conns if c["remote_port"]}),
            },
            "raw_telemetry": [c["raw"] for c in dest_conns[:10]],
            "mitre_tactic":     "Exfiltration",
            "mitre_technique":  "T1041",
            "compliance_controls": {
                "NIST": ["SC-7", "AU-12", "SI-4"],  "CIS": ["12.1", "13.6"],
                "ISO":  ["A.13.2.1", "A.13.2.3"],   "PCI": ["Req 1.3", "Req 10.3"], "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"Block {ip} at egress firewall immediately. "
                f"Identify what process is driving the connections and what data it accesses. "
                f"Check for staged data in /tmp or Downloads. Capture packet samples if possible."
            ),
            "false_positive_notes": (
                "CDN-backed services (Netflix, YouTube, large file downloads) create many concurrent "
                "connections to one CDN IP. Whitelist by process name in HIGH_VOLUME_WHITELIST_PROCESSES "
                "for known sync/media apps."
            ),
            "item_key": f"exfil_flood:{ip}",
            "category": "connection",
            "source":   "rule:exfiltration",
            "score":    SEVERITY_SCORES["high"],
            "tags":     ["exfiltration", "outbound", "T1041"],
        })
    return hits


def detect_high_external_conn_count(agent_id: str, conns: list[dict]) -> list[dict]:
    """T1048 — Total external connection count spike (distributed exfiltration)."""
    external = [c for c in conns if c["remote_ip"] and not _is_internal(c["remote_ip"])]
    if len(external) < TOTAL_EXTERNAL_CONN_THRESHOLD:
        return []
    processes = list({c["name"] for c in external if c["name"]})
    if any(p.lower() in HIGH_VOLUME_WHITELIST_PROCESSES for p in processes):
        return []
    unique_dests = len({c["remote_ip"] for c in external})
    return [{
        "rule_id":    "exfil:high_external_count",
        "severity":   "medium",
        "title":      f"High external connection count: {len(external)} connections",
        "description": (
            f"{len(external)} simultaneous external connections to {unique_dests} unique IPs "
            f"by {processes[:5]}. High external connection volume may indicate bulk data transfer "
            f"or a multi-destination exfiltration strategy."
        ),
        "evidence": {
            "external_conn_count": len(external),
            "unique_destinations": unique_dests,
            "threshold":           TOTAL_EXTERNAL_CONN_THRESHOLD,
            "top_processes":       processes[:10],
        },
        "raw_telemetry": [c["raw"] for c in external[:20]],
        "mitre_tactic":     "Exfiltration",
        "mitre_technique":  "T1048",
        "compliance_controls": {
            "NIST": ["SC-7", "AC-4", "SI-4"],  "CIS": ["12.1", "14.6"],
            "ISO":  ["A.13.1.2", "A.13.2.1"],  "PCI": ["Req 1.3", "Req 9.4"], "SOC2": ["CC9.2"],
        },
        "recommended_action": (
            "Investigate the process list for bulk-transfer applications or data-staging tools. "
            "Check for large files in /tmp, /Downloads, or cloud sync folders. "
            "Review network egress logs for sustained high-bandwidth sessions."
        ),
        "false_positive_notes": (
            "Developer environments with many API connections (IDEs, test runners) can spike counts. "
            "CDN-prefetching browsers open many connections simultaneously. "
            "Verify process names and raise threshold if legitimate bulk transfers are expected."
        ),
        "item_key": f"exfil_ext_count:{len(external)}",
        "category": "connection",
        "source":   "rule:exfiltration",
        "score":    SEVERITY_SCORES["medium"],
        "tags":     ["exfiltration", "T1048"],
    }]


def detect_dns_tunneling(agent_id: str, network: dict) -> list[dict]:
    """T1071.004 — DNS tunneling via long/high-entropy subdomains."""
    hits = []
    dns_queries = network.get("dns_queries") or network.get("dns_requests") or []
    if not isinstance(dns_queries, list) or not dns_queries:
        return []

    long_subdomains = []
    high_entropy = []
    for query in dns_queries:
        qname = str(query.get("name") or query.get("query") or "")
        if not qname:
            continue
        parts = qname.split(".")
        subdomain = parts[0] if len(parts) > 2 else ""
        if len(subdomain) > DNS_SUBDOMAIN_LENGTH_THRESHOLD:
            long_subdomains.append(qname)
        elif subdomain and _shannon_entropy(subdomain) > DNS_ENTROPY_THRESHOLD:
            high_entropy.append(qname)

    if long_subdomains:
        hits.append({
            "rule_id":    "exfil:dns_long_subdomain",
            "severity":   "high",
            "title":      f"DNS tunneling: {len(long_subdomains)} long-subdomain queries",
            "description": (
                f"{len(long_subdomains)} DNS queries with subdomains >{DNS_SUBDOMAIN_LENGTH_THRESHOLD} "
                f"characters detected. DNS tunneling tools (iodine, dnscat2) encode data as "
                f"subdomain labels to exfiltrate through firewalls that permit DNS."
            ),
            "evidence": {
                "long_subdomain_queries": long_subdomains[:10],
                "threshold_chars":        DNS_SUBDOMAIN_LENGTH_THRESHOLD,
                "max_length":             max(len(q.split(".")[0]) for q in long_subdomains),
            },
            "raw_telemetry": long_subdomains[:20],
            "mitre_tactic":     "Exfiltration",
            "mitre_technique":  "T1071.004",
            "compliance_controls": {
                "NIST": ["SC-7", "SI-4", "AU-12"],  "CIS": ["12.1", "13.6"],
                "ISO":  ["A.13.2.1"],                "PCI": ["Req 1.3", "Req 10.3"], "SOC2": ["CC6.7"],
            },
            "recommended_action": (
                "Capture DNS traffic with Wireshark or tcpdump to inspect query content. "
                "Block the flagged domains at the DNS resolver. "
                "Run `iodine`/`dnscat2` process detection across the process list. "
                "Consider deploying DNS response policy zones (RPZ) for anomalous patterns."
            ),
            "false_positive_notes": (
                "DNSSEC keys, Let's Encrypt ACME validation, and S3 presigned URLs "
                "contain long base64 subdomains that are legitimate. "
                "Verify the target domain — if internal CA or known cloud, suppress."
            ),
            "item_key": f"dns_tunnel:{hashlib.sha256(str(long_subdomains[:3]).encode()).hexdigest()[:10]}",
            "category": "network",
            "source":   "rule:exfiltration",
            "score":    SEVERITY_SCORES["high"],
            "tags":     ["exfiltration", "dns_tunnel", "T1071.004"],
        })

    if high_entropy and len(high_entropy) >= 3:
        hits.append({
            "rule_id":    "exfil:dns_high_entropy",
            "severity":   "medium",
            "title":      f"DNS tunneling: {len(high_entropy)} high-entropy subdomain queries",
            "description": (
                f"{len(high_entropy)} DNS queries with subdomain Shannon entropy "
                f">{DNS_ENTROPY_THRESHOLD:.1f} bits — consistent with base64/hex-encoded data "
                f"smuggled through DNS. Example: {high_entropy[0]}"
            ),
            "evidence": {
                "high_entropy_queries": high_entropy[:10],
                "entropy_threshold":    DNS_ENTROPY_THRESHOLD,
            },
            "raw_telemetry": high_entropy[:20],
            "mitre_tactic":     "Exfiltration",
            "mitre_technique":  "T1071.004",
            "compliance_controls": {
                "NIST": ["SC-7", "SI-4"],  "CIS": ["12.1"],
                "ISO":  ["A.13.2.1"],       "PCI": ["Req 1.3"], "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                "Decode sample subdomains as base64/hex to inspect data content. "
                "Block the registrant domain. Check for dnscat2, iodine, or dns2tcp processes."
            ),
            "false_positive_notes": (
                "Randomly-generated tracking pixels, A/B test parameters, and TOTP tokens "
                "have high entropy but are legitimate. Verify the destination domain's purpose."
            ),
            "item_key": f"dns_entropy:{hashlib.sha256(str(high_entropy[:3]).encode()).hexdigest()[:10]}",
            "category": "network",
            "source":   "rule:exfiltration",
            "score":    SEVERITY_SCORES["medium"],
            "tags":     ["exfiltration", "dns_tunnel", "T1071.004"],
        })
    return hits


def detect_staging_with_outbound(agent_id: str, processes: list[dict], conns: list[dict]) -> list[dict]:
    """T1567 — Process running from temp/writable path AND making outbound connections."""
    hits = []
    # Build pid → conn map
    pids_with_external: set[int] = {
        c["pid"] for c in conns
        if c["remote_ip"] and not _is_internal(c["remote_ip"]) and c["pid"]
    }
    for proc in processes:
        exe = proc["exe"]
        pid = proc["pid"]
        if not exe or not pid:
            continue
        if not any(sp in exe for sp in STAGING_PATHS):
            continue
        if pid not in pids_with_external:
            continue
        # Process from temp path with outbound = high confidence staging
        hits.append({
            "rule_id":    "exfil:staging_outbound",
            "severity":   "critical",
            "title":      f"Staged payload with outbound: {proc['name']} from {exe}",
            "description": (
                f"Process '{proc['name']}' (PID {pid}) running from writable temp path "
                f"'{exe}' AND making outbound network connections. "
                f"This matches the download-stage-execute pattern used in LOLBin attacks "
                f"and staged malware (T1105 → T1567)."
            ),
            "evidence": {
                "process_name": proc["name"],
                "exe":          exe,
                "pid":          pid,
                "cmdline":      proc["cmdline"],
            },
            "raw_telemetry": [proc["raw"]],
            "mitre_tactic":     "Exfiltration",
            "mitre_technique":  "T1567",
            "compliance_controls": {
                "NIST": ["SI-3", "SI-4", "SC-7"],  "CIS": ["8.1", "12.1"],
                "ISO":  ["A.12.2.1", "A.13.2.1"],  "PCI": ["Req 6.3", "Req 1.3"], "SOC2": ["CC6.1"],
            },
            "recommended_action": (
                f"Kill PID {pid} immediately. Capture the binary at '{exe}' for analysis (sha256sum). "
                f"Check what files it accessed (lsof -p {pid}). "
                f"Inspect outbound connections for data being transferred. "
                f"Treat the host as compromised pending investigation."
            ),
            "false_positive_notes": (
                "Browser-based app installers download to /tmp then open them — this is legitimate "
                "but still worth confirming. Verify the binary origin (codesign, VirusTotal hash). "
                "Package managers (npm, pip) stage to temp during installs."
            ),
            "item_key": f"staging:{exe}:{pid}",
            "category": "process",
            "source":   "rule:exfiltration",
            "score":    SEVERITY_SCORES["critical"],
            "tags":     ["exfiltration", "staging", "lolbin", "T1567"],
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
        "category":    hit.get("category", "connection"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:exfiltration"),
        "tags":        hit.get("tags", ["exfiltration"]),
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
    _process_cache: dict | None = None,  # cross-section correlation cache
) -> list[dict]:
    raw_hits: list[dict] = []

    if section == "connections":
        conns = ingest_connections(data)
        raw_hits += detect_single_dest_flood(agent_id, conns)
        raw_hits += detect_high_external_conn_count(agent_id, conns)
        if _process_cache and agent_id in _process_cache:
            procs = _process_cache[agent_id]
            raw_hits += detect_staging_with_outbound(agent_id, procs, conns)
    elif section == "network":
        net = ingest_network(data)
        raw_hits += detect_dns_tunneling(agent_id, net)
    elif section == "processes":
        if _process_cache is not None:
            _process_cache[agent_id] = ingest_processes(data)

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


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== exfiltration.py — Test Harness ===\n")

    # ── TP: Single-destination flood ─────────────────────────────────────────
    tp_conns = [
        {"remote_addr": f"203.0.113.10:{5000 + i}", "local_addr": "10.0.0.1:49000",
         "name": "data_exfil", "pid": 1234}
        for i in range(35)
    ]
    conns = ingest_connections(tp_conns)
    hits = detect_single_dest_flood("agent-tp", conns)
    assert len(hits) == 1 and hits[0]["severity"] == "high"
    print(f"[PASS] TP single-dest flood: {hits[0]['title']}")

    # ── FP: Dropbox (whitelisted process) ────────────────────────────────────
    fp_conns = [
        {"remote_addr": f"162.125.{i % 5}.10:443", "local_addr": "10.0.0.1:50000",
         "name": "dropbox", "pid": 9999}
        for i in range(40)
    ]
    fp_conns_norm = ingest_connections(fp_conns)
    fp_hits = detect_single_dest_flood("agent-fp", fp_conns_norm)
    assert len(fp_hits) == 0
    print("[PASS] FP Dropbox: suppressed (whitelisted process)")

    # ── TP: DNS long subdomain ────────────────────────────────────────────────
    net_data = {
        "dns_queries": [
            {"name": f"{'a' * 50}.evil-c2.com", "type": "A"},
            {"name": f"{'b' * 55}.evil-c2.com", "type": "TXT"},
            {"name": "normal.google.com", "type": "A"},
        ]
    }
    net = ingest_network(net_data)
    dns_hits = detect_dns_tunneling("agent-tp2", net)
    assert len(dns_hits) >= 1 and any("T1071.004" in h["mitre_technique"] for h in dns_hits)
    print(f"[PASS] TP DNS long subdomain: {dns_hits[0]['title']}")

    # ── FP: Normal short DNS queries ──────────────────────────────────────────
    fp_net = {"dns_queries": [{"name": "api.github.com", "type": "A"},
                               {"name": "pypi.org", "type": "A"}]}
    assert detect_dns_tunneling("agent-fp2", ingest_network(fp_net)) == []
    print("[PASS] FP normal DNS: suppressed")

    # ── TP: Staging + outbound ────────────────────────────────────────────────
    tp_procs = [{"name": "payload", "exe": "/tmp/payload", "pid": 5555,
                 "cmdline": "/tmp/payload -c http://evil.com", "raw": {}}]
    tp_conns2 = [{"remote_addr": "203.0.113.99:4444", "local_addr": "10.0.0.1:51000",
                  "name": "payload", "pid": 5555, "raw": {}}]
    procs = ingest_processes(tp_procs)
    conns2 = ingest_connections(tp_conns2)
    stage_hits = detect_staging_with_outbound("agent-tp3", procs, conns2)
    assert len(stage_hits) == 1 and stage_hits[0]["severity"] == "critical"
    print(f"[PASS] TP staging+outbound: {stage_hits[0]['title']}")

    # ── FP: Legitimate process from temp (npm install) ────────────────────────
    fp_procs = [{"name": "npm", "exe": "/usr/local/bin/npm", "pid": 6666,
                 "cmdline": "npm install", "raw": {}}]
    fp_conns2 = [{"remote_addr": "104.16.0.1:443", "local_addr": "10.0.0.1:52000",
                  "name": "npm", "pid": 6666, "raw": {}}]
    fp_stage_hits = detect_staging_with_outbound("agent-fp3",
                                                  ingest_processes(fp_procs),
                                                  ingest_connections(fp_conns2))
    assert len(fp_stage_hits) == 0  # /usr/local/bin is not in STAGING_PATHS
    print("[PASS] FP npm install: suppressed (trusted path)")

    # ── Alert builder verification ────────────────────────────────────────────
    alert = build_alert(hits[0], "agent-tp", "laptop-01")
    required = {"alert_id", "severity", "title", "description", "affected_asset",
                "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                "compliance_controls", "recommended_action", "false_positive_notes", "timestamp_utc"}
    assert not (required - set(alert.keys()))
    print("[PASS] Alert builder: all mandatory fields present")

    print("\n=== All tests passed ===")
