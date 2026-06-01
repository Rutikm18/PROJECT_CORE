"""
manager/manager/attacklens/detections/arp_spoofing.py
Production-grade ARP spoofing and man-in-the-middle attack detection.

Monitors real-time ARP table telemetry to detect ARP cache poisoning,
gateway MAC impersonation, and MITM setup attempts with sub-60-second
polling resolution.

Section handled: arp

COMPLIANCE MAPPING:
  NIST CSF:       DE.CM-1 (Network monitored), PR.AC-5 (Network integrity)
  CIS Control 13: Network Monitoring and Defense
  SOC 2:          CC6.6 (Logical access over network)
  ISO 27001:      A.13.1.2 (Security of network services)

MITRE ATT&CK:
  T1557   (Adversary-in-the-Middle)
  T1557.002 (ARP Cache Poisoning)
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

log = logging.getLogger("manager.attacklens.detections.arp_spoofing")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — all thresholds configurable here
# ─────────────────────────────────────────────────────────────────────────────

# ARP table churn detection
CHURN_THRESHOLD: int           = 10    # MAC changes per IP per CHURN_WINDOW_SECS
CHURN_WINDOW_SECS: int         = 60    # sliding window for churn counting
CHURN_ALERT_COOLDOWN_SECS: int = 300   # 5 min cooldown between repeat churn alerts per IP

# DHCP suppression: suppress MAC-change alerts this many seconds after a DHCP event
DHCP_SUPPRESS_SECS: int = 30

# ARP flood threshold: alert when ARP packets/min on an interface exceeds this
ARP_FLOOD_THRESHOLD: int = 500

# OUI baseline: days to retain per-agent OUI observations for rogue-vendor detection
ROGUE_OUI_BASELINE_DAYS: int = 7

# Dedup and rate-limiting
DEDUP_WINDOW_SECS: int       = 3600
RATE_LIMIT_MAX_PER_HOUR: int = 30

# Trusted MACs config (relative to working dir; override via env var)
TRUSTED_MACS_PATH: str = os.environ.get("TRUSTED_MACS_PATH", "config/trusted_macs.json")

# First-hop redundancy protocol virtual MAC prefixes (first 5 bytes, 10 hex chars, lowercase).
# VRRP/HSRP/GLBP failover generates MAC changes that are NOT poisoning — suppress them.
FHRP_MAC_PREFIXES: frozenset[str] = frozenset({
    "00005e0001",   # VRRP IPv4  (00:00:5E:00:01:XX)
    "00005e0002",   # VRRP IPv6  (00:00:5E:00:02:XX)
    "00000c07ac",   # HSRP v1    (00:00:0C:07:AC:XX)
    "00000c9ff5",   # HSRP v2    (00:00:0C:9F:F5:XX)
    "0007b40001",   # GLBP       (00:07:B4:00:01:XX)
})

# Known pentest tool / rogue AP platform OUI prefixes (first 3 bytes, 6 hex chars).
# Source: IEEE public registry cross-referenced with known MITM hardware vendors.
KNOWN_PENTEST_OUI_PREFIXES: frozenset[str] = frozenset({
    "00c0ca",   # Alfa Inc. — AWUS036 series USB WiFi, dominant in MITM/WPA kits
    "28cdc1",   # Alfa Network — second OUI block
    "b827eb",   # Raspberry Pi Foundation — primary rogue AP platform
    "dca632",   # Raspberry Pi Trading Ltd (Pi 3B+/4B)
    "e45f01",   # Raspberry Pi Trading Ltd (Pi 4/5 variants)
    "2ccf67",   # Raspberry Pi Trading Ltd (Pi Zero W)
    "d83add",   # Raspberry Pi Trading Ltd (Pi 4B, later batches)
})

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}
_churn_window: dict[str, list[float]] = {}   # "agent_id:ip" → [change_timestamps]
_churn_alert_ts: dict[str, float]     = {}   # "agent_id:ip" → last_alert_time
_dhcp_suppress: dict[str, float]      = {}   # "agent_id:ip" → suppress_until_ts
_trusted_macs_cache: dict             = {}
_trusted_macs_loaded_at: float        = 0.0

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — MAC normalization, OUI extraction, FHRP/trusted checks
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_mac(mac: str) -> str:
    """Lowercase colon-separated zero-padded MAC. Returns '' on invalid input."""
    clean = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(clean) != 12:
        return ""
    return ":".join(clean[i:i+2].lower() for i in range(0, 12, 2))


def _extract_oui(mac: str) -> str:
    """Return first 3 octets as 6-char lowercase hex (no separators)."""
    clean = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    return clean[:6].lower() if len(clean) >= 6 else ""


def _is_fhrp_mac(mac: str) -> bool:
    """Return True if MAC belongs to a VRRP/HSRP/GLBP virtual MAC range."""
    clean = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    return len(clean) >= 10 and clean[:10] in FHRP_MAC_PREFIXES


def _load_trusted_macs() -> dict:
    """
    Load trusted MACs config.  Reloads every 5 minutes.

    Format:
      {
        "macs": {
          "aa:bb:cc:dd:ee:ff": {"label": "Core switch uplink", "ip": "192.168.1.1"},
          "aa:bb:cc:dd:ee:00": {"label": "VRRP pair B", "multi_ip": true}
        }
      }
    """
    global _trusted_macs_cache, _trusted_macs_loaded_at
    now = time.time()
    if now - _trusted_macs_loaded_at < 300 and _trusted_macs_cache:
        return _trusted_macs_cache
    try:
        p = Path(TRUSTED_MACS_PATH)
        _trusted_macs_cache = json.loads(p.read_text()) if p.exists() else {"macs": {}}
    except Exception as exc:
        log.debug("Trusted MACs load failed (%s): %s", TRUSTED_MACS_PATH, exc)
        _trusted_macs_cache = {"macs": {}}
    _trusted_macs_loaded_at = now
    return _trusted_macs_cache


def _is_trusted_mac(mac: str) -> bool:
    return _normalize_mac(mac) in _load_trusted_macs().get("macs", {})


def _process_dhcp_events(agent_id: str, dhcp_events: list[dict]) -> None:
    """Register recent DHCP events so MAC-change alerts are suppressed for 30 s."""
    now = time.time()
    for ev in dhcp_events:
        et  = str(ev.get("event_type", "")).upper()
        ip  = str(ev.get("ip", "")).strip()
        ts  = float(ev.get("timestamp") or now)
        if ip and et in ("ACK", "OFFER", "DISCOVER", "REQUEST", "RENEW") and abs(now - ts) < 120:
            _dhcp_suppress[f"{agent_id}:{ip}"] = ts + DHCP_SUPPRESS_SECS


def _is_dhcp_suppressed(agent_id: str, ip: str) -> bool:
    return time.time() < _dhcp_suppress.get(f"{agent_id}:{ip}", 0)


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
        log.debug("Rate limit: agent=%s module=arp_spoofing", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

_BASELINE_NS = "arp_spoofing"


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

def ingest_arp(raw: Any) -> dict:
    """
    Normalize ARP section payload from agent.

    Accepts:
      • dict with keys: entries|arp_table, gateway_info|gateways,
                        arp_stats|stats, dhcp_events|dhcp
      • list of ARP entry dicts (flat format)

    Each normalized entry: {ip_address, mac_address, interface, entry_type,
                             timestamp, raw}
    """
    result: dict[str, list] = {
        "entries": [], "gateway_info": [], "arp_stats": [], "dhcp_events": [],
    }

    if isinstance(raw, dict):
        entries_raw = raw.get("entries") or raw.get("arp_table") or []
        gw_raw      = raw.get("gateway_info") or raw.get("gateways") or []
        stats_raw   = raw.get("arp_stats") or raw.get("stats") or []
        dhcp_raw    = raw.get("dhcp_events") or raw.get("dhcp") or []
    elif isinstance(raw, list):
        entries_raw, gw_raw, stats_raw, dhcp_raw = raw, [], [], []
    else:
        return result

    for e in entries_raw:
        if not isinstance(e, dict):
            continue
        ip  = str(e.get("ip_address") or e.get("ip") or "").strip()
        mac = _normalize_mac(str(e.get("mac_address") or e.get("mac") or ""))
        if not ip or not mac:
            continue
        result["entries"].append({
            "ip_address":  ip,
            "mac_address": mac,
            "interface":   str(e.get("interface") or e.get("iface") or ""),
            "entry_type":  str(e.get("entry_type") or e.get("type") or "dynamic"),
            "timestamp":   float(e.get("timestamp") or time.time()),
            "raw":         e,
        })

    for g in (gw_raw if isinstance(gw_raw, list) else [gw_raw]):
        if not isinstance(g, dict):
            continue
        ip  = str(g.get("ip") or g.get("gateway_ip") or "").strip()
        mac = _normalize_mac(str(g.get("mac") or g.get("mac_address") or ""))
        if not ip:
            continue
        result["gateway_info"].append({
            "ip":        ip,
            "mac":       mac,
            "interface": str(g.get("interface") or g.get("iface") or ""),
            "raw":       g,
        })

    for s in (stats_raw if isinstance(stats_raw, list) else []):
        if not isinstance(s, dict):
            continue
        result["arp_stats"].append({
            "interface":       str(s.get("interface") or s.get("iface") or ""),
            "packets_per_min": int(s.get("packets_per_min") or s.get("rate") or 0),
        })

    for d in (dhcp_raw if isinstance(dhcp_raw, list) else []):
        if not isinstance(d, dict):
            continue
        result["dhcp_events"].append({
            "event_type": str(d.get("event_type") or d.get("type") or ""),
            "timestamp":  float(d.get("timestamp") or time.time()),
            "ip":         str(d.get("ip") or d.get("ip_address") or ""),
        })

    return result


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

async def detect_gateway_mac_change(
    agent_id:     str,
    entries:      list[dict],
    gateway_info: list[dict],
    db:           Any,
) -> list[dict]:
    """
    CRITICAL: Gateway IP resolves to a different MAC than the immutable baseline.

    Baseline is established at first observation and updated only on explicit
    admin rebaseline command.  FHRP virtual MACs, trusted MACs, and IPs inside
    the DHCP suppression window are excluded.
    """
    # Ground-truth view of what the host has cached — prefer over routing-table MAC
    arp_snapshot: dict[str, str] = {
        e["ip_address"]: e["mac_address"]
        for e in entries if e.get("ip_address") and e.get("mac_address")
    }

    hits = []
    for gw in gateway_info:
        gw_ip = gw.get("ip", "").strip()
        iface = gw.get("interface", "")
        if not gw_ip:
            continue

        current_mac = arp_snapshot.get(gw_ip) or _normalize_mac(gw.get("mac", ""))
        if not current_mac:
            continue

        key      = f"gateway:{iface}:{gw_ip}"
        baseline = await _load_baseline(agent_id, key, db)

        if not baseline:
            await _save_baseline(agent_id, key, {
                "ip": gw_ip, "mac": current_mac,
                "interface": iface, "first_seen": time.time(),
            }, db)
            log.debug("ARP gateway baseline set: agent=%s gw=%s mac=%s",
                      agent_id, gw_ip, current_mac)
            continue

        baseline_mac = baseline.get("mac", "")
        if not baseline_mac or current_mac == baseline_mac:
            continue

        if _is_dhcp_suppressed(agent_id, gw_ip):
            log.debug("ARP gw MAC change suppressed by DHCP window: %s", gw_ip)
            continue

        if _is_fhrp_mac(current_mac) or _is_fhrp_mac(baseline_mac):
            continue

        if _is_trusted_mac(current_mac):
            continue

        first_seen_str = ""
        try:
            first_seen_str = datetime.fromtimestamp(
                float(baseline.get("first_seen", 0))
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass

        hits.append({
            "rule_id":    "arp:gateway_mac_changed",
            "severity":   "critical",
            "title":      f"Gateway MAC changed: {gw_ip} ({baseline_mac} → {current_mac})",
            "description": (
                f"Default gateway {gw_ip} on interface '{iface}' now resolves to "
                f"MAC {current_mac}, which differs from the baseline MAC {baseline_mac} "
                f"(established {first_seen_str}). "
                f"This is a strong indicator of ARP cache poisoning (T1557.002) — "
                f"an adversary may have sent gratuitous ARP replies to intercept all "
                f"traffic destined for the default gateway."
            ),
            "evidence": {
                "gateway_ip":   gw_ip,
                "current_mac":  current_mac,
                "baseline_mac": baseline_mac,
                "interface":    iface,
                "baseline_set": baseline.get("first_seen", ""),
            },
            "raw_telemetry": [gw.get("raw", gw)],
            "mitre_tactic":     "Collection",
            "mitre_technique":  "T1557.002",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "PR.AC-5"],  "CIS": ["13.4", "13.6"],
                "ISO":  ["A.13.1.2"],             "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"1. Verify physical gateway at {gw_ip}: check switch ARP/CAM table. "
                f"2. Flush endpoint ARP cache: `arp -d {gw_ip}` (macOS/Linux). "
                f"3. Capture ARP traffic: `tcpdump -i {iface} arp` — look for "
                f"unsolicited gratuitous ARP frames from {current_mac}. "
                f"4. Identify device with MAC {current_mac}: `nmap -sn <subnet>`. "
                f"5. If poisoning confirmed: isolate endpoint and rotate sensitive credentials."
            ),
            "false_positive_notes": (
                "Gateway hardware replacement or NIC swap triggers this alert. "
                "VRRP/HSRP/GLBP failover (virtual MAC change) is suppressed automatically. "
                "After confirming the new MAC is legitimate, re-baseline via admin command."
            ),
            "item_key":   f"arp:gw_mac:{gw_ip}",
            "category":   "network",
            "source":     "rule:arp_spoofing",
            "score":      SEVERITY_SCORES["critical"],
            "tags":       ["arp_spoofing", "gateway", "mitm", "T1557.002"],
        })

    return hits


def detect_duplicate_ip_mapping(
    agent_id: str,
    entries:  list[dict],
) -> list[dict]:
    """
    CRITICAL: Same IP maps to 2+ different MACs in a single ARP snapshot.

    The simultaneous presence of duplicate IP entries is a definitive ARP
    poisoning signal.  FHRP virtual MACs are excluded.  Load-balancer IPs
    where all MACs are trusted are excluded.
    """
    ip_to_macs:    dict[str, set[str]]   = {}
    ip_to_entries: dict[str, list[dict]] = {}

    for entry in entries:
        ip  = entry.get("ip_address", "")
        mac = entry.get("mac_address", "")
        if not ip or not mac:
            continue
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        if _is_fhrp_mac(mac):
            continue
        ip_to_macs.setdefault(ip, set()).add(mac)
        ip_to_entries.setdefault(ip, []).append(entry)

    hits = []
    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        # Admin-approved multi-MAC entries (LACP bond, load balancer)
        if all(_is_trusted_mac(m) for m in macs):
            continue
        mac_list = sorted(macs)
        hits.append({
            "rule_id":    "arp:duplicate_ip_mapping",
            "severity":   "critical",
            "title":      f"Duplicate ARP mapping: {ip} → {len(macs)} MACs",
            "description": (
                f"IP {ip} simultaneously maps to {len(macs)} different MAC addresses: "
                f"{', '.join(mac_list)}. "
                f"Two devices are claiming ownership of {ip}. "
                f"The rogue device is injecting spoofed ARP replies to position "
                f"itself as a man-in-the-middle for traffic to/from {ip}."
            ),
            "evidence": {
                "ip_address":    ip,
                "mac_addresses": mac_list,
                "entry_count":   len(ip_to_entries[ip]),
                "entries":       [e.get("raw", e) for e in ip_to_entries[ip][:4]],
            },
            "raw_telemetry": [e.get("raw", e) for e in ip_to_entries[ip][:4]],
            "mitre_tactic":     "Collection",
            "mitre_technique":  "T1557.002",
            "compliance_controls": {
                "NIST": ["DE.CM-1", "PR.AC-5"],  "CIS": ["13.4"],
                "ISO":  ["A.13.1.2"],             "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"1. Identify the legitimate owner of {ip} from DHCP lease table. "
                f"2. For each MAC {mac_list}: trace to a switch port via CAM table. "
                f"3. Disconnect the unauthorized device immediately. "
                f"4. Run `arp -d {ip}` on all endpoints to flush poisoned caches. "
                f"5. Enable Dynamic ARP Inspection (DAI) on managed switches."
            ),
            "false_positive_notes": (
                "Load balancers (ECMP), LACP bond pairs, and VM live migration can "
                "produce duplicate IP→MAC entries legitimately. FHRP virtual IPs "
                "(VRRP/HSRP/GLBP) are suppressed automatically. "
                "Add approved multi-MAC IPs to config/trusted_macs.json."
            ),
            "item_key":   f"arp:dup_ip:{ip}",
            "category":   "network",
            "source":     "rule:arp_spoofing",
            "score":      SEVERITY_SCORES["critical"],
            "tags":       ["arp_spoofing", "duplicate_ip", "mitm", "T1557.002"],
        })

    return hits


async def detect_arp_churn(
    agent_id: str,
    entries:  list[dict],
    db:       Any,
) -> list[dict]:
    """
    HIGH: Same IP changes MAC more than CHURN_THRESHOLD times within a
    60-second sliding window.

    Compares each entry's MAC against the last-seen value in entity state.
    Change events are timestamped in a module-level sliding window per agent:IP.
    A 5-minute cooldown prevents alert storms for the same IP.
    """
    hits = []
    now  = time.time()

    for entry in entries:
        ip  = entry.get("ip_address", "")
        mac = entry.get("mac_address", "")
        if not ip or not mac:
            continue

        key      = f"arp_last:{ip}"
        baseline = await _load_baseline(agent_id, key, db)
        prev_mac = (baseline or {}).get("mac", "")

        if prev_mac and prev_mac != mac:
            if _is_dhcp_suppressed(agent_id, ip):
                await _save_baseline(agent_id, key, {"ip": ip, "mac": mac, "ts": now}, db)
                continue

            churn_key = f"{agent_id}:{ip}"
            window = [t for t in _churn_window.get(churn_key, []) if now - t < CHURN_WINDOW_SECS]
            window.append(now)
            _churn_window[churn_key] = window

            if len(window) >= CHURN_THRESHOLD:
                last_alert = _churn_alert_ts.get(churn_key, 0)
                if now - last_alert >= CHURN_ALERT_COOLDOWN_SECS:
                    _churn_alert_ts[churn_key] = now
                    hits.append({
                        "rule_id":    "arp:rapid_churn",
                        "severity":   "high",
                        "title":      (
                            f"ARP rapid churn: {ip} changed MAC "
                            f"{len(window)}× in {CHURN_WINDOW_SECS}s"
                        ),
                        "description": (
                            f"IP {ip} has changed its MAC address {len(window)} times "
                            f"within the last {CHURN_WINDOW_SECS} seconds "
                            f"(current: {mac}, previous: {prev_mac}). "
                            f"Rapid ARP table churn exceeding {CHURN_THRESHOLD} MAC "
                            f"changes per {CHURN_WINDOW_SECS}s strongly indicates an "
                            f"active ARP poisoning script sending continuous gratuitous "
                            f"ARP floods."
                        ),
                        "evidence": {
                            "ip_address":       ip,
                            "current_mac":      mac,
                            "previous_mac":     prev_mac,
                            "changes_in_window": len(window),
                            "window_secs":      CHURN_WINDOW_SECS,
                            "threshold":        CHURN_THRESHOLD,
                            "interface":        entry.get("interface", ""),
                        },
                        "raw_telemetry": [entry.get("raw", entry)],
                        "mitre_tactic":     "Collection",
                        "mitre_technique":  "T1557.002",
                        "compliance_controls": {
                            "NIST": ["DE.CM-1", "PR.AC-5"],  "CIS": ["13.4", "13.6"],
                            "ISO":  ["A.13.1.2"],             "SOC2": ["CC6.6"],
                        },
                        "recommended_action": (
                            f"An ARP poisoning tool is actively flooding the network for {ip}. "
                            f"1. Capture ARP replies: `tcpdump -i {entry.get('interface','en0')} "
                            f"'arp[6:2] == 2'` to identify the sender. "
                            f"2. Trace MAC {mac} to a switch port via CAM table lookup. "
                            f"3. Disconnect the offending device immediately. "
                            f"4. Enable Dynamic ARP Inspection on the switch."
                        ),
                        "false_positive_notes": (
                            "High-frequency DHCP renewals on unstable links may cause brief "
                            "churn — DHCP events suppress alerts for 30 seconds. "
                            "VM live migration causes legitimate MAC churn during movement. "
                            "5-minute cooldown prevents alert storms for the same IP."
                        ),
                        "item_key":   f"arp:churn:{ip}",
                        "category":   "network",
                        "source":     "rule:arp_spoofing",
                        "score":      SEVERITY_SCORES["high"],
                        "tags":       ["arp_spoofing", "churn", "mitm", "T1557"],
                    })

        await _save_baseline(agent_id, key, {"ip": ip, "mac": mac, "ts": now}, db)

    return hits


async def detect_rogue_oui(
    agent_id: str,
    entries:  list[dict],
    db:       Any,
) -> list[dict]:
    """
    HIGH: A MAC OUI prefix appears for the first time in 7 days AND matches
    a known pentest tool / rogue AP hardware vendor.

    The per-agent OUI baseline is maintained in entity state.  A new OUI only
    triggers an alert if it is in KNOWN_PENTEST_OUI_PREFIXES.
    """
    oui_key  = "oui_baseline"
    row      = await _load_baseline(agent_id, oui_key, db) or {}
    now      = time.time()
    cutoff   = now - (ROGUE_OUI_BASELINE_DAYS * 86400)

    # Load and prune stale OUI observations
    oui_baseline: dict[str, float] = {
        oui: ts
        for oui, ts in (row.get("ouis") or {}).items()
        if ts >= cutoff
    }

    hits:     list[dict]       = []
    new_ouis: dict[str, float] = {}

    for entry in entries:
        mac = entry.get("mac_address", "")
        if not mac:
            continue
        oui = _extract_oui(mac)
        if not oui:
            continue

        new_ouis[oui] = min(new_ouis.get(oui, now), now)

        if oui not in oui_baseline and oui in KNOWN_PENTEST_OUI_PREFIXES:
            ip    = entry.get("ip_address", "unknown")
            iface = entry.get("interface", "")
            hits.append({
                "rule_id":    "arp:rogue_oui",
                "severity":   "high",
                "title":      f"Known pentest tool OUI detected: {mac} (OUI {oui}) on {iface}",
                "description": (
                    f"MAC address {mac} has OUI prefix {oui}, which belongs to a vendor "
                    f"commonly used in MITM attack kits "
                    f"(Alfa Inc. USB WiFi adapters or Raspberry Pi rogue AP platforms). "
                    f"This OUI has not been observed in the {ROGUE_OUI_BASELINE_DAYS}-day "
                    f"ARP history for this endpoint. "
                    f"The device appears at IP {ip} on interface '{iface}'."
                ),
                "evidence": {
                    "mac_address":        mac,
                    "oui_prefix":         oui,
                    "ip_address":         ip,
                    "interface":          iface,
                    "first_time_seen":    True,
                    "baseline_days":      ROGUE_OUI_BASELINE_DAYS,
                },
                "raw_telemetry": [entry.get("raw", entry)],
                "mitre_tactic":     "Collection",
                "mitre_technique":  "T1557",
                "compliance_controls": {
                    "NIST": ["DE.CM-1", "PR.AC-5"],  "CIS": ["13.6"],
                    "ISO":  ["A.13.1.2"],             "SOC2": ["CC6.6"],
                },
                "recommended_action": (
                    f"1. Identify the physical device with MAC {mac}: check switch CAM table "
                    f"and look for an Alfa USB adapter or Raspberry Pi on the LAN. "
                    f"2. If unauthorized: isolate the switch port immediately. "
                    f"3. Verify active MITM: `tcpdump -i {iface} arp`. "
                    f"4. If authorized (security team gear), add to config/trusted_macs.json "
                    f"with a rationale and expiry date."
                ),
                "false_positive_notes": (
                    "Authorized security team equipment (Alfa adapters, Pi-based scanners) "
                    "legitimately uses these OUIs. Internal IoT devices occasionally use "
                    "Raspberry Pi hardware. Add authorized devices to trusted_macs.json."
                ),
                "item_key":   f"arp:rogue_oui:{oui}",
                "category":   "network",
                "source":     "rule:arp_spoofing",
                "score":      SEVERITY_SCORES["high"],
                "tags":       ["arp_spoofing", "rogue_oui", "pentest_vendor", "T1557"],
            })

    # Persist updated OUI baseline
    oui_baseline.update(new_ouis)
    await _save_baseline(agent_id, oui_key, {"ouis": oui_baseline}, db)

    return hits


def detect_arp_flood(
    agent_id:  str,
    arp_stats: list[dict],
) -> list[dict]:
    """
    MEDIUM: ARP broadcast rate on an interface exceeds 500 packets/minute.

    Indicates a potential ARP flood or gratuitous ARP storm — often a
    precursor to MITM setup, or a misconfigured device causing broadcast storm.
    """
    hits = []
    for stat in arp_stats:
        iface = stat.get("interface", "")
        rate  = int(stat.get("packets_per_min") or 0)
        if rate <= ARP_FLOOD_THRESHOLD:
            continue
        excess = round(rate / ARP_FLOOD_THRESHOLD, 1)
        hits.append({
            "rule_id":    "arp:flood",
            "severity":   "medium",
            "title":      (
                f"Excessive ARP rate on {iface}: {rate} pkt/min "
                f"(threshold: {ARP_FLOOD_THRESHOLD}, {excess}×)"
            ),
            "description": (
                f"Interface {iface} is processing {rate} ARP packets per minute, "
                f"{excess}× above the threshold of {ARP_FLOOD_THRESHOLD} pkt/min. "
                f"Elevated ARP rates are characteristic of: "
                f"(1) ARP poisoning tools flooding gratuitous ARP replies, "
                f"(2) network scanning tools using ARP host discovery, or "
                f"(3) misconfigured devices generating ARP broadcast storms."
            ),
            "evidence": {
                "interface":       iface,
                "packets_per_min": rate,
                "threshold":       ARP_FLOOD_THRESHOLD,
                "excess_factor":   excess,
            },
            "raw_telemetry": [stat],
            "mitre_tactic":     "Discovery",
            "mitre_technique":  "T1557",
            "compliance_controls": {
                "NIST": ["DE.CM-1"],  "CIS": ["13.4"],
                "ISO":  ["A.13.1.2"], "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"1. Capture ARP traffic: "
                f"`tcpdump -i {iface} arp -c 200 -w /tmp/arp_flood.pcap`. "
                f"2. Identify flooding source MAC from captured packets. "
                f"3. If authorized scan: confirm with security team. "
                f"4. If not authorized: trace MAC to switch port and isolate. "
                f"5. Enable ARP rate limiting and storm control on managed switches."
            ),
            "false_positive_notes": (
                "Network asset discovery scans (Nessus, Qualys, internal scanners) "
                "generate legitimate high-rate ARP traffic. Confirm with the security "
                "team if a scheduled scan is in progress."
            ),
            "item_key":   f"arp:flood:{iface}",
            "category":   "network",
            "source":     "rule:arp_spoofing",
            "score":      SEVERITY_SCORES["medium"],
            "tags":       ["arp_spoofing", "flood", "T1557"],
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
        "category":    hit.get("category", "network"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:arp_spoofing"),
        "tags":        hit.get("tags", ["arp_spoofing"]),
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
    Main entry point.  Called by AttackLensEngine._dispatch() for 'arp' section.
    Returns list of structured alert dicts ready for IntelDB.upsert_finding().
    """
    if section != "arp":
        return []

    ingested     = ingest_arp(data)
    entries      = ingested["entries"]
    gateway_info = ingested["gateway_info"]
    arp_stats    = ingested["arp_stats"]
    dhcp_events  = ingested["dhcp_events"]

    if not entries and not gateway_info and not arp_stats:
        return []

    # Register DHCP events first — suppression applies to subsequent checks
    _process_dhcp_events(agent_id, dhcp_events)

    raw_hits: list[dict] = []

    try:
        raw_hits.extend(
            await detect_gateway_mac_change(agent_id, entries, gateway_info, db)
        )
    except Exception as exc:
        log.debug("detect_gateway_mac_change error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(detect_duplicate_ip_mapping(agent_id, entries))
    except Exception as exc:
        log.debug("detect_duplicate_ip_mapping error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(await detect_arp_churn(agent_id, entries, db))
    except Exception as exc:
        log.debug("detect_arp_churn error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(await detect_rogue_oui(agent_id, entries, db))
    except Exception as exc:
        log.debug("detect_rogue_oui error agent=%s: %s", agent_id, exc)

    try:
        raw_hits.extend(detect_arp_flood(agent_id, arp_stats))
    except Exception as exc:
        log.debug("detect_arp_flood error agent=%s: %s", agent_id, exc)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Suppressed dedup: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))

    if alerts:
        log.info("ARPSpoofing: agent=%s entries=%d gateways=%d alerts=%d",
                 agent_id, len(entries), len(gateway_info), len(alerts))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS — TP + FP per detection condition
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    print("=== arp_spoofing.py — Test Harness ===\n")

    class MockDB:
        def __init__(self):
            self._state: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._state.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, fingerprint, ts):
            self._state[f"{agent_id}:{ns}:{key}"] = {"fingerprint": fingerprint, "ts": ts}

    def _e(ip, mac, iface="en0"):
        return {
            "ip_address": ip, "mac_address": _normalize_mac(mac),
            "interface": iface, "entry_type": "dynamic",
            "timestamp": time.time(), "raw": {"ip": ip, "mac": mac},
        }

    async def run_tests():
        # ── MAC normalization ─────────────────────────────────────────────────
        assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        assert _normalize_mac("aabbccddeeff")       == "aa:bb:cc:dd:ee:ff"
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
        assert _normalize_mac("invalid")             == ""
        assert _normalize_mac("")                    == ""
        print("[PASS] MAC normalization")

        # ── OUI extraction ────────────────────────────────────────────────────
        assert _extract_oui("aa:bb:cc:dd:ee:ff") == "aabbcc"
        assert _extract_oui("00:c0:ca:12:34:56") == "00c0ca"   # Alfa Inc.
        assert _extract_oui("b8:27:eb:12:34:56") == "b827eb"   # Raspberry Pi
        assert _extract_oui("short")             == ""
        print("[PASS] OUI extraction")

        # ── FHRP MAC detection ────────────────────────────────────────────────
        assert _is_fhrp_mac("00:00:5e:00:01:01") is True    # VRRP IPv4
        assert _is_fhrp_mac("00:00:0c:07:ac:01") is True    # HSRP v1
        assert _is_fhrp_mac("00:07:b4:00:01:ff") is True    # GLBP
        assert _is_fhrp_mac("aa:bb:cc:dd:ee:ff") is False   # normal MAC
        print("[PASS] FHRP MAC detection")

        # ── TP: Duplicate IP mapping ──────────────────────────────────────────
        dup_entries = [
            _e("192.168.1.1", "aa:bb:cc:dd:ee:ff"),
            _e("192.168.1.1", "11:22:33:44:55:66"),
        ]
        dup_hits = detect_duplicate_ip_mapping("agent-dup", dup_entries)
        assert len(dup_hits) == 1 and dup_hits[0]["severity"] == "critical"
        assert "T1557.002" in dup_hits[0]["mitre_technique"]
        assert len(dup_hits[0]["evidence"]["mac_addresses"]) == 2
        print(f"[PASS] TP duplicate IP: {dup_hits[0]['title']}")

        # ── FP: Single MAC per IP ─────────────────────────────────────────────
        assert detect_duplicate_ip_mapping("agent-fp-dup", [_e("192.168.1.1", "aa:bb:cc:dd:ee:ff")]) == []
        print("[PASS] FP single MAC per IP: suppressed")

        # ── FP: FHRP virtual MAC in duplicate pair ────────────────────────────
        fhrp_entries = [
            _e("10.0.0.1", "00:00:5e:00:01:01"),   # VRRP → skipped
            _e("10.0.0.1", "aa:bb:cc:11:22:33"),   # physical → only one non-FHRP
        ]
        assert detect_duplicate_ip_mapping("agent-fhrp", fhrp_entries) == []
        print("[PASS] FP FHRP virtual MAC pair: suppressed")

        # ── TP: Gateway MAC change ────────────────────────────────────────────
        db_gw     = MockDB()
        gw_ip     = "192.168.100.1"
        base_mac  = "aa:bb:cc:00:00:01"
        rogue_mac = "de:ad:be:ef:00:01"
        gw_first  = [{"ip": gw_ip, "mac": base_mac, "interface": "en0", "raw": {}}]
        gw_change = [{"ip": gw_ip, "mac": rogue_mac, "interface": "en0", "raw": {}}]

        # First observation — baseline established, no alert
        h1 = await detect_gateway_mac_change("agent-gw", [], gw_first, db_gw)
        assert h1 == []
        print("[PASS] Gateway baseline set: no alert on first observation")

        # Second observation with changed MAC — CRITICAL
        h2 = await detect_gateway_mac_change("agent-gw", [], gw_change, db_gw)
        assert len(h2) == 1 and h2[0]["severity"] == "critical"
        assert h2[0]["evidence"]["baseline_mac"] == base_mac
        assert h2[0]["evidence"]["current_mac"]  == rogue_mac
        print(f"[PASS] TP gateway MAC change: {h2[0]['title']}")

        # ── FP: Gateway MAC change suppressed by DHCP event ───────────────────
        db_dhcp = MockDB()
        gw2_ip  = "10.10.1.1"
        gw2_a   = "cc:dd:ee:ff:00:01"
        gw2_b   = "cc:dd:ee:ff:00:02"
        await detect_gateway_mac_change("agent-dhcp", [],
            [{"ip": gw2_ip, "mac": gw2_a, "interface": "en1", "raw": {}}], db_dhcp)
        _process_dhcp_events("agent-dhcp", [{"event_type": "ACK", "timestamp": time.time(), "ip": gw2_ip}])
        h_dhcp = await detect_gateway_mac_change("agent-dhcp", [],
            [{"ip": gw2_ip, "mac": gw2_b, "interface": "en1", "raw": {}}], db_dhcp)
        assert h_dhcp == []
        print("[PASS] FP gateway MAC change suppressed by DHCP window")

        # ── TP: ARP table rapid churn ─────────────────────────────────────────
        db_churn    = MockDB()
        churn_ip    = "192.168.5.50"
        churn_agent = "agent-churn"
        # Pre-store previous MAC so the next call sees a change
        await _save_baseline(churn_agent, f"arp_last:{churn_ip}",
                             {"ip": churn_ip, "mac": "11:22:33:44:55:66", "ts": time.time()},
                             db_churn)
        # Pre-fill churn window to CHURN_THRESHOLD - 1 (next change hits threshold)
        ck = f"{churn_agent}:{churn_ip}"
        _churn_window[ck] = [time.time() - i for i in range(CHURN_THRESHOLD - 1)]

        churn_hits = await detect_arp_churn(churn_agent, [_e(churn_ip, "99:88:77:66:55:44")], db_churn)
        assert len(churn_hits) == 1 and churn_hits[0]["severity"] == "high"
        assert churn_hits[0]["evidence"]["changes_in_window"] >= CHURN_THRESHOLD
        print(f"[PASS] TP ARP churn: {churn_hits[0]['title']}")

        # ── FP: Churn below threshold ─────────────────────────────────────────
        db_churn2   = MockDB()
        fp_churn_ip = "192.168.5.51"
        fa          = "agent-churn-fp"
        await _save_baseline(fa, f"arp_last:{fp_churn_ip}",
                             {"ip": fp_churn_ip, "mac": "aa:aa:aa:aa:aa:aa", "ts": time.time()},
                             db_churn2)
        _churn_window[f"{fa}:{fp_churn_ip}"] = [time.time() - 5, time.time() - 3]
        fp_churn = await detect_arp_churn(fa, [_e(fp_churn_ip, "bb:bb:bb:bb:bb:bb")], db_churn2)
        assert fp_churn == []
        print("[PASS] FP ARP churn below threshold: suppressed")

        # ── TP: Rogue OUI — Alfa Inc. ─────────────────────────────────────────
        db_oui   = MockDB()
        alfa_mac = "00:c0:ca:ab:cd:ef"
        oui_hits = await detect_rogue_oui("agent-oui", [_e("192.168.1.99", alfa_mac)], db_oui)
        assert len(oui_hits) == 1 and oui_hits[0]["severity"] == "high"
        assert oui_hits[0]["evidence"]["oui_prefix"] == "00c0ca"
        print(f"[PASS] TP rogue OUI (Alfa): {oui_hits[0]['title']}")

        # ── FP: Same OUI on second call (already in 7-day baseline) ───────────
        oui_hits2 = await detect_rogue_oui("agent-oui", [_e("192.168.1.99", alfa_mac)], db_oui)
        assert oui_hits2 == []
        print("[PASS] FP rogue OUI already in baseline: suppressed")

        # ── FP: Unknown OUI not in pentest list ───────────────────────────────
        db_oui3  = MockDB()
        norm_mac = "aa:bb:cc:12:34:56"   # random OUI, not in pentest list
        assert await detect_rogue_oui("agent-oui3", [_e("192.168.1.100", norm_mac)], db_oui3) == []
        print("[PASS] FP unknown OUI (not in pentest list): suppressed")

        # ── TP: Rogue OUI — Raspberry Pi ─────────────────────────────────────
        db_oui4 = MockDB()
        pi_mac  = "b8:27:eb:12:34:56"
        pi_hits = await detect_rogue_oui("agent-oui4", [_e("192.168.1.98", pi_mac)], db_oui4)
        assert len(pi_hits) == 1
        assert "b827eb" in pi_hits[0]["evidence"]["oui_prefix"]
        print(f"[PASS] TP rogue OUI (Raspberry Pi): {pi_hits[0]['title']}")

        # ── TP: ARP flood ─────────────────────────────────────────────────────
        flood_hits = detect_arp_flood("agent-flood", [{"interface": "en0", "packets_per_min": 750}])
        assert len(flood_hits) == 1 and flood_hits[0]["severity"] == "medium"
        assert flood_hits[0]["evidence"]["packets_per_min"] == 750
        assert flood_hits[0]["evidence"]["excess_factor"] == 1.5
        print(f"[PASS] TP ARP flood: {flood_hits[0]['title']}")

        # ── FP: ARP rate below threshold ──────────────────────────────────────
        assert detect_arp_flood("agent-fp-flood", [{"interface": "en0", "packets_per_min": 300}]) == []
        print("[PASS] FP ARP rate below threshold: suppressed")

        # ── FP: Exactly at threshold (not exceeded) ───────────────────────────
        assert detect_arp_flood("agent-fp-eq", [{"interface": "en0", "packets_per_min": 500}]) == []
        print("[PASS] FP ARP rate at threshold (not exceeded): suppressed")

        # ── Alert builder: all mandatory fields ───────────────────────────────
        alert = build_alert(dup_hits[0], "agent-001", "corp-laptop-01")
        required = {"alert_id", "severity", "title", "description", "affected_asset",
                    "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
                    "compliance_controls", "recommended_action", "false_positive_notes",
                    "timestamp_utc"}
        missing = required - set(alert.keys())
        assert not missing, f"Missing mandatory fields: {missing}"
        assert alert["affected_asset"] == "corp-laptop-01"
        assert alert["alert_id"]  # non-empty UUID
        print("[PASS] Alert builder: all mandatory fields present")

        # ── Dedup ─────────────────────────────────────────────────────────────
        _dedup_cache.clear()
        _rate_counter.clear()
        assert _should_suppress("agent-dd", "arp:test", "key1") is False   # first → pass
        assert _should_suppress("agent-dd", "arp:test", "key1") is True    # repeat → suppress
        assert _should_suppress("agent-dd", "arp:test", "key2") is False   # different key → pass
        assert _should_suppress("agent-dd2", "arp:test", "key1") is False  # different agent → pass
        print("[PASS] Dedup: first=pass, second=suppress, diff_key=pass, diff_agent=pass")

        print("\n=== All tests passed ===")

    asyncio.run(run_tests())
