"""
manager/api/assets.py — Asset Registry endpoints.

GET /api/v1/assets            enriched asset list (all agents + live system stats)
GET /api/v1/assets/{id}       single-asset full detail
GET /api/v1/assets/topology   subnet topology data for diagram

Enrichment strategy — 3 batch queries, not N per agent:
  1. db.get_all_agents()                          → base identity + last_seen
  2. intel_db.list_assets()                       → asset_registry meta (tier, owner…)
  3. db.get_latest_section_per_agent("metrics")   → CPU, RAM, processes, uptime
  4. db.get_latest_section_per_agent("battery")   → charge %, charging, condition
  5. db.get_latest_section_per_agent("network")   → IP interfaces → primary IP + MAC
  6. db.get_latest_section_per_agent("processes") → process count
  7. intel_db.get_summary(agent_id)              → findings counts (per-agent, cached)

All done concurrently via asyncio.gather for minimum latency.
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

log = logging.getLogger("manager.api.assets")

_ONLINE_SECONDS = 90    # < 90s → online
_STALE_SECONDS  = 300   # 90–300s → stale, >300s → offline


def make_assets_router(db: "Database", intel_db: "IntelDB") -> APIRouter:
    router = APIRouter()

    # ── Enriched asset list ───────────────────────────────────────────────────

    @router.get("")
    async def list_assets():
        now = int(time.time())

        # Batch fetch all data concurrently
        (
            agents,
            registry,
            metrics_map,
            battery_map,
            network_map,
            processes_map,
        ) = await asyncio.gather(
            db.get_all_agents(),
            intel_db.list_assets(),
            db.get_latest_section_per_agent("metrics"),
            db.get_latest_section_per_agent("battery"),
            db.get_latest_section_per_agent("network"),
            db.get_latest_section_per_agent("processes"),
        )

        # Index registry by agent_id for O(1) lookup
        reg_by_id: dict[str, dict] = {r["agent_id"]: r for r in registry}

        result = []
        for agent in agents:
            aid = agent["agent_id"]
            reg = reg_by_id.get(aid, {})
            m   = metrics_map.get(aid, {})
            bat = battery_map.get(aid, {})
            net = network_map.get(aid, {})
            procs = processes_map.get(aid, [])

            last_seen = int(agent.get("last_seen") or 0)
            elapsed   = now - last_seen if last_seen else 9999
            status    = (
                "online"  if elapsed < _ONLINE_SECONDS else
                "stale"   if elapsed < _STALE_SECONDS  else
                "offline"
            )

            # Primary IP + MAC from network section
            primary_ip, primary_mac = _extract_primary_interface(net, agent.get("last_ip", ""))

            # Process count
            proc_count = len(procs) if isinstance(procs, list) else 0

            result.append({
                # Identity
                "agent_id":    aid,
                "hostname":    reg.get("hostname") or agent.get("name") or aid,
                "os":          reg.get("os", ""),
                "os_version":  reg.get("os_version", ""),
                "arch":        reg.get("arch", ""),
                # Status
                "status":      status,
                "last_seen":   last_seen,
                "elapsed_s":   elapsed,
                "last_ip":     agent.get("last_ip", ""),
                "first_seen":  int(reg.get("first_seen") or agent.get("created_at") or 0),
                # Network
                "ip":          primary_ip,
                "mac":         primary_mac,
                "interfaces":  _extract_interfaces(net),
                # Asset tier
                "asset_tier":  reg.get("asset_tier", "standard"),
                "importance":  float(reg.get("importance") or 0.3),
                "owner":       reg.get("owner", ""),
                "department":  reg.get("department", ""),
                "asset_group": reg.get("asset_group", ""),
                "tags":        reg.get("tags") or [],
                # Live system metrics
                "cpu_percent":      _safe_float(m.get("cpu_percent")),
                "cpu_cores":        m.get("cpu_cores"),
                "cpu_cores_physical": m.get("cpu_cores_physical"),
                "cpu_freq_mhz":     m.get("cpu_freq_mhz"),
                "mem_percent":      _safe_float(m.get("mem_percent")),
                "mem_used_mb":      m.get("mem_used_mb"),
                "mem_total_mb":     m.get("mem_total_mb"),
                "mem_available_mb": m.get("mem_available_mb"),
                "swap_percent":     _safe_float(m.get("swap_percent")),
                "load_1m":          m.get("load_1m"),
                "load_5m":          m.get("load_5m"),
                "uptime_sec":       m.get("uptime_sec"),
                "process_count":    proc_count,
                # Battery
                "battery_present":  bat.get("present", False),
                "battery_pct":      _safe_float(bat.get("charge_pct")),
                "battery_charging": bat.get("charging"),
                "battery_condition":bat.get("condition", ""),
                "battery_cycles":   bat.get("cycle_count"),
            })

        return result

    # ── Single-asset detail ───────────────────────────────────────────────────

    @router.get("/topology")
    async def topology():
        """
        Subnet topology data for the diagram.
        Groups assets by /24 subnet derived from their primary IP.
        Includes ARP table peers for each asset.
        """
        now = int(time.time())
        agents, arp_map = await asyncio.gather(
            db.get_all_agents(),
            db.get_latest_section_per_agent("arp"),
        )
        network_map = await db.get_latest_section_per_agent("network")

        nodes = []
        for agent in agents:
            aid = agent["agent_id"]
            net = network_map.get(aid, {})
            arp = arp_map.get(aid, {})

            last_seen = int(agent.get("last_seen") or 0)
            elapsed   = now - last_seen if last_seen else 9999
            status    = (
                "online"  if elapsed < _ONLINE_SECONDS else
                "stale"   if elapsed < _STALE_SECONDS  else
                "offline"
            )

            primary_ip, primary_mac = _extract_primary_interface(net, agent.get("last_ip", ""))
            subnet = _subnet(primary_ip or agent.get("last_ip", ""))

            # ARP peers (other hosts this agent has seen on its LAN)
            arp_entries = arp if isinstance(arp, list) else []
            peers = [
                {"ip": e.get("ip", ""), "mac": e.get("mac", ""), "hostname": e.get("hostname", "")}
                for e in arp_entries
                if isinstance(e, dict) and e.get("ip")
            ][:20]

            nodes.append({
                "agent_id": aid,
                "hostname": agent.get("name") or aid,
                "ip":       primary_ip or agent.get("last_ip", ""),
                "mac":      primary_mac,
                "subnet":   subnet,
                "status":   status,
                "peers":    peers,
            })

        # Group nodes by subnet
        subnets: dict[str, list] = {}
        for node in nodes:
            s = node["subnet"] or "unknown"
            subnets.setdefault(s, []).append(node)

        return {
            "nodes":   nodes,
            "subnets": [
                {"subnet": s, "count": len(ns), "nodes": [n["agent_id"] for n in ns]}
                for s, ns in sorted(subnets.items())
            ],
        }

    @router.get("/{agent_id}")
    async def get_asset(agent_id: str):
        """Full asset detail — all system sections for one agent."""
        agent = await db.get_agent(agent_id)
        if not agent:
            raise HTTPException(404, "Agent not found")

        now = int(time.time())

        # Fetch all relevant sections concurrently
        (
            reg,
            metrics,
            battery,
            network,
            processes,
            storage_data,
            users_data,
            sessions,
            findings_summary,
        ) = await asyncio.gather(
            intel_db.get_asset(agent_id),
            db.get_latest_section_per_agent("metrics"),
            db.get_latest_section_per_agent("battery"),
            db.get_latest_section_per_agent("network"),
            db.get_latest_section_per_agent("processes"),
            db.get_latest_section_per_agent("storage"),
            db.get_latest_section_per_agent("users"),
            db.get_agent_sessions(agent_id, limit=5),
            intel_db.get_summary(agent_id),
        )

        m   = metrics.get(agent_id, {})
        bat = battery.get(agent_id, {})
        net = network.get(agent_id, {})
        procs = processes.get(agent_id, [])
        storage = storage_data.get(agent_id, {})
        users   = users_data.get(agent_id, {})

        last_seen = int(agent.get("last_seen") or 0)
        elapsed   = now - last_seen if last_seen else 9999
        status    = (
            "online"  if elapsed < _ONLINE_SECONDS else
            "stale"   if elapsed < _STALE_SECONDS  else
            "offline"
        )

        primary_ip, primary_mac = _extract_primary_interface(net, agent.get("last_ip", ""))

        return {
            "agent_id":    agent_id,
            "hostname":    (reg or {}).get("hostname") or agent.get("name") or agent_id,
            "os":          (reg or {}).get("os", ""),
            "os_version":  (reg or {}).get("os_version", ""),
            "arch":        (reg or {}).get("arch", ""),
            "status":      status,
            "last_seen":   last_seen,
            "elapsed_s":   elapsed,
            "first_seen":  int((reg or {}).get("first_seen") or agent.get("created_at") or 0),
            # Network
            "ip":          primary_ip,
            "mac":         primary_mac,
            "last_ip":     agent.get("last_ip", ""),
            "interfaces":  _extract_interfaces(net),
            "dns_servers": _safe_list(net.get("dns_servers")),
            "gateway":     net.get("gateway", ""),
            "wifi_ssid":   net.get("wifi_ssid", ""),
            "wifi_rssi":   net.get("wifi_rssi"),
            # Asset meta
            "asset_tier":  (reg or {}).get("asset_tier", "standard"),
            "importance":  float((reg or {}).get("importance") or 0.3),
            "owner":       (reg or {}).get("owner", ""),
            "department":  (reg or {}).get("department", ""),
            "tags":        (reg or {}).get("tags") or [],
            # System metrics
            "cpu_percent":        _safe_float(m.get("cpu_percent")),
            "cpu_cores":          m.get("cpu_cores"),
            "cpu_cores_physical": m.get("cpu_cores_physical"),
            "cpu_freq_mhz":       m.get("cpu_freq_mhz"),
            "cpu_per_core":       m.get("cpu_per_core", []),
            "mem_percent":        _safe_float(m.get("mem_percent")),
            "mem_used_mb":        m.get("mem_used_mb"),
            "mem_total_mb":       m.get("mem_total_mb"),
            "mem_available_mb":   m.get("mem_available_mb"),
            "swap_percent":       _safe_float(m.get("swap_percent")),
            "swap_used_mb":       m.get("swap_used_mb"),
            "swap_total_mb":      m.get("swap_total_mb"),
            "load_1m":            m.get("load_1m"),
            "load_5m":            m.get("load_5m"),
            "load_15m":           m.get("load_15m"),
            "uptime_sec":         m.get("uptime_sec"),
            "disk_read_mb_s":     m.get("disk_read_mb_s"),
            "disk_write_mb_s":    m.get("disk_write_mb_s"),
            "net_sent_mb_s":      m.get("net_sent_mb_s"),
            "net_recv_mb_s":      m.get("net_recv_mb_s"),
            # Processes
            "process_count":  len(procs) if isinstance(procs, list) else 0,
            "top_processes":  procs[:10] if isinstance(procs, list) else [],
            # Battery
            "battery_present":   bat.get("present", False),
            "battery_pct":       _safe_float(bat.get("charge_pct")),
            "battery_charging":  bat.get("charging"),
            "battery_condition": bat.get("condition", ""),
            "battery_cycles":    bat.get("cycle_count"),
            "battery_capacity_mah": bat.get("capacity_mah"),
            # Storage
            "storage":  storage if isinstance(storage, list) else [],
            # Users
            "user_count": len(users) if isinstance(users, list) else (1 if users else 0),
            # Sessions
            "sessions":  sessions,
            # Findings summary
            "findings": findings_summary,
        }

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_primary_interface(net: dict, fallback_ip: str) -> tuple[str, str]:
    """
    Extract the primary IP + MAC from the network section.
    Prefers en0 (WiFi), then en1, then first valid IPv4 interface.
    Returns (ip, mac).
    """
    if not isinstance(net, dict):
        return fallback_ip, ""
    interfaces = net.get("interfaces") or []
    if not isinstance(interfaces, list):
        return fallback_ip, ""

    preferred = ["en0", "en1", "eth0", "eth1"]

    # Try preferred interface names first
    for pref in preferred:
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            if iface.get("name") == pref:
                ip  = iface.get("ip", "") or iface.get("ipv4", "")
                mac = iface.get("mac", "") or iface.get("ether", "")
                if ip and ip != "127.0.0.1":
                    return ip, mac

    # Fall back to any interface with a non-loopback IPv4
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        ip  = iface.get("ip", "") or iface.get("ipv4", "")
        mac = iface.get("mac", "") or iface.get("ether", "")
        if ip and not ip.startswith("127."):
            return ip, mac

    return fallback_ip, ""


def _extract_interfaces(net: dict) -> list[dict]:
    """Return clean interface list from network section."""
    if not isinstance(net, dict):
        return []
    ifaces = net.get("interfaces") or []
    if not isinstance(ifaces, list):
        return []
    result = []
    for iface in ifaces:
        if not isinstance(iface, dict):
            continue
        result.append({
            "name": iface.get("name", ""),
            "ip":   iface.get("ip") or iface.get("ipv4", ""),
            "mac":  iface.get("mac") or iface.get("ether", ""),
            "type": iface.get("type", ""),
            "up":   iface.get("up", True),
        })
    return result


def _subnet(ip: str) -> str:
    """Return /24 subnet string, e.g. '192.168.1' from '192.168.1.42'."""
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip


def _safe_float(v: object) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _safe_list(v: object) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v:
        return [v]
    return []
