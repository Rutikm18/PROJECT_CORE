"""
agents/windows/normalizer.py — Windows-specific normalizer.

Maps Windows collector output to the canonical section schemas in shared/schema.py.
Windows collectors use WMI, PowerShell, Win32 API, and psutil.

Status: SKELETON — collectors not yet implemented.

To implement:
  1. Copy agent/agent/collectors/ structure
  2. Implement collectors using WMI / PowerShell / psutil on Windows
  3. Fill in each normalize_*() function below
  4. Run: python3 -c "from agents.windows.normalizer import normalize; print('OK')"

Windows-specific notes:
  - No load average: use CPU queue length from WMI Win32_Processor.LoadPercentage
  - No battery on servers: present=False
  - Services: sc.exe or win32service
  - Security: Defender, UAC, BitLocker (WMI / PowerShell)
  - Packages: winget, chocolatey, pip, npm
"""
from __future__ import annotations

from typing import Any

from agent.agent.normalizer import (
    normalize_connections, normalize_processes, normalize_ports,
    normalize_arp, normalize_mounts, normalize_openfiles,
    normalize_services, normalize_users, normalize_hardware,
    normalize_containers, normalize_storage, normalize_tasks,
    normalize_sysctl, normalize_configs, normalize_apps,
    normalize_packages, normalize_binaries, normalize_sbom,
    _f, _i, _s, _b,
)


def normalize(section: str, raw: Any) -> Any:
    fn = _NORMALIZERS.get(section)
    if fn is None:
        raise ValueError(f"No Windows normalizer for section: {section!r}")
    return fn(raw)


def normalize_metrics(raw: dict) -> dict:
    """
    Windows: WMI Win32_OperatingSystem (memory), Win32_Processor (CPU).
    No traditional load average — use CPU queue as proxy.
    raw keys: cpu_percent, memory_percent, memory_used, memory_total,
              page_file_percent, cpu_queue_length, cpu_count, uptime
    """
    cpu_queue = _f(raw.get("cpu_queue_length"))
    return {
        "cpu_pct":      _f(raw.get("cpu_percent")),
        "mem_pct":      _f(raw.get("memory_percent")),
        "mem_used_mb":  _i(raw.get("memory_used")),
        "mem_total_mb": _i(raw.get("memory_total")),
        "swap_pct":     _f(raw.get("page_file_percent")),
        "swap_used_mb": None,
        "swap_total_mb":None,
        # Windows has no load average — use CPU queue as approximation
        "load_1m":      cpu_queue,
        "load_5m":      None,
        "load_15m":     None,
        "cpu_cores":    _i(raw.get("cpu_count")),
        "uptime_sec":   _i(raw.get("uptime")),
    }


def normalize_network(raw: dict) -> dict:
    """Windows: ipconfig, netsh, WMI Win32_NetworkAdapterConfiguration."""
    interfaces = []
    for iface in (raw.get("interfaces") or []):
        interfaces.append({
            "name":   _s(iface.get("name")) or "",
            "mac":    _s(iface.get("mac")),
            "ipv4":   _s(iface.get("ipv4")),
            "ipv6":   _s(iface.get("ipv6")),
            "status": _s(iface.get("status")),
            "mtu":    _i(iface.get("mtu")),
        })
    return {
        "interfaces":  interfaces,
        "dns_servers": [str(x) for x in (raw.get("dns_servers") or [])],
        "default_gw":  _s(raw.get("default_gateway")),
        "hostname":    _s(raw.get("hostname")) or "",
        "domain":      _s(raw.get("domain")),
        "wifi_ssid":   _s(raw.get("wifi_ssid")),
        "wifi_rssi":   _i(raw.get("wifi_rssi")),
    }


def normalize_battery(raw: dict) -> dict:
    """Windows: WMI Win32_Battery. Present=False on desktops/servers."""
    present = bool(raw.get("present", False))
    return {
        "present":      present,
        "charging":     _b(raw.get("charging")) if present else None,
        "charge_pct":   _i(raw.get("percent"))  if present else None,
        "cycle_count":  None,   # WMI doesn't expose cycle count
        "condition":    _s(raw.get("condition")),
        "capacity_mah": None,
        "design_mah":   None,
        "voltage_mv":   _i(raw.get("voltage")),
    }


def normalize_security(raw: dict) -> dict:
    """Windows: Defender, UAC, BitLocker via WMI / PowerShell."""
    def _flag(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, bool):
            return "enabled" if val else "disabled"
        s = str(val).lower()
        if s in ("enabled", "on", "true", "yes", "1", "active"):
            return "enabled"
        if s in ("disabled", "off", "false", "no", "0", "inactive"):
            return "disabled"
        return s

    return {
        # macOS-specific — always None on Windows
        "sip":          None,
        "gatekeeper":   None,
        "filevault":    None,
        "firewall":     _flag(raw.get("windows_firewall")),
        "xprotect":     None,
        "secure_boot":  _s(raw.get("secure_boot")),
        # Cross-platform
        "av_installed": _b(raw.get("av_installed")),
        "av_product":   _s(raw.get("av_product")),
        "os_patched":   _b(raw.get("os_patched")),
        "auto_update":  _b(raw.get("auto_update")),
        # Linux-specific — always None on Windows
        "selinux":      None,
        "apparmor":     None,
        "ufw":          None,
        # Windows-specific
        "uac":          _flag(raw.get("uac")),
        "bitlocker":    _flag(raw.get("bitlocker")),
        "defender":     _flag(raw.get("defender")),
    }


_NORMALIZERS: dict[str, Any] = {
    "metrics":     normalize_metrics,
    "connections": normalize_connections,
    "processes":   normalize_processes,
    "ports":       normalize_ports,
    "network":     normalize_network,
    "arp":         normalize_arp,
    "mounts":      normalize_mounts,
    "battery":     normalize_battery,
    "openfiles":   normalize_openfiles,
    "services":    normalize_services,
    "users":       normalize_users,
    "hardware":    normalize_hardware,
    "containers":  normalize_containers,
    "storage":     normalize_storage,
    "tasks":       normalize_tasks,
    "security":    normalize_security,
    "sysctl":      normalize_sysctl,        # Windows: registry security keys
    "configs":     normalize_configs,
    "apps":        normalize_apps,          # Windows: Add/Remove Programs, winget
    "packages":    normalize_packages,      # Windows: winget, choco, pip, npm
    "binaries":    normalize_binaries,
    "sbom":        normalize_sbom,
}
