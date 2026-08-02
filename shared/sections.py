"""
shared/sections.py — Canonical section definitions.

Single source of truth for:
  - Valid section names (agent collector registry + manager API validation)
  - Default collection intervals and categories

To add a new section:
  1. Add a SectionDef entry to SECTION_DEFS below
  2. Create a collector class in agent/agent/collectors/<category>.py
  3. Register it in agent/agent/collectors/__init__.py
  4. Add a [collection.sections.<name>] block in agent.toml.example
  5. Run: make test
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class SectionDef:
    name: str
    category: str           # volatile | network | system | posture | inventory
    default_interval: int   # seconds
    description: str


SECTION_DEFS: tuple[SectionDef, ...] = (
    # ── Volatile (10 s) ──────────────────────────────────────────────────
    SectionDef("metrics",     "volatile",  10,    "CPU, RAM, swap, load average"),
    SectionDef("connections", "volatile",  10,    "Established TCP connections"),
    SectionDef("processes",   "volatile",  10,    "Top processes by CPU + RAM"),
    # ── Network (30 s – 2 min) ───────────────────────────────────────────
    SectionDef("ports",       "network",   30,    "All LISTEN sockets"),
    SectionDef("network",     "network",   120,   "Interfaces, DNS, WiFi, routing"),
    SectionDef("arp",         "network",   120,   "ARP table — local network hosts"),
    SectionDef("mounts",      "network",   120,   "Active filesystem mounts"),
    # ── System state (2 min) ─────────────────────────────────────────────
    SectionDef("battery",     "system",    120,   "Charge %, cycle count, condition"),
    SectionDef("openfiles",   "system",    120,   "Top processes by open FD count"),
    SectionDef("services",    "system",    120,   "launchd daemons and login items"),
    SectionDef("users",       "system",    120,   "Local users, groups, login history"),
    SectionDef("hardware",    "system",    120,   "USB, Thunderbolt, Bluetooth"),
    SectionDef("containers",  "system",    120,   "Docker / Podman containers"),
    # ── Storage (10 min) ─────────────────────────────────────────────────
    SectionDef("storage",     "inventory", 600,   "Disk usage per volume"),
    SectionDef("tasks",       "inventory", 600,   "Crontabs and launchd timers"),
    # ── Security posture (1 hr) ──────────────────────────────────────────
    SectionDef("security",    "posture",   3600,  "SIP, Gatekeeper, FileVault, Firewall"),
    SectionDef("sysctl",      "posture",   3600,  "Kernel security parameters"),
    SectionDef("configs",     "posture",   3600,  "Shell rc, SSH config, /etc/hosts"),
    SectionDef("developer_security", "posture", 3600,
               "Developer tools, AI agents, MCP, browser and package-manager posture"),
    SectionDef("sca",         "posture",   43200, "Security configuration assessment checks"),
    # ── Software inventory (24 hr) ───────────────────────────────────────
    SectionDef("apps",        "inventory", 86400, "Installed .app bundles"),
    SectionDef("packages",    "inventory", 86400, "brew, pip, npm, gems"),
    SectionDef("binaries",    "inventory", 86400, "Executables in known bin dirs"),
    SectionDef("sbom",        "inventory", 86400, "Full software bill of materials"),
    # ── Agent diagnostics (synthetic — emitted by orchestrator) ──────────
    SectionDef("agent_health", "diagnostic", 60,  "Circuit-breaker state, queue depth, uptime"),
)

# O(1) lookup by name
SECTIONS: dict[str, SectionDef] = {s.name: s for s in SECTION_DEFS}

# Frozenset of valid names — used for fast validation in the API layer
VALID_SECTION_NAMES: FrozenSet[str] = frozenset(SECTIONS)

# Accepted producer aliases. Normalize once at ingest so storage, detection,
# correlation, and reconciliation all use the same durable section key.
SECTION_ALIASES: dict[str, str] = {
    "listening_ports": "ports", "netstat": "ports", "ss_output": "ports",
    "net_tcp_connection": "ports", "open_ports": "ports",
    "network_sessions": "connections", "connectivity": "connections",
    "open_files": "openfiles",
    "user_accounts": "users", "passwd_entries": "users", "local_users": "users",
    "kernel_params": "sysctl", "sysctl_output": "sysctl",
    "launchd_services": "services", "systemd_services": "services",
    "windows_services": "services",
    "scheduled_tasks": "tasks", "cron_jobs": "tasks", "launchd_tasks": "tasks",
    "systemd_timers": "tasks",
    "brew_packages": "packages", "pip_packages": "packages",
    "npm_packages": "packages", "dpkg_packages": "packages",
    "rpm_packages": "packages", "winget_packages": "packages",
    "choco_packages": "packages", "scoop_packages": "packages",
    "installed_packages": "packages", "installed_apps": "apps",
    "sbom_cyclonedx": "sbom", "sbom_spdx": "sbom", "pip_list": "sbom",
    "npm_list": "sbom", "gem_list": "sbom",
    "security_posture": "security", "endpoint_posture": "security",
    "pods": "containers", "container_security": "containers",
}


def canonical_section(section: object) -> str:
    value = str(section or "").strip().lower().replace("-", "_")
    return SECTION_ALIASES.get(value, value)
