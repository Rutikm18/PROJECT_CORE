"""Canonical AttackTerrain definitions and category classification."""
from __future__ import annotations

from dataclasses import dataclass


UNCLASSIFIED_TERRAIN_ID = "unclassified"


@dataclass(frozen=True, slots=True)
class TerrainDefinition:
    id: str
    label: str
    validation_label: str
    description: str
    color: str
    route: str
    categories: tuple[str, ...]


_TERRAINS = (
    TerrainDefinition(
        "citadels",
        "Citadels",
        "Citadels (Execution & Persistence)",
        "Execution, persistence, and malware signals",
        "#ef4444",
        "/terrain/citadels",
        ("execution", "process", "script", "container", "persistence", "service", "task", "malware"),
    ),
    TerrainDefinition(
        "vector",
        "Vector",
        "Vector (Network & Reachability)",
        "Network connections, ports, ARP, lateral movement",
        "#f97316",
        "/terrain/vector",
        ("network", "connection", "port", "arp", "covert", "lateral", "mount"),
    ),
    TerrainDefinition(
        "origin",
        "Origin",
        "Origin (Surface, Packages, Configs)",
        "Vulnerabilities, packages, SBOM, and configuration drift",
        "#eab308",
        "/terrain/origin",
        ("package", "vulnerability", "sbom", "config", "binary", "sysctl", "app", "open_file", "storage"),
    ),
    TerrainDefinition(
        "identity",
        "Identity",
        "Identity (Accounts & Credentials)",
        "User accounts, credentials, and identity anomalies",
        "#3b82f6",
        "/terrain/identity",
        ("user", "identity", "account", "credential"),
    ),
    TerrainDefinition(
        "posture",
        "Posture",
        "Posture (Security Controls)",
        "Security posture, SIP, Gatekeeper, FileVault, and firewall",
        "#8b5cf6",
        "/posture/overview",
        ("security", "posture", "sip", "firewall", "agent_health", "battery", "hardware"),
    ),
    TerrainDefinition(
        "mesh",
        "Mesh",
        "Mesh (Developer & Agent Tooling)",
        "Developer tools, AI agents, extensions, credentials, and local runtimes",
        "#06b6d4",
        "/terrain/mesh",
        ("developer_security",),
    ),
)

_BY_CATEGORY = {
    category: definition.id
    for definition in _TERRAINS
    for category in definition.categories
}


def all_terrains() -> tuple[TerrainDefinition, ...]:
    """Return the ordered, immutable terrain catalogue."""
    return _TERRAINS


def terrain_for_category(category: str) -> str | None:
    """Return the canonical terrain ID, or ``None`` for an unknown category."""
    return _BY_CATEGORY.get(str(category or "").strip().lower())


__all__ = [
    "TerrainDefinition",
    "UNCLASSIFIED_TERRAIN_ID",
    "all_terrains",
    "terrain_for_category",
]
