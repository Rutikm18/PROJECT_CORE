"""
manager/manager/attacklens/cross_matrix.py — Cross-layer confidence floor table.

If a cluster matches one of these patterns (requires signals from the specified
layers with matching rule_id prefixes/values), its confidence is guaranteed to
be at least the listed floor — regardless of what the multiplier math computes.
"""
from __future__ import annotations

from .clustering import SignalCluster

CROSS_LAYER_PATTERNS: list[dict] = [
    {
        "name": "Exploitable vuln + reachable + running",
        "requires": {
            "surface":   {"rule_id_prefix": "S-APP-"},
            "exposure":  {"rule_id_prefix": "E-PORT-"},
            "execution": {"rule_id_prefix": "X-PROC-"},
        },
        "confidence_floor": 0.95,
    },
    {
        "name": "Active C2 + fileless persistence",
        "requires": {
            "exposure":  {"rule_id": "E-CON-C2-BEACON"},
            "execution": {"rule_id": "X-PROC-DELETED-BINARY"},
        },
        "confidence_floor": 0.96,
    },
    {
        "name": "Cloud IAM wildcard + exfil + suspicious proc",
        "requires": {
            "surface":   {"rule_id": "S-CFG-IAM-WILDCARD"},
            "exposure":  {"rule_id_prefix": "E-CON-EXFIL"},
            "execution": {"rule_id_prefix": "X-PROC-"},
        },
        "confidence_floor": 0.96,
    },
    {
        "name": "Malware hash + active network + execution",
        "requires": {
            "surface":   {"rule_id": "S-APP-MALHASH"},
            "execution": {"rule_id_prefix": "X-PROC-"},
        },
        "confidence_floor": 0.97,
    },
    {
        "name": "Office/browser macro spawn",
        "requires": {
            "execution": {"rule_id_prefix": "rule:process_lineage"},
        },
        "confidence_floor": 0.95,
    },
    {
        "name": "Correlated attack chain (correlator hit)",
        "requires": {
            "execution": {"rule_id_prefix": "C-"},
        },
        "confidence_floor": 0.95,
    },
    {
        "name": "Process hollowing (standalone)",
        "requires": {
            "execution": {"rule_id": "X-PROC-HOLLOWING"},
        },
        "confidence_floor": 0.96,
    },
    {
        "name": "Hidden process (rootkit)",
        "requires": {
            "execution": {"rule_id": "X-PROC-HIDDEN"},
        },
        "confidence_floor": 0.97,
    },
]


def matched_floor(cluster: SignalCluster) -> float | None:
    """Return the highest confidence floor matched by cluster, or None."""
    floors = [
        p["confidence_floor"]
        for p in CROSS_LAYER_PATTERNS
        if _cluster_matches(cluster, p["requires"])
    ]
    return max(floors) if floors else None


def _cluster_matches(cluster: SignalCluster, requires: dict) -> bool:
    for layer, criteria in requires.items():
        if layer not in cluster.layers_covered:
            return False
        layer_sigs = [s for s in cluster.signals if s.layer == layer]
        if "rule_id" in criteria:
            if not any(s.rule_id == criteria["rule_id"] for s in layer_sigs):
                return False
        if "rule_id_prefix" in criteria:
            if not any(s.rule_id.startswith(criteria["rule_id_prefix"]) for s in layer_sigs):
                return False
    return True
