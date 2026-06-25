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

    # ── Single-signal floors for the live detections/*.py modules ──────────
    # These rule_ids were previously unindexed (fell back to the generic
    # weight=0.65 default), so a single hit could never clear the 0.95
    # confidence_threshold gate regardless of how unambiguous the evidence
    # was — e.g. a Metasploit-port listener or a UID-0 clone scored ~0.4 and
    # was silently dropped. Each entry below was individually verified against
    # its detector's FP-mitigation logic before being added — NOT a blanket
    # floor for the whole module. Rule_ids deliberately excluded (still
    # require cross-layer/TI corroboration): high_risk_port (its port list
    # mixes genuine backdoors with common legitimate services like SSH/RDP),
    # wildcard_bind/new_listener/unknown_process (known FP-prone), and any
    # novelty- or heuristic-based rule (new_account, sensitive_env_var, etc).
    {
        "name": "UID 0 clone (non-root account with root privileges)",
        "requires": {"execution": {"rule_id": "uid_zero_clone"}},
        "confidence_floor": 0.97,
    },
    {
        "name": "Hidden/system-mimicking user account",
        "requires": {"execution": {"rule_id": "hidden_user"}},
        "confidence_floor": 0.95,
    },
    {
        "name": "Critical kernel security parameter tampered",
        "requires": {"surface": {"rule_id": "sysctl_critical"}},
        "confidence_floor": 0.96,
    },
    {
        "name": "Duplicate ARP IP→MAC mapping (definitive poisoning signal)",
        "requires": {"exposure": {"rule_id": "arp:duplicate_ip_mapping"}},
        "confidence_floor": 0.96,
    },
    {
        "name": "Gateway MAC changed from established baseline",
        "requires": {"exposure": {"rule_id": "arp:gateway_mac_changed"}},
        "confidence_floor": 0.95,
    },
    {
        "name": "Privileged container with host networking",
        "requires": {"surface": {"rule_id": "cs:privileged_host_network"}},
        "confidence_floor": 0.97,
    },
    {
        "name": "Unauthenticated management/database port exposed in container",
        "requires": {"surface": {"rule_id": "cs:exposed_mgmt_port"}},
        "confidence_floor": 0.95,
    },
    {
        "name": "Security control disabled (SIP/Gatekeeper/FileVault/Firewall)",
        "requires": {"surface": {"rule_id": "rule:security_posture"}},
        "confidence_floor": 0.95,
    },
    {
        # port_listener.HIGH_RISK_PORTS mixes genuine backdoor/RAT/C2 ports with
        # commonly-legitimate services (SSH 22, RDP 3389, SMB 445, WinRM, generic
        # HTTP-alt 8080) — flooring the whole "high_risk_port" rule_id would
        # auto-promote every exposed SSH server. Instead this floor only matches
        # the evidence.port itself against the subset with zero legitimate use.
        "name": "Listener on a port with no legitimate use (Metasploit/RAT/backdoor)",
        "requires": {
            "exposure": {
                "rule_id": "high_risk_port",
                "evidence_in": {"field": "port", "values": {
                    4444, 4445, 31337, 12345, 65535, 6666, 6667, 1234, 5554, 9999, 54321,
                }},
            },
        },
        "confidence_floor": 0.95,
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
            layer_sigs = [s for s in layer_sigs if s.rule_id == criteria["rule_id"]]
            if not layer_sigs:
                return False
        if "rule_id_prefix" in criteria:
            layer_sigs = [s for s in layer_sigs if s.rule_id.startswith(criteria["rule_id_prefix"])]
            if not layer_sigs:
                return False
        if "evidence_in" in criteria:
            field  = criteria["evidence_in"]["field"]
            values = criteria["evidence_in"]["values"]
            if not any((s.evidence or {}).get(field) in values for s in layer_sigs):
                return False
    return True
