"""
manager/manager/attacklens/signals.py — Signal dataclass and entity-key extraction.

A Signal is the intermediate representation produced when a rule fires.
Signals are persisted to intel.db and clustered before the confidence/validation
pipeline decides whether to emit a finding.

Entity keys are the join keys for cross-layer clustering:
  same entity_key on two signals from different layers → same cluster.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

Layer = Literal["surface", "exposure", "execution"]

# Layer assigned to each data_point section.  Used when rules don't specify.
_DATA_POINT_LAYER: dict[str, Layer] = {
    "apps":           "surface",
    "packages":       "surface",
    "sbom":           "surface",
    "configs":        "surface",
    "security":       "surface",
    "sysctl":         "surface",
    "containers":     "surface",
    "ports":          "exposure",
    "connections":    "exposure",
    "network":        "exposure",
    "arp":            "exposure",
    "processes":      "execution",
    "tasks":          "execution",
    "services":       "execution",
    "autoruns":       "execution",
    "binaries":       "execution",
    "users":          "execution",
    "behavioral":     "execution",
    "correlation":    "execution",
    "metrics":        "execution",
}


def layer_for(data_point: str) -> Layer:
    return _DATA_POINT_LAYER.get(data_point, "execution")


@dataclass(slots=True)
class Signal:
    rule_id:        str
    layer:          Layer
    data_point:     str
    entity_key:     str
    agent_id:       str
    severity_hint:  str
    evidence:       dict[str, Any]
    weight:         float          # 0–1: how diagnostic the rule is in isolation
    strength:       float          # 0–1: confidence in this specific match
    detected_at:    float = field(default_factory=time.time)
    # Populated after DB insert; used to link signals → cluster
    id:             int | None = field(default=None, compare=False)
    cluster_id:     int | None = field(default=None, compare=False)

    def to_db_row(self) -> tuple:
        """Return values matching the INSERT columns in IntelDB.upsert_signal()."""
        return (
            self.rule_id,
            self.layer,
            self.data_point,
            self.entity_key,
            self.agent_id,
            self.severity_hint,
            json.dumps(self.evidence, default=str),
            self.weight,
            self.strength,
            self.detected_at,
            time.time(),   # created_at
        )


def entity_keys_for(signal: Signal) -> list[str]:
    """
    Return ALL entity keys this signal touches.  Clustering joins on ANY
    shared key — a process signal contributes its PID, binary hash, and CPE;
    a port signal contributes the listening PID; etc.  This lets a Log4Shell
    package signal join with the Java process signal on the same host.
    """
    ev  = signal.evidence
    aid = signal.agent_id
    keys: set[str] = {signal.entity_key}

    dp = signal.data_point
    if dp == "processes":
        if pid := ev.get("pid"):
            keys.add(f"process:{pid}@{aid}")
        if h := ev.get("binary_hash") or ev.get("sha256"):
            keys.add(f"file:sha256:{h}")
        if cpe := ev.get("cpe"):
            keys.add(cpe)
    elif dp in ("connections", "connectivity", "network"):
        if dst := ev.get("dst_ip") or ev.get("remote_ip") or ev.get("remote_addr", "").rsplit(":", 1)[0].strip("[]"):
            if dst and dst not in ("-", "0.0.0.0", ""):
                keys.add(f"ip:{dst}")
        if pid := ev.get("pid"):
            keys.add(f"process:{pid}@{aid}")
    elif dp == "ports":
        if pid := ev.get("pid"):
            keys.add(f"process:{pid}@{aid}")
        if p := ev.get("port"):
            proto = ev.get("proto", "tcp")
            keys.add(f"port:{proto}:{p}@{aid}")
    elif dp in ("apps", "packages", "installed_software", "sbom"):
        if name := ev.get("name"):
            keys.add(f"pkg:{name.lower()}@{aid}")
        if cpe := ev.get("cpe"):
            keys.add(cpe)
        if h := ev.get("sha256") or ev.get("hash"):
            keys.add(f"file:sha256:{h}")
    elif dp == "services":
        if path := ev.get("binary_path") or ev.get("path") or ev.get("program"):
            keys.add(f"file:path:{path}@{aid}")
        if label := ev.get("label") or ev.get("name"):
            keys.add(f"service:{label}@{aid}")
    elif dp in ("autoruns", "launch_agents", "scheduled_tasks", "tasks"):
        if path := ev.get("target_path") or ev.get("program") or ev.get("command"):
            keys.add(f"file:path:{path}@{aid}")
    elif dp == "binaries":
        if path := ev.get("path"):
            keys.add(f"file:path:{path}@{aid}")
        if h := ev.get("sha256"):
            keys.add(f"file:sha256:{h}")
    elif dp in ("users",):
        if name := ev.get("name") or ev.get("username"):
            keys.add(f"user:{name}@{aid}")
    elif dp == "configs":
        if path := ev.get("path"):
            keys.add(f"config:{path}@{aid}")

    return list(keys)
