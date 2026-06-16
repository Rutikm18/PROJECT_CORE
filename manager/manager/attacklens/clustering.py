"""
manager/manager/attacklens/clustering.py — Entity-key cross-layer signal clustering.

Algorithm: union-find.  Two signals are in the same cluster if they share ANY
entity key (as returned by entity_keys_for()).  This is intentionally transitive:
  pkg_signal  ← entity_key "pkg:log4j@agent"
  port_signal ← entity_key "port:tcp:8080@agent"
  proc_signal ← entity_keys ["process:9876@agent", "process:1234@agent",
                               "port:tcp:8080@agent"]          ← shared key!
→ all three end up in one cluster.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from .signals import Signal, entity_keys_for


@dataclass
class SignalCluster:
    agent_id:        str
    entity_key:      str            # primary key: highest-weight signal's entity_key
    signals:         list[Signal]
    layers_covered:  set[str] = field(default_factory=set)
    confidence:      float | None = None
    id:              int | None = None   # set after DB persist

    def has_layer(self, layer: str) -> bool:
        return layer in self.layers_covered


def cluster_signals(signals: list[Signal], window_sec: int) -> list[SignalCluster]:
    """
    Group signals into clusters by shared entity keys within window_sec.
    Returns one SignalCluster per connected component in the entity-key graph.
    """
    if not signals:
        return []

    now = max(s.detected_at for s in signals)
    in_window = [s for s in signals if now - s.detected_at <= window_sec]
    if not in_window:
        return []

    # Build entity-key index: key → list of signals touching it
    key_to_sigs: dict[str, list[Signal]] = {}
    for s in in_window:
        for k in entity_keys_for(s):
            key_to_sigs.setdefault(k, []).append(s)

    # Union-find on signal identity (id(signal) as integer key)
    parent: dict[int, int] = {}

    def find(sid: int) -> int:
        if parent.setdefault(sid, sid) == sid:
            return sid
        root = find(parent[sid])
        parent[sid] = root
        return root

    def union(a: int, b: int) -> None:
        parent[find(a)] = find(b)

    for group in key_to_sigs.values():
        for i in range(1, len(group)):
            union(id(group[0]), id(group[i]))

    components: dict[int, list[Signal]] = {}
    for s in in_window:
        components.setdefault(find(id(s)), []).append(s)

    clusters: list[SignalCluster] = []
    for sigs in components.values():
        primary = max(sigs, key=lambda x: x.weight).entity_key
        clusters.append(SignalCluster(
            agent_id=sigs[0].agent_id,
            entity_key=primary,
            signals=sigs,
            layers_covered={s.layer for s in sigs},
        ))
    return clusters
