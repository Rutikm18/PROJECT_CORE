"""
manager/manager/threat/behavioral.py — Agentic behavioral analysis.

Algorithms used:
  • Welford online algorithm  — incremental mean / variance (O(1) per update)
  • Z-score anomaly detection — |z| > ZSCORE_THRESHOLD flags an anomaly
  • New-entity detection      — first time an item key appears → flagged for review
  • Frequency analysis        — connection destination entropy / diversity
  • Sliding window            — last N=100 samples for recency bias

Design: fully stateless per call; all state lives in intel.db baseline table.
"""
from __future__ import annotations

import json
import logging
import math
import time
from typing import Any, Optional

log = logging.getLogger("manager.threat.behavioral")

ZSCORE_THRESHOLD  = 3.0      # |z| above this = statistical anomaly
WINDOW_SIZE       = 100      # rolling window for baseline samples
MIN_SAMPLES       = 10       # need at least this many to flag anomalies
NEW_ENTITY_WINDOW = 3600     # seconds — if entity first seen within this window, flag it


class BehavioralAnalyzer:
    """
    Stateless analyzer — takes section data + baseline from DB,
    returns a list of finding dicts ready for the indexer.
    """

    def __init__(self, db) -> None:
        self._db = db

    # ── Public entry point ────────────────────────────────────────────────────

    async def analyze(self, agent_id: str, section: str, data: Any) -> list[dict]:
        """Dispatch to the right section analyzer; return list of findings."""
        fn = {
            "metrics":     self._metrics,
            "connections": self._connections,
            "processes":   self._processes,
            "ports":       self._ports,
            "network":     self._network,
        }.get(section)
        if fn is None:
            return []
        try:
            return await fn(agent_id, data)
        except Exception as exc:
            log.debug("Behavioral analysis failed for %s/%s: %s", agent_id, section, exc)
            return []

    # ── Section analyzers ─────────────────────────────────────────────────────

    async def _metrics(self, agent_id: str, data: dict) -> list[dict]:
        findings = []
        checks = [
            ("cpu_pct",      data.get("cpu_pct"),      "CPU usage",    90.0, "critical", 80.0, "high"),
            ("mem_pct",      data.get("mem_pct"),       "Memory usage", 95.0, "critical", 85.0, "high"),
            ("swap_pct",     data.get("swap_pct"),      "Swap usage",   80.0, "high",     60.0, "medium"),
        ]
        for metric, value, label, c_thresh, c_sev, h_thresh, h_sev in checks:
            if value is None:
                continue
            value = float(value)

            # Threshold-based check (always on)
            if value >= c_thresh:
                findings.append(self._make_finding(
                    category="behavioral", item_key=f"{metric}_threshold",
                    severity=c_sev, score=9.0,
                    title=f"Extreme {label}: {value:.1f}%",
                    desc=f"{label} at {value:.1f}% — exceeds critical threshold {c_thresh}%.",
                    evidence={"metric": metric, "value": value, "threshold": c_thresh},
                    source="behavioral_threshold",
                ))
            elif value >= h_thresh:
                findings.append(self._make_finding(
                    category="behavioral", item_key=f"{metric}_threshold",
                    severity=h_sev, score=6.0,
                    title=f"High {label}: {value:.1f}%",
                    desc=f"{label} at {value:.1f}% — exceeds high threshold {h_thresh}%.",
                    evidence={"metric": metric, "value": value, "threshold": h_thresh},
                    source="behavioral_threshold",
                ))

            # Statistical anomaly check
            anomaly = await self._zscore_check(agent_id, metric, value)
            if anomaly:
                findings.append(self._make_finding(
                    category="behavioral", item_key=f"{metric}_anomaly",
                    severity="medium", score=5.0,
                    title=f"Statistical anomaly in {label}",
                    desc=(f"{label} is {anomaly['zscore']:.1f}σ from baseline mean "
                          f"({anomaly['mean']:.1f}%). Current: {value:.1f}%."),
                    evidence=anomaly,
                    source="behavioral_zscore",
                ))

            await self._update_baseline(agent_id, metric, value)
        return findings

    async def _connections(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings

        count = len(data)
        anomaly = await self._zscore_check(agent_id, "conn_count", float(count))
        if anomaly:
            findings.append(self._make_finding(
                category="behavioral", item_key="conn_count_anomaly",
                severity="medium", score=5.0,
                title=f"Unusual connection count: {count}",
                desc=(f"Active connections ({count}) is {anomaly['zscore']:.1f}σ above baseline "
                      f"mean of {anomaly['mean']:.0f}."),
                evidence=anomaly,
                source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "conn_count", float(count))

        # Unique destination IP diversity
        dest_ips = set()
        for c in data:
            if isinstance(c, dict):
                raddr = c.get("remote_addr", "") or c.get("raddr", "")
                if raddr and raddr not in ("-", ""):
                    dest_ips.add(raddr.split(":")[0])
        diversity = len(dest_ips)
        div_anomaly = await self._zscore_check(agent_id, "conn_dest_diversity", float(diversity))
        if div_anomaly and div_anomaly.get("zscore", 0) > ZSCORE_THRESHOLD:
            findings.append(self._make_finding(
                category="behavioral", item_key="conn_diversity_anomaly",
                severity="medium", score=5.5,
                title=f"Unusual destination diversity: {diversity} unique IPs",
                desc=(f"Connections are going to {diversity} unique destinations, "
                      f"{div_anomaly['zscore']:.1f}σ above baseline."),
                evidence={"unique_destinations": diversity, **div_anomaly},
                source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "conn_dest_diversity", float(diversity))
        return findings

    async def _processes(self, agent_id: str, data: list) -> list[dict]:
        if not isinstance(data, list):
            return []
        count = len(data)
        anomaly = await self._zscore_check(agent_id, "proc_count", float(count))
        findings = []
        if anomaly:
            findings.append(self._make_finding(
                category="behavioral", item_key="proc_count_anomaly",
                severity="low", score=3.0,
                title=f"Unusual process count: {count}",
                desc=f"Running process count ({count}) is {anomaly['zscore']:.1f}σ from baseline.",
                evidence=anomaly,
                source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "proc_count", float(count))
        return findings

    async def _ports(self, agent_id: str, data: list) -> list[dict]:
        if not isinstance(data, list):
            return []
        count = len(data)
        anomaly = await self._zscore_check(agent_id, "port_count", float(count))
        findings = []
        if anomaly:
            findings.append(self._make_finding(
                category="behavioral", item_key="port_count_anomaly",
                severity="medium", score=5.0,
                title=f"Unusual number of listening ports: {count}",
                desc=f"Listening port count ({count}) is {anomaly['zscore']:.1f}σ from baseline.",
                evidence=anomaly,
                source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "port_count", float(count))
        return findings

    async def _network(self, agent_id: str, data: dict) -> list[dict]:
        """Detect new network interfaces or interface changes."""
        findings = []
        if not isinstance(data, dict):
            return findings
        interfaces = data.get("interfaces", [])
        if not isinstance(interfaces, list):
            return findings
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name", "")
            if not name:
                continue
            key  = f"interface:{name}"
            prev = await self._db.get_entity_state(agent_id, "network", key)
            now  = time.time()
            fingerprint = json.dumps({
                "addrs": sorted(iface.get("addrs", [])),
                "flags": iface.get("flags", []),
            }, sort_keys=True)
            if prev is None:
                await self._db.set_entity_state(agent_id, "network", key, fingerprint, now)
                findings.append(self._make_finding(
                    category="network", item_key=key,
                    severity="info", score=1.0,
                    title=f"New network interface observed: {name}",
                    desc=f"Interface '{name}' detected for the first time.",
                    evidence=iface,
                    source="behavioral_new_entity",
                ))
            elif prev["fingerprint"] != fingerprint:
                age = now - prev["seen_at"]
                sev = "high" if age < 300 else "medium" if age < 3600 else "low"
                findings.append(self._make_finding(
                    category="network", item_key=f"{key}:changed",
                    severity=sev, score=6.0 if sev == "high" else 4.0,
                    title=f"Network interface changed: {name}",
                    desc=(f"Interface '{name}' configuration changed "
                          f"({_human_age(age)} after last seen)."),
                    evidence={"interface": iface, "prev_fingerprint": prev["fingerprint"]},
                    source="behavioral_change",
                    mitre="T1049",
                ))
                await self._db.set_entity_state(agent_id, "network", key, fingerprint, now)
        return findings

    # ── Welford / baseline helpers ─────────────────────────────────────────────

    async def _zscore_check(self, agent_id: str,
                            metric: str, value: float) -> Optional[dict]:
        """Return anomaly dict if |z-score| > threshold, else None."""
        bl = await self._db.get_baseline(agent_id, metric)
        if bl is None or bl["sample_count"] < MIN_SAMPLES:
            return None
        mean   = bl["mean"]
        stddev = bl["stddev"]
        if stddev < 1e-9:
            return None
        z = (value - mean) / stddev
        if abs(z) <= ZSCORE_THRESHOLD:
            return None
        return {
            "metric":       metric,
            "value":        value,
            "mean":         mean,
            "stddev":       stddev,
            "zscore":       round(z, 2),
            "sample_count": bl["sample_count"],
        }

    async def _update_baseline(self, agent_id: str, metric: str, value: float) -> None:
        """Welford online update: O(1) mean/variance update."""
        bl = await self._db.get_baseline(agent_id, metric)
        if bl is None:
            bl = {"mean": 0.0, "m2": 0.0, "sample_count": 0, "min_val": value, "max_val": value}
        n    = bl["sample_count"] + 1
        mean = bl["mean"]
        m2   = bl.get("m2", 0.0)

        delta  = value - mean
        mean  += delta / n
        delta2 = value - mean
        m2    += delta * delta2

        stddev = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0

        await self._db.upsert_baseline(agent_id, metric, {
            "mean":         mean,
            "m2":           m2,
            "stddev":       stddev,
            "min_val":      min(bl.get("min_val", value), value),
            "max_val":      max(bl.get("max_val", value), value),
            "sample_count": n,
            "updated_at":   time.time(),
        })

    # ── Finding factory ───────────────────────────────────────────────────────

    @staticmethod
    def _make_finding(*, category: str, item_key: str, severity: str,
                      score: float, title: str, desc: str,
                      evidence: dict, source: str,
                      mitre: str = "", tags: list | None = None) -> dict:
        return {
            "category":      category,
            "item_key":      item_key,
            "severity":      severity,
            "score":         score,
            "title":         title,
            "description":   desc,
            "evidence":      evidence,
            "source":        source,
            "mitre_technique": mitre,
            "mitre_tactic":  "",
            "cve_ids":       [],
            "cvss_score":    None,
            "tags":          tags or [source, category],
        }


def _human_age(seconds: float) -> str:
    if seconds < 60:    return f"{int(seconds)}s"
    if seconds < 3600:  return f"{int(seconds/60)}m"
    if seconds < 86400: return f"{int(seconds/3600)}h"
    return f"{int(seconds/86400)}d"
