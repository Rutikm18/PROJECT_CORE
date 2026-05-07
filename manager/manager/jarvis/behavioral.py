"""
manager/manager/jarvis/behavioral.py — Agentic behavioral analysis.

Algorithms:
  • Welford online algorithm  — incremental mean / variance (O(1) per update)
  • Modified z-score          — |z| > ZSCORE_THRESHOLD flags an anomaly
  • Velocity detection        — rate-of-change spike detection
  • Shannon entropy           — connection destination diversity / beaconing
  • New-entity detection      — first-seen tracking per agent entity
  • Count anomaly             — statistical count anomaly for all 12 sections

Sections covered: metrics, connections, ports, processes, services, users,
                  tasks, apps, packages, binaries, security, configs, network
"""
from __future__ import annotations

import json
import logging
import math
import time
from typing import Any, Optional

log = logging.getLogger("manager.jarvis.behavioral")

ZSCORE_THRESHOLD   = 3.0      # |z| above this = statistical anomaly
VELOCITY_THRESHOLD = 2.5      # rate-of-change ratio (current / prev > this → alert)
WINDOW_SIZE        = 100      # rolling window for baseline samples
MIN_SAMPLES        = 10       # need at least this many to flag statistical anomalies
NEW_ENTITY_WINDOW  = 3600     # seconds — flag entity if first seen within this window
ENTROPY_BEACON_LOW = 1.2      # low entropy = same destination repeatedly (beaconing)
ENTROPY_BEACON_HIGH = 4.5     # very high entropy = scanning / DGA


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
            "services":    self._services,
            "users":       self._users,
            "tasks":       self._tasks,
            "apps":        self._apps,
            "packages":    self._packages,
            "binaries":    self._binaries,
            "security":    self._security_posture,
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
            ("cpu_pct",  data.get("cpu_pct"),  "CPU usage",    90.0, "critical", 80.0, "high"),
            ("mem_pct",  data.get("mem_pct"),   "Memory usage", 95.0, "critical", 85.0, "high"),
            ("swap_pct", data.get("swap_pct"),  "Swap usage",   80.0, "high",     60.0, "medium"),
            ("disk_pct", data.get("disk_pct"),  "Disk usage",   98.0, "high",     90.0, "medium"),
        ]
        for metric, value, label, c_thresh, c_sev, h_thresh, h_sev in checks:
            if value is None:
                continue
            value = float(value)

            # Threshold check
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

            # Statistical anomaly
            anomaly = await self._zscore_check(agent_id, metric, value)
            if anomaly:
                findings.append(self._make_finding(
                    category="behavioral", item_key=f"{metric}_anomaly",
                    severity="medium", score=5.0,
                    title=f"Statistical anomaly in {label}",
                    desc=(f"{label} is {anomaly['zscore']:.1f}σ from baseline mean "
                          f"({anomaly['mean']:.1f}%). Current: {value:.1f}%."),
                    evidence=anomaly, source="behavioral_zscore",
                ))

            # Velocity check (sudden spike vs previous value)
            prev_bl = await self._db.get_baseline(agent_id, metric)
            if prev_bl and prev_bl.get("sample_count", 0) >= 3:
                prev_mean = prev_bl.get("mean", 0)
                if prev_mean > 5.0 and value / prev_mean >= VELOCITY_THRESHOLD:
                    findings.append(self._make_finding(
                        category="behavioral", item_key=f"{metric}_velocity",
                        severity="high", score=7.0,
                        title=f"Rapid {label} spike: {value:.1f}% (was {prev_mean:.1f}%)",
                        desc=(f"{label} jumped {value/prev_mean:.1f}× above recent baseline "
                              f"— sudden spike may indicate cryptominer or attack activity."),
                        evidence={"metric": metric, "value": value, "prev_mean": prev_mean,
                                  "ratio": round(value / prev_mean, 2)},
                        source="behavioral_velocity", mitre="T1496",
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
                evidence=anomaly, source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "conn_count", float(count))

        # Unique destination IP diversity + Shannon entropy
        dest_ips: list[str] = []
        dest_ports: dict[int, int] = {}
        for c in data:
            if not isinstance(c, dict):
                continue
            raddr = c.get("remote_addr", "") or c.get("raddr", "")
            if raddr and raddr not in ("-", "0.0.0.0:0", "*:*"):
                ip = raddr.rsplit(":", 1)[0].strip("[]")
                if ip:
                    dest_ips.append(ip)
            rport_str = (raddr or "").rsplit(":", 1)
            if len(rport_str) == 2:
                try:
                    dest_ports[int(rport_str[1])] = dest_ports.get(int(rport_str[1]), 0) + 1
                except ValueError:
                    pass

        diversity = len(set(dest_ips))
        div_anomaly = await self._zscore_check(agent_id, "conn_dest_diversity", float(diversity))
        if div_anomaly and div_anomaly.get("zscore", 0) > ZSCORE_THRESHOLD:
            findings.append(self._make_finding(
                category="behavioral", item_key="conn_diversity_anomaly",
                severity="medium", score=5.5,
                title=f"Unusual destination diversity: {diversity} unique IPs",
                desc=(f"Connections to {diversity} unique IPs, "
                      f"{div_anomaly['zscore']:.1f}σ above baseline."),
                evidence={"unique_destinations": diversity, **div_anomaly},
                source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "conn_dest_diversity", float(diversity))

        # Shannon entropy analysis — low entropy = same host repeatedly (beaconing candidate)
        entropy = _shannon_entropy(dest_ips)
        if count >= 5 and entropy < ENTROPY_BEACON_LOW:
            top_ip = max(set(dest_ips), key=dest_ips.count) if dest_ips else "unknown"
            ratio = dest_ips.count(top_ip) / max(count, 1)
            findings.append(self._make_finding(
                category="behavioral", item_key="conn_beacon_candidate",
                severity="medium", score=5.5,
                title=f"Beaconing candidate: {ratio*100:.0f}% connections to {top_ip}",
                desc=(f"Low destination entropy ({entropy:.2f} bits) — {count} connections "
                      f"overwhelmingly targeting {top_ip} ({ratio*100:.0f}%). "
                      f"Pattern consistent with C2 beaconing."),
                evidence={"entropy": round(entropy, 3), "top_ip": top_ip,
                          "total": count, "ratio": round(ratio, 3)},
                source="behavioral_entropy", mitre="T1071",
            ))
        elif count >= 10 and entropy > ENTROPY_BEACON_HIGH:
            findings.append(self._make_finding(
                category="behavioral", item_key="conn_scan_entropy",
                severity="low", score=3.0,
                title=f"High connection diversity: {diversity} unique IPs",
                desc=(f"Very high destination entropy ({entropy:.2f} bits) across {count} connections — "
                      f"pattern consistent with internal recon or scanning."),
                evidence={"entropy": round(entropy, 3), "unique_ips": diversity, "total": count},
                source="behavioral_entropy", mitre="T1046",
            ))

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

    async def _services(self, agent_id: str, data: list) -> list[dict]:
        """Track new/changed services — sudden new LaunchDaemon is suspicious."""
        findings = []
        if not isinstance(data, list):
            return findings
        now = time.time()
        count = len(data)
        anomaly = await self._zscore_check(agent_id, "service_count", float(count))
        if anomaly:
            findings.append(self._make_finding(
                category="behavioral", item_key="service_count_anomaly",
                severity="medium", score=5.5,
                title=f"Unusual service count: {count}",
                desc=f"Running service count ({count}) is {anomaly['zscore']:.1f}σ from baseline.",
                evidence=anomaly, source="behavioral_zscore", mitre="T1543.004",
            ))
        await self._update_baseline(agent_id, "service_count", float(count))

        for item in data:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "") or item.get("name", "") or "")
            if not label:
                continue
            key = f"svc:{label}"
            prev = await self._db.get_entity_state(agent_id, "service", key)
            if prev is None:
                await self._db.set_entity_state(agent_id, "service", key,
                                                 json.dumps(item, default=str), now)
                findings.append(self._make_finding(
                    category="behavioral", item_key=key,
                    severity="low", score=3.0,
                    title=f"New service observed: {label}",
                    desc=f"Service '{label}' detected for the first time — review if expected.",
                    evidence=item, source="behavioral_new_entity", mitre="T1543.004",
                ))
        return findings

    async def _users(self, agent_id: str, data: list) -> list[dict]:
        """Detect new admin/root users — newly granted admin is a strong signal."""
        findings = []
        if not isinstance(data, list):
            return findings
        now = time.time()
        admin_count = sum(1 for u in data
                         if isinstance(u, dict) and (u.get("is_admin") or u.get("admin")))
        anomaly = await self._zscore_check(agent_id, "admin_count", float(admin_count))
        if anomaly and anomaly.get("zscore", 0) > 0:  # only flag increases
            findings.append(self._make_finding(
                category="behavioral", item_key="admin_count_anomaly",
                severity="high", score=7.0,
                title=f"Admin user count increased: {admin_count}",
                desc=(f"Admin account count ({admin_count}) is "
                      f"{anomaly['zscore']:.1f}σ above baseline — new admin may have been added."),
                evidence=anomaly, source="behavioral_zscore", mitre="T1078.003",
            ))
        await self._update_baseline(agent_id, "admin_count", float(admin_count))

        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or item.get("username", "") or "")
            if not name:
                continue
            is_admin = item.get("is_admin", False) or item.get("admin", False)
            key = f"user:{name}"
            prev = await self._db.get_entity_state(agent_id, "user", key)
            fingerprint = json.dumps({"admin": is_admin, "uid": item.get("uid")}, sort_keys=True)
            if prev is None:
                await self._db.set_entity_state(agent_id, "user", key, fingerprint, now)
                sev = "medium" if is_admin else "info"
                score = 5.0 if is_admin else 0.5
                findings.append(self._make_finding(
                    category="behavioral", item_key=key,
                    severity=sev, score=score,
                    title=f"New {'admin ' if is_admin else ''}user observed: {name}",
                    desc=f"User '{name}' detected for the first time{' — has admin privileges' if is_admin else ''}.",
                    evidence=item, source="behavioral_new_entity",
                    mitre="T1136.001" if is_admin else "",
                ))
            elif prev.get("fingerprint", "") != fingerprint:
                prev_data = {}
                try:
                    prev_data = json.loads(prev.get("fingerprint", "{}"))
                except Exception:
                    pass
                if not prev_data.get("admin") and is_admin:
                    findings.append(self._make_finding(
                        category="behavioral", item_key=f"{key}:admin_granted",
                        severity="high", score=8.0,
                        title=f"Admin privileges granted to existing user: {name}",
                        desc=f"User '{name}' was not admin previously and now has admin rights.",
                        evidence=item, source="behavioral_change", mitre="T1078.003",
                    ))
                await self._db.set_entity_state(agent_id, "user", key, fingerprint, now)
        return findings

    async def _tasks(self, agent_id: str, data: list) -> list[dict]:
        """Track new/changed scheduled tasks — new cron/launchd task is suspicious."""
        findings = []
        if not isinstance(data, list):
            return findings
        now = time.time()
        count = len(data)
        anomaly = await self._zscore_check(agent_id, "task_count", float(count))
        if anomaly and anomaly.get("zscore", 0) > 0:
            findings.append(self._make_finding(
                category="behavioral", item_key="task_count_anomaly",
                severity="medium", score=5.0,
                title=f"Scheduled task count increased: {count}",
                desc=f"Task count ({count}) is {anomaly['zscore']:.1f}σ above baseline.",
                evidence=anomaly, source="behavioral_zscore", mitre="T1053",
            ))
        await self._update_baseline(agent_id, "task_count", float(count))

        for item in data:
            if not isinstance(item, dict):
                continue
            label = str(item.get("name", "") or item.get("label", "") or "")
            cmd = str(item.get("command", "") or item.get("cmd", "") or "")
            key = f"task:{label or cmd[:40]}"
            prev = await self._db.get_entity_state(agent_id, "task", key)
            if prev is None:
                await self._db.set_entity_state(agent_id, "task", key,
                                                 json.dumps(item, default=str), now)
                findings.append(self._make_finding(
                    category="behavioral", item_key=key,
                    severity="low", score=3.0,
                    title=f"New scheduled task: {label or cmd[:60]}",
                    desc=f"Task '{label}' observed for the first time — verify it is legitimate.",
                    evidence=item, source="behavioral_new_entity", mitre="T1053",
                ))
        return findings

    async def _apps(self, agent_id: str, data: list) -> list[dict]:
        """Track unsigned/quarantined app count anomaly."""
        findings = []
        if not isinstance(data, list):
            return findings
        unsigned_count = sum(1 for a in data
                            if isinstance(a, dict) and not a.get("signed", True))
        anomaly = await self._zscore_check(agent_id, "unsigned_app_count", float(unsigned_count))
        if anomaly and anomaly.get("zscore", 0) > 0:
            findings.append(self._make_finding(
                category="behavioral", item_key="unsigned_app_count_anomaly",
                severity="medium", score=5.0,
                title=f"Unsigned app count increased: {unsigned_count}",
                desc=(f"Unsigned app count ({unsigned_count}) is "
                      f"{anomaly['zscore']:.1f}σ above baseline — new unsigned apps installed."),
                evidence=anomaly, source="behavioral_zscore", mitre="T1553.001",
            ))
        await self._update_baseline(agent_id, "unsigned_app_count", float(unsigned_count))
        return findings

    async def _packages(self, agent_id: str, data: list) -> list[dict]:
        """Track total package count anomaly — sudden large install is suspicious."""
        findings = []
        if not isinstance(data, list):
            return findings
        count = len(data)
        anomaly = await self._zscore_check(agent_id, "pkg_count", float(count))
        if anomaly and anomaly.get("zscore", 0) > 1.5:
            findings.append(self._make_finding(
                category="behavioral", item_key="pkg_count_anomaly",
                severity="low", score=3.5,
                title=f"Package count spike: {count}",
                desc=(f"Installed package count ({count}) is "
                      f"{anomaly['zscore']:.1f}σ above baseline — bulk install may indicate staging."),
                evidence=anomaly, source="behavioral_zscore",
            ))
        await self._update_baseline(agent_id, "pkg_count", float(count))
        return findings

    async def _binaries(self, agent_id: str, data: list) -> list[dict]:
        """Track SUID binary count — unexpected new SUID binary is high confidence."""
        findings = []
        if not isinstance(data, list):
            return findings
        suid_count = sum(1 for b in data
                        if isinstance(b, dict) and (b.get("suid") or b.get("is_suid")))
        anomaly = await self._zscore_check(agent_id, "suid_count", float(suid_count))
        if anomaly and anomaly.get("zscore", 0) > 0:
            findings.append(self._make_finding(
                category="behavioral", item_key="suid_count_anomaly",
                severity="high", score=7.5,
                title=f"SUID binary count increased: {suid_count}",
                desc=(f"SUID binary count ({suid_count}) is "
                      f"{anomaly['zscore']:.1f}σ above baseline — a new SUID binary was added."),
                evidence=anomaly, source="behavioral_zscore", mitre="T1548.001",
            ))
        await self._update_baseline(agent_id, "suid_count", float(suid_count))
        return findings

    async def _security_posture(self, agent_id: str, data: dict) -> list[dict]:
        """Track changes in security posture keys (SIP, Gatekeeper, FileVault)."""
        findings = []
        if not isinstance(data, dict):
            return findings
        key = "security_posture"
        now = time.time()
        fingerprint = json.dumps({
            k: data.get(k) for k in ("sip_enabled", "gatekeeper", "filevault", "firewall")
        }, sort_keys=True)
        prev = await self._db.get_entity_state(agent_id, "security", key)
        if prev is None:
            await self._db.set_entity_state(agent_id, "security", key, fingerprint, now)
        elif prev.get("fingerprint", "") != fingerprint:
            try:
                prev_data = json.loads(prev.get("fingerprint", "{}"))
            except Exception:
                prev_data = {}
            changes = []
            for k in ("sip_enabled", "gatekeeper", "filevault", "firewall"):
                if prev_data.get(k) != data.get(k):
                    changes.append(f"{k}: {prev_data.get(k)} → {data.get(k)}")
            if changes:
                age = now - prev.get("seen_at", now)
                findings.append(self._make_finding(
                    category="behavioral", item_key="security_posture_changed",
                    severity="high", score=8.0,
                    title=f"Security posture changed ({len(changes)} setting(s))",
                    desc=(f"Security configuration changed {_human_age(age)} after last seen: "
                          f"{'; '.join(changes)}"),
                    evidence={"changes": changes, "current": data, "previous": prev_data},
                    source="behavioral_change", mitre="T1562",
                ))
            await self._db.set_entity_state(agent_id, "security", key, fingerprint, now)
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


def _shannon_entropy(items: list[str]) -> float:
    """Shannon entropy in bits — low = repetitive (beaconing), high = diverse (scanning)."""
    if not items:
        return 0.0
    total = len(items)
    counts: dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
