"""
manager/manager/jarvis/engine.py — Jarvis AI Engine: correlates raw telemetry into verified findings.

Processing pipeline per payload:
  1. Route section → appropriate analyzer(s)
  2. Each analyzer emits a list of raw finding dicts
  3. Findings are upserted into intel.db (dedup by agent_id+category+item_key)
  4. Change timeline entry created for new/modified items
  5. Behavioral baseline updated

Analyzers:
  ports       — malicious port detection, unusual binding
  processes   — suspicious cmdline / path / SUID patterns
  connections — threat-feed IP lookup, unknown destinations
  services    — suspicious LaunchDaemon labels / paths
  apps        — unsigned / quarantined apps
  packages    — CVE lookup, risky tool detection
  network     — new/changed interfaces
  users       — new admin accounts, locked-out users
  tasks       — suspicious cron / launchd tasks
  security    — SIP/GK/FV posture changes
  configs     — suspicious content in monitored files
  binaries    — SUID/SGID binaries, world-writable
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any, Optional

from .rules import (
    MALICIOUS_PORTS, PROCESS_RULES, SUSPICIOUS_PATHS, CONFIG_RULES,
    RISKY_PACKAGES, SUSPICIOUS_SERVICE_PATTERNS, PARENT_CHILD_RULES,
    OBFUSCATION_RULES, get_tactic, severity_to_score,
)
from .allowlist import (
    is_trusted_ip, is_apple_system_process, get_dual_use_info,
    is_suspicious_spawn, has_benign_parent, adjust_finding_for_allowlist,
    cap_severity, APPLE_SYSTEM_PROCS,
)
from .behavioral  import BehavioralAnalyzer
from .feeds       import FeedManager
from .nvd         import CVELookup
from .correlator  import CorrelationEngine
from ..threat.scoring import score_matrix

log = logging.getLogger("manager.jarvis.engine")

# Private IP ranges — never flag as threat-feed hits
_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)"
)

# Ports that are genuinely safe to listen on (reduce FP)
_SAFE_LISTEN: set[int] = {22, 25, 53, 80, 443, 587, 993, 995,
                           3389, 5985, 5986, 27017, 5432, 3306,
                           6379, 5672, 8080, 8443, 8000, 8001, 2375}


class JarvisEngine:
    """
    Jarvis — AI-powered correlation engine. Created once at server startup.
    Receives raw telemetry from the ingest pipeline, correlates against threat
    intelligence sources, applies behavioral baselines, and writes verified
    findings into the IntelDB (verified findings store).
    """

    def __init__(self, db, intel_db) -> None:
        self._db      = db           # main manager DB (agents, keys)
        self._idb     = intel_db     # IntelDB (findings, timeline, baseline)
        self._feeds   = FeedManager(intel_db)
        self._nvd     = CVELookup(intel_db)
        self._behav   = BehavioralAnalyzer(intel_db)
        self._corr    = CorrelationEngine(intel_db)
        self._ready   = False
        self._nvd_queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        # Per-agent payload counter — run correlation every 3 payloads
        self._payload_count: dict[str, int] = {}

    @property
    def feeds(self) -> "FeedManager":
        """Shared FeedManager instance (used by ThreatIntelWorker)."""
        return self._feeds

    @property
    def nvd(self) -> "CVELookup":
        """Shared CVELookup instance (used by ThreatIntelWorker)."""
        return self._nvd

    async def start(self) -> None:
        """Call once at startup. Feed scheduling is owned by ThreatIntelWorker."""
        await self._feeds.refresh()   # initial load from DB cache only (no network)
        asyncio.create_task(self._nvd_worker())
        self._ready = True
        log.info("Jarvis engine started")

    async def process(
        self,
        agent_id: str,
        section: str,
        data: Any,
        skip_correlation: bool = False,
    ) -> None:
        """
        Entry point for every payload (or chunk).

        skip_correlation=True when the caller is processing a chunk that is
        part of a larger chunk set — the ChunkTracker will fire correlation
        once when the final chunk completes, rather than once per chunk.
        """
        if not self._ready:
            return
        try:
            findings = await self._dispatch(agent_id, section, data)
            beh = await self._behav.analyze(agent_id, section, data)
            findings.extend(beh)

            ts = time.time()
            for f in findings:
                f["agent_id"] = agent_id
                await self._idb.upsert_finding(f, ts)

            if not skip_correlation:
                count = self._payload_count.get(agent_id, 0) + 1
                self._payload_count[agent_id] = count
                if count % 3 == 0:
                    asyncio.create_task(self._run_correlations(agent_id))
        except Exception as exc:
            log.warning("Jarvis.process error agent=%s section=%s: %s",
                        agent_id, section, exc)

    async def run_correlations(self, agent_id: str) -> None:
        """
        Public trigger for cross-section correlation.
        Called by ChunkTracker when the last chunk of a chunk set completes.
        """
        asyncio.create_task(self._run_correlations(agent_id))

    async def _run_correlations(self, agent_id: str) -> None:
        """Evaluate cross-section correlation rules and store results."""
        try:
            correlations = await self._corr.correlate(agent_id)
            ts = time.time()
            for c in correlations:
                await self._idb.upsert_correlation(c, ts)
        except Exception as exc:
            log.warning("Correlation error agent=%s: %s", agent_id, exc)

    async def get_correlations(self, agent_id: str) -> list[dict]:
        """Return current correlations for an agent (called by API)."""
        try:
            return await self._idb.get_correlations(agent_id)
        except Exception:
            return []

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def _dispatch(self, agent_id: str, section: str, data: Any) -> list[dict]:
        fn = {
            "ports":       self._ports,
            "processes":   self._processes,
            "connections": self._connections,
            "services":    self._services,
            "apps":        self._apps,
            "packages":    self._packages,
            "network":     self._network,
            "users":       self._users,
            "tasks":       self._tasks,
            "security":    self._security,
            "configs":     self._configs,
            "binaries":    self._binaries,
        }.get(section)
        if fn is None:
            return []
        return await fn(agent_id, data)

    # ── Section analyzers ─────────────────────────────────────────────────────

    async def _ports(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        seen_ports: set[int] = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            port   = int(item.get("port", 0) or 0)
            proto  = item.get("proto", "tcp")
            proc   = item.get("process", "") or item.get("name", "")
            path   = item.get("path", "") or item.get("exe", "")
            bind   = item.get("bind_addr", item.get("addr", ""))
            key    = f"{proto}:{port}"

            if port in seen_ports:
                continue
            seen_ports.add(port)

            # Known malicious port
            if port in MALICIOUS_PORTS and port not in _SAFE_LISTEN:
                rule = MALICIOUS_PORTS[port]
                findings.append(self._finding(
                    category="port", item_key=key,
                    severity=rule["severity"],
                    score=severity_to_score(rule["severity"]),
                    title=f"Malicious port listening: {proto.upper()}/{port}",
                    desc=f"{rule['desc']}. Bound by process: {proc or 'unknown'}.",
                    evidence=item, source="rule:malicious_port",
                    mitre=rule["mitre"],
                    tags=["port", "c2", proto],
                ))

            # Process running from suspicious path
            if path:
                for sp in SUSPICIOUS_PATHS:
                    if sp["pattern"].match(path):
                        findings.append(self._finding(
                            category="port", item_key=f"{key}:susppath",
                            severity=sp["severity"],
                            score=severity_to_score(sp["severity"]),
                            title=f"Listening process in suspicious path: {path}",
                            desc=f"{sp['desc']} — {proc} listening on {proto}/{port}.",
                            evidence=item, source="rule:suspicious_path",
                            mitre="T1036", tags=["port", "suspicious_path"],
                        ))
                        break

            # Binding to 0.0.0.0 on unusual port
            if bind in ("0.0.0.0", "::") and port not in _SAFE_LISTEN and port > 1024:
                findings.append(self._finding(
                    category="port", item_key=f"{key}:wildcard",
                    severity="low", score=2.5,
                    title=f"Port {port} bound to all interfaces",
                    desc=f"Process '{proc}' is listening on 0.0.0.0:{port} (world-accessible).",
                    evidence=item, source="rule:wildcard_bind",
                    mitre="T1049", tags=["port", "exposure"],
                ))
        return findings

    async def _processes(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings

        # Build a pid → name/exe lookup for parent-child analysis
        pid_map: dict[int, dict] = {}
        for item in data:
            if isinstance(item, dict):
                try:
                    pid_map[int(item.get("pid", 0) or 0)] = item
                except (ValueError, TypeError):
                    pass

        for item in data:
            if not isinstance(item, dict):
                continue
            name    = str(item.get("name", "") or "")
            cmd     = str(item.get("cmdline", "") or item.get("cmd", "") or "")
            exe     = str(item.get("exe", "") or item.get("path", "") or "")
            pid     = item.get("pid", "?")
            ppid    = item.get("ppid") or item.get("parent_pid")
            full    = f"{exe} {cmd}".strip()

            # Skip Apple system processes entirely
            if is_apple_system_process(name, exe):
                continue

            # Resolve parent name for lineage checks
            parent_name = ""
            if ppid:
                try:
                    parent_item = pid_map.get(int(ppid), {})
                    parent_name = str(parent_item.get("name", "") or "")
                except (ValueError, TypeError):
                    pass

            # Benign parent check — suppress if spawned from known-good IDE/shell
            if parent_name and has_benign_parent(parent_name, name):
                continue

            # Parent-child lineage rules (Office/browser → shell is critical)
            for lrule in PARENT_CHILD_RULES:
                if parent_name and lrule["parent_re"].search(parent_name):
                    if lrule["child_re"].search(name) or lrule["child_re"].search(cmd):
                        f = self._finding(
                            category="process",
                            item_key=f"lineage:{parent_name}:{name}:{pid}",
                            severity=lrule["severity"],
                            score=severity_to_score(lrule["severity"]),
                            title=f"Suspicious spawn: {parent_name} → {name}",
                            desc=(f"{lrule['desc']} — "
                                  f"'{parent_name}' (PID {ppid}) spawned '{name}' (PID {pid}): {cmd[:100]}"),
                            evidence={**item, "parent_name": parent_name, "ppid": ppid},
                            source="rule:process_lineage", mitre=lrule["mitre"],
                            tags=["process", "lineage", "high_confidence"],
                        )
                        findings.append(f)
                        break

            # Standard process pattern rules
            for rule in PROCESS_RULES:
                if rule["compiled"].search(full) or rule["compiled"].search(name):
                    f = self._finding(
                        category="process",
                        item_key=f"proc:{name}:{_fp(exe or cmd)}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]) * rule.get("confidence", 0.8),
                        title=f"Suspicious process: {name}",
                        desc=f"{rule['desc']} — PID {pid}: {cmd[:120]}",
                        evidence=item, source="rule:process_pattern",
                        mitre=rule["mitre"], tags=["process", "suspicious"],
                    )
                    # Apply dual-use allowlist adjustment
                    f = adjust_finding_for_allowlist(f, name=name, path=exe, cmd=cmd,
                                                     parent_name=parent_name)
                    if f:
                        findings.append(f)
                    break

            # Obfuscation pattern check against cmdline
            for orule in OBFUSCATION_RULES:
                if orule["compiled"].search(cmd):
                    f = self._finding(
                        category="process",
                        item_key=f"obfusc:{name}:{_fp(cmd)}",
                        severity=orule["severity"],
                        score=severity_to_score(orule["severity"]) * orule.get("confidence", 0.8),
                        title=f"Obfuscated command in process: {name}",
                        desc=f"{orule['desc']} — PID {pid}: {cmd[:150]}",
                        evidence=item, source="rule:obfuscation",
                        mitre=orule["mitre"], tags=["process", "obfuscation"],
                    )
                    findings.append(f)
                    break

            # SUID / SGID check
            if item.get("suid") or item.get("is_suid"):
                findings.append(self._finding(
                    category="process", item_key=f"proc_suid:{_fp(exe or name)}",
                    severity="medium", score=4.5,
                    title=f"SUID process running: {name}",
                    desc=f"Process {name} (PID {pid}) is running with SUID bit set.",
                    evidence=item, source="rule:suid_process",
                    mitre="T1548.001", tags=["process", "privilege_escalation"],
                ))

        return findings

    async def _connections(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            raddr = str(item.get("remote_addr", "") or item.get("raddr", "") or "")
            if not raddr or raddr in ("-", "0.0.0.0:0", "*:*"):
                continue
            ip = raddr.rsplit(":", 1)[0].strip("[]")
            if not ip or _PRIVATE_RE.match(ip):
                continue
            # Skip trusted CDN/cloud IPs to reduce FP
            if is_trusted_ip(ip):
                continue

            # Threat feed check
            if self._feeds.is_malicious_ip(ip):
                meta = self._feeds.get_details(ip) or {}
                findings.append(self._finding(
                    category="connection",
                    item_key=f"conn:{ip}",
                    severity=meta.get("severity", "high"),
                    score=severity_to_score(meta.get("severity", "high")),
                    title=f"Connection to threat-feed IP: {ip}",
                    desc=(f"Active connection to {raddr} — "
                          f"{meta.get('description','Known malicious IP')} "
                          f"(source: {meta.get('source','')}, confidence: {meta.get('confidence',0)}%)"),
                    evidence={**item, "threat_meta": meta},
                    source=f"feed:{meta.get('source','unknown')}",
                    mitre="T1071", tags=["connection", "c2", "threat_feed"],
                ))
            else:
                # Queue for live AbuseIPDB check (non-blocking)
                try:
                    self._nvd_queue.put_nowait(("abuseipdb", agent_id, ip, item))
                except asyncio.QueueFull:
                    pass
        return findings

    async def _services(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "") or item.get("name", "") or "")
            prog  = str(item.get("program", "") or item.get("path", "") or "")
            for rule in SUSPICIOUS_SERVICE_PATTERNS:
                if rule["pattern"].search(label) or (prog and rule["pattern"].search(prog)):
                    findings.append(self._finding(
                        category="service", item_key=f"svc:{label}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious service: {label}",
                        desc=f"{rule['desc']}.",
                        evidence=item, source="rule:suspicious_service",
                        mitre="T1543.004",
                        tags=["service", "persistence"],
                    ))
                    break
        return findings

    async def _apps(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name   = str(item.get("name", "") or "")
            signed = item.get("signed", True)
            notarized = item.get("notarized", True)
            quarantine = item.get("quarantined", False)
            path   = str(item.get("path", "") or "")

            if not signed:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:unsigned",
                    severity="medium", score=5.0,
                    title=f"Unsigned application: {name}",
                    desc=f"'{name}' at {path} is not code-signed by Apple.",
                    evidence=item, source="rule:unsigned_app",
                    mitre="T1553.001", tags=["app", "unsigned"],
                ))
            elif not notarized:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:notarized",
                    severity="low", score=2.0,
                    title=f"Non-notarized application: {name}",
                    desc=f"'{name}' is signed but not notarized by Apple.",
                    evidence=item, source="rule:not_notarized",
                    mitre="T1553.001", tags=["app", "notarization"],
                ))
            if quarantine:
                findings.append(self._finding(
                    category="app", item_key=f"app:{path or name}:quarantine",
                    severity="medium", score=4.0,
                    title=f"Quarantined application running: {name}",
                    desc=f"'{name}' has a quarantine flag — was downloaded from internet.",
                    evidence=item, source="rule:quarantine",
                    mitre="T1204.002", tags=["app", "quarantine"],
                ))
        return findings

    async def _packages(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name    = str(item.get("name", "") or "").lower()
            version = str(item.get("version", "") or "")
            manager = str(item.get("manager", "brew") or "")

            # Risky package rule check
            for pkg_name, rule in RISKY_PACKAGES.items():
                if pkg_name in name:
                    f = self._finding(
                        category="package",
                        item_key=f"pkg:{manager}:{name}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Risky package installed: {name}",
                        desc=f"{rule['desc']} — installed via {manager} v{version}.",
                        evidence=item, source="rule:risky_package",
                        mitre=rule["mitre"],
                        tags=["package", "tool", manager],
                    )
                    # Apply dual-use downgrade for legitimate pentest/admin tools
                    f = adjust_finding_for_allowlist(f, name=name)
                    if f:
                        findings.append(f)
                    break

            # Queue for NVD CVE lookup (async, non-blocking)
            try:
                self._nvd_queue.put_nowait(("nvd", agent_id, name, version, item))
            except asyncio.QueueFull:
                pass
        return findings

    async def _network(self, agent_id: str, data: dict) -> list[dict]:
        # Handled by behavioral analyzer
        return []

    async def _users(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            name  = str(item.get("name", "") or item.get("username", "") or "")
            admin = item.get("is_admin", False) or item.get("admin", False)
            uid   = item.get("uid", -1)
            shell = str(item.get("shell", "") or "")

            # UID 0 (root) with non-root name
            if uid == 0 and name not in ("root",):
                findings.append(self._finding(
                    category="user", item_key=f"user:{name}:uid0",
                    severity="critical", score=9.0,
                    title=f"Non-root account with UID 0: {name}",
                    desc=f"Account '{name}' has UID 0 (root-equivalent) — possible privilege escalation.",
                    evidence=item, source="rule:uid0",
                    mitre="T1078.003", tags=["user", "privilege_escalation"],
                ))

            # Interactive shell for service accounts
            if uid and 0 < int(uid) < 500 and shell not in ("/bin/false", "/usr/bin/false", "/sbin/nologin", ""):
                findings.append(self._finding(
                    category="user", item_key=f"user:{name}:svc_shell",
                    severity="medium", score=4.0,
                    title=f"Service account with interactive shell: {name}",
                    desc=f"System account '{name}' (UID {uid}) has shell {shell}.",
                    evidence=item, source="rule:svc_interactive_shell",
                    mitre="T1078", tags=["user", "lateral_movement"],
                ))
        return findings

    async def _tasks(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            cmd  = str(item.get("command", "") or item.get("cmd", "") or "")
            name = str(item.get("name", "") or item.get("label", "") or "")
            for rule in CONFIG_RULES:
                if rule["compiled"].search(cmd):
                    findings.append(self._finding(
                        category="task", item_key=f"task:{name}:{_fp(cmd)}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious scheduled task: {name or cmd[:60]}",
                        desc=f"{rule['desc']} — found in scheduled task.",
                        evidence=item, source="rule:task_pattern",
                        mitre=rule["mitre"], tags=["task", "persistence"],
                    ))
                    break
        return findings

    async def _security(self, agent_id: str, data: dict) -> list[dict]:
        findings = []
        if not isinstance(data, dict):
            return findings
        checks = [
            ("sip_enabled",      False,  "critical", "SIP disabled",      "System Integrity Protection is disabled — attacker can modify protected files.", "T1562.001"),
            ("gatekeeper",       False,  "high",     "Gatekeeper disabled","Gatekeeper is off — unsigned apps can run without warning.", "T1553.001"),
            ("filevault",        False,  "high",     "FileVault disabled", "Full-disk encryption is not enabled — data at risk if device lost.", "T1486"),
            ("firewall",         False,  "medium",   "Firewall disabled",  "macOS application firewall is disabled.", "T1562.004"),
            ("lockdown_mode",    True,   "info",     "Lockdown Mode active","Device is in Lockdown Mode (highest security posture).", ""),
        ]
        for key, good_val, severity, title, desc, mitre in checks:
            val = data.get(key)
            if val is None:
                continue
            is_bad = (val == good_val) if isinstance(good_val, bool) else False
            if key == "lockdown_mode":
                is_bad = False  # always info, not bad
            if not is_bad and key != "lockdown_mode":
                continue
            findings.append(self._finding(
                category="security", item_key=f"sec:{key}",
                severity=severity if is_bad else "info",
                score=severity_to_score(severity) if is_bad else 0.5,
                title=title,
                desc=desc,
                evidence={key: val},
                source="rule:security_posture",
                mitre=mitre,
                tags=["security", "posture"],
            ))
        return findings

    async def _configs(self, agent_id: str, data: Any) -> list[dict]:
        findings = []
        items = data if isinstance(data, list) else (
            [{"path": k, "content": v} for k, v in data.items()]
            if isinstance(data, dict) else []
        )
        for item in items:
            if not isinstance(item, dict):
                continue
            path    = str(item.get("path", "") or "")
            content = str(item.get("content", "") or "")
            if not content:
                continue
            for rule in CONFIG_RULES:
                if rule["compiled"].search(content):
                    findings.append(self._finding(
                        category="config",
                        item_key=f"cfg:{path}:{rule['compiled'].pattern[:20]}",
                        severity=rule["severity"],
                        score=severity_to_score(rule["severity"]),
                        title=f"Suspicious pattern in config: {path}",
                        desc=f"{rule['desc']} — found in {path}.",
                        evidence={"path": path, "match_preview": content[:200]},
                        source="rule:config_pattern",
                        mitre=rule["mitre"],
                        tags=["config", "persistence"],
                    ))
        return findings

    async def _binaries(self, agent_id: str, data: list) -> list[dict]:
        findings = []
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            path  = str(item.get("path", "") or "")
            suid  = item.get("suid", False) or item.get("is_suid", False)
            sgid  = item.get("sgid", False) or item.get("is_sgid", False)
            ww    = item.get("world_writable", False)
            if suid:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_suid:{path}",
                    severity="high", score=7.0,
                    title=f"SUID binary: {path}",
                    desc=f"SUID bit set on {path} — can be used for privilege escalation.",
                    evidence=item, source="rule:suid_binary",
                    mitre="T1548.001", tags=["binary", "suid", "privesc"],
                ))
            if sgid:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_sgid:{path}",
                    severity="medium", score=4.5,
                    title=f"SGID binary: {path}",
                    desc=f"SGID bit set on {path}.",
                    evidence=item, source="rule:sgid_binary",
                    mitre="T1548.001", tags=["binary", "sgid"],
                ))
            if ww:
                findings.append(self._finding(
                    category="binary", item_key=f"bin_ww:{path}",
                    severity="medium", score=5.0,
                    title=f"World-writable binary: {path}",
                    desc=f"{path} is world-writable — could be tampered.",
                    evidence=item, source="rule:world_writable",
                    mitre="T1222", tags=["binary", "world_writable"],
                ))
        return findings

    # ── Background workers ─────────────────────────────────────────────────────

    async def _nvd_worker(self) -> None:
        """Drain the NVD / AbuseIPDB queue at a controlled rate."""
        while True:
            item = await self._nvd_queue.get()
            try:
                if item[0] == "nvd":
                    _, agent_id, name, version, raw = item
                    cves = await self._nvd.lookup(name, version)
                    for cve in cves:
                        score = cve.get("cvss_score") or 0
                        if score < 4.0:
                            continue
                        sev = cve.get("severity", "medium")
                        f = self._finding(
                            category="package",
                            item_key=f"cve:{name}:{cve['cve_id']}",
                            severity=sev, score=score,
                            title=f"CVE in {name}: {cve['cve_id']} (CVSS {score})",
                            desc=cve.get("description", "")[:300],
                            evidence={**raw, "cve": cve},
                            source="nvd",
                            mitre="",
                            tags=["cve", "package", name],
                        )
                        f["agent_id"] = agent_id
                        f["cve_ids"]  = [cve["cve_id"]]
                        f["cvss_score"] = score
                        f["cvss_vector"] = cve.get("cvss_vector", "")
                        f.update(_intel_fields_from_cve(cve, raw))
                        f["composite_score"] = score_matrix.compute(
                            f, agent_id=agent_id, collected_ts=time.time(),
                        )
                        f["priority_reason"] = _priority_reason(f)
                        f["action_plan"] = _action_plan_for(f)
                        await self._idb.upsert_finding(f, time.time())

                elif item[0] == "abuseipdb":
                    _, agent_id, ip, raw_item = item
                    result = await self._feeds.check_ip_live(ip)
                    if result:
                        f = self._finding(
                            category="connection",
                            item_key=f"abuseipdb:{ip}",
                            severity=result["severity"],
                            score=severity_to_score(result["severity"]),
                            title=f"AbuseIPDB: Malicious IP {ip}",
                            desc=result.get("description", ""),
                            evidence={**raw_item, "abuseipdb": result},
                            source="abuseipdb", mitre="T1071",
                            tags=["connection", "abuseipdb"],
                        )
                        f["agent_id"] = agent_id
                        f["asset_tier"] = _asset_tier_from_evidence(raw_item)
                        f["asset_importance"] = _asset_importance(f["asset_tier"])
                        f["composite_score"] = max(
                            f["score"],
                            score_matrix.compute(f, agent_id=agent_id, collected_ts=time.time()),
                        )
                        f["priority_reason"] = _priority_reason(f)
                        f["action_plan"] = _action_plan_for(f)
                        await self._idb.upsert_finding(f, time.time())

            except Exception as exc:
                log.debug("NVD worker error: %s", exc)
            finally:
                self._nvd_queue.task_done()
                await asyncio.sleep(2)   # gentle rate limiting

    # ── Finding factory ───────────────────────────────────────────────────────

    @staticmethod
    def _finding(*, category: str, item_key: str, severity: str,
                 score: float, title: str, desc: str, evidence: dict,
                 source: str, mitre: str = "", tags: list | None = None,
                 cve_ids: list | None = None, cvss_score: float | None = None,
                 cvss_vector: str = "") -> dict:
        return {
            "category":        category,
            "item_key":        item_key,
            "severity":        severity,
            "score":           round(score, 2),
            "title":           title,
            "description":     desc,
            "evidence":        evidence,
            "source":          source,
            "rule_id":         source,
            "mitre_technique": mitre,
            "mitre_tactic":    get_tactic(mitre),
            "cve_ids":         cve_ids or [],
            "cvss_score":      cvss_score,
            "cvss_vector":     cvss_vector,
            "tags":            tags or [category, source],
        }


def _fp(s: str) -> str:
    """Short fingerprint for use in item_key."""
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _intel_fields_from_cve(cve: dict, evidence: dict) -> dict:
    refs = cve.get("references") or cve.get("reference_urls") or []
    ref_text = " ".join(map(str, refs)).lower()
    desc = str(cve.get("description", "")).lower()
    kev = bool(cve.get("kev") or cve.get("cisa_kev") or cve.get("known_exploited"))
    exploit_sources: list[str] = []
    if cve.get("exploit_db_id"):
        exploit_sources.append(f"ExploitDB:{cve.get('exploit_db_id')}")
    if "exploit-db" in ref_text or "exploitdb" in ref_text:
        exploit_sources.append("ExploitDB reference")
    if "metasploit" in ref_text or "metasploit" in desc:
        exploit_sources.append("Metasploit reference")
    if "proof-of-concept" in desc or "poc" in ref_text:
        exploit_sources.append("public PoC reference")
    epss = float(cve.get("epss_score") or cve.get("epss") or 0)
    tier = _asset_tier_from_evidence(evidence)
    return {
        "kev": kev,
        "epss_score": epss,
        "exploit_available": bool(exploit_sources or cve.get("exploit_available")),
        "exploit_sources": sorted(set(exploit_sources)),
        "asset_tier": tier,
        "asset_importance": _asset_importance(tier),
    }


def _asset_tier_from_evidence(evidence: dict) -> str:
    text = json.dumps(evidence or {}, default=str).lower()
    if any(x in text for x in ("server", "runner", "build", "prod", "database", "k8s", "container")):
        return "server"
    if any(x in text for x in ("executive", "finance", "admin", "ciso", "ceo")):
        return "crown_jewel"
    if any(x in text for x in ("laptop", "macbook", "workstation", "desktop")):
        return "workstation"
    return "endpoint"


def _asset_importance(tier: str) -> float:
    return {
        "crown_jewel": 1.0,
        "server": 0.9,
        "workstation": 0.55,
        "endpoint": 0.4,
    }.get(tier, 0.3)


def _priority_reason(f: dict) -> str:
    bits = []
    if f.get("kev"):
        bits.append("CISA KEV")
    if f.get("exploit_available"):
        bits.append("public exploit")
    if f.get("epss_score"):
        bits.append(f"EPSS {float(f['epss_score']) * 100:.0f}%")
    if f.get("cvss_score"):
        bits.append(f"CVSS {float(f['cvss_score']):.1f}")
    if f.get("asset_tier"):
        bits.append(f"{f['asset_tier']} asset")
    return ", ".join(bits) or "telemetry/rule correlation"


def _action_plan_for(f: dict) -> list[dict]:
    cat = f.get("category", "")
    if cat == "package":
        return [
            {"type": "contain", "title": "Restrict exposure for affected service", "detail": "Firewall or segment the service until the package is patched."},
            {"type": "remediate", "title": "Patch or upgrade vulnerable package", "detail": "Use the package manager to move to a non-vulnerable version and rescan."},
            {"type": "hunt", "title": "Review logs for exploitation attempts", "detail": "Search service and proxy logs for payloads matching the CVE window."},
        ]
    if cat == "connection":
        return [
            {"type": "contain", "title": "Block destination IOC", "detail": "Block the IP/domain at egress controls and DNS where applicable."},
            {"type": "investigate", "title": "Identify owning process and parent chain", "detail": "Map PID, binary path, signer, launch mechanism, and user context."},
        ]
    return [
        {"type": "investigate", "title": "Validate evidence and owner", "detail": "Confirm the finding, affected asset, business owner, and immediate blast radius."},
        {"type": "remediate", "title": "Apply recommended mitigation", "detail": "Track status, assignee, and closure notes in the finding activity log."},
    ]
