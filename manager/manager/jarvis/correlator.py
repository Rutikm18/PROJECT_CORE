"""
manager/manager/jarvis/correlator.py — Cross-section attack-chain correlation.

Thinks like a senior SOC analyst: a single signal is noise; multiple signals
from different sections forming a coherent ATT&CK chain is a verified threat.

Each correlation rule defines:
  - required_signals  : section→field patterns that must ALL be present
  - optional_signals  : additional signals that raise confidence if present
  - attack_chain      : ordered MITRE tactics (tells the story)
  - severity / score

The correlator is called after each payload is processed.  It reads the
most-recent findings for an agent from intel.db and checks which rules fire.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

log = logging.getLogger("manager.jarvis.correlator")


# ── Correlation rule definitions ──────────────────────────────────────────────

CORRELATION_RULES: list[dict] = [

    # ── 1. C2 Beacon + Tool ───────────────────────────────────────────────────
    {
        "id":          "corr:c2_beacon_tool",
        "title":       "C2 Tool + Active External Connection",
        "description": (
            "A known C2/offensive tool is running AND there is an active "
            "connection to an external IP. This combination strongly indicates "
            "a command-and-control beaconing session."
        ),
        "required_categories": ["process", "connection"],
        "required_sources":    ["rule:process_pattern", "feed:feodo", "feed:emerging", "abuseipdb"],
        "severity":    "critical",
        "score":       9.5,
        "confidence":  95,
        "attack_chain": [
            {"tactic": "Execution",             "technique": "T1059",     "label": "C2 tool executed"},
            {"tactic": "Command and Control",   "technique": "T1071",     "label": "Beacon to C2 server"},
        ],
        "recommendation": (
            "Isolate the host immediately. Kill the offending process, capture "
            "memory if forensics are needed, block the external IP at the firewall, "
            "and begin incident response. Investigate how the tool arrived on the host."
        ),
    },

    # ── 2. Defense Evasion Chain ──────────────────────────────────────────────
    {
        "id":          "corr:defense_evasion_chain",
        "title":       "Defense Evasion Chain: SIP/Gatekeeper + Unsigned Execution",
        "description": (
            "System Integrity Protection or Gatekeeper is disabled AND an unsigned "
            "or quarantined application is installed. This is a classic attacker "
            "pattern: disable controls, then run untrusted code."
        ),
        "required_categories": ["security", "app"],
        "required_sources":    ["rule:security_posture", "rule:unsigned_app", "rule:quarantine"],
        "severity":    "high",
        "score":       8.5,
        "confidence":  85,
        "attack_chain": [
            {"tactic": "Defense Evasion",   "technique": "T1562.001", "label": "SIP/Gatekeeper disabled"},
            {"tactic": "Execution",         "technique": "T1553.001", "label": "Unsigned code executed"},
        ],
        "recommendation": (
            "Re-enable SIP (boot into Recovery Mode → csrutil enable) and Gatekeeper. "
            "Investigate why controls were disabled. Remove the unsigned application "
            "and audit recent installation history."
        ),
    },

    # ── 3. Persistence Trifecta ───────────────────────────────────────────────
    {
        "id":          "corr:persistence_trifecta",
        "title":       "Persistence Trifecta: Service + Task + Config",
        "description": (
            "Suspicious findings in three persistence mechanisms simultaneously: "
            "a LaunchDaemon/service, a scheduled task (cron/launchd), and a "
            "modified shell config. Attackers layer persistence to survive reboots "
            "and remediation attempts."
        ),
        "required_categories": ["service", "task", "config"],
        "severity":    "critical",
        "score":       9.0,
        "confidence":  90,
        "attack_chain": [
            {"tactic": "Persistence", "technique": "T1543.004", "label": "Malicious LaunchDaemon"},
            {"tactic": "Persistence", "technique": "T1053.003", "label": "Malicious cron/launchd task"},
            {"tactic": "Persistence", "technique": "T1546.004", "label": "Shell config hijack"},
        ],
        "recommendation": (
            "Audit all LaunchDaemons in /Library/LaunchDaemons and ~/Library/LaunchAgents. "
            "Review crontab -l for all users. Check .zshrc, .bashrc, .zprofile for injected "
            "commands. Remove malicious entries and rotate credentials."
        ),
    },

    # ── 4. Privilege Escalation → Execution ──────────────────────────────────
    {
        "id":          "corr:privesc_execution",
        "title":       "Privilege Escalation → Execution: SUID Binary + Root Process",
        "description": (
            "A SUID binary is present AND a suspicious process is running with elevated "
            "privileges. This indicates a privilege escalation attack has likely succeeded."
        ),
        "required_categories": ["binary", "process"],
        "required_sources":    ["rule:suid_binary", "rule:process_pattern"],
        "severity":    "high",
        "score":       8.0,
        "confidence":  80,
        "attack_chain": [
            {"tactic": "Privilege Escalation", "technique": "T1548.001", "label": "SUID binary exploited"},
            {"tactic": "Execution",            "technique": "T1059",     "label": "Elevated process spawned"},
        ],
        "recommendation": (
            "Run 'find / -perm -4000' to audit all SUID binaries. Remove SUID bit from "
            "any non-essential binaries (chmod u-s <path>). Investigate the elevated "
            "process lineage and determine what actions it performed."
        ),
    },

    # ── 5. LOLBin Abuse: Download + Execute ──────────────────────────────────
    {
        "id":          "corr:lolbin_download_execute",
        "title":       "LOLBin Abuse: Download-and-Execute Pattern",
        "description": (
            "A native binary (curl, wget, python) is being used for execution AND "
            "a process is running from a temporary path (/tmp, /var/tmp, Downloads). "
            "Living-off-the-land binaries evade AV by using trusted OS tools."
        ),
        "required_categories": ["process", "port"],
        "required_sources":    ["rule:process_pattern", "rule:suspicious_path"],
        "severity":    "high",
        "score":       7.5,
        "confidence":  78,
        "attack_chain": [
            {"tactic": "Defense Evasion", "technique": "T1218",     "label": "LOLBin used for execution"},
            {"tactic": "Execution",       "technique": "T1059",     "label": "Payload from temp path"},
            {"tactic": "Persistence",     "technique": "T1036",     "label": "Masquerading in temp dir"},
        ],
        "recommendation": (
            "Restrict curl/wget/python from writing to /tmp. Investigate what was "
            "downloaded and executed. Check for persistence mechanisms installed by the payload. "
            "Consider application allowlisting to prevent execution from temp directories."
        ),
    },

    # ── 6. Cryptominer Full Stack ─────────────────────────────────────────────
    {
        "id":          "corr:cryptominer_full_stack",
        "title":       "Cryptominer: Process + Port + External Connection",
        "description": (
            "Cryptomining indicators found across process list, listening ports, and "
            "network connections simultaneously. Full cryptominer deployment confirmed: "
            "the miner is running, listening for management connections, and reaching out "
            "to a stratum pool."
        ),
        "required_categories": ["process", "port"],
        "optional_categories": ["connection"],
        "required_sources":    ["rule:process_pattern", "rule:malicious_port"],
        "severity":    "critical",
        "score":       9.2,
        "confidence":  92,
        "attack_chain": [
            {"tactic": "Execution",         "technique": "T1059",  "label": "Miner process spawned"},
            {"tactic": "Impact",            "technique": "T1496",  "label": "CPU resources hijacked"},
            {"tactic": "Command and Control","technique":"T1071",  "label": "Stratum pool connection"},
        ],
        "recommendation": (
            "Kill all cryptominer processes immediately. Remove the miner binary and any "
            "persistence mechanisms (cron, launchd). Block stratum pool IPs/domains at the "
            "firewall. Audit how the miner was installed — check for initial access vectors "
            "such as compromised credentials, vulnerable services, or malicious packages."
        ),
    },

    # ── 7. Account Takeover Signal ────────────────────────────────────────────
    {
        "id":          "corr:account_takeover",
        "title":       "Account Takeover Signal: Privileged User + External C2",
        "description": (
            "A user account with admin or root-equivalent privileges is active AND "
            "there is an external connection to a flagged IP. This pattern is consistent "
            "with credential theft followed by remote attacker operations."
        ),
        "required_categories": ["user", "connection"],
        "severity":    "critical",
        "score":       9.0,
        "confidence":  82,
        "attack_chain": [
            {"tactic": "Credential Access",   "technique": "T1078",  "label": "Privileged account active"},
            {"tactic": "Command and Control", "technique": "T1071",  "label": "External C2 connection"},
            {"tactic": "Lateral Movement",    "technique": "T1021",  "label": "Remote access established"},
        ],
        "recommendation": (
            "Immediately disable and audit the privileged account. Force password reset "
            "for all admin accounts. Review authentication logs for anomalous login times "
            "or source IPs. Check for new admin accounts created recently (dscl . list /Users)."
        ),
    },

    # ── 8. Package CVE + Active Exploitation ─────────────────────────────────
    {
        "id":          "corr:vuln_package_active_network",
        "title":       "Vulnerable Package + Active Network Service",
        "description": (
            "A package with a critical/high CVE is installed AND a related service "
            "is listening on a network port. A publicly-known vulnerability in an "
            "internet-accessible service is a prime exploitation target."
        ),
        "required_categories": ["package", "port"],
        "required_sources":    ["nvd"],
        "severity":    "high",
        "score":       8.0,
        "confidence":  75,
        "attack_chain": [
            {"tactic": "Initial Access",  "technique": "T1190", "label": "Vulnerable service exposed"},
            {"tactic": "Execution",       "technique": "T1203", "label": "CVE exploitation risk"},
        ],
        "recommendation": (
            "Immediately patch or upgrade the vulnerable package. If patching is not "
            "immediately possible, restrict network access to the service via firewall rules. "
            "Check service logs for exploitation attempts (scanner patterns, unusual payloads)."
        ),
    },

    # ── 9. Kernel + Security Config Tampering ────────────────────────────────
    {
        "id":          "corr:kernel_security_tamper",
        "title":       "Kernel Security + Config Tampering Combo",
        "description": (
            "Security posture controls (SIP, Firewall, FileVault) are degraded AND "
            "suspicious patterns are found in shell/SSH configuration files. This "
            "indicates systematic security weakening — either by an attacker or "
            "a severely misconfigured system."
        ),
        "required_categories": ["security", "config"],
        "severity":    "high",
        "score":       7.8,
        "confidence":  80,
        "attack_chain": [
            {"tactic": "Defense Evasion", "technique": "T1562",     "label": "Security controls disabled"},
            {"tactic": "Persistence",     "technique": "T1546.004", "label": "Config file persistence"},
        ],
        "recommendation": (
            "Run a full security posture audit. Re-enable all macOS security controls. "
            "Audit shell config files for injected commands. Consider a full OS reinstall "
            "if the scope of tampering is unclear. Review who has admin access."
        ),
    },
]


# ── Correlator class ──────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Cross-section correlation engine.  Called after each section is processed.
    Reads the current active findings for an agent and checks which correlation
    rules fire based on category combinations.
    """

    def __init__(self, intel_db) -> None:
        self._idb = intel_db

    async def correlate(self, agent_id: str) -> list[dict]:
        """
        Evaluate all correlation rules against current active findings.
        Returns list of correlation dicts (not upserted — caller does that).
        """
        try:
            # Fetch active findings, grouped by category + source
            rows = await self._idb.get_findings(
                agent_id, active_only=True, limit=500
            )
        except Exception as exc:
            log.warning("Correlator fetch error agent=%s: %s", agent_id, exc)
            return []

        # Build lookup: category → list of findings
        by_category: dict[str, list[dict]] = {}
        by_source:   dict[str, list[dict]] = {}
        for row in rows:
            cat = row.get("category", "")
            src = row.get("source", "")
            by_category.setdefault(cat, []).append(row)
            by_source.setdefault(src, []).append(row)

        correlations: list[dict] = []
        for rule in CORRELATION_RULES:
            result = self._eval_rule(rule, by_category, by_source, rows, agent_id)
            if result:
                correlations.append(result)

        return correlations

    def _eval_rule(
        self,
        rule:        dict,
        by_category: dict[str, list[dict]],
        by_source:   dict[str, list[dict]],
        all_findings:list[dict],
        agent_id:    str,
    ) -> dict | None:
        required_cats = rule.get("required_categories", [])
        required_srcs = rule.get("required_sources", [])

        # All required categories must have at least one active finding
        matched_cats: dict[str, list[dict]] = {}
        for cat in required_cats:
            findings_in_cat = by_category.get(cat, [])
            if not findings_in_cat:
                return None  # Required category missing → rule doesn't fire
            matched_cats[cat] = findings_in_cat

        # If rule specifies required sources, at least one finding in those
        # sources must exist (across any category)
        if required_srcs:
            all_sources = set()
            for f in all_findings:
                all_sources.add(f.get("source", ""))
            if not any(s in all_sources for s in required_srcs):
                return None

        # Gather evidence from all matched categories
        evidence_findings: list[dict] = []
        for cat_findings in matched_cats.values():
            # Take highest-score finding per category
            best = max(cat_findings, key=lambda x: x.get("score", 0))
            evidence_findings.append(best)

        # Optional categories boost confidence
        optional_cats = rule.get("optional_categories", [])
        bonus = sum(5 for c in optional_cats if c in by_category)
        confidence = min(99, rule.get("confidence", 75) + bonus)

        return {
            "rule_id":       rule["id"],
            "agent_id":      agent_id,
            "category":      "correlation",
            "item_key":      rule["id"],
            "severity":      rule["severity"],
            "score":         rule["score"],
            "confidence":    confidence,
            "title":         rule["title"],
            "description":   rule["description"],
            "recommendation":rule.get("recommendation", ""),
            "attack_chain":  rule["attack_chain"],
            "signals":       evidence_findings,
            "signal_count":  len(evidence_findings),
            "source":        "correlation_engine",
            "detected_at":   time.time(),
        }


def build_correlation_summary(correlations: list[dict]) -> dict:
    """Summarise a list of correlations for the dashboard hero card."""
    if not correlations:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0,
                "max_score": 0.0, "top_chain": None}
    by_sev: dict[str, int] = {}
    max_score = 0.0
    top = None
    for c in correlations:
        sev = c.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        s = c.get("score", 0.0)
        if s > max_score:
            max_score = s
            top = c
    return {
        "total":     len(correlations),
        "critical":  by_sev.get("critical", 0),
        "high":      by_sev.get("high", 0),
        "medium":    by_sev.get("medium", 0),
        "max_score": round(max_score, 1),
        "top_chain": top,
    }
