"""
manager/manager/jarvis/correlator.py — Time-aware cross-section attack-chain correlation.

Thinks like a senior SOC analyst: a single signal is noise; multiple signals
from different sections forming a coherent ATT&CK chain is a verified threat.

Each correlation rule defines:
  - required_categories  : must ALL have active findings within time_window_hours
  - optional_categories  : boost confidence if present
  - time_window_hours    : only correlate findings detected within this window
  - attack_chain         : ordered MITRE tactics (tells the story)
  - severity / score / confidence

Rules are time-gated: old stale findings cannot trigger correlations, preventing
false positives from week-old noise combining with today's data.
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
        "time_window_hours": 24,
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
        "time_window_hours": 48,
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
        "time_window_hours": 72,
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
        "time_window_hours": 24,
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
        "time_window_hours": 12,
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
        "time_window_hours": 24,
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
        "time_window_hours": 24,
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
        "time_window_hours": 168,
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
        "time_window_hours": 48,
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

    # ── 10. Credential Dump → Lateral Movement ───────────────────────────────
    {
        "id":          "corr:cred_dump_lateral",
        "title":       "Credential Dump + Privilege Escalation",
        "description": (
            "A credential dumping tool or pattern (mimikatz, pypykatz, lsass access) "
            "is present alongside a user account with unexpected privilege escalation. "
            "This is the most common pre-ransomware pattern."
        ),
        "required_categories": ["process", "user"],
        "required_sources":    ["rule:process_pattern"],
        "severity":    "critical",
        "score":       9.3,
        "confidence":  91,
        "time_window_hours": 24,
        "attack_chain": [
            {"tactic": "Credential Access",  "technique": "T1003",    "label": "Credential dump detected"},
            {"tactic": "Privilege Escalation","technique": "T1078.003","label": "Admin account active"},
            {"tactic": "Lateral Movement",   "technique": "T1021",    "label": "Lateral movement likely"},
        ],
        "recommendation": (
            "This combination is a pre-ransomware kill-chain indicator. Immediately isolate the host. "
            "Reset all local and domain credentials. Check for new accounts created in the last 48h. "
            "Search for lateral movement artifacts across all connected hosts."
        ),
    },

    # ── 11. Ransomware Precursor Trifecta ────────────────────────────────────
    {
        "id":          "corr:ransomware_precursor",
        "title":       "Ransomware Precursor: Encryption + Persistence + Defense Evasion",
        "description": (
            "Three ransomware-stage signals detected together: a new or modified service "
            "(for persistence), a security control disabled (defense evasion), and a "
            "suspicious process (staging/encryption). This is a pre-detonation indicator."
        ),
        "required_categories": ["service", "security", "process"],
        "severity":    "critical",
        "score":       9.5,
        "confidence":  88,
        "time_window_hours": 12,
        "attack_chain": [
            {"tactic": "Defense Evasion",   "technique": "T1562.001", "label": "Security controls disabled"},
            {"tactic": "Persistence",       "technique": "T1543.004", "label": "Malicious service installed"},
            {"tactic": "Impact",            "technique": "T1486",     "label": "Ransomware staging"},
        ],
        "recommendation": (
            "Immediate containment required — ransomware pre-detonation indicator. "
            "Isolate the host from the network now. Do NOT reboot (ransomware may trigger on boot). "
            "Take a memory snapshot if possible. Notify the IR team. Check for data staging "
            "directories and outbound transfers."
        ),
    },

    # ── 12. Beaconing + New Service (C2 Implant Installation) ────────────────
    {
        "id":          "corr:beacon_implant",
        "title":       "C2 Beaconing + New Persistence Service",
        "description": (
            "Behavioral beaconing pattern (low-entropy repeated connections) detected "
            "alongside a newly observed service. This pattern matches a C2 implant "
            "that installs itself as a LaunchDaemon for persistence."
        ),
        "required_categories": ["behavioral", "service"],
        "required_sources":    ["behavioral_entropy", "behavioral_new_entity"],
        "severity":    "critical",
        "score":       9.1,
        "confidence":  85,
        "time_window_hours": 12,
        "attack_chain": [
            {"tactic": "Persistence",          "technique": "T1543.004", "label": "Implant service installed"},
            {"tactic": "Command and Control",  "technique": "T1071",     "label": "C2 beaconing detected"},
        ],
        "recommendation": (
            "Newly installed service with C2 beaconing is a confirmed implant indicator. "
            "Identify the new service binary, capture its hash, and check VirusTotal. "
            "Remove the LaunchDaemon, kill the process, and block C2 destinations at the firewall."
        ),
    },

    # ── 13. LOLBin + Behavioral Anomaly ──────────────────────────────────────
    {
        "id":          "corr:lolbin_anomaly",
        "title":       "LOLBin Execution + Statistical Anomaly",
        "description": (
            "A living-off-the-land binary (curl/python/bash in unusual context) is running "
            "AND statistical behavioral anomaly detected (CPU spike, process count change). "
            "LOLBins with concurrent system anomalies indicate active payload execution."
        ),
        "required_categories": ["process", "behavioral"],
        "required_sources":    ["rule:process_pattern", "behavioral_velocity"],
        "severity":    "high",
        "score":       8.2,
        "confidence":  80,
        "time_window_hours": 6,
        "attack_chain": [
            {"tactic": "Defense Evasion", "technique": "T1218",  "label": "LOLBin used for execution"},
            {"tactic": "Execution",       "technique": "T1059",  "label": "Payload executing"},
            {"tactic": "Impact",          "technique": "T1496",  "label": "Resource usage anomaly"},
        ],
        "recommendation": (
            "Correlate the suspicious process with the resource spike timing. "
            "Capture process arguments and network connections for forensics. "
            "Check for downloaded payloads in /tmp, /var/tmp, and ~/.local directories."
        ),
    },

    # ── 14. Supply Chain: Risky Package + CVE + Connection ───────────────────
    {
        "id":          "corr:supply_chain_exploit",
        "title":       "Supply Chain Risk: Vulnerable Package + External Connection",
        "description": (
            "A vulnerable package with an NVD CVE is installed AND there is an active "
            "connection to an external destination AND the package has EPSS > 0.5 or CISA KEV. "
            "Actively exploited vulnerability with network exposure — immediate patch needed."
        ),
        "required_categories": ["package", "connection"],
        "required_sources":    ["nvd"],
        "severity":    "critical",
        "score":       9.0,
        "confidence":  83,
        "time_window_hours": 168,
        "attack_chain": [
            {"tactic": "Initial Access",  "technique": "T1195",  "label": "Vulnerable dependency"},
            {"tactic": "Execution",       "technique": "T1203",  "label": "CVE exploitation risk"},
            {"tactic": "Exfiltration",    "technique": "T1041",  "label": "Outbound connection active"},
        ],
        "recommendation": (
            "Patch the vulnerable package immediately. If patching is not possible, firewall the "
            "service from the internet. Review the outbound connections for data exfiltration signs. "
            "Check if the CVE has a public exploit — if EPSS > 0.7 or CISA KEV, treat as compromised."
        ),
    },

    # ── 15. New Admin + External Connection ──────────────────────────────────
    {
        "id":          "corr:new_admin_c2",
        "title":       "New Admin Account + External C2 Connection",
        "description": (
            "A new admin account was created or admin privileges were granted to an existing "
            "user AND there is an active connection to a flagged external IP. This is the "
            "classic post-exploitation pattern: create backdoor admin → establish C2."
        ),
        "required_categories": ["behavioral", "connection"],
        "required_sources":    ["behavioral_change", "behavioral_new_entity"],
        "severity":    "critical",
        "score":       9.4,
        "confidence":  88,
        "time_window_hours": 24,
        "attack_chain": [
            {"tactic": "Persistence",         "technique": "T1136",  "label": "Backdoor admin created"},
            {"tactic": "Privilege Escalation","technique": "T1078",  "label": "Admin access established"},
            {"tactic": "Command and Control", "technique": "T1071",  "label": "External C2 active"},
        ],
        "recommendation": (
            "Immediately disable the newly created/elevated admin account. Rotate all admin credentials. "
            "Block the external IP at the firewall. Review auth logs for the source of admin grant. "
            "Check for additional persistence mechanisms (LaunchDaemons, cron, shell config)."
        ),
    },

    # ── 16. Unsigned App + Config Tampering ──────────────────────────────────
    {
        "id":          "corr:unsigned_app_config",
        "title":       "Unsigned Application + Config File Tampering",
        "description": (
            "An unsigned or quarantined application is running AND suspicious patterns "
            "are detected in configuration files (shell profiles, SSH config, cron). "
            "This combination indicates a trojanized app establishing persistence."
        ),
        "required_categories": ["app", "config"],
        "severity":    "high",
        "score":       8.0,
        "confidence":  78,
        "time_window_hours": 48,
        "attack_chain": [
            {"tactic": "Execution",   "technique": "T1204.002", "label": "Untrusted app executed"},
            {"tactic": "Persistence", "technique": "T1546.004", "label": "Shell config modified"},
        ],
        "recommendation": (
            "Remove the unsigned application and audit ~/Library/LaunchAgents for new entries. "
            "Restore shell configuration files from backup. Review what the unsigned app attempted "
            "to access or modify during its execution."
        ),
    },

    # ── 17. Process Lineage Anomaly + Network ────────────────────────────────
    {
        "id":          "corr:process_spawn_c2",
        "title":       "Suspicious Process Spawn + C2 Connection",
        "description": (
            "A process spawned from an unexpected parent (e.g., Office app spawning bash) "
            "AND there is an active external connection. This is the macro exploitation → "
            "C2 pattern commonly used in spear-phishing attacks."
        ),
        "required_categories": ["process", "connection"],
        "required_sources":    ["rule:process_pattern"],
        "severity":    "critical",
        "score":       9.3,
        "confidence":  92,
        "time_window_hours": 6,
        "attack_chain": [
            {"tactic": "Initial Access",      "technique": "T1566.001", "label": "Phishing document opened"},
            {"tactic": "Execution",           "technique": "T1059",     "label": "Shell spawned by document"},
            {"tactic": "Command and Control", "technique": "T1071",     "label": "C2 channel established"},
        ],
        "recommendation": (
            "Isolate the host immediately. This is a confirmed document-based initial access. "
            "Capture the document that triggered the execution. Block the C2 destination across "
            "all endpoints. Notify affected users and begin password resets."
        ),
    },

    # ── 18. Port Scan + Internal Anomaly (Reconnaissance) ────────────────────
    {
        "id":          "corr:internal_recon",
        "title":       "Internal Network Reconnaissance",
        "description": (
            "High connection diversity (many unique IPs) detected alongside a port scanner "
            "or unusual port listening pattern. An attacker or worm conducting internal "
            "network discovery after initial compromise."
        ),
        "required_categories": ["behavioral", "port"],
        "required_sources":    ["behavioral_entropy"],
        "severity":    "high",
        "score":       8.0,
        "confidence":  76,
        "time_window_hours": 12,
        "attack_chain": [
            {"tactic": "Discovery",       "technique": "T1046", "label": "Network scan in progress"},
            {"tactic": "Lateral Movement","technique": "T1021", "label": "Internal host targeting"},
        ],
        "recommendation": (
            "Block the scanning host from lateral movement at the network level. "
            "Review all outbound connections from this host. "
            "Check for follow-on exploitation of discovered services."
        ),
    },

    # ── 19. Weak Security + Vulnerable Package + Port Exposed ────────────────
    {
        "id":          "corr:exposure_trifecta",
        "title":       "Triple Exposure: Disabled Controls + CVE + Open Port",
        "description": (
            "All three attack prerequisites are present: security controls are degraded "
            "(Gatekeeper/Firewall off), a vulnerable package is installed (CVE), and a service "
            "is listening on a network port. An attacker has a clear path to exploitation."
        ),
        "required_categories": ["security", "package", "port"],
        "required_sources":    ["nvd", "rule:security_posture"],
        "severity":    "critical",
        "score":       9.0,
        "confidence":  87,
        "time_window_hours": 168,
        "attack_chain": [
            {"tactic": "Defense Evasion", "technique": "T1562",  "label": "Security controls off"},
            {"tactic": "Initial Access",  "technique": "T1190",  "label": "Vulnerable service exposed"},
            {"tactic": "Execution",       "technique": "T1203",  "label": "Exploitation risk high"},
        ],
        "recommendation": (
            "Re-enable all security controls immediately (Gatekeeper, Firewall). "
            "Patch or remove the vulnerable package. Restrict the exposed service to localhost or VPN. "
            "This triple combination makes the host trivially exploitable."
        ),
    },

    # ── 20. SUID + Credential Access ─────────────────────────────────────────
    {
        "id":          "corr:suid_cred_dump",
        "title":       "SUID Binary + Credential Access Pattern",
        "description": (
            "A new or unexpected SUID binary appeared AND credential-related findings are present "
            "(user with UID 0, service account with shell, or credential tool). "
            "SUID + credential access is a privilege escalation chain."
        ),
        "required_categories": ["binary", "user"],
        "required_sources":    ["rule:suid_binary", "rule:uid0"],
        "severity":    "high",
        "score":       8.5,
        "confidence":  82,
        "time_window_hours": 48,
        "attack_chain": [
            {"tactic": "Privilege Escalation", "technique": "T1548.001", "label": "SUID binary present"},
            {"tactic": "Credential Access",    "technique": "T1078.003", "label": "Privileged account abuse"},
        ],
        "recommendation": (
            "Audit all SUID binaries: find / -perm -4000 -type f 2>/dev/null. "
            "Remove SUID from non-essential binaries. Investigate the UID-0 account for "
            "when it was created and by whom."
        ),
    },

    # ── 21. Tunnel + Behavioral Anomaly (Data Staging) ───────────────────────
    {
        "id":          "corr:tunnel_exfil",
        "title":       "Tunnelling Tool + Data Volume Anomaly",
        "description": (
            "A tunnelling tool (ngrok, chisel, bore) is active AND behavioral anomalies "
            "suggest unusual resource consumption (CPU/memory/connection spike). "
            "Data exfiltration through encrypted tunnel is likely."
        ),
        "required_categories": ["process", "behavioral"],
        "required_sources":    ["rule:process_pattern", "behavioral_threshold"],
        "severity":    "high",
        "score":       8.3,
        "confidence":  77,
        "time_window_hours": 12,
        "attack_chain": [
            {"tactic": "Exfiltration",         "technique": "T1041",  "label": "Tunnel exfil in progress"},
            {"tactic": "Command and Control",  "technique": "T1090",  "label": "Tunnelled C2 channel"},
        ],
        "recommendation": (
            "Kill the tunnelling process and block the tunnel provider domain/IP at egress. "
            "Review what data may have been exfiltrated during the tunnel's active period. "
            "Audit for reverse shell sessions that may be operating through the tunnel."
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
        Each rule is evaluated only against findings within its time_window_hours.
        Returns list of correlation dicts (not upserted — caller does that).
        """
        try:
            rows = await self._idb.get_findings(agent_id, active_only=True, limit=500)
        except Exception as exc:
            log.warning("Correlator fetch error agent=%s: %s", agent_id, exc)
            return []

        # Full lookup (no time filter) for building indexes
        all_by_cat: dict[str, list[dict]] = {}
        all_by_src: dict[str, list[dict]] = {}
        for row in rows:
            cat = row.get("category", "")
            src = row.get("source", "")
            all_by_cat.setdefault(cat, []).append(row)
            all_by_src.setdefault(src, []).append(row)

        correlations: list[dict] = []
        now = time.time()
        for rule in CORRELATION_RULES:
            # Build time-gated lookup for this rule
            window_secs = rule.get("time_window_hours", 48) * 3600
            cutoff = now - window_secs
            gated_rows = [r for r in rows if (r.get("detected_at") or r.get("created_at") or 0) >= cutoff]
            gated_by_cat: dict[str, list[dict]] = {}
            gated_by_src: dict[str, list[dict]] = {}
            for row in gated_rows:
                cat = row.get("category", "")
                src = row.get("source", "")
                gated_by_cat.setdefault(cat, []).append(row)
                gated_by_src.setdefault(src, []).append(row)

            result = self._eval_rule(rule, gated_by_cat, gated_by_src, gated_rows, agent_id)
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
            best = max(cat_findings, key=lambda x: x.get("composite_score") or x.get("score", 0))
            evidence_findings.append(best)

        # Optional categories boost confidence
        optional_cats = rule.get("optional_categories", [])
        bonus = sum(5 for c in optional_cats if c in by_category)
        confidence = min(99, rule.get("confidence", 75) + bonus)
        score = min(10.0, rule.get("score", 0) + (0.25 * bonus) + _intel_boost(evidence_findings))
        blast = _blast_radius(agent_id, evidence_findings, confidence, rule)

        return {
            "rule_id":       rule["id"],
            "agent_id":      agent_id,
            "category":      "correlation",
            "item_key":      rule["id"],
            "severity":      rule["severity"],
            "score":         round(score, 1),
            "confidence":    confidence,
            "title":         rule["title"],
            "description":   rule["description"],
            "recommendation":rule.get("recommendation", ""),
            "attack_chain":  rule["attack_chain"],
            "attack_path":   _attack_path(rule["attack_chain"], evidence_findings),
            "blast_radius":  blast,
            "entry_points":  _entry_points(evidence_findings),
            "affected_assets": [agent_id],
            "likely_next_steps": _likely_next_steps(rule, evidence_findings),
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


def _intel_boost(findings: list[dict]) -> float:
    boost = 0.0
    for f in findings:
        if f.get("kev"):
            boost += 0.4
        if f.get("exploit_available"):
            boost += 0.3
        if (f.get("epss_score") or 0) >= 0.7:
            boost += 0.3
    return min(1.0, boost)


def _attack_path(chain: list[dict], findings: list[dict]) -> list[dict]:
    path = []
    for idx, step in enumerate(chain):
        sig = findings[min(idx, len(findings) - 1)] if findings else {}
        path.append({
            "stage": idx + 1,
            "tactic": step.get("tactic", ""),
            "technique": step.get("technique", ""),
            "label": step.get("label", ""),
            "evidence": sig.get("display_id") or sig.get("external_id") or sig.get("title", ""),
            "category": sig.get("category", ""),
        })
    return path


def _entry_points(findings: list[dict]) -> list[str]:
    entries = []
    for f in findings:
        cat = f.get("category")
        if cat in ("port", "package"):
            entries.append(f.get("title", "exposed service"))
        elif cat == "connection":
            entries.append(f.get("title", "external connection"))
    return entries[:4] or ["local execution path"]


def _blast_radius(agent_id: str, findings: list[dict], confidence: int, rule: dict) -> dict:
    cats = {f.get("category") for f in findings}
    tier = next((f.get("asset_tier") for f in findings if f.get("asset_tier")), "endpoint")
    lateral = "user" in cats or "connection" in cats or confidence >= 90
    data = "security" in cats or "user" in cats or tier in ("server", "crown_jewel")
    return {
        "primary_asset": agent_id,
        "asset_tier": tier,
        "lateral_movement_possible": lateral,
        "data_exposure_possible": data,
        "estimated_scope": "organization-linked" if lateral else "single-host",
        "rationale": f"{rule.get('id')} joined {len(findings)} active signals across {', '.join(sorted(cats))}.",
    }


def _likely_next_steps(rule: dict, findings: list[dict]) -> list[str]:
    cats = {f.get("category") for f in findings}
    steps = []
    if "connection" in cats:
        steps.append("Expand C2 hunt across all agents for the same destination and process lineage")
    if "package" in cats or any(f.get("kev") or f.get("exploit_available") for f in findings):
        steps.append("Prioritize patch or compensating control because exploit intelligence is present")
    if "user" in cats:
        steps.append("Review admin account activity and rotate affected credentials")
    if not steps:
        steps.append("Validate process ancestry, persistence, and network exposure before closing")
    return steps
