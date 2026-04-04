"""
manager/manager/threat/rules.py — Static detection rules.

Sources: SANS Internet Storm Center, Feodo Tracker, MITRE ATT&CK,
Emerging Threats, NIST NVD, public security research.
"""
from __future__ import annotations
import re

# ── Known malicious / high-risk ports ────────────────────────────────────────
# Keyed by port number; value contains severity, description, MITRE technique.
MALICIOUS_PORTS: dict[int, dict] = {
    # Metasploit / exploit frameworks
    4444:  {"severity": "critical", "desc": "Metasploit default listener",           "mitre": "T1571"},
    4445:  {"severity": "high",     "desc": "Common RAT/backdoor alternate",         "mitre": "T1571"},
    # Hacker-culture / RATs
    1337:  {"severity": "high",     "desc": "L33t/RAT common port",                  "mitre": "T1571"},
    31337: {"severity": "high",     "desc": "Back Orifice / elite port",             "mitre": "T1571"},
    12345: {"severity": "medium",   "desc": "NetBus trojan",                         "mitre": "T1571"},
    27374: {"severity": "medium",   "desc": "Sub7 trojan",                           "mitre": "T1571"},
    65535: {"severity": "high",     "desc": "Common trojan / overflow port",         "mitre": "T1571"},
    65533: {"severity": "high",     "desc": "Common backdoor port",                  "mitre": "T1571"},
    # Tor anonymisation
    9001:  {"severity": "medium",   "desc": "Tor relay default",                     "mitre": "T1090.003"},
    9030:  {"severity": "medium",   "desc": "Tor directory authority",               "mitre": "T1090.003"},
    9050:  {"severity": "medium",   "desc": "Tor SOCKS proxy",                       "mitre": "T1090.003"},
    9150:  {"severity": "medium",   "desc": "Tor Browser SOCKS",                     "mitre": "T1090.003"},
    # IRC / Botnet C2
    6666:  {"severity": "high",     "desc": "IRC C2 — DarkComet / Gh0st RAT",       "mitre": "T1071.003"},
    6667:  {"severity": "high",     "desc": "IRC default — botnet C2",              "mitre": "T1071.003"},
    6668:  {"severity": "high",     "desc": "IRC variant — botnet C2",              "mitre": "T1071.003"},
    6669:  {"severity": "high",     "desc": "IRC variant — botnet C2",              "mitre": "T1071.003"},
    6697:  {"severity": "medium",   "desc": "IRC over TLS — encrypted C2",          "mitre": "T1071.003"},
    # Cryptominer stratum protocol
    3333:  {"severity": "high",     "desc": "Cryptominer stratum pool",              "mitre": "T1496"},
    5555:  {"severity": "medium",   "desc": "Cryptominer / ADB exploit",             "mitre": "T1496"},
    7777:  {"severity": "medium",   "desc": "Cryptominer pool variant",              "mitre": "T1496"},
    8888:  {"severity": "low",      "desc": "Cryptominer / Jupyter (dual-use)",      "mitre": "T1496"},
    14444: {"severity": "high",     "desc": "Monero (XMR) mining pool",             "mitre": "T1496"},
    14433: {"severity": "high",     "desc": "Monero mining pool TLS",               "mitre": "T1496"},
    45700: {"severity": "high",     "desc": "XMRig default mining port",            "mitre": "T1496"},
    3032:  {"severity": "medium",   "desc": "Cryptominer stratum variant",           "mitre": "T1496"},
    # Tunnelling / reverse proxies
    4443:  {"severity": "low",      "desc": "Alternate HTTPS / C2 tunnel",           "mitre": "T1090"},
    8008:  {"severity": "low",      "desc": "Alt HTTP / Cobalt Strike beacon",       "mitre": "T1090"},
    50050: {"severity": "critical", "desc": "Cobalt Strike team server default",     "mitre": "T1587.001"},
}

# ── Suspicious process name / cmdline patterns (compiled regex) ───────────────
_PROC_RULES_RAW: list[dict] = [
    {"pattern": r"(?i)(xmrig|xmr-?stak|minergate|cpuminer|minerd|cryptonight)",
     "severity": "critical", "desc": "Cryptominer process", "mitre": "T1496"},
    {"pattern": r"(?i)(msfconsole|msfvenom|msfd)",
     "severity": "critical", "desc": "Metasploit component", "mitre": "T1587.001"},
    {"pattern": r"(?i)(cobalt.?strike|cobaltstrike|beacon\.x64|beacon\.x86)",
     "severity": "critical", "desc": "Cobalt Strike beacon", "mitre": "T1587.001"},
    {"pattern": r"(?i)(empire|starkiller|powershell.empire)",
     "severity": "critical", "desc": "Empire C2 framework", "mitre": "T1059.001"},
    {"pattern": r"(?i)(mimikatz|pypykatz|lsassdump|procdump.*lsass)",
     "severity": "critical", "desc": "Credential dumping tool", "mitre": "T1003"},
    {"pattern": r"(?i)(lazagne|credstealer|credgrap)",
     "severity": "critical", "desc": "Credential harvester", "mitre": "T1003"},
    {"pattern": r"(?i)(ngrok|frpc?|bore\.sh|chisel|ligolo|rpivot)",
     "severity": "high",     "desc": "Tunnelling / port-forward tool", "mitre": "T1090"},
    {"pattern": r"(?i)(ncrack|hydra|medusa|thc-?hydra)\s",
     "severity": "high",     "desc": "Network brute-force tool", "mitre": "T1110.001"},
    {"pattern": r"(?i)(hashcat|john.?the.?ripper|ophcrack)\s",
     "severity": "high",     "desc": "Password cracking tool", "mitre": "T1110.002"},
    {"pattern": r"(?i)(sqlmap|sqli.dumper)\s",
     "severity": "high",     "desc": "SQL injection tool", "mitre": "T1190"},
    {"pattern": r"(?i)(masscan|nmap|zmap|rustscan)\s",
     "severity": "medium",   "desc": "Network/port scanner", "mitre": "T1046"},
    {"pattern": r"(?i)python[23]?\s+-c\s+['\"].*base64",
     "severity": "high",     "desc": "Python executing base64-encoded payload", "mitre": "T1027"},
    {"pattern": r"(?i)(bash|sh|zsh)\s+-c\s+['\"].*base64",
     "severity": "high",     "desc": "Shell executing base64-encoded command", "mitre": "T1027"},
    {"pattern": r"(?i)/dev/shm/",
     "severity": "critical", "desc": "Process running from /dev/shm (memory-only evasion)", "mitre": "T1036.005"},
    {"pattern": r"(?i)/tmp/[a-z0-9_-]{6,20}$",
     "severity": "medium",   "desc": "Process from /tmp with random-looking name", "mitre": "T1036"},
    {"pattern": r"(?i)(curl|wget)\s+.*\|\s*(bash|sh|python)",
     "severity": "critical", "desc": "Remote code execution via pipe-to-shell", "mitre": "T1059"},
]

PROCESS_RULES: list[dict] = [
    {**r, "compiled": re.compile(r["pattern"])} for r in _PROC_RULES_RAW
]

# ── Suspicious process executable paths ──────────────────────────────────────
SUSPICIOUS_PATHS: list[dict] = [
    {"pattern": re.compile(r"^/tmp/"),       "severity": "high",     "desc": "Binary executing from /tmp"},
    {"pattern": re.compile(r"^/dev/shm/"),   "severity": "critical", "desc": "Binary executing from /dev/shm"},
    {"pattern": re.compile(r"^/var/tmp/"),   "severity": "high",     "desc": "Binary executing from /var/tmp"},
    {"pattern": re.compile(r"/\.\./"),       "severity": "high",     "desc": "Path traversal in executable path"},
    {"pattern": re.compile(r"^/Users/[^/]+/Downloads/"),
     "severity": "medium",  "desc": "Binary running from Downloads folder"},
]

# ── Config / script content suspicious patterns ───────────────────────────────
_CONFIG_RULES_RAW: list[dict] = [
    {"pattern": r"(?i)(curl|wget)\s+.*\|\s*(bash|sh|python|perl|ruby)",
     "severity": "critical", "desc": "Pipe-to-shell remote code execution", "mitre": "T1059"},
    {"pattern": r"(?i)eval\s*\(\s*(base64_decode|atob|Buffer\.from|__import__)",
     "severity": "critical", "desc": "Obfuscated eval execution", "mitre": "T1027"},
    {"pattern": r"(?i)osascript\s+-e",
     "severity": "medium",   "desc": "AppleScript execution (possible persistence)", "mitre": "T1059.002"},
    {"pattern": r"(?i)python[23]?\s+-c\s+['\"]import socket",
     "severity": "high",     "desc": "Python reverse shell pattern", "mitre": "T1059.006"},
    {"pattern": r"(?i)(launchctl)\s+(load|bootstrap|enable)",
     "severity": "low",      "desc": "LaunchDaemon loading in config/script", "mitre": "T1543.004"},
    {"pattern": r"(?i)chmod\s+[0-9]*7[0-9]*\s+",
     "severity": "low",      "desc": "World-writable chmod", "mitre": "T1222"},
    {"pattern": r"(?i)0\.0\.0\.0:([0-9]+)",
     "severity": "low",      "desc": "Binding to all interfaces in config", "mitre": "T1049"},
]

CONFIG_RULES: list[dict] = [
    {**r, "compiled": re.compile(r["pattern"])} for r in _CONFIG_RULES_RAW
]

# ── Risky packages / apps (manager / brew / pip / npm / gem) ─────────────────
RISKY_PACKAGES: dict[str, dict] = {
    "xmrig":        {"severity": "critical", "desc": "Monero CPU miner",              "mitre": "T1496"},
    "xmr-stak":     {"severity": "critical", "desc": "Monero miner",                  "mitre": "T1496"},
    "cpuminer":     {"severity": "critical", "desc": "Generic CPU miner",             "mitre": "T1496"},
    "metasploit":   {"severity": "critical", "desc": "Exploit framework",             "mitre": "T1587.001"},
    "msfconsole":   {"severity": "critical", "desc": "Metasploit console",            "mitre": "T1587.001"},
    "mimikatz":     {"severity": "critical", "desc": "Credential dumper",             "mitre": "T1003"},
    "cobalt-strike":{"severity": "critical", "desc": "Commercial C2 framework",       "mitre": "T1587.001"},
    "john":         {"severity": "high",     "desc": "Password cracker",              "mitre": "T1110.002"},
    "hashcat":      {"severity": "high",     "desc": "GPU password cracker",          "mitre": "T1110.002"},
    "hydra":        {"severity": "high",     "desc": "Network brute-forcer",          "mitre": "T1110.001"},
    "ncrack":       {"severity": "high",     "desc": "Network auth cracker",          "mitre": "T1110.001"},
    "aircrack-ng":  {"severity": "high",     "desc": "WiFi handshake cracker",        "mitre": "T1110"},
    "sqlmap":       {"severity": "high",     "desc": "SQL injection framework",       "mitre": "T1190"},
    "masscan":      {"severity": "medium",   "desc": "Mass port scanner",             "mitre": "T1046"},
    "nmap":         {"severity": "low",      "desc": "Network scanner (dual-use)",    "mitre": "T1046"},
    "rustscan":     {"severity": "medium",   "desc": "Fast port scanner",             "mitre": "T1046"},
    "ngrok":        {"severity": "medium",   "desc": "Tunnel service (dual-use)",     "mitre": "T1090"},
    "frp":          {"severity": "medium",   "desc": "Fast reverse proxy",            "mitre": "T1090"},
    "chisel":       {"severity": "high",     "desc": "TCP/UDP tunnel over HTTP",      "mitre": "T1090"},
    "tor":          {"severity": "medium",   "desc": "Anonymisation network",         "mitre": "T1090.003"},
    "proxychains":  {"severity": "medium",   "desc": "Proxy chaining tool",           "mitre": "T1090"},
    "tcpdump":      {"severity": "low",      "desc": "Packet capture (dual-use)",     "mitre": "T1040"},
    "wireshark":    {"severity": "low",      "desc": "Packet analyser (dual-use)",    "mitre": "T1040"},
    "lazagne":      {"severity": "critical", "desc": "Multi-platform cred stealer",   "mitre": "T1003"},
    "empire":       {"severity": "critical", "desc": "PowerShell/Python C2",          "mitre": "T1059.001"},
}

# ── Suspicious LaunchDaemon label patterns ────────────────────────────────────
SUSPICIOUS_SERVICE_PATTERNS: list[dict] = [
    {"pattern": re.compile(r"(?i)com\.(update|sync|helper|agent)\d{6,}"),
     "severity": "medium", "desc": "LaunchDaemon with numeric suffix (common malware pattern)"},
    {"pattern": re.compile(r"(?i)(miner|crypto|xmr|monero)"),
     "severity": "critical","desc": "Cryptominer service label"},
    {"pattern": re.compile(r"(?i)/tmp/|/dev/shm/"),
     "severity": "critical","desc": "Service binary in memory-mapped or temp path"},
    {"pattern": re.compile(r"(?i)(ngrok|frpc?|chisel|bore)"),
     "severity": "high",    "desc": "Tunnel service registered as LaunchDaemon"},
]

# ── MITRE ATT&CK technique → tactic lookup ───────────────────────────────────
MITRE_TACTIC: dict[str, str] = {
    "T1059": "Execution",       "T1059.001": "Execution",   "T1059.002": "Execution",
    "T1059.006": "Execution",   "T1496": "Impact",          "T1571": "C&C",
    "T1090": "C&C",             "T1090.003": "C&C",         "T1071.003": "C&C",
    "T1046": "Discovery",       "T1040": "Collection",      "T1003": "Credential Access",
    "T1110": "Credential Access","T1110.001": "Credential Access","T1110.002": "Credential Access",
    "T1027": "Defense Evasion", "T1036": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1543.004": "Persistence", "T1053.003": "Persistence", "T1587.001": "Resource Dev.",
    "T1190": "Initial Access",  "T1222": "Defense Evasion", "T1049": "Discovery",
}

SEVERITY_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.5,
}

def get_tactic(technique: str) -> str:
    return MITRE_TACTIC.get(technique, "")

def severity_to_score(severity: str) -> float:
    return SEVERITY_SCORE.get(severity.lower(), 0.5)
