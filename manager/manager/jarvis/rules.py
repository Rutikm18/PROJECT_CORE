"""
manager/manager/jarvis/rules.py — Static detection rules with confidence scoring.

Sources: SANS Internet Storm Center, Feodo Tracker, MITRE ATT&CK,
Emerging Threats, NIST NVD, public security research, LOLBAS project.

Each rule carries:
  - confidence : base confidence 0.0–1.0 (high = very few false positives)
  - dual_use   : True if tool is legitimately used by sysadmins/pentesters
  - severity   : critical / high / medium / low / info
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
    # ── Confirmed offensive tools ─────────────────────────────────────────────
    {"pattern": r"(?i)(xmrig|xmr-?stak|minergate|cpuminer|minerd|cryptonight)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Cryptominer process", "mitre": "T1496"},
    {"pattern": r"(?i)(msfconsole|msfvenom|msfd)",
     "severity": "critical", "confidence": 0.92, "dual_use": True,
     "desc": "Metasploit component", "mitre": "T1587.001"},
    {"pattern": r"(?i)(cobalt.?strike|cobaltstrike|beacon\.x64|beacon\.x86)",
     "severity": "critical", "confidence": 0.98, "dual_use": False,
     "desc": "Cobalt Strike beacon", "mitre": "T1587.001"},
    {"pattern": r"(?i)(empire|starkiller|powershell.empire)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Empire C2 framework", "mitre": "T1059.001"},
    {"pattern": r"(?i)(mimikatz|pypykatz|lsassdump|procdump.*lsass)",
     "severity": "critical", "confidence": 0.98, "dual_use": False,
     "desc": "Credential dumping tool", "mitre": "T1003"},
    {"pattern": r"(?i)(lazagne|credstealer|credgrap)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Credential harvester", "mitre": "T1003"},
    {"pattern": r"(?i)(sliver|havoc.?\s*c2|brute.?ratel|nighthawk)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Modern C2 framework (Sliver/Havoc/BruteRatel)", "mitre": "T1587.001"},
    {"pattern": r"(?i)(pwncat|platypus|villain\.py)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Reverse shell framework", "mitre": "T1059"},
    # ── Tunnelling / proxy (dual-use) ─────────────────────────────────────────
    {"pattern": r"(?i)(ngrok|frpc?|bore\.sh|chisel|ligolo|rpivot|rathole|cloudflared.*tunnel)",
     "severity": "high", "confidence": 0.70, "dual_use": True,
     "desc": "Tunnelling / port-forward tool", "mitre": "T1090"},
    # ── Auth attack tools ─────────────────────────────────────────────────────
    {"pattern": r"(?i)(ncrack|hydra|medusa|thc-?hydra)\s",
     "severity": "high", "confidence": 0.85, "dual_use": True,
     "desc": "Network brute-force tool", "mitre": "T1110.001"},
    {"pattern": r"(?i)(hashcat|john.?the.?ripper|ophcrack)\s",
     "severity": "high", "confidence": 0.80, "dual_use": True,
     "desc": "Password cracking tool", "mitre": "T1110.002"},
    {"pattern": r"(?i)(sqlmap|sqli.dumper)\s",
     "severity": "high", "confidence": 0.82, "dual_use": True,
     "desc": "SQL injection tool", "mitre": "T1190"},
    # ── Scanners (dual-use, lower confidence) ─────────────────────────────────
    {"pattern": r"(?i)(masscan|rustscan|zmap)\s",
     "severity": "medium", "confidence": 0.65, "dual_use": True,
     "desc": "High-speed network/port scanner", "mitre": "T1046"},
    {"pattern": r"(?i)nmap\s+.*(--script\s*(vuln|exploit|brute)|--open)\s",
     "severity": "medium", "confidence": 0.70, "dual_use": True,
     "desc": "Nmap vulnerability/brute scan mode", "mitre": "T1046"},
    # ── Obfuscation / RCE patterns ────────────────────────────────────────────
    {"pattern": r"(?i)python[23]?\s+-c\s+['\"].*base64",
     "severity": "high", "confidence": 0.85, "dual_use": False,
     "desc": "Python executing base64-encoded payload", "mitre": "T1027"},
    {"pattern": r"(?i)(bash|sh|zsh)\s+-c\s+['\"].*base64.*decode",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "Shell executing base64-decoded command", "mitre": "T1027"},
    {"pattern": r"(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|python)",
     "severity": "critical", "confidence": 0.93, "dual_use": False,
     "desc": "Remote code execution via pipe-to-shell", "mitre": "T1059"},
    {"pattern": r"(?i)bash\s+-i\s+>&\s*/dev/tcp/",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Bash TCP reverse shell", "mitre": "T1059.004"},
    {"pattern": r"(?i)python[23]?\s+-c\s+['\"]import\s+socket",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Python reverse shell", "mitre": "T1059.006"},
    # ── Living-off-the-land (LOLBin) patterns ─────────────────────────────────
    {"pattern": r"(?i)/dev/shm/",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Process running from /dev/shm (memory-only evasion)", "mitre": "T1036.005"},
    {"pattern": r"(?i)/tmp/[a-z0-9_.\-]{6,30}$",
     "severity": "medium", "confidence": 0.60, "dual_use": False,
     "desc": "Process from /tmp with random-looking name", "mitre": "T1036"},
    {"pattern": r"(?i)osascript\s+(-e\s+['\"].*do\s+shell|.*javascript)",
     "severity": "high", "confidence": 0.82, "dual_use": False,
     "desc": "AppleScript executing shell command or JavaScript (T1059.002)", "mitre": "T1059.002"},
    {"pattern": r"(?i)launchctl\s+(submit|load)\s+.*(/tmp/|/var/tmp/|/dev/shm/)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "launchctl loading service from temp/memory path", "mitre": "T1543.004"},
    {"pattern": r"(?i)(perl|ruby)\s+-e\s+['\"].*exec\s*\(",
     "severity": "high", "confidence": 0.80, "dual_use": False,
     "desc": "Perl/Ruby one-liner process execution", "mitre": "T1059"},
    # ── Keylogging / exfiltration ─────────────────────────────────────────────
    {"pattern": r"(?i)(keylogger|keystroke|pynput|pynput\.keyboard|evdev.*grab)",
     "severity": "critical", "confidence": 0.90, "dual_use": False,
     "desc": "Keylogger library or process", "mitre": "T1056.001"},
    {"pattern": r"(?i)(dnscat|iodine|dns2tcp|dnscrypt.*tunnel)",
     "severity": "high", "confidence": 0.90, "dual_use": False,
     "desc": "DNS tunnelling tool (C2/exfil via DNS)", "mitre": "T1071.004"},
]

PROCESS_RULES: list[dict] = [
    {**r, "compiled": re.compile(r["pattern"])} for r in _PROC_RULES_RAW
]

# ── Suspicious parent→child process spawn patterns ────────────────────────────
# Office/browser apps spawning shells is almost always malicious (T1203, T1566)
_PARENT_CHILD_RAW: list[dict] = [
    {
        "parent_pattern": r"(?i)(microsoft\s+word|word|pages\.app|libreoffice|soffice)",
        "child_pattern":  r"(?i)(bash|sh|zsh|python|perl|ruby|osascript|curl|wget)",
        "severity": "critical", "confidence": 0.96,
        "desc": "Office document spawning shell/interpreter (macro exploit)", "mitre": "T1566.001",
    },
    {
        "parent_pattern": r"(?i)(safari|chrome|firefox|brave|opera|chromium|edge)",
        "child_pattern":  r"(?i)(bash|sh|zsh|python3?|perl|ruby|osascript)",
        "severity": "critical", "confidence": 0.95,
        "desc": "Browser spawning shell (drive-by exploit)", "mitre": "T1189",
    },
    {
        "parent_pattern": r"(?i)(microsoft\s+excel|excel|numbers\.app)",
        "child_pattern":  r"(?i)(bash|sh|zsh|python|perl|curl|wget|nc|ncat)",
        "severity": "critical", "confidence": 0.96,
        "desc": "Spreadsheet spawning shell/downloader (macro exploit)", "mitre": "T1566.001",
    },
    {
        "parent_pattern": r"(?i)(mail\.app|thunderbird|outlook|evolution)",
        "child_pattern":  r"(?i)(bash|sh|zsh|python3?|curl|wget|open\s+-a)",
        "severity": "critical", "confidence": 0.94,
        "desc": "Email client spawning shell (phishing exploit)", "mitre": "T1566.002",
    },
    {
        "parent_pattern": r"(?i)(preview|adobe\s+acrobat|pdf\s*viewer|evince)",
        "child_pattern":  r"(?i)(bash|sh|zsh|python3?|osascript|curl)",
        "severity": "critical", "confidence": 0.95,
        "desc": "PDF viewer spawning shell (malicious PDF exploit)", "mitre": "T1566.001",
    },
]

PARENT_CHILD_RULES: list[dict] = [
    {**r,
     "parent_re": re.compile(r["parent_pattern"]),
     "child_re":  re.compile(r["child_pattern"])}
    for r in _PARENT_CHILD_RAW
]

# ── Obfuscation / encoding detection patterns ─────────────────────────────────
_OBFUSCATION_RAW: list[dict] = [
    {
        "pattern": r"(?i)(eval\s*\(|exec\s*\()\s*(base64|atob|Buffer\.from|__import__)",
        "severity": "critical", "confidence": 0.92,
        "desc": "Eval of encoded/obfuscated payload", "mitre": "T1027",
    },
    {
        "pattern": r"(?:[A-Za-z0-9+/]{60,}={0,2})",   # Long base64 blob
        "severity": "medium", "confidence": 0.55,
        "desc": "Long base64-encoded blob (possible obfuscated payload)", "mitre": "T1027",
    },
    {
        "pattern": r"(?i)\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){15,}",  # Hex shellcode
        "severity": "high", "confidence": 0.80,
        "desc": "Hex-encoded string (possible shellcode)", "mitre": "T1027",
    },
    {
        "pattern": r"(?i)(fromcharcode|charCodeAt|String\.fromCharCode)",
        "severity": "medium", "confidence": 0.65,
        "desc": "Character-code obfuscation (JS/JScript)", "mitre": "T1027",
    },
    {
        "pattern": r"(?i)IEX\s*\(|Invoke-Expression",
        "severity": "high", "confidence": 0.88,
        "desc": "PowerShell IEX / Invoke-Expression (obfuscated exec)", "mitre": "T1059.001",
    },
]

OBFUSCATION_RULES: list[dict] = [
    {**r, "compiled": re.compile(r["pattern"])} for r in _OBFUSCATION_RAW
]

# ── DNS / beacon suspicious patterns ─────────────────────────────────────────
BEACON_REGEX = re.compile(
    r"(?i)([a-z0-9]{20,}\.[a-z]{2,6}$|"     # long random subdomain
    r"[a-z0-9]{8,}\.(top|xyz|tk|ml|ga|cf|gq|pw|click|download|loan|online|site|tech|bid|win)$)"
)

# Entropy threshold for DNS label (high entropy = DGA / beaconing)
BEACON_ENTROPY_THRESHOLD = 3.8  # bits per character

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
