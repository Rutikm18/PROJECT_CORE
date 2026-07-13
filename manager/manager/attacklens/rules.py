"""
manager/manager/attacklens/rules.py — Static detection rules with confidence scoring.

Sources: SANS Internet Storm Center, Feodo Tracker, MITRE ATT&CK,
Emerging Threats, NIST NVD, public security research, LOLBAS project.

Each rule carries:
  - id         : stable rule identifier (used by confidence engine)
  - layer      : 'surface' | 'exposure' | 'execution' (ATT&CK kill-chain layer)
  - data_point : telemetry section this rule fires on
  - weight     : 0–1 how diagnostic the rule is when it fires in isolation
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
    {"id": "X-PROC-CRYPTOMINER",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)(xmrig|xmr-?stak|minergate|cpuminer|minerd|cryptonight)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Cryptominer process", "mitre": "T1496"},
    {"id": "X-PROC-MSF",
     "layer": "execution", "data_point": "processes", "weight": 0.85,
     "pattern": r"(?i)(msfconsole|msfvenom|msfd)",
     "severity": "critical", "confidence": 0.92, "dual_use": True,
     "desc": "Metasploit component", "mitre": "T1587.001"},
    {"id": "X-PROC-COBALTSTRIKE",
     "layer": "execution", "data_point": "processes", "weight": 0.95,
     "pattern": r"(?i)(cobalt.?strike|cobaltstrike|beacon\.x64|beacon\.x86)",
     "severity": "critical", "confidence": 0.98, "dual_use": False,
     "desc": "Cobalt Strike beacon", "mitre": "T1587.001"},
    {"id": "X-PROC-EMPIRE",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)(empire|starkiller|powershell.empire)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Empire C2 framework", "mitre": "T1059.001"},
    {"id": "X-PROC-MIMIKATZ",
     "layer": "execution", "data_point": "processes", "weight": 0.95,
     "pattern": r"(?i)(mimikatz|pypykatz|lsassdump|procdump.*lsass)",
     "severity": "critical", "confidence": 0.98, "dual_use": False,
     "desc": "Credential dumping tool", "mitre": "T1003"},
    {"id": "X-PROC-CREDSTEALER",
     "layer": "execution", "data_point": "processes", "weight": 0.93,
     "pattern": r"(?i)(lazagne|credstealer|credgrap)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Credential harvester", "mitre": "T1003"},
    {"id": "X-PROC-MODERN-C2",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)(sliver|havoc.?\s*c2|brute.?ratel|nighthawk)",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Modern C2 framework (Sliver/Havoc/BruteRatel)", "mitre": "T1587.001"},
    {"id": "X-PROC-REVSHELL-FW",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)(pwncat|platypus|villain\.py)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Reverse shell framework", "mitre": "T1059"},
    # ── Tunnelling / proxy (dual-use) ─────────────────────────────────────────
    {"id": "X-PROC-TUNNEL",
     "layer": "execution", "data_point": "processes", "weight": 0.60,
     "pattern": r"(?i)(ngrok|frpc?|bore\.sh|chisel|ligolo|rpivot|rathole|cloudflared.*tunnel)",
     "severity": "high", "confidence": 0.70, "dual_use": True,
     "desc": "Tunnelling / port-forward tool", "mitre": "T1090"},
    # ── Auth attack tools ─────────────────────────────────────────────────────
    {"id": "X-PROC-BRUTEFORCE",
     "layer": "execution", "data_point": "processes", "weight": 0.75,
     "pattern": r"(?i)(ncrack|hydra|medusa|thc-?hydra)\s",
     "severity": "high", "confidence": 0.85, "dual_use": True,
     "desc": "Network brute-force tool", "mitre": "T1110.001"},
    {"id": "X-PROC-PASSCRACK",
     "layer": "execution", "data_point": "processes", "weight": 0.70,
     "pattern": r"(?i)(hashcat|john.?the.?ripper|ophcrack)\s",
     "severity": "high", "confidence": 0.80, "dual_use": True,
     "desc": "Password cracking tool", "mitre": "T1110.002"},
    {"id": "X-PROC-SQLINJECT",
     "layer": "execution", "data_point": "processes", "weight": 0.72,
     "pattern": r"(?i)(sqlmap|sqli.dumper)\s",
     "severity": "high", "confidence": 0.82, "dual_use": True,
     "desc": "SQL injection tool", "mitre": "T1190"},
    # ── Scanners (dual-use, lower confidence) ─────────────────────────────────
    {"id": "X-PROC-MASSCAN",
     "layer": "execution", "data_point": "processes", "weight": 0.55,
     "pattern": r"(?i)(masscan|rustscan|zmap)\s",
     "severity": "medium", "confidence": 0.65, "dual_use": True,
     "desc": "High-speed network/port scanner", "mitre": "T1046"},
    {"id": "X-PROC-NMAP-VULN",
     "layer": "execution", "data_point": "processes", "weight": 0.58,
     "pattern": r"(?i)nmap\s+.*(--script\s*(vuln|exploit|brute)|--open)\s",
     "severity": "medium", "confidence": 0.70, "dual_use": True,
     "desc": "Nmap vulnerability/brute scan mode", "mitre": "T1046"},
    # ── Obfuscation / RCE patterns ────────────────────────────────────────────
    {"id": "X-PROC-B64-PYTHON",
     "layer": "execution", "data_point": "processes", "weight": 0.75,
     "pattern": r"(?i)python[23]?\s+-c\s+['\"].*base64",
     "severity": "high", "confidence": 0.85, "dual_use": False,
     "desc": "Python executing base64-encoded payload", "mitre": "T1027"},
    {"id": "X-PROC-B64-SHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.78,
     "pattern": r"(?i)(bash|sh|zsh)\s+-c\s+['\"].*base64.*decode",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "Shell executing base64-decoded command", "mitre": "T1027"},
    {"id": "X-PROC-PIPE-SHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.85,
     "pattern": r"(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|python)",
     "severity": "critical", "confidence": 0.93, "dual_use": False,
     "desc": "Remote code execution via pipe-to-shell", "mitre": "T1059"},
    {"id": "X-PROC-BASH-TCP",
     "layer": "execution", "data_point": "processes", "weight": 0.92,
     "pattern": r"(?i)bash\s+-i\s+>&\s*/dev/tcp/",
     "severity": "critical", "confidence": 0.97, "dual_use": False,
     "desc": "Bash TCP reverse shell", "mitre": "T1059.004"},
    {"id": "X-PROC-PY-REVSHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)python[23]?\s+-c\s+['\"]import\s+socket",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Python reverse shell", "mitre": "T1059.006"},
    # ── Living-off-the-land (LOLBin) patterns ─────────────────────────────────
    {"id": "X-PROC-DEVSHM",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)/dev/shm/",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Process running from /dev/shm (memory-only evasion)", "mitre": "T1036.005"},
    {"id": "X-PROC-TMP-RAND",
     "layer": "execution", "data_point": "processes", "weight": 0.50,
     "pattern": r"(?i)/tmp/[a-z0-9_.\-]{6,30}$",
     "severity": "medium", "confidence": 0.60, "dual_use": False,
     "desc": "Process from /tmp with random-looking name", "mitre": "T1036"},
    {"id": "X-PROC-OSASCRIPT",
     "layer": "execution", "data_point": "processes", "weight": 0.72,
     "pattern": r"(?i)osascript\s+(-e\s+['\"].*do\s+shell|.*javascript)",
     "severity": "high", "confidence": 0.82, "dual_use": False,
     "desc": "AppleScript executing shell command or JavaScript (T1059.002)", "mitre": "T1059.002"},
    {"id": "X-PROC-LAUNCHCTL-TMP",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)launchctl\s+(submit|load)\s+.*(/tmp/|/var/tmp/|/dev/shm/)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "launchctl loading service from temp/memory path", "mitre": "T1543.004"},
    {"id": "X-PROC-PERL-RUBY-EXEC",
     "layer": "execution", "data_point": "processes", "weight": 0.70,
     "pattern": r"(?i)(perl|ruby)\s+-e\s+['\"].*exec\s*\(",
     "severity": "high", "confidence": 0.80, "dual_use": False,
     "desc": "Perl/Ruby one-liner process execution", "mitre": "T1059"},
    # ── Keylogging / exfiltration ─────────────────────────────────────────────
    {"id": "X-PROC-KEYLOGGER",
     "layer": "execution", "data_point": "processes", "weight": 0.82,
     "pattern": r"(?i)(keylogger|keystroke|pynput|pynput\.keyboard|evdev.*grab)",
     "severity": "critical", "confidence": 0.90, "dual_use": False,
     "desc": "Keylogger library or process", "mitre": "T1056.001"},
    {"id": "X-PROC-DNS-TUNNEL",
     "layer": "execution", "data_point": "processes", "weight": 0.82,
     "pattern": r"(?i)(dnscat|iodine|dns2tcp|dnscrypt.*tunnel)",
     "severity": "high", "confidence": 0.90, "dual_use": False,
     "desc": "DNS tunnelling tool (C2/exfil via DNS)", "mitre": "T1071.004"},
    # ── SSH reverse tunnel / port-forward (living-off-the-land exfil/C2) ──────
    {"id": "X-PROC-SSH-REVTUNNEL",
     "layer": "execution", "data_point": "processes", "weight": 0.80,
     "pattern": r"(?i)ssh\s+.*(-[Rr]\s+\d{1,5}:|-N\s+-[Rr]|-w\s+\d+:\d+)",
     "severity": "high", "confidence": 0.85, "dual_use": True,
     "desc": "SSH reverse tunnel / port-forward (covert channel)", "mitre": "T1572"},
    # ── Socat relay / reverse shell ───────────────────────────────────────────
    {"id": "X-PROC-SOCAT-REVSHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)socat\s+.*(exec:|system:|tcp.*listen|tcp.*back)",
     "severity": "critical", "confidence": 0.92, "dual_use": False,
     "desc": "Socat relay or reverse shell (T1059 LOLBin)", "mitre": "T1059"},
    # ── mkfifo FIFO-based shell ───────────────────────────────────────────────
    {"id": "X-PROC-MKFIFO-SHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)mkfifo\s+/\w+.*&&.*cat\s+.*nc|nc.*<\s*/\w+\s*\|",
     "severity": "critical", "confidence": 0.93, "dual_use": False,
     "desc": "FIFO-based reverse shell (mkfifo + nc pattern)", "mitre": "T1059.004"},
    # ── Netcat listener / reverse shell ─────────────────────────────────────
    {"id": "X-PROC-NC-REVSHELL",
     "layer": "execution", "data_point": "processes", "weight": 0.85,
     "pattern": r"(?i)\b(nc|ncat|netcat)\b\s+.*(-e\s+/bin|-c\s+['\"]?(bash|sh|zsh)|-lvp?\s+\d{2,5})",
     "severity": "critical", "confidence": 0.90, "dual_use": False,
     "desc": "Netcat reverse shell or listener (-e shell, -c shell, -lvp)", "mitre": "T1059.004"},
    # ── LD_PRELOAD / DYLD_INSERT_LIBRARIES injection ─────────────────────────
    {"id": "X-PROC-LDPRELOAD-INJECT",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)(LD_PRELOAD|DYLD_INSERT_LIBRARIES)=(/tmp/|/dev/shm/|/var/tmp/)",
     "severity": "critical", "confidence": 0.94, "dual_use": False,
     "desc": "Library injection via LD_PRELOAD/DYLD_INSERT_LIBRARIES from temp path", "mitre": "T1574.006"},
    # ── Container escape via nsenter or docker privileged ────────────────────
    {"id": "X-PROC-CONTAINER-ESCAPE",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)(nsenter\s+--mount=.*/proc/1|docker\s+run\s+.*--privileged.*--pid=host|unshare\s+--user\s+--pid)",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "Container escape via nsenter/docker --privileged/unshare", "mitre": "T1611"},
    # ── at/batch persistence scheduling ─────────────────────────────────────
    {"id": "X-PROC-AT-SCHED",
     "layer": "execution", "data_point": "processes", "weight": 0.70,
     "pattern": r"(?i)\bat\b\s+now\s+\+|\batq\b\s+-c|\batrm\b\s+|\bbatch\b\s+.*</",
     "severity": "medium", "confidence": 0.75, "dual_use": True,
     "desc": "at/batch one-shot scheduled task (T1053.002 persistence)", "mitre": "T1053.002"},
    # ── launchctl unload of security daemons ─────────────────────────────────
    {"id": "X-PROC-LAUNCHCTL-UNLOAD-SEC",
     "layer": "execution", "data_point": "processes", "weight": 0.88,
     "pattern": r"(?i)launchctl\s+(unload|disable|kickstart\s+-k)\s+.*(security|gatekeeper|xprotect|mrt|santa|osquery)",
     "severity": "critical", "confidence": 0.93, "dual_use": False,
     "desc": "launchctl unloading/disabling a security daemon (defense evasion)", "mitre": "T1562.001"},
    # ── defaults write security bypass ───────────────────────────────────────
    {"id": "X-PROC-DEFAULTS-WRITE-BYPASS",
     "layer": "execution", "data_point": "processes", "weight": 0.82,
     "pattern": r"(?i)defaults\s+write\s+.*(LSFileQuarantineEnabled|AllowAllApps|GKAllowed|SecAssessment|GlobalPreferences.*Disabled)",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "defaults write disabling macOS security feature (Gatekeeper/quarantine bypass)", "mitre": "T1553.001"},
    # ── dscl user account manipulation ───────────────────────────────────────
    {"id": "X-PROC-DSCL-USER",
     "layer": "execution", "data_point": "processes", "weight": 0.85,
     "pattern": r"(?i)dscl\s+\.\s+(-create\s+/Users/|\s+-delete\s+/Users/|-append\s+/Groups/admin)",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "dscl creating/deleting user or adding user to admin group", "mitre": "T1136.001"},
    # ── OpenSSL decrypt / payload staging ────────────────────────────────────
    {"id": "X-PROC-OPENSSL-DECRYPT",
     "layer": "execution", "data_point": "processes", "weight": 0.75,
     "pattern": r"(?i)openssl\s+enc\s+-d\s+.*(-pass\s+|\|\s*(bash|sh|python))",
     "severity": "high", "confidence": 0.82, "dual_use": False,
     "desc": "OpenSSL decrypt piped to shell (encrypted payload staging)", "mitre": "T1027"},
    # ── dd memory/disk dump (data staging, anti-forensics) ───────────────────
    {"id": "X-PROC-DD-MEMDUMP",
     "layer": "execution", "data_point": "processes", "weight": 0.80,
     "pattern": r"(?i)dd\s+if=/dev/(mem|kmem|sda|nvme\d|disk\d)\s+of=",
     "severity": "high", "confidence": 0.85, "dual_use": False,
     "desc": "dd reading raw memory or disk (memory/disk dump for credential extraction)", "mitre": "T1003.007"},
    # ── Python/Perl/Ruby interactive PTY (common post-exploitation shell stabilization)
    {"id": "X-PROC-PTY-STABILIZE",
     "layer": "execution", "data_point": "processes", "weight": 0.78,
     "pattern": r"(?i)python[23]?\s+-c\s+['\"]import\s+pty|python[23]?\s+-c\s+['\"]import\s+os.*pty|script\s+-qc\s+/bin/bash",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "PTY stabilization (python -c 'import pty' / script) — common post-exploit shell upgrade", "mitre": "T1059.006"},
    # ── xattr quarantine removal (Gatekeeper bypass) ─────────────────────────
    {"id": "X-PROC-XATTR-QUARANTINE",
     "layer": "execution", "data_point": "processes", "weight": 0.80,
     "pattern": r"(?i)xattr\s+-r?\s*-d\s+(com\.apple\.quarantine|com\.apple\.macl)",
     "severity": "high", "confidence": 0.88, "dual_use": False,
     "desc": "xattr removing quarantine/MACL attribute (Gatekeeper bypass)", "mitre": "T1553.001"},
    # ── spctl disable (Gatekeeper master switch off) ──────────────────────────
    {"id": "X-PROC-SPCTL-DISABLE",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)spctl\s+--master-disable",
     "severity": "critical", "confidence": 0.96, "dual_use": False,
     "desc": "spctl --master-disable: Gatekeeper turned off system-wide", "mitre": "T1553.001"},
    # ── csrutil disable (SIP deactivation — requires Recovery, but flag it) ──
    {"id": "X-PROC-CSRUTIL-DISABLE",
     "layer": "execution", "data_point": "processes", "weight": 0.90,
     "pattern": r"(?i)csrutil\s+disable",
     "severity": "critical", "confidence": 0.95, "dual_use": False,
     "desc": "csrutil disable: System Integrity Protection being turned off", "mitre": "T1562.001"},
    # ── DoH-based C2 (DNS over HTTPS covert channel) ─────────────────────────
    {"id": "X-PROC-DOH-COVERT",
     "layer": "execution", "data_point": "processes", "weight": 0.75,
     "pattern": r"(?i)(curl|wget)\s+.*cloudflare-dns\.com/dns-query.*\?.*name=|dns-over-https\s+.*--type",
     "severity": "high", "confidence": 0.80, "dual_use": False,
     "desc": "DNS-over-HTTPS query with unusual name parameter (DoH covert channel)", "mitre": "T1071.004"},
]

PROCESS_RULES: list[dict] = [
    {**r, "compiled": re.compile(r["pattern"])} for r in _PROC_RULES_RAW
]

# ── Suspicious parent→child process spawn patterns ────────────────────────────
# Office/browser apps spawning shells is almost always malicious (T1203, T1566)
_PARENT_CHILD_RAW: list[dict] = [
    {
        "parent_pattern": r"(?i)(microsoft\s+word|word|pages\.app|libreoffice|soffice)",
        # \b word boundaries prevent "sh" matching inside "crash-reporter", "Shared", etc.
        "child_pattern":  r"(?i)\b(bash|sh|zsh|python|perl|ruby|osascript|curl|wget)\b",
        "severity": "critical", "confidence": 0.96,
        "desc": "Office document spawning shell/interpreter (macro exploit)", "mitre": "T1566.001",
    },
    {
        "parent_pattern": r"(?i)(safari|chrome|firefox|brave|opera|chromium|edge|zen)",
        # Must match the child PROCESS NAME, not substrings in its cmdline flags.
        # \b prevents "sh" from matching inside "--enable-crash-reporter" or
        # feature names like "SharedArrayBuffer" that appear in Chromium's argv.
        "child_pattern":  r"(?i)\b(bash|sh|zsh|python3?|perl|ruby|osascript)\b",
        "severity": "critical", "confidence": 0.95,
        "desc": "Browser spawning shell (drive-by exploit)", "mitre": "T1189",
    },
    {
        "parent_pattern": r"(?i)(microsoft\s+excel|excel|numbers\.app)",
        "child_pattern":  r"(?i)\b(bash|sh|zsh|python|perl|curl|wget|nc|ncat)\b",
        "severity": "critical", "confidence": 0.96,
        "desc": "Spreadsheet spawning shell/downloader (macro exploit)", "mitre": "T1566.001",
    },
    {
        "parent_pattern": r"(?i)(mail\.app|thunderbird|outlook|evolution)",
        "child_pattern":  r"(?i)\b(bash|sh|zsh|python3?|curl|wget)\b",
        "severity": "critical", "confidence": 0.94,
        "desc": "Email client spawning shell (phishing exploit)", "mitre": "T1566.002",
    },
    {
        "parent_pattern": r"(?i)(preview|adobe\s+acrobat|pdf\s*viewer|evince)",
        "child_pattern":  r"(?i)\b(bash|sh|zsh|python3?|osascript|curl)\b",
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
    {"pattern": re.compile(r"(?i)\b(xmrig|xmr-?stak|cpuminer|minerd|xmr|monero|cryptonight)\b|(?<!\w)miner(?!\w)"),
     "severity": "critical","desc": "Cryptominer service label"},
    {"pattern": re.compile(r"(?i)/tmp/|/dev/shm/"),
     "severity": "critical","desc": "Service binary in memory-mapped or temp path"},
    {"pattern": re.compile(r"(?i)(ngrok|frpc?|chisel|bore)"),
     "severity": "high",    "desc": "Tunnel service registered as LaunchDaemon"},
]

# ── MITRE ATT&CK technique → tactic lookup ───────────────────────────────────
MITRE_TACTIC: dict[str, str] = {
    "T1059": "Execution",       "T1059.001": "Execution",   "T1059.002": "Execution",
    "T1059.004": "Execution",   "T1059.006": "Execution",   "T1496": "Impact",
    "T1571": "C&C",             "T1090": "C&C",             "T1090.003": "C&C",
    "T1071.003": "C&C",         "T1071.004": "C&C",         "T1572": "C&C",
    "T1046": "Discovery",       "T1040": "Collection",      "T1003": "Credential Access",
    "T1003.007": "Credential Access",
    "T1110": "Credential Access","T1110.001": "Credential Access","T1110.002": "Credential Access",
    "T1027": "Defense Evasion", "T1036": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1553.001": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1543.004": "Persistence", "T1053.002": "Persistence", "T1053.003": "Persistence",
    "T1547.004": "Persistence", "T1546.004": "Persistence", "T1546.012": "Persistence",
    "T1587.001": "Resource Dev.", "T1190": "Initial Access","T1222": "Defense Evasion",
    "T1049": "Discovery",       "T1574.006": "Privilege Escalation",
    "T1548.003": "Privilege Escalation", "T1548.001": "Privilege Escalation",
    "T1055.012": "Defense Evasion", "T1014": "Defense Evasion",
    "T1611": "Privilege Escalation", "T1098.004": "Persistence",
    "T1584.007": "Resource Dev.", "T1136.001": "Persistence",
    "T1078.003": "Defense Evasion", "T1215": "Persistence",
    "T1056.001": "Collection",  "T1204.002": "Execution",
    "T1098": "Persistence",     "T1189": "Initial Access",  "T1566.001": "Initial Access",
    "T1566.002": "Initial Access",
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


# ── 7 stand-alone high-confidence rules ──────────────────────────────────────
# These promote to findings at confidence ≥ 0.95 even without cross-layer
# corroboration because they are individually catastrophic.

STANDALONE_RULES: list[dict] = [
    {
        "id":          "S-APP-MALHASH",
        "layer":       "surface",
        "data_point":  "apps",
        "severity":    "critical",
        "weight":      0.90,
        "stand_alone": True,
        "desc":        "Application binary hash matches known-malware database",
        "mitre":       "T1204.002",
        "match": lambda item: bool(item.get("malware_hash_hit") or item.get("threat_hash_match")),
    },
    {
        "id":          "S-CFG-IAM-WILDCARD",
        "layer":       "surface",
        "data_point":  "configs",
        "severity":    "critical",
        "weight":      0.88,
        "stand_alone": True,
        "desc":        "IAM policy grants wildcard (*:*) access to privileged actions",
        "mitre":       "T1098",
        "match": lambda item: (
            "*:*" in (item.get("content") or "")
            and any(k in (item.get("path") or "").lower()
                    for k in ("iam", "policy", "role", "permission"))
        ),
    },
    {
        "id":          "E-PORT-DB-EXTERNAL",
        "layer":       "exposure",
        "data_point":  "ports",
        "severity":    "critical",
        "weight":      0.85,
        "stand_alone": True,
        "desc":        "Database port (MySQL/Postgres/MongoDB/Redis/ES) bound to all interfaces",
        "mitre":       "T1190",
        "match": lambda item: (
            int(item.get("port", 0) or 0) in {3306, 5432, 27017, 6379, 9200, 5984, 1521}
            and item.get("bind_addr", item.get("addr", "")) in ("0.0.0.0", "::")
        ),
    },
    {
        "id":          "X-PROC-HOLLOWING",
        "layer":       "execution",
        "data_point":  "processes",
        "severity":    "critical",
        "weight":      0.95,
        "stand_alone": True,
        "desc":        "Process hollowing — in-memory image hash differs from on-disk binary",
        "mitre":       "T1055.012",
        "match": lambda item: (
            item.get("image_disk_sha256")
            and item.get("image_mem_sha256")
            and item["image_disk_sha256"] != item["image_mem_sha256"]
        ),
    },
    {
        "id":          "X-PROC-HIDDEN",
        "layer":       "execution",
        "data_point":  "processes",
        "severity":    "critical",
        "weight":      0.93,
        "stand_alone": True,
        "desc":        "Kernel PID list includes process absent from userspace enumeration (rootkit indicator)",
        "mitre":       "T1014",
        "match": lambda item: bool(item.get("kernel_only") or item.get("hidden_process")),
    },
    {
        "id":          "X-AR-IFEO-HIJACK",
        "layer":       "execution",
        "data_point":  "autoruns",
        "severity":    "critical",
        "weight":      0.92,
        "stand_alone": True,
        "desc":        "Image File Execution Options Debugger set to non-approved binary (IFEO hijack)",
        "mitre":       "T1546.012",
        "match": lambda item: (
            "ifeo" in (item.get("path") or item.get("label") or "").lower()
            or item.get("ifeo_hijack")
        ),
    },
    {
        "id":          "X-AR-WINLOGON-SHELL",
        "layer":       "execution",
        "data_point":  "autoruns",
        "severity":    "critical",
        "weight":      0.92,
        "stand_alone": True,
        "desc":        "Winlogon Shell value set to non-standard binary (credential harvesting)",
        "mitre":       "T1547.004",
        "match": lambda item: (
            "winlogon" in (item.get("path") or item.get("key") or "").lower()
            and item.get("program", "") not in ("explorer.exe", "", None)
        ),
    },
    # ── SSH authorized_keys modification ─────────────────────────────────────
    {
        "id":          "X-CFG-SSH-AUTHKEYS",
        "layer":       "execution",
        "data_point":  "configs",
        "severity":    "high",
        "weight":      0.88,
        "stand_alone": True,
        "desc":        "SSH authorized_keys file modified — backdoor SSH key may have been added",
        "mitre":       "T1098.004",
        "match": lambda item: (
            "authorized_keys" in (item.get("path") or "").lower()
            and item.get("content_changed", False)
        ),
    },
    # ── sudoers file modification ─────────────────────────────────────────────
    {
        "id":          "X-CFG-SUDOERS-MOD",
        "layer":       "execution",
        "data_point":  "configs",
        "severity":    "critical",
        "weight":      0.93,
        "stand_alone": True,
        "desc":        "sudoers file modified — NOPASSWD or privilege escalation rule may have been inserted",
        "mitre":       "T1548.003",
        "match": lambda item: (
            ("/etc/sudoers" in (item.get("path") or "") or "/etc/sudoers.d/" in (item.get("path") or ""))
            and item.get("content_changed", False)
        ),
    },
    # ── /etc/hosts domain redirect ────────────────────────────────────────────
    {
        "id":          "X-CFG-HOSTS-REDIRECT",
        "layer":       "surface",
        "data_point":  "configs",
        "severity":    "high",
        "weight":      0.85,
        "stand_alone": True,
        "desc":        "/etc/hosts modified with non-loopback redirect — DNS poisoning or C2 pivot",
        "mitre":       "T1584.007",
        "match": lambda item: (
            (item.get("path") or "").endswith("/etc/hosts")
            and item.get("content_changed", False)
        ),
    },
    # ── LD_PRELOAD set in process environment ─────────────────────────────────
    {
        "id":          "X-PROC-LDPRELOAD-ENV",
        "layer":       "execution",
        "data_point":  "processes",
        "severity":    "critical",
        "weight":      0.90,
        "stand_alone": True,
        "desc":        "LD_PRELOAD or DYLD_INSERT_LIBRARIES set in process environment (library hijack)",
        "mitre":       "T1574.006",
        "match": lambda item: bool(
            (item.get("env") or {}).get("LD_PRELOAD")
            or (item.get("env") or {}).get("DYLD_INSERT_LIBRARIES")
            or "LD_PRELOAD=" in (item.get("cmdline") or "")
            or "DYLD_INSERT_LIBRARIES=" in (item.get("cmdline") or "")
        ),
    },
    # ── Root crontab with suspicious command ─────────────────────────────────
    {
        "id":          "X-TASK-ROOT-CRON-MOD",
        "layer":       "execution",
        "data_point":  "tasks",
        "severity":    "high",
        "weight":      0.85,
        "stand_alone": True,
        "desc":        "Root crontab entry with suspicious command (download/exec/shell)",
        "mitre":       "T1053.003",
        "match": lambda item: (
            str(item.get("user", "")).lower() in ("root", "0")
            and item.get("is_new", False)
            and any(
                sus in (item.get("command") or "").lower()
                for sus in ("/tmp/", "/dev/shm/", "curl ", "wget ", "python ", "bash -i", "nc ", "bash -c ")
            )
        ),
    },
]


def all_rules_by_data_point() -> dict[str, list[dict]]:
    """Group every rule (existing + stand-alone) by data_point for the engine dispatcher."""
    from collections import defaultdict
    out: dict[str, list] = defaultdict(list)
    for rule_list in (PROCESS_RULES, STANDALONE_RULES):
        for r in rule_list:
            dp = r.get("data_point", "")
            if dp:
                out[dp].append(r)
    return dict(out)
