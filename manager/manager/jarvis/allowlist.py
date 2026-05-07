"""
manager/manager/jarvis/allowlist.py — Context-aware allowlist for FP suppression.

Philosophy:
  - Never silently drop findings — reduce severity to 'info' or suppress via flag
  - Apple system binaries: always safe (path + name checked)
  - Dual-use security tools: reduce severity cap + add context note
  - Known-good parent→child pairs: suppress child when parent is trusted IDE/shell
  - Trusted CDN/cloud IP ranges: don't flag connections to Apple, Cloudflare, Google
  - Process lineage: suspicious parent spawning trusted child is still suspicious
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

# ── Apple / macOS system process names ───────────────────────────────────────
APPLE_SYSTEM_PROCS: frozenset[str] = frozenset({
    "launchd", "kernel_task", "WindowServer", "mds", "mds_stores",
    "mdworker_shared", "mdworker", "Spotlight", "coreaudiod", "configd",
    "notifyd", "syslogd", "diskarbitrationd", "fseventsd", "kextd",
    "loginwindow", "securityd", "cfprefsd", "UserEventAgent",
    "nsurlsessiond", "nsurlstoraged", "secd", "trustd", "syspolicyd",
    "amfid", "bluetoothd", "powerd", "mDNSResponder", "SystemUIServer",
    "Finder", "Dock", "ControlStrip", "AirPlayXPCHelper",
    "com.apple.WebKit.Networking", "com.apple.WebKit.WebContent",
    "commerce", "accountsd", "cloudd", "bird", "diagnosticd", "logd",
    "opendirectoryd", "sharingd", "identityservicesd", "lsd", "coreduetd",
    "rapportd", "imagent", "apsd", "symptomsd", "audiomxd", "audioanalyticsd",
    "AirPlayXPCHelper", "AppleIDAuthAgent", "ATSServer", "autofsd",
    "AutoFillAgentService", "BaseBoardManagementController", "com.apple.audio",
    "com.apple.icloud", "com.apple.media", "ctkd", "dbexecutor",
    "endpointsecurityd", "espd", "IMDPersistenceAgent", "mdmclient",
    "osqueryd", "auditd", "sysmond", "sudo", "su", "sshd-keygen-wrapper",
    "installd", "softwareupdate", "storedownloadd", "storeaccountd",
    "CoreServicesUIAgent", "helpd", "iconservicesagent",
})

# ── Apple-signed path prefixes — processes from these are generally safe ──────
APPLE_SYSTEM_PATH_PREFIXES: tuple[str, ...] = (
    "/System/Library/",
    "/System/Applications/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
    "/Library/Developer/",
)

# ── Dual-use security / dev tools ─────────────────────────────────────────────
# These are legitimately used by pentesters, sysadmins, and developers.
# We still emit findings but cap the severity and add context note.
DUAL_USE_TOOLS: dict[str, dict] = {
    "nmap":        {"severity_cap": "low",    "context": "Network scanner — legitimate for IT/security work"},
    "masscan":     {"severity_cap": "medium", "context": "Port scanner — legitimate for asset discovery"},
    "rustscan":    {"severity_cap": "medium", "context": "Fast port scanner — legitimate for security testing"},
    "zmap":        {"severity_cap": "medium", "context": "Internet scanner — legitimate for research/security"},
    "wireshark":   {"severity_cap": "low",    "context": "Packet analyser — legitimate for network debugging"},
    "tshark":      {"severity_cap": "low",    "context": "CLI packet analyser — legitimate for network debugging"},
    "tcpdump":     {"severity_cap": "low",    "context": "Packet capture — legitimate for network debugging"},
    "ngrok":       {"severity_cap": "medium", "context": "Tunnelling service — legitimate for dev/demo environments"},
    "frp":         {"severity_cap": "medium", "context": "Reverse proxy — legitimate for dev environments"},
    "tor":         {"severity_cap": "medium", "context": "Anonymisation — may be legitimate for privacy research"},
    "john":        {"severity_cap": "medium", "context": "Password cracker — legitimate for security assessment"},
    "hashcat":     {"severity_cap": "medium", "context": "Password cracker — legitimate for security assessment"},
    "hydra":       {"severity_cap": "medium", "context": "Auth brute-forcer — legitimate for security assessment"},
    "ncrack":      {"severity_cap": "medium", "context": "Auth tester — legitimate for security assessment"},
    "proxychains": {"severity_cap": "low",    "context": "Proxy chaining — common in pentesting / dev"},
    "sqlmap":      {"severity_cap": "medium", "context": "SQL injection tester — legitimate for security assessment"},
    "aircrack-ng": {"severity_cap": "medium", "context": "WiFi analysis — legitimate for security assessment"},
    "metasploit":  {"severity_cap": "high",   "context": "Exploit framework — review authorisation before flagging critical"},
    "msfconsole":  {"severity_cap": "high",   "context": "Metasploit console — review authorisation before flagging critical"},
}

# ── Known-good parent → child pairs ───────────────────────────────────────────
# If the parent process is one of these IDE/editors/shells, the child is expected.
BENIGN_PARENT_CHILD: dict[str, frozenset] = {
    "Xcode":         frozenset({"lldb", "gcc", "clang", "swiftc", "swift", "python3", "ruby", "make"}),
    "Terminal":      frozenset({"bash", "zsh", "fish", "python3", "ruby", "perl", "node", "ssh", "vim", "nano"}),
    "iTerm2":        frozenset({"bash", "zsh", "fish", "python3", "ruby", "perl", "node", "ssh", "vim"}),
    "Hyper":         frozenset({"bash", "zsh", "fish", "python3", "node", "ssh"}),
    "Code Helper":   frozenset({"node", "python3", "git", "npm", "yarn", "cargo", "rustc", "bash", "zsh"}),
    "electron":      frozenset({"node", "python3", "git", "npm", "bash"}),
    "PyCharm":       frozenset({"python3", "python", "pip", "pipenv", "poetry", "pytest"}),
    "IntelliJ IDEA": frozenset({"java", "mvn", "gradle", "kotlin"}),
    "GoLand":        frozenset({"go", "dlv", "bash"}),
    "DataGrip":      frozenset({"psql", "mysql", "sqlite3"}),
    "brew":          frozenset({"ruby", "curl", "git", "tar", "gzip", "make", "cmake"}),
    "Homebrew":      frozenset({"curl", "git", "ruby", "bash", "tar", "gzip", "make"}),
    "jenkins":       frozenset({"mvn", "gradle", "npm", "python3", "docker", "bash", "sh"}),
    "Ansible":       frozenset({"python3", "ssh", "bash", "sh"}),
    "git":           frozenset({"ssh", "bash", "sh", "diff", "less"}),
    "npm":           frozenset({"node", "bash", "sh", "python3"}),
    "pip3":          frozenset({"python3", "python", "bash"}),
    "cargo":         frozenset({"rustc", "gcc", "clang", "bash"}),
}

# ── Suspicious parent processes (should NOT spawn shells/interpreters) ─────────
# Office apps / browsers spawning command interpreters = strong attack signal
SUSPICIOUS_PARENTS: frozenset[str] = frozenset({
    # Office apps
    "Microsoft Word", "Word", "WINWORD",
    "Microsoft Excel", "Excel", "EXCEL",
    "Microsoft PowerPoint", "PowerPoint",
    "Microsoft Outlook", "Outlook",
    "LibreOffice", "soffice",
    # Browsers
    "Safari", "Google Chrome", "Chrome", "Firefox", "Brave",
    "Opera", "Edge", "Chromium",
    # PDF viewers
    "Preview", "Adobe Acrobat",
    # Email clients
    "Mail", "Thunderbird",
    # Media
    "VLC", "QuickTime Player",
})

# Child process types that are suspicious if spawned from SUSPICIOUS_PARENTS
SHELL_INTERPRETERS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "fish", "ksh", "tcsh",
    "python", "python2", "python3",
    "ruby", "perl", "php", "node", "nodejs",
    "powershell", "pwsh",
    "osascript",
    "cmd",
})

# ── Trusted network CIDR ranges ───────────────────────────────────────────────
_TRUSTED_CIDRS_RAW: list[str] = [
    # Apple
    "17.0.0.0/8",
    # Cloudflare
    "104.16.0.0/13", "104.24.0.0/14", "173.245.48.0/20",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "162.158.0.0/15", "198.41.128.0/17", "197.234.240.0/22",
    "190.93.240.0/20", "188.114.96.0/20", "141.101.64.0/18",
    "108.162.192.0/18", "131.0.72.0/22",
    # Google DNS + GCP
    "8.8.8.0/24", "8.8.4.0/24",
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
    "35.184.0.0/13", "34.80.0.0/12",
    # AWS CloudFront
    "13.224.0.0/14", "13.32.0.0/15", "52.84.0.0/15",
    "54.230.0.0/16", "54.239.128.0/18",
    # Microsoft / Azure
    "13.64.0.0/11", "20.33.0.0/16", "40.64.0.0/10",
    "52.224.0.0/11",
    # Akamai (CDN)
    "23.0.0.0/12", "104.64.0.0/10",
    # GitHub
    "140.82.112.0/20", "143.55.64.0/20", "192.30.252.0/22",
    # Fastly CDN
    "151.101.0.0/16", "199.232.0.0/16",
]

_TRUSTED_NETS: list = []
for _cidr in _TRUSTED_CIDRS_RAW:
    try:
        _TRUSTED_NETS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        pass

# ── Severity ordering ─────────────────────────────────────────────────────────
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


# ── Public API ─────────────────────────────────────────────────────────────────

def is_trusted_ip(ip: str) -> bool:
    """Return True if IP belongs to a trusted CDN/cloud/infrastructure range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TRUSTED_NETS)
    except ValueError:
        return False


def is_apple_system_process(name: str, path: str = "") -> bool:
    """Return True if this process is an Apple system component."""
    if name in APPLE_SYSTEM_PROCS:
        return True
    if path and any(path.startswith(p) for p in APPLE_SYSTEM_PATH_PREFIXES):
        return True
    return False


def get_dual_use_info(name: str, cmd: str = "") -> Optional[dict]:
    """
    Return dual-use metadata if this is a known dual-use security/dev tool.
    Caller should still emit the finding but cap severity and add context.
    """
    name_lower = name.lower()
    cmd_lower = (cmd or "").lower()
    for tool, info in DUAL_USE_TOOLS.items():
        if tool in name_lower or (cmd_lower and tool in cmd_lower):
            return info
    return None


def has_benign_parent(parent_name: str, child_name: str) -> bool:
    """Return True if child spawned from this parent is an expected pattern."""
    parent_lower = parent_name.lower()
    child_lower = child_name.lower()
    for parent, children in BENIGN_PARENT_CHILD.items():
        if parent.lower() in parent_lower:
            return any(c in child_lower for c in children)
    return False


def is_suspicious_spawn(parent_name: str, child_name: str) -> bool:
    """Return True if a non-shell parent is spawning a shell/interpreter (T1203)."""
    for p in SUSPICIOUS_PARENTS:
        if p.lower() in parent_name.lower():
            child_lower = child_name.lower()
            return any(shell in child_lower for shell in SHELL_INTERPRETERS)
    return False


def cap_severity(severity: str, cap: str) -> str:
    """Return the lower of the two severities."""
    try:
        s_idx = _SEV_ORDER.index(severity.lower())
        c_idx = _SEV_ORDER.index(cap.lower())
        return _SEV_ORDER[min(s_idx, c_idx)]
    except ValueError:
        return severity


def adjust_finding_for_allowlist(
    finding: dict,
    name: str = "",
    path: str = "",
    cmd: str = "",
    parent_name: str = "",
) -> Optional[dict]:
    """
    Apply allowlist logic to a finding. Returns:
      - None  → suppress (Apple system process, completely safe)
      - dict  → original or modified finding (with adjusted severity/context)

    Modifies the finding in-place and returns it.
    """
    # Suppress Apple system processes entirely
    if is_apple_system_process(name, path):
        return None

    # Dual-use tool: cap severity and add context note
    dual = get_dual_use_info(name, cmd)
    if dual:
        capped = cap_severity(finding.get("severity", "medium"), dual["severity_cap"])
        finding["severity"] = capped
        finding["score"] = min(finding.get("score", 5.0), _score_for_sev(capped))
        note = finding.get("description", "")
        finding["description"] = f"{note} [Dual-use: {dual['context']}]"
        finding.setdefault("tags", []).append("dual_use")

    # Benign parent → child: reduce to info
    if parent_name and has_benign_parent(parent_name, name):
        finding["severity"] = "info"
        finding["score"] = 0.5
        finding.setdefault("tags", []).append("benign_parent")

    return finding


def _score_for_sev(sev: str) -> float:
    return {"info": 0.5, "low": 2.5, "medium": 5.0, "high": 7.5, "critical": 9.5}.get(sev, 5.0)
