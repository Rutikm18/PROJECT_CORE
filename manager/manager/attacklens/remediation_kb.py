"""
manager/manager/attacklens/remediation_kb.py — Deterministic remediation knowledge base.

Each recipe returns concise, on-the-point steps with OS-specific commands.
Recipes are matched in priority order; the first one that matches a finding wins.

A finding's recipe is always populated (even without AI) by calling
`recipe_for_finding(finding)` — the LLM is only used to elaborate or to handle
finding shapes outside this KB.

Output shape:
  {
    "recipe_id":      "<stable id>",
    "summary":        "<≤ 1 sentence summary of the fix>",
    "applies_to":     "<short rationale for why this recipe matched>",
    "risk_level":     "low|medium|high",
    "estimated_time": "<5 min | 30 min | ...>",
    "steps": [
        {
            "n":            1,
            "title":        "<imperative, ≤ 8 words>",
            "detail":       "<≤ 25 words plain English>",
            "commands": {
                "macos":   ["…", "…"],     # zero-or-more shell commands
                "linux":   ["…"],
                "windows": ["…"],
            },
            "verify":       "<≤ 15 words — how to confirm the step worked>",
        },
        ...
    ],
    "validation":            "<how to confirm the remediation worked overall>",
    "compensating_controls": "<what to do if the fix isn't immediately possible>",
    "references":            ["<URL>", ...],
  }
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_maybe_json(v: Any, default: Any) -> Any:
    """SQLite stores JSON columns as strings.  Decode on access so the KB works
    whether callers pre-parsed or handed us raw rows."""
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return default
    return default


def _evidence(f: dict) -> dict:
    return _parse_maybe_json(f.get("evidence"), {}) or {}


def _cve_ids(f: dict) -> list:
    return _parse_maybe_json(f.get("cve_ids"), []) or []


def _ev(f: dict, *keys: str) -> str:
    """Fetch a string from evidence/top-level using first match."""
    ev = _evidence(f)
    for k in keys:
        v = ev.get(k)
        if v:
            return str(v)
        v = f.get(k)
        if v:
            return str(v)
    return ""


def _has(f: dict, key: str) -> bool:
    ev = _evidence(f)
    if ev.get(key):
        return True
    return bool(f.get(key))


def _first_cve(f: dict) -> str:
    cves = _cve_ids(f)
    if cves:
        return str(cves[0])
    ev = _evidence(f)
    ev_cve = ev.get("cve")
    if isinstance(ev_cve, dict) and ev_cve.get("cve_id"):
        return str(ev_cve["cve_id"])
    if isinstance(ev_cve, str) and ev_cve:
        return ev_cve
    if ev.get("cve_id"):
        return str(ev["cve_id"])
    return ""


# ── Recipe builders ──────────────────────────────────────────────────────────

def _kev_package(f: dict) -> dict:
    pkg = _ev(f, "name", "package")
    ver = _ev(f, "version", "installed_version")
    cve = _first_cve(f)
    return {
        "recipe_id": "kev-package",
        "summary": f"Patch KEV-listed CVE in {pkg or 'package'} ({cve or 'CVE'}) immediately — actively exploited in the wild.",
        "applies_to": "KEV-listed package vulnerability",
        "risk_level": "high",
        "estimated_time": "30 minutes",
        "steps": [
            {
                "n": 1, "title": "Confirm installed version",
                "detail": f"Verify {pkg or 'package'} is actually at the reported version before patching.",
                "commands": {
                    "macos":   [f"brew list --versions {pkg}" if pkg else "brew list --versions"],
                    "linux":   [f"dpkg -l {pkg} || rpm -qi {pkg}" if pkg else "dpkg -l"],
                    "windows": [f"Get-Package -Name '{pkg}*' | Format-List" if pkg else "Get-Package"],
                },
                "verify": "Confirms package + version match the finding evidence.",
            },
            {
                "n": 2, "title": "Block reachable exposure first",
                "detail": "If the package serves an exposed port, firewall it until the patch lands.",
                "commands": {
                    "macos":   ["sudo pfctl -e", "sudo pfctl -t blocked -T add <attacker_ip>"],
                    "linux":   ["sudo iptables -A INPUT -p tcp --dport <port> -j DROP",
                                "sudo iptables-save | sudo tee /etc/iptables/rules.v4"],
                    "windows": ["New-NetFirewallRule -DisplayName 'Block-CVE' -Direction Inbound -LocalPort <port> -Protocol TCP -Action Block"],
                },
                "verify": "Run nmap/ss against the host to confirm the port is unreachable.",
            },
            {
                "n": 3, "title": f"Upgrade {pkg or 'package'}",
                "detail": "Pull the vendor-patched release. Restart any service that links against the library.",
                "commands": {
                    "macos":   [f"brew upgrade {pkg}" if pkg else "brew upgrade",
                                f"brew services restart {pkg}" if pkg else ""],
                    "linux":   [f"sudo apt-get update && sudo apt-get install --only-upgrade -y {pkg}" if pkg else "sudo apt-get upgrade",
                                f"sudo systemctl restart {pkg}" if pkg else ""],
                    "windows": [f"winget upgrade --id {pkg} --silent" if pkg else "winget upgrade --all"],
                },
                "verify": "Re-run step 1 — version must be greater than the fixed-in version of the CVE.",
            },
            {
                "n": 4, "title": "Hunt for prior exploitation",
                "detail": "KEV CVEs have public exploits. Search logs for payloads since CVE publication.",
                "commands": {
                    "macos":   ["log show --predicate 'subsystem == \"com.apple.security\"' --last 30d | grep -i exploit"],
                    "linux":   [f"sudo grep -RIn '{cve}' /var/log/" if cve else "sudo grep -RIn 'exploit' /var/log/"],
                    "windows": ["Get-WinEvent -LogName Security -MaxEvents 5000 | Where-Object {$_.Message -match 'exploit'}"],
                },
                "verify": "Zero hits or only known-benign references → host likely clean.",
            },
        ],
        "validation": f"Re-scan with agent; the {cve or 'CVE'} finding should auto-resolve once the package version exceeds the fixed range.",
        "compensating_controls":
            "If patching is blocked: isolate the host via VLAN, disable the affected service, "
            "or apply the vendor's published mitigation (often a configuration flag).",
        "references": [
            f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://nvd.nist.gov/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    }


def _malicious_outbound(f: dict) -> dict:
    ip   = _ev(f, "dst_ip", "remote_ip", "remote_addr")
    pid  = _ev(f, "pid", "process_pid")
    proc = _ev(f, "process", "process_name", "comm")
    return {
        "recipe_id": "malicious-outbound",
        "summary": f"Active outbound to known-bad IP {ip or '(see evidence)'} — kill the process, block the IP, hunt persistence.",
        "applies_to": "Network connection to threat-intel-flagged IP",
        "risk_level": "high",
        "estimated_time": "15 minutes",
        "steps": [
            {
                "n": 1, "title": "Capture process + connection state",
                "detail": "Snapshot the offending process and full 5-tuple before killing — needed for IR.",
                "commands": {
                    "macos":   [f"sudo lsof -nP -i 4 | grep {ip}" if ip else "sudo lsof -nP -i 4",
                                f"ps -p {pid} -o pid,ppid,user,comm,args" if pid else "ps aux"],
                    "linux":   [f"sudo ss -ntpa | grep {ip}" if ip else "sudo ss -ntpa",
                                f"sudo ls -l /proc/{pid}/exe" if pid else ""],
                    "windows": [f"Get-NetTCPConnection -RemoteAddress {ip} | Format-List" if ip else "Get-NetTCPConnection -State Established"],
                },
                "verify": "Process name, parent, binary path, and user context all captured.",
            },
            {
                "n": 2, "title": "Terminate the process",
                "detail": "Kill the connected process. Children may respawn — kill the whole tree.",
                "commands": {
                    "macos":   [f"sudo kill -9 {pid}" if pid else "sudo killall <process_name>"],
                    "linux":   [f"sudo kill -9 {pid}" if pid else "sudo pkill -9 -f <process_name>"],
                    "windows": [f"Stop-Process -Id {pid} -Force" if pid else "Stop-Process -Name <process_name> -Force"],
                },
                "verify": "ps/Get-Process confirms the PID is gone and not respawned.",
            },
            {
                "n": 3, "title": "Block the IOC at egress",
                "detail": "Firewall the destination IP — even after the process dies, persistence may dial out again.",
                "commands": {
                    "macos":   [f"echo 'block out quick to {ip}' | sudo pfctl -ef -" if ip else ""],
                    "linux":   [f"sudo iptables -A OUTPUT -d {ip} -j DROP" if ip else ""],
                    "windows": [f"New-NetFirewallRule -DisplayName 'Block-{ip}' -Direction Outbound -RemoteAddress {ip} -Action Block" if ip else ""],
                },
                "verify": "curl/Test-NetConnection to the IP must fail.",
            },
            {
                "n": 4, "title": "Hunt for persistence",
                "detail": "C2 connections often have launchd/cron/Run-key persistence. Check before declaring done.",
                "commands": {
                    "macos":   ["sudo find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents -mtime -30 -ls"],
                    "linux":   ["sudo find /etc/systemd /etc/cron.* /etc/rc.* -mtime -30 -ls",
                                "for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -u $u -l 2>/dev/null; done"],
                    "windows": ["Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-30)}",
                                "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                },
                "verify": "No unexpected recently-created persistence entries.",
            },
        ],
        "validation": "Network monitor confirms no further connections to the IOC IP for 24h.",
        "compensating_controls":
            "If the process must run (e.g. legitimate but mis-flagged), submit a verified false-positive disposition "
            "so the rule + entity_key pair is allowlisted and not auto-blocked again.",
        "references": [
            f"https://www.abuseipdb.com/check/{ip}" if ip else "https://www.abuseipdb.com/",
            "https://feodotracker.abuse.ch/",
        ],
    }


def _open_port(f: dict) -> dict:
    port = _ev(f, "port", "dst_port", "local_port")
    proc = _ev(f, "process", "process_name")
    return {
        "recipe_id": "risky-open-port",
        "summary": f"Port {port or '?'} listening — restrict access, validate owning service, or close it entirely.",
        "applies_to": "Risky open / exposed port",
        "risk_level": "medium",
        "estimated_time": "10 minutes",
        "steps": [
            {
                "n": 1, "title": "Identify the listener",
                "detail": "Map the port to its owning process, user, and binary signature.",
                "commands": {
                    "macos":   [f"sudo lsof -nP -iTCP:{port} -sTCP:LISTEN" if port else "sudo lsof -nP -iTCP -sTCP:LISTEN"],
                    "linux":   [f"sudo ss -ltnp 'sport = :{port}'" if port else "sudo ss -ltnp"],
                    "windows": [f"Get-NetTCPConnection -State Listen -LocalPort {port} | Select-Object OwningProcess" if port else "Get-NetTCPConnection -State Listen"],
                },
                "verify": "You know the binary path, PID, parent process, and user.",
            },
            {
                "n": 2, "title": "Decide: close, restrict, or accept",
                "detail": "Unneeded → stop the service. Needed → bind to loopback or restrict source IPs.",
                "commands": {
                    "macos":   ["sudo launchctl unload -w /Library/LaunchDaemons/<plist>"],
                    "linux":   [f"sudo systemctl stop {proc} && sudo systemctl disable {proc}" if proc else "sudo systemctl stop <service>"],
                    "windows": [f"Stop-Service -Name '{proc}' -Force; Set-Service -Name '{proc}' -StartupType Disabled" if proc else "Stop-Service -Name <name>"],
                },
                "verify": "ss / Get-NetTCPConnection shows the port no longer listening (or only on 127.0.0.1).",
            },
            {
                "n": 3, "title": "Firewall if the service must stay",
                "detail": "Only allow the management VLAN or specific source IPs.",
                "commands": {
                    "macos":   [f"echo 'block in quick proto tcp to any port {port}' | sudo pfctl -ef -" if port else ""],
                    "linux":   [f"sudo iptables -A INPUT -p tcp --dport {port} -s <allowed_cidr> -j ACCEPT" if port else "",
                                f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP" if port else ""],
                    "windows": [f"New-NetFirewallRule -DisplayName 'Restrict-{port}' -Direction Inbound -LocalPort {port} -Protocol TCP -RemoteAddress <allowed_cidr> -Action Allow" if port else ""],
                },
                "verify": "External nmap shows the port filtered/closed from non-allowed sources.",
            },
        ],
        "validation": "Re-scan from an external host — port is closed or restricted to expected sources only.",
        "compensating_controls":
            "If the port must remain open to the world (e.g. public-facing service), require authentication, "
            "enable rate limiting at the edge, and monitor for brute-force / scanner activity.",
        "references": ["https://attack.mitre.org/techniques/T1133/"],
    }


def _suspicious_process(f: dict) -> dict:
    proc = _ev(f, "process", "process_name", "comm")
    pid  = _ev(f, "pid")
    path = _ev(f, "path", "exe", "image")
    return {
        "recipe_id": "suspicious-process",
        "summary": f"Suspicious process {proc or 'unknown'} running — capture forensics, terminate, hunt persistence.",
        "applies_to": "Offensive-tool / LOLBin / malware-pattern process",
        "risk_level": "high",
        "estimated_time": "20 minutes",
        "steps": [
            {
                "n": 1, "title": "Capture forensics first",
                "detail": "Hash the binary, snapshot args, parent chain, open files before killing.",
                "commands": {
                    "macos":   [f"shasum -a 256 '{path}'" if path else "",
                                f"sudo ps -p {pid} -o pid,ppid,user,comm,args" if pid else "",
                                f"sudo lsof -p {pid}" if pid else ""],
                    "linux":   [f"sha256sum '{path}'" if path else "",
                                f"sudo cat /proc/{pid}/cmdline | tr '\\0' ' '" if pid else "",
                                f"sudo ls -l /proc/{pid}/fd" if pid else ""],
                    "windows": [f"Get-FileHash -Algorithm SHA256 '{path}'" if path else "",
                                f"Get-Process -Id {pid} | Select-Object *" if pid else ""],
                },
                "verify": "SHA256 captured. Submit to VirusTotal to confirm verdict.",
            },
            {
                "n": 2, "title": "Terminate the process tree",
                "detail": "Kill the process and any children to prevent immediate respawn.",
                "commands": {
                    "macos":   [f"sudo pkill -9 -P {pid}; sudo kill -9 {pid}" if pid else f"sudo pkill -9 -f {proc}"],
                    "linux":   [f"sudo pkill -9 -P {pid}; sudo kill -9 {pid}" if pid else f"sudo pkill -9 -f {proc}"],
                    "windows": [f"taskkill /F /T /PID {pid}" if pid else f"taskkill /F /IM {proc}.exe"],
                },
                "verify": "ps / Get-Process shows the PID and its children all gone.",
            },
            {
                "n": 3, "title": "Quarantine the binary",
                "detail": "Move the binary out of execution path so re-launch fails — preserve for analysis.",
                "commands": {
                    "macos":   [f"sudo mv '{path}' '/var/quarantine/'" if path else ""],
                    "linux":   [f"sudo mv '{path}' '/var/quarantine/'" if path else "",
                                f"sudo chmod 000 /var/quarantine/$(basename '{path}')" if path else ""],
                    "windows": [f"Move-Item '{path}' 'C:\\Quarantine\\'" if path else ""],
                },
                "verify": "Re-launching by name fails (command not found / access denied).",
            },
            {
                "n": 4, "title": "Hunt persistence + lateral movement",
                "detail": "Check launch agents, cron, services, and recent file modifications around process start.",
                "commands": {
                    "macos":   ["sudo find /Library/Launch* ~/Library/LaunchAgents -mtime -7 -ls"],
                    "linux":   ["sudo find /etc/systemd /etc/cron.* -mtime -7 -ls",
                                "sudo find / -mtime -1 -type f \\( -path '/proc' -o -path '/sys' \\) -prune -o -print 2>/dev/null | head -200"],
                    "windows": ["Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-7)}"],
                },
                "verify": "No unexpected recently-created persistence artefacts.",
            },
        ],
        "validation": "Re-run the agent telemetry sweep; the process should no longer appear in subsequent scans.",
        "compensating_controls":
            "If this is a sanctioned red-team/pentest tool, mark as accepted_risk and add (rule_id, entity_key) "
            "to the allowlist so it doesn't re-fire.",
        "references": [
            "https://attack.mitre.org/techniques/T1059/",
            "https://www.virustotal.com/",
        ],
    }


def _persistence(f: dict) -> dict:
    path = _ev(f, "path", "plist", "service_path")
    name = _ev(f, "label", "name", "service_name")
    return {
        "recipe_id": "persistence",
        "summary": f"Persistence mechanism {name or path or 'unknown'} found — unload, delete, and audit creator.",
        "applies_to": "LaunchDaemon / cron / Run key / shell-config persistence",
        "risk_level": "high",
        "estimated_time": "15 minutes",
        "steps": [
            {
                "n": 1, "title": "Read the persistence content",
                "detail": "Capture the full body before touching it. Note RunAtLoad, command, and target binary.",
                "commands": {
                    "macos":   [f"sudo cat '{path}'" if path else "sudo find /Library/LaunchDaemons -name '*.plist'"],
                    "linux":   [f"sudo cat '{path}'" if path else "sudo systemctl list-unit-files --type=service"],
                    "windows": [f"reg query '{path}'" if path else "Get-CimInstance Win32_StartupCommand"],
                },
                "verify": "Full configuration content saved to your IR notes.",
            },
            {
                "n": 2, "title": "Unload / disable",
                "detail": "Stop the persistence from re-launching the payload.",
                "commands": {
                    "macos":   [f"sudo launchctl unload -w '{path}'" if path else "sudo launchctl unload -w <plist>"],
                    "linux":   [f"sudo systemctl disable --now {name}" if name else "sudo systemctl disable --now <service>"],
                    "windows": [f"Disable-ScheduledTask -TaskName '{name}'" if name else "Disable-ScheduledTask -TaskName <task>"],
                },
                "verify": "launchctl list / systemctl status / Get-ScheduledTask shows the entry inactive.",
            },
            {
                "n": 3, "title": "Remove the persistence file",
                "detail": "Delete the persistence entry — keep a copy in quarantine for analysis.",
                "commands": {
                    "macos":   [f"sudo cp '{path}' /var/quarantine/ && sudo rm '{path}'" if path else ""],
                    "linux":   [f"sudo cp '{path}' /var/quarantine/ && sudo rm '{path}'" if path else ""],
                    "windows": [f"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false" if name else ""],
                },
                "verify": "File is no longer present in its location; quarantine copy exists for forensics.",
            },
            {
                "n": 4, "title": "Audit how it got there",
                "detail": "Find the parent process and user that created the persistence. That is the real entry point.",
                "commands": {
                    "macos":   [f"sudo log show --predicate 'eventMessage contains \"{name or path}\"' --last 30d" if (name or path) else ""],
                    "linux":   [f"sudo ausearch -f '{path}' || sudo grep -RIn '{name or path}' /var/log/" if (name or path) else ""],
                    "windows": ["Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 200"],
                },
                "verify": "You know which user / process created the persistence and when.",
            },
        ],
        "validation": "Subsequent agent scans show the persistence entry gone and not re-created.",
        "compensating_controls":
            "If the persistence is legitimate (MDM, vendor agent), confirm the signer and mark as accepted_risk.",
        "references": [
            "https://attack.mitre.org/tactics/TA0003/",
            "https://objective-see.org/blog.html",
        ],
    }


def _suid_binary(f: dict) -> dict:
    path = _ev(f, "path")
    return {
        "recipe_id": "suid-binary",
        "summary": f"SUID binary {path or '(see evidence)'} — verify legitimacy, remove SUID bit if not required.",
        "applies_to": "Unexpected SUID / SGID / world-writable binary",
        "risk_level": "medium",
        "estimated_time": "5 minutes",
        "steps": [
            {
                "n": 1, "title": "Inspect ownership + permissions",
                "detail": "SUID + non-root owner OR SUID in non-standard path is the worst combination.",
                "commands": {
                    "macos":   [f"ls -la '{path}'" if path else "sudo find / -perm -4000 -type f 2>/dev/null"],
                    "linux":   [f"ls -la '{path}'" if path else "sudo find / -perm -4000 -type f 2>/dev/null"],
                    "windows": [f"Get-Acl '{path}' | Format-List" if path else ""],
                },
                "verify": "Confirmed owner, mode, install source, signature.",
            },
            {
                "n": 2, "title": "Remove the SUID bit",
                "detail": "If not a known system binary, strip SUID — execution still works for the owner.",
                "commands": {
                    "macos":   [f"sudo chmod u-s '{path}'" if path else ""],
                    "linux":   [f"sudo chmod u-s '{path}'" if path else ""],
                    "windows": ["icacls <path> /remove:g <user>"],
                },
                "verify": "ls -la shows mode without the leading `s` in the user triplet.",
            },
            {
                "n": 3, "title": "Audit recent SUID exploitation attempts",
                "detail": "Many SUID exploits leave kernel audit traces; check them.",
                "commands": {
                    "macos":   ["sudo log show --predicate 'subsystem == \"com.apple.security\"' --last 7d"],
                    "linux":   ["sudo ausearch -m EXECVE -ts recent | grep -i suid"],
                    "windows": ["Get-WinEvent -LogName Security -MaxEvents 500 | Where-Object {$_.Id -in 4672,4673}"],
                },
                "verify": "No recent exec events from this binary by non-root users.",
            },
        ],
        "validation": "find / -perm -4000 confirms the binary no longer has the SUID bit.",
        "compensating_controls":
            "If SUID is required (mount, ping on some distros), restrict the binary via AppArmor/SELinux/SIP.",
        "references": ["https://attack.mitre.org/techniques/T1548/001/"],
    }


def _security_posture(f: dict) -> dict:
    control = _ev(f, "key", "control")
    return {
        "recipe_id": "posture-control-off",
        "summary": f"Security control '{control or 'one of SIP/FileVault/Gatekeeper/Firewall'}' is disabled — re-enable.",
        "applies_to": "macOS security posture finding",
        "risk_level": "high",
        "estimated_time": "10 minutes",
        "steps": [
            {
                "n": 1, "title": "Confirm current posture",
                "detail": "Check the actual state before re-enabling — confirms agent telemetry is current.",
                "commands": {
                    "macos":   ["csrutil status",
                                "sudo spctl --status",
                                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                                "fdesetup status"],
                    "linux":   ["sudo aa-status", "sudo getenforce", "sudo ufw status"],
                    "windows": ["Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, FirewallEnabled"],
                },
                "verify": "Each control's state is known and documented.",
            },
            {
                "n": 2, "title": "Re-enable the control",
                "detail": "Pick the command matching the disabled control from the finding.",
                "commands": {
                    "macos":   ["# SIP: reboot to Recovery → Terminal → csrutil enable",
                                "sudo spctl --master-enable                # Gatekeeper",
                                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                                "sudo fdesetup enable                       # FileVault"],
                    "linux":   ["sudo systemctl enable --now ufw",
                                "sudo setenforce 1"],
                    "windows": ["Set-MpPreference -DisableRealtimeMonitoring $false",
                                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"],
                },
                "verify": "Re-run step 1 — control is now enabled.",
            },
            {
                "n": 3, "title": "Investigate why it was disabled",
                "detail": "Posture controls rarely disable themselves — find the actor and timeframe.",
                "commands": {
                    "macos":   ["sudo log show --predicate 'eventMessage CONTAINS \"csrutil\" OR eventMessage CONTAINS \"spctl\"' --last 30d"],
                    "linux":   ["sudo grep -RIn 'setenforce\\|ufw disable' /var/log/"],
                    "windows": ["Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 200"],
                },
                "verify": "You have an event with timestamp + actor for the original disable.",
            },
        ],
        "validation": "Posture telemetry on the next agent scan shows control = enabled.",
        "compensating_controls":
            "If the control must remain off (developer workstation), document the exception in the asset registry "
            "tag list and add compensating EDR coverage.",
        "references": [
            "https://support.apple.com/guide/security/welcome/web",
            "https://learn.microsoft.com/en-us/windows/security/",
        ],
    }


def _uid0_account(f: dict) -> dict:
    user = _ev(f, "name", "username")
    return {
        "recipe_id": "uid0-account",
        "summary": f"Non-root account '{user or '?'}' has UID 0 — disable immediately, audit creation.",
        "applies_to": "Privilege escalation via UID-0 backdoor account",
        "risk_level": "high",
        "estimated_time": "10 minutes",
        "steps": [
            {
                "n": 1, "title": "Lock the account",
                "detail": "Disable login before doing anything else.",
                "commands": {
                    "macos":   [f"sudo dscl . -delete /Users/{user}" if user else "sudo dscl . list /Users UniqueID"],
                    "linux":   [f"sudo usermod -L {user} && sudo passwd -l {user}" if user else "awk -F: '$3==0' /etc/passwd"],
                    "windows": [f"Disable-LocalUser -Name '{user}'" if user else "Get-LocalUser | Where-Object {$_.SID -match '-500$'}"],
                },
                "verify": "Login attempts as that user are rejected.",
            },
            {
                "n": 2, "title": "Audit creation",
                "detail": "Determine when and by whom this account was elevated to UID 0.",
                "commands": {
                    "macos":   ["sudo log show --predicate 'subsystem == \"com.apple.opendirectoryd\"' --last 30d"],
                    "linux":   ["sudo grep -RIn 'useradd\\|usermod' /var/log/secure /var/log/auth.log 2>/dev/null"],
                    "windows": ["Get-WinEvent -LogName Security -FilterXPath \"*[System[EventID=4720 or EventID=4738]]\""],
                },
                "verify": "You have a clear creation/modification record with timestamp + actor.",
            },
            {
                "n": 3, "title": "Hunt for related backdoors",
                "detail": "Attackers often plant multiple persistence layers — search for others.",
                "commands": {
                    "macos":   ["sudo dscl . list /Users UniqueID | awk '$2==0'"],
                    "linux":   ["awk -F: '$3==0' /etc/passwd",
                                "sudo find /home /root -name '.ssh' -exec ls -la {} \\;"],
                    "windows": ["Get-LocalGroupMember -Group 'Administrators'"],
                },
                "verify": "Only the intended root account remains at UID 0 (or in admin group).",
            },
        ],
        "validation": "Asset registry + agent scan confirm only sanctioned UID-0 accounts exist.",
        "compensating_controls":
            "If business requires shared root, switch to sudo-with-MFA instead of multiple UID-0 accounts.",
        "references": ["https://attack.mitre.org/techniques/T1078/003/"],
    }


def _config_pattern(f: dict) -> dict:
    path = _ev(f, "path", "config_path")
    return {
        "recipe_id": "shell-config-tamper",
        "summary": f"Suspicious pattern in {path or 'shell/config file'} — restore from backup, audit shell history.",
        "applies_to": "Shell or config file injection (pipe-to-shell, eval, backdoor)",
        "risk_level": "high",
        "estimated_time": "15 minutes",
        "steps": [
            {
                "n": 1, "title": "Snapshot the current content",
                "detail": "Keep a copy before remediation — needed for IR + supplier notification.",
                "commands": {
                    "macos":   [f"sudo cp '{path}' /var/quarantine/" if path else ""],
                    "linux":   [f"sudo cp '{path}' /var/quarantine/" if path else ""],
                    "windows": [f"Copy-Item '{path}' 'C:\\Quarantine\\'" if path else ""],
                },
                "verify": "Forensic copy exists at /var/quarantine/.",
            },
            {
                "n": 2, "title": "Restore a clean version",
                "detail": "Use vendor default or a known-good backup — never edit attacker-injected content in place.",
                "commands": {
                    "macos":   [f"# Compare against git or Time Machine version, then: sudo cp <clean_source> '{path}'" if path else ""],
                    "linux":   [f"sudo dpkg -V <package> && sudo apt-get install --reinstall <package>" if path else ""],
                    "windows": ["sfc /scannow"],
                },
                "verify": "diff against the clean baseline shows no unexpected modifications.",
            },
            {
                "n": 3, "title": "Audit shell history",
                "detail": "The user whose dotfile was tampered may have run attacker-injected commands.",
                "commands": {
                    "macos":   ["cat ~/.zsh_history ~/.bash_history 2>/dev/null"],
                    "linux":   ["cat ~/.bash_history ~/.zsh_history 2>/dev/null",
                                "sudo grep -RIn 'curl.*|.*sh' /home/*/"],
                    "windows": ["Get-Content (Get-PSReadLineOption).HistorySavePath"],
                },
                "verify": "No suspicious download-and-execute patterns in history.",
            },
        ],
        "validation": "Re-scan finds no injection patterns in the config file.",
        "compensating_controls":
            "Enable file-integrity monitoring (FIM) on dotfiles and shell configs going forward.",
        "references": ["https://attack.mitre.org/techniques/T1546/004/"],
    }


def _generic_finding(f: dict) -> dict:
    return {
        "recipe_id": "generic",
        "summary": "Validate the finding evidence, scope the affected asset, and apply category-specific mitigation.",
        "applies_to": "Generic fallback when no specific recipe matched",
        "risk_level": "medium",
        "estimated_time": "30 minutes",
        "steps": [
            {
                "n": 1, "title": "Confirm the evidence",
                "detail": "Read the finding evidence carefully and verify the underlying state on the host.",
                "commands": {
                    "macos":   ["# Open the finding in the dashboard and read the Evidence section"],
                    "linux":   ["# Open the finding in the dashboard and read the Evidence section"],
                    "windows": ["# Open the finding in the dashboard and read the Evidence section"],
                },
                "verify": "You can describe the malicious behaviour in one sentence.",
            },
            {
                "n": 2, "title": "Scope the impact",
                "detail": "Identify the asset, owner, and whether any other hosts share the same exposure.",
                "commands": {
                    "macos":   ["# Cross-check the Assets page for tier, group, and last-seen"],
                    "linux":   ["# Cross-check the Assets page for tier, group, and last-seen"],
                    "windows": ["# Cross-check the Assets page for tier, group, and last-seen"],
                },
                "verify": "Asset tier, group, and blast radius documented.",
            },
            {
                "n": 3, "title": "Apply mitigation + verify",
                "detail": "Apply the rule-specific fix from the engine documentation, then re-scan.",
                "commands": {
                    "macos":   [], "linux": [], "windows": [],
                },
                "verify": "Finding auto-resolves on the next agent scan.",
            },
        ],
        "validation": "Finding moves to remediated/verified after re-scan.",
        "compensating_controls":
            "Move to accepted_risk only after security-team sign-off and document the rationale.",
        "references": [],
    }


# ── Dispatch table ──────────────────────────────────────────────────────────

# Order matters — first match wins. Each entry: (predicate, builder).
_MATCHERS: list[tuple[Callable[[dict], bool], Callable[[dict], dict]]] = [
    # KEV-listed CVE — highest priority
    (lambda f: bool(f.get("kev")) and f.get("category") == "package", _kev_package),
    # Any package CVE
    (lambda f: f.get("category") == "package" and bool(_first_cve(f) or _cve_ids(f)),
     _kev_package),
    # Malicious outbound IOC match
    (lambda f: f.get("category") == "connection", _malicious_outbound),
    # Network anomalies (ARP, covert, interface drift)
    (lambda f: f.get("category") == "network", _malicious_outbound),
    # Risky / exposed port
    (lambda f: f.get("category") == "port", _open_port),
    # Persistence categories
    (lambda f: f.get("category") in ("service", "task"), _persistence),
    # Shell / config injection
    (lambda f: f.get("category") == "config", _config_pattern),
    # SUID / SGID / world-writable binary
    (lambda f: f.get("category") == "binary", _suid_binary),
    # macOS security posture controls
    (lambda f: f.get("category") == "security", _security_posture),
    # User-account anomalies
    (lambda f: f.get("category") == "user", _uid0_account),
    # Suspicious app or process
    (lambda f: f.get("category") in ("process", "app"), _suspicious_process),
]


def recipe_for_finding(f: dict) -> dict:
    """
    Return the best deterministic remediation recipe for a finding.
    Always returns a dict (the generic recipe is the floor).
    """
    for predicate, builder in _MATCHERS:
        try:
            if predicate(f):
                recipe = builder(f)
                # Light hygiene: strip empty command strings so the UI doesn't render blanks.
                for step in recipe.get("steps", []):
                    for os_name, cmds in (step.get("commands") or {}).items():
                        step["commands"][os_name] = [c for c in cmds if str(c).strip()]
                return recipe
        except Exception:
            continue
    return _generic_finding(f)


def action_plan_for(f: dict) -> list[dict]:
    """
    Compact action-plan format used by the engine + findings list. Each entry:
        {"type": "contain|remediate|investigate|hunt", "title": str, "detail": str}
    """
    recipe = recipe_for_finding(f)
    type_map = {1: "investigate", 2: "remediate", 3: "remediate", 4: "hunt"}
    out: list[dict] = []
    for step in recipe.get("steps", []):
        n = int(step.get("n", 0))
        out.append({
            "type":   type_map.get(n, "remediate"),
            "title":  step.get("title", ""),
            "detail": step.get("detail", ""),
        })
    return out
