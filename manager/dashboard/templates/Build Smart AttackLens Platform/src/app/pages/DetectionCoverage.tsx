/**
 * DetectionCoverage — 14-module detection coverage dashboard
 * 4 attack surface zones · severity filter · per-zone accordion · sendPrompt integration
 */
import { useState, useCallback } from "react";
import {
  ChevronDown, ChevronRight, ExternalLink, Shield,
  CheckCircle2, Layers, Cpu, Globe, Package, Users,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── sendPrompt integration ────────────────────────────────────────────────────

function sendPrompt(text: string) {
  if (typeof (window as any).sendPrompt === "function") {
    (window as any).sendPrompt(text);
  } else {
    navigator.clipboard.writeText(text).catch(() => {});
  }
}

// ── Data model ────────────────────────────────────────────────────────────────

interface DetectionModule {
  id: string;
  name: string;
  zone: 1 | 2 | 3 | 4;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  detectionConditions: string[];
  mitreTechniques: string[];
  complianceControls: string[];
  promptText: string;
}

const MODULES: DetectionModule[] = [
  // ── Zone 1 — Endpoint OS Integrity ────────────────────────────────────────
  {
    id: "process-injection",
    name: "Process Injection",
    zone: 1,
    severity: "CRITICAL",
    description: "Detects code injected into legitimate processes via hollowing, DLL injection, or shellcode mapping",
    detectionConditions: [
      "Remote thread creation targeting a process owned by a different user (CreateRemoteThread / task_for_pid)",
      "WriteProcessMemory or mach_vm_write followed by VirtualProtectEx with PAGE_EXECUTE permissions",
      "Unsigned memory-mapped region executing inside a signed process address space",
      "Thread start address located outside any known mapped module image (shellcode stub pattern)",
      "Process entropy spike above 7.2 in a region that was previously read-only clean",
    ],
    mitreTechniques: [
      "T1055 – Process Injection",
      "T1055.001 – Dynamic-link Library Injection",
      "T1055.012 – Process Hollowing",
      "T1055.004 – Asynchronous Procedure Call",
    ],
    complianceControls: [
      "NIST 800-53 SI-3",
      "NIST 800-53 SI-7",
      "CIS Control 10.5",
      "ISO 27001 A.12.2.1",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Process Injection.

Detection conditions:
- Remote thread creation targeting a process owned by a different user (CreateRemoteThread / task_for_pid)
- WriteProcessMemory or mach_vm_write followed by VirtualProtectEx with PAGE_EXECUTE permissions
- Unsigned memory-mapped region executing inside a signed process address space
- Thread start address located outside any known mapped module image (shellcode stub pattern)
- Process entropy spike above 7.2 in a region that was previously read-only clean

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1055, T1055.001, T1055.012, T1055.004.
Compliance: NIST 800-53 SI-3, SI-7; CIS Control 10.5.
Output as a code block with inline comments.`,
  },
  {
    id: "lsass-tampering",
    name: "LSASS Memory Tampering",
    zone: 1,
    severity: "CRITICAL",
    description: "Detects unauthorized reads or dumps of the LSASS process memory to extract credentials",
    detectionConditions: [
      "OpenProcess with PROCESS_VM_READ on lsass.exe from a non-system process",
      "MiniDumpWriteDump API call targeting pid matching lsass.exe",
      "Procdump, comsvcs.dll or Mimikatz module signatures in memory of any process",
      "LSASS handle access from a process spawned via WMI, PowerShell, or cmd.exe",
      "Suspicious DLL loaded into lsass.exe with no corresponding authenticode signature",
    ],
    mitreTechniques: [
      "T1003.001 – LSASS Memory",
      "T1003 – OS Credential Dumping",
      "T1134 – Access Token Manipulation",
      "T1548.002 – Bypass UAC via CMSTP",
    ],
    complianceControls: [
      "NIST 800-53 AC-6",
      "NIST 800-53 AU-12",
      "CIS Control 16.6",
      "PCI DSS 8.6",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: LSASS Memory Tampering.

Detection conditions:
- OpenProcess with PROCESS_VM_READ on lsass.exe from a non-system process
- MiniDumpWriteDump API call targeting pid matching lsass.exe
- Procdump, comsvcs.dll or Mimikatz module signatures in memory of any process
- LSASS handle access from a process spawned via WMI, PowerShell, or cmd.exe
- Suspicious DLL loaded into lsass.exe with no corresponding authenticode signature

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1003.001 – LSASS Memory, T1003 – OS Credential Dumping, T1134.
Compliance: NIST 800-53 AC-6, AU-12; CIS Control 16.6.
Output as a code block with inline comments.`,
  },
  {
    id: "boot-integrity",
    name: "Boot Integrity Violation",
    zone: 1,
    severity: "CRITICAL",
    description: "Detects modifications to bootloader, firmware, or Secure Boot policy indicating a pre-OS implant",
    detectionConditions: [
      "kern.bootargs changed from baseline — arbitrary kernel flags indicate unauthorized boot modification",
      "Secure Boot status flipped from enabled to disabled between consecutive scans",
      "Unexpected EFI binary hash mismatch vs known-good firmware manifest",
      "SIP (System Integrity Protection) disabled and no MDM enrollment justifying it",
      "BootCamp partition with unsigned EFI executable detected on macOS host",
    ],
    mitreTechniques: [
      "T1542 – Pre-OS Boot",
      "T1542.001 – System Firmware",
      "T1542.003 – Bootkit",
      "T1553.001 – Gatekeeper Bypass",
    ],
    complianceControls: [
      "NIST 800-53 SI-7",
      "NIST 800-53 CM-6",
      "CIS Control 3.4",
      "ISO 27001 A.12.6.2",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Boot Integrity Violation.

Detection conditions:
- kern.bootargs changed from baseline — arbitrary kernel flags indicate unauthorized boot modification
- Secure Boot status flipped from enabled to disabled between consecutive scans
- Unexpected EFI binary hash mismatch vs known-good firmware manifest
- SIP (System Integrity Protection) disabled and no MDM enrollment justifying it
- BootCamp partition with unsigned EFI executable detected on macOS host

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1542 – Pre-OS Boot, T1542.001 – System Firmware, T1542.003 – Bootkit.
Compliance: NIST 800-53 SI-7, CM-6; CIS Control 3.4.
Output as a code block with inline comments.`,
  },
  {
    id: "kernel-driver-load",
    name: "Kernel Driver Loading",
    zone: 1,
    severity: "HIGH",
    description: "Detects unsigned or unexpected kernel extensions and drivers being loaded at runtime",
    detectionConditions: [
      "kext loaded with no Apple notarization or valid Team ID outside approved allowlist",
      "NtLoadDriver or ZwLoadDriver called from a non-administrator, non-SYSTEM context",
      "Kernel module appearing in /proc/modules or lsmod output that has no corresponding package",
      "Driver binary path located in a user-writable directory (/tmp, ~/Downloads, %APPDATA%)",
      "kextd process spawned by a non-launchd parent — indicator of kext injection via ptrace",
    ],
    mitreTechniques: [
      "T1215 – Kernel Modules and Extensions",
      "T1547.006 – Boot or Logon Autostart – Kernel Modules",
      "T1014 – Rootkit",
      "T1601 – Modify System Image",
    ],
    complianceControls: [
      "NIST 800-53 CM-7",
      "NIST 800-53 SI-7",
      "CIS Control 5.1",
      "SOC 2 CC7.2",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Kernel Driver Loading.

Detection conditions:
- kext loaded with no Apple notarization or valid Team ID outside approved allowlist
- NtLoadDriver or ZwLoadDriver called from a non-administrator, non-SYSTEM context
- Kernel module appearing in /proc/modules or lsmod output that has no corresponding package
- Driver binary path located in a user-writable directory (/tmp, ~/Downloads, %APPDATA%)
- kextd process spawned by a non-launchd parent — indicator of kext injection via ptrace

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1215 – Kernel Modules and Extensions, T1547.006, T1014 – Rootkit.
Compliance: NIST 800-53 CM-7, SI-7; CIS Control 5.1.
Output as a code block with inline comments.`,
  },

  // ── Zone 2 — Network & C2 ─────────────────────────────────────────────────
  {
    id: "beaconing-detection",
    name: "C2 Beaconing Pattern",
    zone: 2,
    severity: "CRITICAL",
    description: "Detects periodic outbound connections consistent with command-and-control beaconing intervals",
    detectionConditions: [
      "Outbound connection to the same IP/domain at regular intervals (jitter < 15%) over a 2-hour window",
      "Connection payload size falls in the 64–256 byte range consistently — matches heartbeat profile",
      "Destination not in CDN, cloud provider, or corporate allowlist and has low Alexa/Cisco Umbrella rank",
      "Parent process is not a browser, mail client, or known update agent",
      "TLS SNI mismatch: certificate CN differs from the DNS name used to connect (domain fronting indicator)",
    ],
    mitreTechniques: [
      "T1071 – Application Layer Protocol",
      "T1071.001 – Web Protocols",
      "T1573 – Encrypted Channel",
      "T1008 – Fallback Channels",
    ],
    complianceControls: [
      "NIST 800-53 SI-4",
      "CIS Control 13.6",
      "MITRE D3FEND D3-NTCD",
      "ISO 27001 A.13.1.2",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: C2 Beaconing Pattern.

Detection conditions:
- Outbound connection to the same IP/domain at regular intervals (jitter < 15%) over a 2-hour window
- Connection payload size falls in the 64–256 byte range consistently — matches heartbeat profile
- Destination not in CDN, cloud provider, or corporate allowlist and has low Alexa/Cisco Umbrella rank
- Parent process is not a browser, mail client, or known update agent
- TLS SNI mismatch: certificate CN differs from the DNS name used to connect (domain fronting indicator)

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1071 – Application Layer Protocol, T1573 – Encrypted Channel, T1008.
Compliance: NIST 800-53 SI-4; CIS Control 13.6.
Output as a code block with inline comments.`,
  },
  {
    id: "dns-tunneling",
    name: "DNS Tunneling",
    zone: 2,
    severity: "HIGH",
    description: "Detects data exfiltration or C2 communication encoded inside DNS query/response streams",
    detectionConditions: [
      "Single DNS query name exceeds 60 characters — base64 or hex payload encoded in subdomain label",
      "More than 50 unique subdomains queried for the same second-level domain within 10 minutes",
      "DNS query volume from a single host exceeds 500 requests per minute",
      "TXT or NULL record type used in queries — uncommon in legitimate corporate traffic",
      "Query name entropy exceeds 3.9 bits per character — strongly indicates encoded content",
    ],
    mitreTechniques: [
      "T1048.003 – Exfiltration over Unencrypted Protocol",
      "T1071.004 – DNS",
      "T1041 – Exfiltration over C2 Channel",
      "T1568 – Dynamic Resolution",
    ],
    complianceControls: [
      "NIST 800-53 SC-20",
      "NIST 800-53 SI-4",
      "CIS Control 9.2",
      "PCI DSS 1.3.4",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: DNS Tunneling.

Detection conditions:
- Single DNS query name exceeds 60 characters — base64 or hex payload encoded in subdomain label
- More than 50 unique subdomains queried for the same second-level domain within 10 minutes
- DNS query volume from a single host exceeds 500 requests per minute
- TXT or NULL record type used in queries — uncommon in legitimate corporate traffic
- Query name entropy exceeds 3.9 bits per character — strongly indicates encoded content

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1048.003, T1071.004 – DNS, T1041 – Exfiltration over C2 Channel.
Compliance: NIST 800-53 SC-20, SI-4; CIS Control 9.2.
Output as a code block with inline comments.`,
  },
  {
    id: "lateral-movement-smb",
    name: "Lateral Movement via SMB/WMI",
    zone: 2,
    severity: "HIGH",
    description: "Detects adversarial use of SMB shares or WMI for remote code execution and host-to-host pivoting",
    detectionConditions: [
      "Successful authentication to SMB (port 445) from an internal host not part of the deployment pipeline",
      "WMI subscription created (Win32_EventFilter + Win32_EventConsumer) by a non-administrative process",
      "PsExec, WMIC, or sc.exe executed with remote host argument targeting a workstation not a server",
      "IPC$ share access followed by service creation on the remote target within the same minute",
      "svchost.exe or wmiprvse.exe spawning a new child process on a non-DC, non-server host",
    ],
    mitreTechniques: [
      "T1021.002 – Remote Services: SMB/Windows Admin Shares",
      "T1047 – Windows Management Instrumentation",
      "T1570 – Lateral Tool Transfer",
      "T1543.003 – Windows Service",
    ],
    complianceControls: [
      "NIST 800-53 AC-17",
      "NIST 800-53 SI-4",
      "CIS Control 12.4",
      "SOC 2 CC6.6",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Lateral Movement via SMB/WMI.

Detection conditions:
- Successful authentication to SMB (port 445) from an internal host not part of the deployment pipeline
- WMI subscription created (Win32_EventFilter + Win32_EventConsumer) by a non-administrative process
- PsExec, WMIC, or sc.exe executed with remote host argument targeting a workstation not a server
- IPC$ share access followed by service creation on the remote target within the same minute
- svchost.exe or wmiprvse.exe spawning a new child process on a non-DC, non-server host

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1021.002 – SMB/Windows Admin Shares, T1047 – WMI, T1570.
Compliance: NIST 800-53 AC-17, SI-4; CIS Control 12.4.
Output as a code block with inline comments.`,
  },

  // ── Zone 3 — Supply Chain & Vulnerability ─────────────────────────────────
  {
    id: "software-update-hijack",
    name: "Software Update Hijack",
    zone: 3,
    severity: "CRITICAL",
    description: "Detects tampering with software update mechanisms to deliver malicious payloads via trusted channels",
    detectionConditions: [
      "Update binary hash mismatch vs vendor-published SHA256 manifest before execution",
      "Update downloaded over HTTP (not HTTPS) from a domain not matching the vendor's known CDN",
      "Installer spawning unexpected child processes or creating files outside the application bundle path",
      "Code signing certificate on the update package issued less than 30 days ago for a long-established vendor",
      "DNS response for the update server resolving to a non-canonical IP (BGP hijack or DNS poisoning indicator)",
    ],
    mitreTechniques: [
      "T1195.002 – Supply Chain Compromise: Compromise Software Supply Chain",
      "T1072 – Software Deployment Tools",
      "T1553.002 – Subvert Trust Controls: Code Signing",
      "T1036 – Masquerading",
    ],
    complianceControls: [
      "NIST 800-53 SA-12",
      "NIST 800-53 SI-7",
      "CIS Control 2.5",
      "SLSA Level 3",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Software Update Hijack.

Detection conditions:
- Update binary hash mismatch vs vendor-published SHA256 manifest before execution
- Update downloaded over HTTP (not HTTPS) from a domain not matching the vendor's known CDN
- Installer spawning unexpected child processes or creating files outside the application bundle path
- Code signing certificate on the update package issued less than 30 days ago for a long-established vendor
- DNS response for the update server resolving to a non-canonical IP (BGP hijack or DNS poisoning indicator)

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1195.002 – Supply Chain Compromise, T1072, T1553.002, T1036.
Compliance: NIST 800-53 SA-12, SI-7; CIS Control 2.5; SLSA Level 3.
Output as a code block with inline comments.`,
  },
  {
    id: "unsigned-binary-exec",
    name: "Unsigned Binary Execution",
    zone: 3,
    severity: "HIGH",
    description: "Detects execution of binaries lacking valid code signatures or signed with revoked/expired certificates",
    detectionConditions: [
      "Binary executed with no Team ID, no Apple Developer signature, and no organizational code signing certificate",
      "Gatekeeper quarantine attribute present on executing binary — bypassed without MDM exemption",
      "Executable loaded from a temporary directory (/tmp, %TEMP%, ~/Downloads) with no package manager provenance",
      "Signature timestamp on binary more than 90 days in the future — clock skew or timestamp forgery",
      "DLL/dylib loaded without accompanying entitlement plist and parent process is a system service",
    ],
    mitreTechniques: [
      "T1553.002 – Subvert Trust Controls: Code Signing",
      "T1553 – Subvert Trust Controls",
      "T1036.005 – Match Legitimate Name or Location",
      "T1218 – System Binary Proxy Execution",
    ],
    complianceControls: [
      "NIST 800-53 SI-7",
      "CIS Control 10.1",
      "ISO 27001 A.12.5.1",
      "CMMC AC.3.018",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Unsigned Binary Execution.

Detection conditions:
- Binary executed with no Team ID, no Apple Developer signature, and no organizational code signing certificate
- Gatekeeper quarantine attribute present on executing binary — bypassed without MDM exemption
- Executable loaded from a temporary directory (/tmp, %TEMP%, ~/Downloads) with no package manager provenance
- Signature timestamp on binary more than 90 days in the future — clock skew or timestamp forgery
- DLL/dylib loaded without accompanying entitlement plist and parent process is a system service

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1553.002 – Code Signing, T1553, T1036.005, T1218.
Compliance: NIST 800-53 SI-7; CIS Control 10.1; ISO 27001 A.12.5.1.
Output as a code block with inline comments.`,
  },
  {
    id: "cve-exploit-pattern",
    name: "CVE Exploit Pattern Detection",
    zone: 3,
    severity: "CRITICAL",
    description: "Detects exploitation attempts targeting known CVEs via behavioral IOC matching and CVSS/KEV scoring",
    detectionConditions: [
      "Process crash followed immediately by a new shell spawn with elevated privileges — heap spray pattern",
      "Library function return address overwritten — stack canary violation logged by OS crash reporter",
      "Network connection from a process that has never made outbound connections in baseline period",
      "Component version in SBOM or package inventory matches a CVE with CVSS ≥ 9.0 and KEV listing",
      "File write to /etc/passwd, /etc/sudoers, or SAM registry hive from a non-administrative process",
    ],
    mitreTechniques: [
      "T1190 – Exploit Public-Facing Application",
      "T1203 – Exploitation for Client Execution",
      "T1068 – Exploitation for Privilege Escalation",
      "T1211 – Exploitation for Defense Evasion",
    ],
    complianceControls: [
      "NIST 800-53 RA-5",
      "NIST 800-53 SI-2",
      "CIS Control 7.1",
      "PCI DSS 6.3.3",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: CVE Exploit Pattern Detection.

Detection conditions:
- Process crash followed immediately by a new shell spawn with elevated privileges — heap spray pattern
- Library function return address overwritten — stack canary violation logged by OS crash reporter
- Network connection from a process that has never made outbound connections in baseline period
- Component version in SBOM or package inventory matches a CVE with CVSS ≥ 9.0 and KEV listing
- File write to /etc/passwd, /etc/sudoers, or SAM registry hive from a non-administrative process

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1190 – Exploit Public-Facing Application, T1203, T1068, T1211.
Compliance: NIST 800-53 RA-5, SI-2; CIS Control 7.1; PCI DSS 6.3.3.
Output as a code block with inline comments.`,
  },
  {
    id: "dependency-confusion",
    name: "Dependency Confusion Attack",
    zone: 3,
    severity: "HIGH",
    description: "Detects packages installed from public registries that shadow internal private package names",
    detectionConditions: [
      "Package installed from npm/PyPI/RubyGems with the same name as a known internal private package",
      "Package version number on public registry higher than the internal registry version — classic confusion attack",
      "Post-install script in a newly installed package making outbound network connections",
      "Package maintainer email or homepage domain registered within 90 days with no prior history",
      "Internal CI/CD pipeline downloading a package from a fallback public registry not in approved sources",
    ],
    mitreTechniques: [
      "T1195.001 – Supply Chain Compromise: Compromise Software Dependencies",
      "T1072 – Software Deployment Tools",
      "T1059 – Command and Scripting Interpreter",
      "T1078 – Valid Accounts",
    ],
    complianceControls: [
      "NIST 800-53 SA-12",
      "NIST 800-53 CM-3",
      "CIS Control 2.6",
      "SSDF PW.4.2",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Dependency Confusion Attack.

Detection conditions:
- Package installed from npm/PyPI/RubyGems with the same name as a known internal private package
- Package version number on public registry higher than the internal registry version — classic confusion attack
- Post-install script in a newly installed package making outbound network connections
- Package maintainer email or homepage domain registered within 90 days with no prior history
- Internal CI/CD pipeline downloading a package from a fallback public registry not in approved sources

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1195.001 – Supply Chain Compromise, T1072, T1059, T1078.
Compliance: NIST 800-53 SA-12, CM-3; CIS Control 2.6; SSDF PW.4.2.
Output as a code block with inline comments.`,
  },

  // ── Zone 4 — Identity & Persistence ──────────────────────────────────────
  {
    id: "privileged-account-creation",
    name: "Privileged Account Creation",
    zone: 4,
    severity: "CRITICAL",
    description: "Detects creation of new accounts with UID 0, sudo rights, or Domain Admin membership outside provisioning windows",
    detectionConditions: [
      "New local user created with UID=0 or GID=0 and username is not 'root'",
      "User added to wheel, sudo, Administrators, or Domain Admins group by a non-IT-provisioning process",
      "Account creation event outside business hours (22:00–06:00 local) with no approved change ticket correlation",
      "New account with /bin/bash or /bin/zsh shell and home directory under /tmp or non-standard path",
      "Active Directory user account created with AdminCount=1 and no corresponding HR onboarding event",
    ],
    mitreTechniques: [
      "T1136 – Create Account",
      "T1136.001 – Create Account: Local Account",
      "T1136.002 – Create Account: Domain Account",
      "T1098 – Account Manipulation",
    ],
    complianceControls: [
      "NIST 800-53 AC-2",
      "NIST 800-53 AC-6",
      "CIS Control 5.2",
      "SOX ITGC AC-01",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Privileged Account Creation.

Detection conditions:
- New local user created with UID=0 or GID=0 and username is not 'root'
- User added to wheel, sudo, Administrators, or Domain Admins group by a non-IT-provisioning process
- Account creation event outside business hours (22:00–06:00 local) with no approved change ticket correlation
- New account with /bin/bash or /bin/zsh shell and home directory under /tmp or non-standard path
- Active Directory user account created with AdminCount=1 and no corresponding HR onboarding event

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1136 – Create Account, T1136.001, T1136.002, T1098 – Account Manipulation.
Compliance: NIST 800-53 AC-2, AC-6; CIS Control 5.2; SOX ITGC AC-01.
Output as a code block with inline comments.`,
  },
  {
    id: "scheduled-task-implant",
    name: "Scheduled Task Implant",
    zone: 4,
    severity: "HIGH",
    description: "Detects unauthorized cron jobs, LaunchDaemons, or Windows Scheduled Tasks created for persistence",
    detectionConditions: [
      "New LaunchDaemon or LaunchAgent plist created by a process other than an MDM agent or pkg installer",
      "Cron job added that executes a binary from /tmp, ~/Downloads, or a path with world-write permissions",
      "Scheduled Task created on Windows with a RunAsUser other than SYSTEM outside of provisioning tools",
      "Task executable binary hash changed since initial registration — binary swap persistence technique",
      "More than 3 new scheduled tasks created within a 10-minute window on the same host (burst pattern)",
    ],
    mitreTechniques: [
      "T1053 – Scheduled Task/Job",
      "T1053.003 – Cron",
      "T1053.004 – Launchd",
      "T1053.005 – Scheduled Task",
    ],
    complianceControls: [
      "NIST 800-53 CM-7",
      "NIST 800-53 SI-3",
      "CIS Control 10.3",
      "ISO 27001 A.12.1.2",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Scheduled Task Implant.

Detection conditions:
- New LaunchDaemon or LaunchAgent plist created by a process other than an MDM agent or pkg installer
- Cron job added that executes a binary from /tmp, ~/Downloads, or a path with world-write permissions
- Scheduled Task created on Windows with a RunAsUser other than SYSTEM outside of provisioning tools
- Task executable binary hash changed since initial registration — binary swap persistence technique
- More than 3 new scheduled tasks created within a 10-minute window on the same host (burst pattern)

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1053 – Scheduled Task/Job, T1053.003 – Cron, T1053.004 – Launchd, T1053.005.
Compliance: NIST 800-53 CM-7, SI-3; CIS Control 10.3.
Output as a code block with inline comments.`,
  },
  {
    id: "security-service-termination",
    name: "Security Service Termination",
    zone: 4,
    severity: "CRITICAL",
    description: "Detects processes stopping or disabling EDR, AV, logging, or audit services to enable blind-spot attacks",
    detectionConditions: [
      "Falcon Sensor, CrowdStrike agent, SentinelOne, Carbon Black, or Defender service transitions to stopped state",
      "auditd, syslog, or systemd-journald stopped by a process other than systemd or an approved admin account",
      "Process calling TerminateProcess on a known security vendor PID or issuing 'sc stop' / 'net stop' for EDR services",
      "LaunchDaemon for a security tool unloaded via launchctl without MDM authorization",
      "Windows event log service (eventlog) stopped or event log cleared (event ID 1102) by non-SYSTEM",
    ],
    mitreTechniques: [
      "T1562 – Impair Defenses",
      "T1562.001 – Disable or Modify Tools",
      "T1562.002 – Disable Windows Event Logging",
      "T1489 – Service Stop",
    ],
    complianceControls: [
      "NIST 800-53 AU-9",
      "NIST 800-53 SI-4",
      "CIS Control 8.2",
      "PCI DSS 10.6.1",
    ],
    promptText: `You are a senior detection engineer. Generate a complete detection rule for the following module: Security Service Termination.

Detection conditions:
- Falcon Sensor, CrowdStrike agent, SentinelOne, Carbon Black, or Defender service transitions to stopped state
- auditd, syslog, or systemd-journald stopped by a process other than systemd or an approved admin account
- Process calling TerminateProcess on a known security vendor PID or issuing 'sc stop' / 'net stop' for EDR services
- LaunchDaemon for a security tool unloaded via launchctl without MDM authorization
- Windows event log service (eventlog) stopped or event log cleared (event ID 1102) by non-SYSTEM

Target platform: Elastic SIEM / Splunk / Sigma (ask the user which).
Include: rule logic, field mappings, threshold tuning guidance, and false positive mitigations.
MITRE techniques covered: T1562 – Impair Defenses, T1562.001, T1562.002, T1489 – Service Stop.
Compliance: NIST 800-53 AU-9, SI-4; CIS Control 8.2; PCI DSS 10.6.1.
Output as a code block with inline comments.`,
  },
];

// ── Zone metadata ─────────────────────────────────────────────────────────────

const ZONE_COLOR = {
  1: {
    accent: "#DC2626",       // --red-600
    bg: "#FEF5F5",           // --red-50
    lightBg: "#FEE2E2",      // --red-100
    text: "#DC2626",
    badgeBg: "rgba(220,38,38,0.08)",
    badgeBorder: "rgba(220,38,38,0.2)",
  },
  2: {
    accent: "#D97706",       // --amber-600
    bg: "#FFFBF0",           // --amber-50
    lightBg: "#FEF3C7",      // --amber-100
    text: "#D97706",
    badgeBg: "rgba(217,119,6,0.08)",
    badgeBorder: "rgba(217,119,6,0.2)",
  },
  3: {
    accent: "#2563EB",       // --blue-600
    bg: "#F0F9FF",           // --blue-50
    lightBg: "#E0F2FE",      // --blue-100
    text: "#2563EB",
    badgeBg: "rgba(37,99,235,0.08)",
    badgeBorder: "rgba(37,99,235,0.2)",
  },
  4: {
    accent: "#9333EA",       // --purple-600
    bg: "#FAF5FF",           // --purple-50
    lightBg: "#E9D5FF",      // --purple-200
    text: "#9333EA",
    badgeBg: "rgba(147,51,234,0.08)",
    badgeBorder: "rgba(147,51,234,0.2)",
  },
} as const;

interface ZoneMeta {
  id: 1 | 2 | 3 | 4;
  label: string;
  subtitle: string;
  icon: React.ElementType;
}

const ZONES: ZoneMeta[] = [
  {
    id: 1,
    label: "Zone 1 — Endpoint OS Integrity",
    subtitle: "Post-EDR attacker behavior: what they target once inside",
    icon: Cpu,
  },
  {
    id: 2,
    label: "Zone 2 — Network & C2",
    subtitle: "Communication and lateral movement channels",
    icon: Globe,
  },
  {
    id: 3,
    label: "Zone 3 — Supply Chain & Vulnerability",
    subtitle: "Initial access and software-layer persistence",
    icon: Package,
  },
  {
    id: 4,
    label: "Zone 4 — Identity & Persistence",
    subtitle: "Pre-ransomware actions: accounts, tasks, service kills",
    icon: Users,
  },
];

// ── Severity badge ────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "#FEE2E2", text: "#B91C1C", border: "rgba(220,38,38,0.3)" },
  HIGH:     { bg: "#FEF3C7", text: "#B45309", border: "rgba(217,119,6,0.3)"  },
  MEDIUM:   { bg: "#E0F2FE", text: "#1D4ED8", border: "rgba(37,99,235,0.3)" },
};

function SevBadge({ sev }: { sev: "CRITICAL" | "HIGH" | "MEDIUM" }) {
  const s = SEV_STYLES[sev];
  return (
    <span
      style={{
        background: s.bg,
        color: s.text,
        border: `1px solid ${s.border}`,
        borderRadius: 9999,
        padding: "2px 8px",
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.04em",
        textTransform: "uppercase" as const,
      }}
    >
      {sev}
    </span>
  );
}

// ── Module card ───────────────────────────────────────────────────────────────

interface ModuleCardProps {
  module: DetectionModule;
  expanded: boolean;
  onToggle: () => void;
  onGenerate: () => void;
  copied: boolean;
}

function ModuleCard({ module: m, expanded, onToggle, onGenerate, copied }: ModuleCardProps) {
  const zc = ZONE_COLOR[m.zone];

  return (
    <div
      style={{
        background: "#FFFFFF",
        border: `0.5px solid ${expanded ? "rgba(0,0,0,0.18)" : "rgba(0,0,0,0.08)"}`,
        borderRadius: 12,
        padding: "1rem",
        transition: "border-color 0.18s ease",
        cursor: "pointer",
        position: "relative" as const,
      }}
    >
      {/* Card header — always visible */}
      <div
        role="button"
        aria-expanded={expanded}
        tabIndex={0}
        onClick={onToggle}
        onKeyDown={e => (e.key === "Enter" || e.key === " ") && onToggle()}
        style={{ outline: "none" }}
        className="focus-visible:ring-1 focus-visible:ring-[--brand-orange] rounded"
      >
        <div className="flex items-start justify-between gap-2 mb-1.5">
          <span className="text-[13px] font-bold text-[--gray-900] leading-tight">{m.name}</span>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <SevBadge sev={m.severity} />
            <span style={{ color: "#9BA3AF", flexShrink: 0 }}>
              {expanded
                ? <ChevronDown className="w-3.5 h-3.5" />
                : <ChevronRight className="w-3.5 h-3.5" />
              }
            </span>
          </div>
        </div>
        <p className="text-[12px] text-[--gray-500] leading-relaxed">{m.description}</p>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div
          style={{
            marginTop: "1rem",
            paddingTop: "1rem",
            borderTop: "1px solid rgba(0,0,0,0.06)",
            animation: "expandIn 0.18s ease",
          }}
        >
          {/* Detection conditions */}
          <div className="mb-4">
            <p
              className="text-[10px] font-bold uppercase tracking-widest mb-2"
              style={{ color: "#6C7383", letterSpacing: "0.1em" }}
            >
              Detection Conditions
            </p>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {m.detectionConditions.map((c, i) => (
                <li
                  key={i}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 8,
                    fontSize: 13,
                    color: "#374151",
                    marginBottom: 6,
                    lineHeight: 1.5,
                  }}
                >
                  <span
                    style={{
                      width: 5,
                      height: 5,
                      borderRadius: "50%",
                      background: zc.accent,
                      marginTop: 6,
                      flexShrink: 0,
                    }}
                  />
                  {c}
                </li>
              ))}
            </ul>
          </div>

          {/* MITRE ATT&CK */}
          <div className="mb-4">
            <p
              className="text-[10px] font-bold uppercase tracking-widest mb-2"
              style={{ color: "#6C7383", letterSpacing: "0.1em" }}
            >
              MITRE ATT&CK
            </p>
            <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 5 }}>
              {m.mitreTechniques.map((t, i) => {
                const [id, ...rest] = t.split(" – ");
                return (
                  <span
                    key={i}
                    style={{
                      background: "#1F2937",
                      color: "#E0F2FE",
                      borderRadius: 5,
                      padding: "2px 7px",
                      fontSize: 11,
                      fontFamily: "monospace",
                      fontWeight: 600,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    {id}
                    {rest.length > 0 && (
                      <span style={{ color: "#9BA3AF", fontFamily: "inherit", fontWeight: 400 }}>
                        · {rest.join(" – ")}
                      </span>
                    )}
                  </span>
                );
              })}
            </div>
          </div>

          {/* Compliance controls */}
          <div className="mb-4">
            <p
              className="text-[10px] font-bold uppercase tracking-widest mb-2"
              style={{ color: "#6C7383", letterSpacing: "0.1em" }}
            >
              Compliance Controls
            </p>
            <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 5 }}>
              {m.complianceControls.map((c, i) => (
                <span
                  key={i}
                  style={{
                    background: "transparent",
                    color: "#4D5562",
                    border: "1px solid #D2D6DC",
                    borderRadius: 5,
                    padding: "2px 8px",
                    fontSize: 11,
                    fontWeight: 500,
                  }}
                >
                  {c}
                </span>
              ))}
            </div>
          </div>

          {/* Generate button */}
          <button
            onClick={e => { e.stopPropagation(); onGenerate(); }}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 7,
              padding: "7px 14px",
              background: copied ? "#059669" : "#E8581A",
              color: "#fff",
              border: "none",
              borderRadius: 8,
              fontSize: 12,
              fontWeight: 600,
              cursor: "pointer",
              transition: "background 0.2s ease",
              width: "100%",
              justifyContent: "center",
            }}
          >
            {copied ? (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                Prompt copied to clipboard
              </>
            ) : (
              <>
                Generate detection code for {m.name}
                <ExternalLink className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function DetectionCoverage() {
  const [severityFilter, setSeverityFilter] = useState<"ALL" | "CRITICAL" | "HIGH">("ALL");
  const [expandedCards, setExpandedCards] = useState<Record<number, string | null>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const toggleCard = useCallback((zoneId: number, moduleId: string) => {
    setExpandedCards(prev => ({
      ...prev,
      [zoneId]: prev[zoneId] === moduleId ? null : moduleId,
    }));
  }, []);

  const handleGenerate = useCallback((module: DetectionModule) => {
    sendPrompt(module.promptText);
    setCopiedId(module.id);
    setTimeout(() => setCopiedId(null), 2500);
  }, []);

  const visibleModules = severityFilter === "ALL"
    ? MODULES
    : MODULES.filter(m => m.severity === severityFilter);

  const totalVisible = visibleModules.length;

  return (
    <div style={{ fontFamily: "inherit" }}>
      <style>{`
        @keyframes expandIn {
          from { opacity: 0; transform: translateY(-4px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      {/* ── Page header ──────────────────────────────────────────────────── */}
      <div
        style={{
          background: "linear-gradient(to right, #FFF7F2, #FFFFFF)",
          border: "1px solid #E4E7EB",
          borderLeft: "4px solid #E8581A",
          borderRadius: 8,
          padding: "16px 20px",
          marginBottom: 20,
        }}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div
              style={{
                width: 36, height: 36, borderRadius: 8,
                background: "rgba(232,88,26,0.1)",
                border: "1px solid rgba(232,88,26,0.2)",
                display: "flex", alignItems: "center", justifyContent: "center",
                flexShrink: 0, marginTop: 2,
              }}
            >
              <Layers className="w-4 h-4" style={{ color: "#E8581A" }} />
            </div>
            <div>
              <h1 className="text-base font-bold text-[--gray-900] mb-0.5">Detection Coverage Dashboard</h1>
              <p className="text-xs font-medium text-[--gray-500] mb-1">14 modules · 4 attack surface zones</p>
              <p className="text-xs text-[--gray-600] leading-relaxed max-w-2xl">
                End-to-end view of the AttackLens detection surface — from endpoint OS integrity through supply chain, network C2, and identity persistence. Each module maps to MITRE ATT&CK techniques and compliance controls.
              </p>
            </div>
          </div>

          {/* KPIs */}
          <div className="flex items-center gap-5 flex-shrink-0">
            {[
              { label: "Total modules", value: 14, color: "#374151" },
              { label: "Critical", value: MODULES.filter(m => m.severity === "CRITICAL").length, color: "#DC2626" },
              { label: "High",     value: MODULES.filter(m => m.severity === "HIGH").length,     color: "#D97706" },
            ].map(k => (
              <div key={k.label} className="text-center">
                <div className="text-xl font-black leading-none" style={{ color: k.color }}>{k.value}</div>
                <div className="text-[10px] text-[--gray-500] font-medium mt-0.5">{k.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Sticky filter bar ─────────────────────────────────────────────── */}
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 20,
          background: "rgba(247,248,250,0.95)",
          backdropFilter: "blur(8px)",
          borderBottom: "1px solid #E4E7EB",
          padding: "10px 0",
          marginBottom: 24,
          display: "flex",
          alignItems: "center",
          gap: 10,
        }}
      >
        <span className="text-[11px] font-bold text-[--gray-500] uppercase tracking-wide mr-1">Severity</span>
        <div role="group" aria-label="Severity filter" style={{ display: "flex", gap: 6 }}>
          {(["ALL", "CRITICAL", "HIGH"] as const).map(f => {
            const active = severityFilter === f;
            const colors: Record<string, [string, string]> = {
              ALL:      ["#374151", "rgba(55,65,81,0.08)"],
              CRITICAL: ["#DC2626", "rgba(220,38,38,0.1)"],
              HIGH:     ["#D97706", "rgba(217,119,6,0.1)"],
            };
            const [c, bg] = colors[f];
            return (
              <button
                key={f}
                onClick={() => setSeverityFilter(f)}
                style={{
                  padding: "4px 12px",
                  borderRadius: 9999,
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.04em",
                  textTransform: "uppercase" as const,
                  cursor: "pointer",
                  border: active ? `1.5px solid ${c}` : "1.5px solid #E4E7EB",
                  background: active ? bg : "transparent",
                  color: active ? c : "#6C7383",
                  transition: "all 0.15s ease",
                }}
              >
                {f}
              </button>
            );
          })}
        </div>
        <span
          className="text-[11px] text-[--gray-400] font-medium ml-auto"
          style={{ marginLeft: "auto" }}
        >
          {totalVisible} / 14 modules visible
        </span>
      </div>

      {/* ── Zone sections ─────────────────────────────────────────────────── */}
      <div style={{ display: "flex", flexDirection: "column" as const, gap: "2rem" }}>
        {ZONES.map(zone => {
          const zoneModules = visibleModules.filter(m => m.zone === zone.id);
          if (zoneModules.length === 0) return null;

          const totalInZone = MODULES.filter(m => m.zone === zone.id).length;
          const zc = ZONE_COLOR[zone.id];
          const ZoneIcon = zone.icon;

          return (
            <section key={zone.id} aria-label={zone.label}>
              {/* Zone header */}
              <div
                style={{
                  borderLeft: `3px solid ${zc.accent}`,
                  paddingLeft: 14,
                  marginBottom: 14,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap" as const,
                  gap: 8,
                }}
              >
                <div className="flex items-center gap-2.5">
                  <div
                    style={{
                      width: 28, height: 28, borderRadius: 7,
                      background: zc.badgeBg,
                      border: `1px solid ${zc.badgeBorder}`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <ZoneIcon className="w-3.5 h-3.5" style={{ color: zc.accent }} />
                  </div>
                  <div>
                    <div className="text-[13px] font-bold text-[--gray-900]">{zone.label}</div>
                    <div className="text-[11px] text-[--gray-500]">{zone.subtitle}</div>
                  </div>
                </div>

                {/* Coverage chip */}
                <span
                  style={{
                    background: zc.badgeBg,
                    color: zc.text,
                    border: `1px solid ${zc.badgeBorder}`,
                    borderRadius: 9999,
                    padding: "3px 10px",
                    fontSize: 11,
                    fontWeight: 700,
                  }}
                >
                  {zoneModules.length} / {totalInZone} modules
                </span>
              </div>

              {/* Module grid */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                  gap: 12,
                }}
              >
                {zoneModules.map(module => (
                  <ModuleCard
                    key={module.id}
                    module={module}
                    expanded={expandedCards[module.zone] === module.id}
                    onToggle={() => toggleCard(module.zone, module.id)}
                    onGenerate={() => handleGenerate(module)}
                    copied={copiedId === module.id}
                  />
                ))}
              </div>
            </section>
          );
        })}
      </div>

      {/* Empty state when filter returns nothing */}
      {totalVisible === 0 && (
        <div
          className="flex flex-col items-center justify-center py-20 text-center"
          style={{ color: "#9BA3AF" }}
        >
          <Shield className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium">No modules match the current filter</p>
          <p className="text-xs mt-1">Try selecting ALL to see all 14 modules</p>
        </div>
      )}
    </div>
  );
}
