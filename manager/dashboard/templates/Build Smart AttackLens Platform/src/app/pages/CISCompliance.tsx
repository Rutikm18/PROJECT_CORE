/**
 * CISCompliance — Senior compliance engineer view.
 *
 * Fleet-wide CIS benchmark status across all enrolled agents.
 * Worst-case aggregation: a check FAILS fleet-wide if it fails on ANY agent.
 *
 * Tracking workflow per check:
 *   Open → In Progress → Remediated | Risk Accepted | False Positive
 *
 * Data: GET /api/v1/posture/agents  +  GET /api/v1/posture/{id} per agent
 */
import { useState, useEffect, useCallback, useMemo } from "react";
import {
  ShieldCheck, RefreshCw, AlertTriangle, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, AlertCircle, HelpCircle, Download,
  ClipboardList, Search, Filter, User, Calendar, FileText,
  Save, Target, Info, Sparkles, X, Clock, Users, Activity,
  TrendingUp, Shield,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API    = "/api/v1/posture";
const HF_API = "https://api-inference.huggingface.co/models/google/flan-t5-base";
const LS_KEY = "al_cis_track_v3";

// ── Types ─────────────────────────────────────────────────────────────────────

type CheckStatus    = "pass" | "fail" | "warn" | "unknown";
type TrackingStatus = "open" | "in_progress" | "remediated" | "risk_accepted" | "false_positive";

interface AgentSummary {
  agent_id: string; hostname: string; status: string;
  score: number; grade: string; fail: number; warn: number;
  pass: number; total: number; has_data: boolean; last_seen: number;
}

interface Check {
  id: string; name: string;
  cis_control: number; cis_label: string;
  severity: string; status: CheckStatus;
  actual: string; mitre: string; remediation: string;
}

interface PostureDetail {
  agent_id: string; hostname: string; last_seen: number;
  score: { score: number; grade: string };
  checks: Check[]; has_data: boolean;
}

interface AgentResult {
  hostname: string; agent_id: string; status: CheckStatus; actual: string;
}

interface FleetCheck extends Check {
  fleet_status:   CheckStatus;
  agent_results:  AgentResult[];
  pass_count:     number;
  fail_count:     number;
  warn_count:     number;
  total_agents:   number;
}

interface TrackingRecord {
  status:    TrackingStatus;
  notes:     string;
  assignee:  string;
  due_date:  string;
  updated_at: number;
}

// ── CIS macOS Benchmark accurate reference table ───────────────────────────────
// Maps check ID → CIS macOS Benchmark v3.x section + metadata

const CIS_REF: Record<string, {
  section:  string;
  fullName: string;
  ig:       1 | 2 | 3;
  level:    1 | 2;
  category: string;
  rationale: string;
  expected:  string;
  impact:    string;
  steps:     string[];
  refs:      string[];
}> = {
  SIP: {
    section:  "§ 4.1",
    fullName: "Ensure System Integrity Protection (SIP) Is Enabled",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "SIP prevents root-level processes from modifying protected system files, directories, and kernel extensions — the primary defense against rootkit installation.",
    expected:  "csrutil status → 'System Integrity Protection status: enabled'",
    impact:    "CRITICAL: Without SIP any process with root access can install kernel-level rootkits, modify system binaries, and persist invisibly.",
    steps: [
      "SIP can only be enabled from macOS Recovery Mode — do NOT disable in production",
      "Intel Mac: Reboot → hold Cmd+R → Utilities → Terminal → csrutil enable → reboot",
      "Apple Silicon: Shutdown → hold Power until Options appear → Continue → Terminal → csrutil enable",
      "Verify after reboot: csrutil status",
    ],
    refs: ["CIS macOS Benchmark v3.0 §4.1", "Apple Platform Security Guide", "NIST SP 800-123"],
  },
  FV2: {
    section:  "§ 2.5.1",
    fullName: "Ensure FileVault Is Enabled",
    ig: 1, level: 1,
    category: "Data Protection",
    rationale: "FileVault encrypts the entire startup disk using XTS-AES-128 with a 256-bit key. Without it, all data is accessible to anyone with physical access or cold-boot attack.",
    expected:  "fdesetup status → 'FileVault is On.'",
    impact:    "CRITICAL: A stolen or lost device exposes all data, credentials, certificates, and secrets without encryption.",
    steps: [
      "System Settings → Privacy & Security → FileVault → Turn On FileVault",
      "Store recovery key in institutional key escrow or secure password manager",
      "CLI: sudo fdesetup enable (interactive, will prompt for user password)",
      "Verify: fdesetup status",
      "Note: Encryption runs in background, may take hours on large disks",
    ],
    refs: ["CIS macOS Benchmark v3.0 §2.5.1", "NIST SP 800-111", "FIPS 140-3"],
  },
  GK: {
    section:  "§ 2.6.1",
    fullName: "Ensure Gatekeeper Is Enabled",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "Gatekeeper verifies that downloaded apps are signed by an Apple-identified developer and notarised by Apple, blocking unsigned or malicious binaries.",
    expected:  "spctl --status → 'assessments enabled'",
    impact:    "HIGH: Users can run any unsigned binary including malware, trojans, and pirated software without warning.",
    steps: [
      "System Settings → Privacy & Security → Security → 'App Store and identified developers'",
      "CLI: sudo spctl --global-enable",
      "Verify: spctl --status",
      "For stricter control, set to 'App Store' only",
    ],
    refs: ["CIS macOS Benchmark v3.0 §2.6.1", "Apple Security Overview", "NIST SP 800-167"],
  },
  FW: {
    section:  "§ 3.5",
    fullName: "Enable Application Firewall",
    ig: 1, level: 1,
    category: "Network Infrastructure",
    rationale: "The macOS Application Firewall controls inbound connections per-application, blocking unsolicited network access to services and reducing the external attack surface.",
    expected:  "socketfilterfw --getglobalstate → 'Firewall is enabled'",
    impact:    "HIGH: Without the firewall, any application can receive inbound connections, enabling lateral movement if the host is on an internal network.",
    steps: [
      "System Settings → Network → Firewall → Turn On Firewall",
      "Enable 'Block all incoming connections' for maximum security (enables stealth mode)",
      "CLI: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
      "Enable stealth mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
      "Verify: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
    ],
    refs: ["CIS macOS Benchmark v3.0 §3.5", "NIST SP 800-41", "PCI DSS v4.0 Req 1.3"],
  },
  SB: {
    section:  "§ 5.3",
    fullName: "Ensure Secure Boot Level Is Full Security",
    ig: 1, level: 2,
    category: "Secure Configuration",
    rationale: "Full Security ensures only Apple-signed operating systems boot on this Mac, preventing bootkits and unauthorized OS installation.",
    expected:  "Secure Boot Level = 'Full Security' (0x02 in nvram)",
    impact:    "HIGH: Without Full Security, an attacker with physical access can boot a malicious OS that bypasses all OS-level controls.",
    steps: [
      "Intel Mac with T2: Reboot → Cmd+R → Utilities → Startup Security Utility → Full Security",
      "Apple Silicon: Shutdown → hold Power → Continue → Startup Security Utility → Full Security",
      "This setting requires a firmware password or admin credential to change",
      "Verify: system_profiler SPiBridgeDataType | grep 'Secure Boot'",
    ],
    refs: ["CIS macOS Benchmark v3.0 §5.3", "Apple T2 Security Chip Overview", "NIST SP 800-147"],
  },
  AU: {
    section:  "§ 1.1",
    fullName: "Ensure All Apple-provided Software Is Current",
    ig: 1, level: 1,
    category: "Vulnerability Management",
    rationale: "Unpatched software is the #1 attack vector. Automatic updates ensure Rapid Security Responses (RSRs) and kernel patches are applied within hours of release.",
    expected:  "AutomaticCheckEnabled = 1, AutomaticDownload = 1, AutomaticallyInstallMacOSUpdates = 1",
    impact:    "HIGH: Known CVEs (including CISA KEV entries) remain exploitable indefinitely on unpatched systems.",
    steps: [
      "System Settings → General → Software Update → Automatic Updates → Turn All On",
      "Specifically enable: Download new updates when available, Install macOS updates, Install app updates, Install Security Responses and system files",
      "CLI verify: defaults read /Library/Preferences/com.apple.SoftwareUpdate",
      "Check for pending updates: softwareupdate -l",
    ],
    refs: ["CIS macOS Benchmark v3.0 §1.1", "CISA Known Exploited Vulnerabilities Catalog", "NIST SP 800-40"],
  },
  SCR: {
    section:  "§ 5.8.1",
    fullName: "Ensure Screensaver Requires a Password to Wake",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "Requiring a password on screensaver wake prevents unauthorized physical access when a user leaves their workstation unattended.",
    expected:  "askForPassword = 1 in com.apple.screensaver",
    impact:    "HIGH: An unattended unlocked Mac provides full access to all data, applications, and credentials stored on the device.",
    steps: [
      "System Settings → Lock Screen → 'Require password after screen saver begins or display is turned off': set to 'Immediately'",
      "CLI: defaults write com.apple.screensaver askForPassword -int 1",
      "CLI: defaults write com.apple.screensaver askForPasswordDelay -int 0",
      "Verify: defaults read com.apple.screensaver askForPassword",
    ],
    refs: ["CIS macOS Benchmark v3.0 §5.8.1", "NIST SP 800-53 AC-11", "ISO 27001 A.11.2.9"],
  },
  STO: {
    section:  "§ 5.8.2",
    fullName: "Ensure Screensaver Idle Timeout Is 5 Minutes or Less",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "A short idle timeout limits the window of exposure if a user leaves their workstation without manually locking it.",
    expected:  "idleTime ≤ 300 seconds (5 minutes)",
    impact:    "MEDIUM: A long or disabled timeout means an unattended workstation remains unlocked for an extended period.",
    steps: [
      "System Settings → Lock Screen → 'Start Screen Saver after': set to 5 minutes or less",
      "System Settings → Lock Screen → 'Turn display off on battery when inactive': 5 min or less",
      "CLI: defaults -currentHost write com.apple.screensaver idleTime -int 300",
      "Verify: defaults -currentHost read com.apple.screensaver idleTime",
    ],
    refs: ["CIS macOS Benchmark v3.0 §5.8.2", "NIST SP 800-53 AC-11(1)"],
  },
  SSH: {
    section:  "§ 3.2",
    fullName: "Ensure SSH Access Is Limited (No Password Auth)",
    ig: 1, level: 1,
    category: "Account Management",
    rationale: "SSH with password authentication is vulnerable to brute-force and credential-stuffing attacks. It should be disabled or restricted to key-based authentication.",
    expected:  "SSH disabled OR PasswordAuthentication = no in /etc/ssh/sshd_config",
    impact:    "HIGH: SSH with password auth is a top target for automated credential attacks. Compromise gives full shell access.",
    steps: [
      "If SSH not required: System Settings → General → Sharing → Remote Login → OFF",
      "If SSH is required: edit /etc/ssh/sshd_config",
      "  Set: PasswordAuthentication no",
      "  Set: ChallengeResponseAuthentication no",
      "  Set: PubkeyAuthentication yes",
      "Restart SSH: sudo launchctl kickstart -k system/com.openssh.sshd",
      "Verify: ssh -o PasswordAuthentication=yes localhost (should be rejected)",
    ],
    refs: ["CIS macOS Benchmark v3.0 §3.2", "NIST SP 800-53 IA-2(8)", "NSA IAD SSH Guidelines"],
  },
  SRL: {
    section:  "§ 3.2.1",
    fullName: "Ensure SSH PermitRootLogin Is Disabled",
    ig: 1, level: 1,
    category: "Account Management",
    rationale: "Disabling root SSH login forces attackers to first compromise a regular account then escalate, adding an additional defensive layer.",
    expected:  "PermitRootLogin = no (or prohibit-password) in /etc/ssh/sshd_config",
    impact:    "MEDIUM: Direct root SSH access eliminates the audit trail from regular user login and gives attackers immediate privileged access.",
    steps: [
      "Edit /etc/ssh/sshd_config (requires sudo)",
      "Add or update: PermitRootLogin no",
      "Restart SSH: sudo launchctl kickstart -k system/com.openssh.sshd",
      "Verify: grep PermitRootLogin /etc/ssh/sshd_config",
    ],
    refs: ["CIS macOS Benchmark v3.0 §3.2.1", "NIST SP 800-53 AC-6(2)", "PCI DSS v4.0 Req 8.6"],
  },
  SCN: {
    section:  "§ 3.6",
    fullName: "Ensure Screen Sharing (VNC) Is Disabled",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "Screen Sharing enables VNC access to the desktop which provides full graphical control. It should be disabled unless explicitly required and access-controlled.",
    expected:  "com.apple.screensharing LaunchDaemon not loaded",
    impact:    "MEDIUM: VNC without proper authentication gives attackers graphical desktop access with no audit trail.",
    steps: [
      "System Settings → General → Sharing → Screen Sharing → toggle OFF",
      "CLI: sudo launchctl disable system/com.apple.screensharing",
      "CLI: sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist",
      "Verify: launchctl list com.apple.screensharing (should show error = not found)",
    ],
    refs: ["CIS macOS Benchmark v3.0 §3.6", "NIST SP 800-53 AC-17", "ISO 27001 A.9.4.2"],
  },
  ARD: {
    section:  "§ 3.7",
    fullName: "Ensure Remote Management (ARD) Is Disabled",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "Apple Remote Desktop allows full remote control of the system. If not explicitly required for IT management, it should be disabled to reduce attack surface.",
    expected:  "Remote Management: Off (systemsetup -getremoteappleevents → 'Remote Apple Events: Off')",
    impact:    "MEDIUM: ARD exposes the system to remote desktop attacks and can be exploited for lateral movement.",
    steps: [
      "System Settings → General → Sharing → Remote Management → toggle OFF",
      "CLI: sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
      "Verify: systemsetup -getremoteappleevents",
    ],
    refs: ["CIS macOS Benchmark v3.0 §3.7", "NIST SP 800-53 AC-17(1)"],
  },
  XP: {
    section:  "§ 1.2",
    fullName: "Ensure XProtect and Malware Removal Tool Are Current",
    ig: 1, level: 1,
    category: "Malware Defenses",
    rationale: "XProtect is Apple's built-in malware signature database. Keeping it current ensures known macOS malware families are detected and blocked on launch.",
    expected:  "XProtect version > 0 (auto-updates via SoftwareUpdate)",
    impact:    "MEDIUM: Outdated malware signatures miss recently discovered malware families.",
    steps: [
      "XProtect updates automatically via Apple's software update infrastructure",
      "Ensure AutomaticCheckEnabled = 1 in com.apple.SoftwareUpdate",
      "Check version: defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString",
      "Force update check: sudo softwareupdate -l",
    ],
    refs: ["CIS macOS Benchmark v3.0 §1.2", "Apple Security Updates", "NIST SP 800-83"],
  },
  CFG: {
    section:  "§ 4.6",
    fullName: "Ensure No Shell Configuration Backdoors Exist",
    ig: 1, level: 1,
    category: "Secure Configuration",
    rationale: "Shell configuration files (.zshrc, .bash_profile, etc.) can be abused to persist malicious code executed on every login. Download-cradle patterns (curl|sh, eval base64) indicate active backdoors.",
    expected:  "No suspicious patterns in shell config files and authorized_keys",
    impact:    "HIGH: A backdoored shell config executes malicious code for every interactive session — persistence that survives reboots.",
    steps: [
      "Review all flagged files manually for download-cradle patterns",
      "Common patterns to remove: curl ... | sh, wget ... | bash, eval $(base64 -d ...), osascript -e",
      "Check all users: for user in /Users/*; do cat $user/.zshrc $user/.bashrc 2>/dev/null; done",
      "Review /etc/zshrc and /etc/bashrc for system-wide backdoors",
      "Check authorized_keys: find /Users -name 'authorized_keys' -exec cat {} \\;",
    ],
    refs: ["CIS macOS Benchmark v3.0 §4.6", "MITRE ATT&CK T1546.004", "NIST SP 800-53 CM-7"],
  },
  DT: {
    section:  "§ 4.9",
    fullName: "Ensure Developer Tools Access Is Restricted",
    ig: 2, level: 2,
    category: "Secure Configuration",
    rationale: "Developer Tools Security controls whether debuggers can be attached to non-root processes. Enabling it for all users allows any user-space process to inspect and modify other processes.",
    expected:  "DevToolsSecurity: disabled (or restricted to Developer Tools group)",
    impact:    "LOW: Over-permissive developer tools access allows debugging/injection of other processes (privilege escalation vector).",
    steps: [
      "Restrict to specific users only: sudo DevToolsSecurity -disable",
      "Or add only required users to the developer tools group",
      "Verify: DevToolsSecurity -status",
      "Consider using endpoint MDM to enforce this policy fleet-wide",
    ],
    refs: ["CIS macOS Benchmark v3.0 §4.9", "Apple Developer Documentation", "NIST SP 800-53 CM-6"],
  },
  LM: {
    section:  "§ 2.14",
    fullName: "Ensure Lockdown Mode Is Enabled (High-Risk Users)",
    ig: 3, level: 2,
    category: "Secure Configuration",
    rationale: "Lockdown Mode (macOS 13+) dramatically reduces the attack surface by disabling message link previews, wired connections, configuration profiles, and limiting web features. Recommended for executives and high-value targets.",
    expected:  "com.apple.security.lockdown = 1 (launchd environment)",
    impact:    "LOW: High-risk users (executives, journalists, activists) are more likely targets of sophisticated spyware like Pegasus.",
    steps: [
      "System Settings → Privacy & Security → Lockdown Mode → Turn On Lockdown Mode",
      "Requires device restart to take effect",
      "Note: Lockdown Mode intentionally reduces usability — deploy selectively for high-risk users",
      "Verify: launchctl getenv com.apple.security.lockdown (should return '1')",
    ],
    refs: ["CIS macOS Benchmark v3.0 §2.14", "Apple Lockdown Mode", "Citizen Lab Research on Pegasus"],
  },
};

// ── Tracking helpers ──────────────────────────────────────────────────────────

function lsGet<T>(key: string, def: T): T {
  try { return JSON.parse(localStorage.getItem(key) ?? "") ?? def; } catch { return def; }
}
function lsSet(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }

function getTracking(): Record<string, TrackingRecord> { return lsGet(LS_KEY, {}); }
function setTracking(r: Record<string, TrackingRecord>) { lsSet(LS_KEY, r); }

// ── Design constants ──────────────────────────────────────────────────────────

const GRADE_COLOR: Record<string, string> = {
  A: "#16a34a", B: "#2563eb", C: "#d97706", D: "#ea580c", F: "#dc2626",
};

const STATUS_CFG: Record<CheckStatus, { badge: string; dot: string; label: string; icon: React.ReactNode }> = {
  pass:    { badge: "bg-green-50 text-green-700 border-green-200",  dot: "bg-green-500",            label: "PASS",    icon: <CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> },
  fail:    { badge: "bg-red-50 text-red-700 border-red-200",        dot: "bg-red-500 animate-pulse", label: "FAIL",    icon: <XCircle      className="w-3.5 h-3.5 text-red-500" />   },
  warn:    { badge: "bg-amber-50 text-amber-700 border-amber-200",  dot: "bg-amber-400",            label: "WARN",    icon: <AlertCircle  className="w-3.5 h-3.5 text-amber-500" /> },
  unknown: { badge: "bg-gray-100 text-gray-500 border-gray-200",    dot: "bg-gray-300",             label: "N/A",     icon: <HelpCircle   className="w-3.5 h-3.5 text-gray-400" />  },
};

const TRACK_CFG: Record<TrackingStatus, { label: string; badge: string; dot: string }> = {
  open:           { label: "Open",           badge: "bg-gray-100 text-gray-600 border-gray-300",       dot: "bg-gray-400"   },
  in_progress:    { label: "In Progress",    badge: "bg-blue-50 text-blue-700 border-blue-200",        dot: "bg-blue-500"   },
  remediated:     { label: "Remediated",     badge: "bg-green-50 text-green-700 border-green-200",     dot: "bg-green-500"  },
  risk_accepted:  { label: "Risk Accepted",  badge: "bg-amber-50 text-amber-700 border-amber-200",     dot: "bg-amber-500"  },
  false_positive: { label: "False Positive", badge: "bg-purple-50 text-purple-700 border-purple-200",  dot: "bg-purple-400" },
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high:     "bg-amber-50 text-amber-700 border-amber-200",
  medium:   "bg-blue-50 text-blue-700 border-blue-200",
  low:      "bg-gray-100 text-gray-500 border-gray-200",
};

const IG_BADGE: Record<number, string> = {
  1: "bg-green-100 text-green-800 border-green-200",
  2: "bg-blue-100 text-blue-800 border-blue-200",
  3: "bg-purple-100 text-purple-800 border-purple-200",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function relTime(ts: number): string {
  if (!ts) return "—";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const STATUS_ORDER: Record<string, number> = { fail: 3, warn: 2, unknown: 1, pass: 0 };

function worstStatus(statuses: CheckStatus[]): CheckStatus {
  return statuses.reduce((w, s) =>
    (STATUS_ORDER[s] ?? 0) > (STATUS_ORDER[w] ?? 0) ? s : w
  , "pass" as CheckStatus);
}

function aggregateFleet(details: PostureDetail[]): FleetCheck[] {
  const byId = new Map<string, { base: Check; results: AgentResult[] }>();
  for (const d of details) {
    for (const c of d.checks) {
      if (!byId.has(c.id)) byId.set(c.id, { base: c, results: [] });
      byId.get(c.id)!.results.push({
        hostname:  d.hostname,
        agent_id:  d.agent_id,
        status:    c.status,
        actual:    c.actual,
      });
    }
  }
  return Array.from(byId.values()).map(({ base, results }) => ({
    ...base,
    fleet_status:  worstStatus(results.map(r => r.status)),
    agent_results: results,
    pass_count:    results.filter(r => r.status === "pass").length,
    fail_count:    results.filter(r => r.status === "fail").length,
    warn_count:    results.filter(r => r.status === "warn").length,
    total_agents:  results.length,
  }));
}

async function simplifyWithAI(text: string): Promise<string> {
  const res = await fetch(HF_API, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({
      inputs:     `Explain this security fix in 2 simple sentences for a manager: ${text}`,
      parameters: { max_new_tokens: 120, temperature: 0.3 },
    }),
  });
  if (!res.ok) throw new Error(`HF ${res.status}`);
  const d = await res.json();
  if (Array.isArray(d) && d[0]?.generated_text) return d[0].generated_text;
  if (d?.generated_text)                        return d.generated_text;
  if (d?.error)                                 throw new Error(d.error);
  throw new Error("No output");
}

// ── CSV export ────────────────────────────────────────────────────────────────

function exportCSV(checks: FleetCheck[], tracking: Record<string, TrackingRecord>) {
  const rows = [
    "ID,CIS Section,Name,Category,IG,Severity,Fleet Status,Pass,Fail,Warn,Tracking,Assignee,Due Date,Notes",
    ...checks.map(c => {
      const ref  = CIS_REF[c.id];
      const t    = tracking[c.id];
      return [
        c.id,
        ref?.section ?? `CIS-${c.cis_control}`,
        `"${c.name}"`,
        ref?.category ?? c.cis_label,
        ref?.ig ?? "",
        c.severity,
        c.fleet_status,
        c.pass_count,
        c.fail_count,
        c.warn_count,
        t?.status ?? "open",
        `"${t?.assignee ?? ""}"`,
        t?.due_date ?? "",
        `"${(t?.notes ?? "").replace(/"/g, "'")}"`,
      ].join(",");
    }),
  ].join("\n");
  const a = Object.assign(document.createElement("a"), {
    href:     URL.createObjectURL(new Blob([rows], { type: "text/csv" })),
    download: `cis-compliance-${new Date().toISOString().slice(0, 10)}.csv`,
  });
  a.click(); URL.revokeObjectURL(a.href);
}

// ── Tracking form ─────────────────────────────────────────────────────────────

function TrackingForm({
  checkId, initial, onSave, onClose,
}: {
  checkId: string;
  initial: TrackingRecord;
  onSave: (r: TrackingRecord) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<TrackingRecord>({ ...initial });
  const upd = (k: keyof TrackingRecord, v: string) => setForm(f => ({ ...f, [k]: v }));

  return (
    <div className="rounded-xl border border-blue-200 bg-blue-50 overflow-hidden mt-3">
      <div className="flex items-center justify-between px-4 py-2.5 bg-blue-100/70 border-b border-blue-200">
        <div className="flex items-center gap-1.5">
          <ClipboardList className="w-3.5 h-3.5 text-blue-700" />
          <span className="text-[10px] font-black text-blue-800 uppercase tracking-wide">Track Finding</span>
        </div>
        <button onClick={onClose} className="text-blue-400 hover:text-blue-600">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="p-4 space-y-3">
        {/* Status selector */}
        <div>
          <div className="text-[9px] font-bold text-gray-500 uppercase tracking-wide mb-1.5">Finding Status</div>
          <div className="flex flex-wrap gap-1.5">
            {(Object.entries(TRACK_CFG) as [TrackingStatus, typeof TRACK_CFG[TrackingStatus]][]).map(([k, c]) => (
              <button key={k} onClick={() => upd("status", k)}
                className={cn(
                  "px-2.5 py-1 rounded-full border text-[9px] font-bold transition-all",
                  form.status === k ? c.badge + " shadow-sm" : "bg-white text-gray-500 border-gray-200 hover:bg-gray-50"
                )}>
                {c.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {/* Assignee */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
              <User className="w-3 h-3" />Assigned To
            </label>
            <input
              type="text" placeholder="analyst@company.com"
              value={form.assignee}
              onChange={e => upd("assignee", e.target.value)}
              className="w-full px-3 py-1.5 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-blue-300"
            />
          </div>
          {/* Due date */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
              <Calendar className="w-3 h-3" />Due Date
            </label>
            <input
              type="date"
              value={form.due_date}
              onChange={e => upd("due_date", e.target.value)}
              className="w-full px-3 py-1.5 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-blue-300"
            />
          </div>
        </div>

        {/* Notes */}
        <div>
          <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
            <FileText className="w-3 h-3" />Notes / Justification
          </label>
          <textarea
            rows={2} placeholder="Add context, justification for risk acceptance, or remediation notes…"
            value={form.notes}
            onChange={e => upd("notes", e.target.value)}
            className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-blue-200 focus:border-blue-300 resize-none"
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-1">
          <button onClick={onClose}
            className="px-3 py-1.5 text-[10px] font-semibold text-gray-500 hover:text-gray-700 border border-gray-200 rounded-lg bg-white transition-colors">
            Cancel
          </button>
          <button
            onClick={() => { onSave({ ...form, updated_at: Math.floor(Date.now() / 1000) }); onClose(); }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition-colors">
            <Save className="w-3 h-3" />Save
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Check row ─────────────────────────────────────────────────────────────────

function CheckRow({
  check, tracking, onTrackingUpdate,
}: {
  check: FleetCheck;
  tracking: TrackingRecord;
  onTrackingUpdate: (r: TrackingRecord) => void;
}) {
  const [open,       setOpen]       = useState(false);
  const [showTrack,  setShowTrack]  = useState(false);
  const [aiText,     setAiText]     = useState<string | null>(null);
  const [aiLoading,  setAiLoading]  = useState(false);
  const [aiError,    setAiError]    = useState<string | null>(null);

  const ref  = CIS_REF[check.id];
  const st   = STATUS_CFG[check.fleet_status] ?? STATUS_CFG.unknown;
  const tc   = TRACK_CFG[tracking.status];
  const isFail = check.fleet_status === "fail";
  const isPass = check.fleet_status === "pass";

  const handleAI = async () => {
    const text = ref
      ? `${ref.rationale} Fix: ${ref.steps.join(". ")}`
      : check.remediation;
    setAiLoading(true); setAiError(null);
    try   { setAiText(await simplifyWithAI(text)); }
    catch (e) { setAiError(String(e)); }
    finally   { setAiLoading(false); }
  };

  return (
    <>
      <tr
        onClick={() => { setOpen(o => !o); setShowTrack(false); }}
        className={cn(
          "border-b border-gray-100 cursor-pointer transition-all group",
          isFail
            ? "bg-red-50/30 hover:bg-red-50/50 shadow-[inset_3px_0_0_#ef4444]"
            : check.fleet_status === "warn"
            ? "hover:bg-amber-50/20"
            : isPass
            ? "hover:bg-green-50/20"
            : "hover:bg-gray-50",
          tracking.status === "remediated" && "opacity-60",
        )}
      >
        {/* Status icon */}
        <td className="pl-4 pr-2 py-3 w-10">{st.icon}</td>

        {/* Check name + CIS section */}
        <td className="px-3 py-3">
          <div className="text-[11px] font-semibold text-gray-800 leading-snug">{check.name}</div>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="text-[9px] font-mono text-orange-600 font-bold bg-orange-50 px-1.5 py-0.5 rounded border border-orange-100">
              {ref?.section ?? `CIS-${check.cis_control}`}
            </span>
            {ref && (
              <span className="text-[9px] text-gray-400 truncate max-w-[220px]">{ref.category}</span>
            )}
          </div>
        </td>

        {/* IG level */}
        <td className="px-3 py-3 w-16">
          {ref && (
            <span className={cn("px-2 py-0.5 rounded-full border text-[9px] font-bold", IG_BADGE[ref.ig])}>
              IG{ref.ig}
            </span>
          )}
        </td>

        {/* Severity */}
        <td className="px-3 py-3 w-20">
          <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", SEV_BADGE[check.severity] ?? SEV_BADGE.low)}>
            {check.severity}
          </span>
        </td>

        {/* Fleet status */}
        <td className="px-3 py-3 w-20">
          <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", st.badge)}>
            {st.label}
          </span>
        </td>

        {/* Agent breakdown */}
        <td className="px-3 py-3 w-28">
          <div className="flex items-center gap-1">
            {check.pass_count > 0  && <span className="text-[9px] font-bold text-green-600">{check.pass_count}✓</span>}
            {check.fail_count > 0  && <span className="text-[9px] font-bold text-red-600">{check.fail_count}✗</span>}
            {check.warn_count > 0  && <span className="text-[9px] font-semibold text-amber-600">{check.warn_count}!</span>}
            <span className="text-[9px] text-gray-300 ml-0.5">/{check.total_agents}</span>
          </div>
        </td>

        {/* Tracking badge */}
        <td className="px-3 py-3 w-32" onClick={e => { e.stopPropagation(); setShowTrack(s => !s); setOpen(true); }}>
          <span className={cn(
            "flex items-center gap-1 px-2 py-0.5 rounded-full border text-[9px] font-bold cursor-pointer hover:shadow-sm transition-all w-fit",
            tc.badge
          )}>
            <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", tc.dot)} />
            {tc.label}
          </span>
        </td>

        {/* Expand */}
        <td className="pr-3 py-3 w-6 text-gray-300">
          {open
            ? <ChevronDown className="w-3.5 h-3.5" />
            : <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          }
        </td>
      </tr>

      {open && (
        <tr className="border-b border-gray-100 bg-gray-50/30">
          <td />
          <td colSpan={7} className="px-4 pb-5 pt-3">
            <div className="space-y-3">

              {/* Tracking form or summary */}
              {showTrack ? (
                <TrackingForm
                  checkId={check.id}
                  initial={tracking}
                  onSave={onTrackingUpdate}
                  onClose={() => setShowTrack(false)}
                />
              ) : tracking.status !== "open" && (
                <div className="flex items-start gap-3 px-3 py-2.5 bg-white border border-gray-100 rounded-xl">
                  <span className={cn("w-2 h-2 rounded-full flex-shrink-0 mt-1", tc.dot)} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={cn("px-2 py-0.5 rounded-full border text-[9px] font-bold", tc.badge)}>{tc.label}</span>
                      {tracking.assignee && <span className="text-[9px] text-gray-500 flex items-center gap-0.5"><User className="w-2.5 h-2.5" />{tracking.assignee}</span>}
                      {tracking.due_date && <span className="text-[9px] text-gray-500 flex items-center gap-0.5"><Calendar className="w-2.5 h-2.5" />Due {tracking.due_date}</span>}
                      {tracking.updated_at > 0 && <span className="text-[9px] text-gray-400">{relTime(tracking.updated_at)}</span>}
                    </div>
                    {tracking.notes && <p className="text-[10px] text-gray-600 mt-1 italic">"{tracking.notes}"</p>}
                  </div>
                  <button onClick={e => { e.stopPropagation(); setShowTrack(true); }}
                    className="text-[9px] text-orange-500 hover:text-orange-700 font-bold flex-shrink-0">
                    Edit
                  </button>
                </div>
              )}

              {/* 3-column detail grid */}
              <div className="grid grid-cols-3 gap-3">
                {/* Observed vs expected */}
                <div className="rounded-xl bg-white border border-gray-100 p-3.5">
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide flex items-center gap-1.5 mb-2">
                    <Info className="w-3 h-3 text-blue-400" />Evidence
                  </div>
                  <div className="space-y-2">
                    <div>
                      <div className="text-[8px] text-gray-400 font-semibold mb-0.5">OBSERVED</div>
                      <p className="font-mono text-[10px] text-gray-700 bg-gray-50 rounded px-2 py-1 break-all">{check.actual || "—"}</p>
                    </div>
                    {ref?.expected && (
                      <div>
                        <div className="text-[8px] text-gray-400 font-semibold mb-0.5">EXPECTED</div>
                        <p className="font-mono text-[10px] text-green-700 bg-green-50 rounded px-2 py-1">{ref.expected}</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Risk / rationale */}
                <div className="rounded-xl bg-white border border-gray-100 p-3.5">
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide flex items-center gap-1.5 mb-2">
                    <Target className="w-3 h-3 text-red-400" />Risk
                  </div>
                  {ref ? (
                    <div className="space-y-2">
                      <p className="text-[10px] text-gray-700 leading-relaxed">{ref.rationale}</p>
                      {!isPass && (
                        <p className="text-[9px] font-semibold text-red-700 bg-red-50 px-2 py-1.5 rounded border border-red-100 leading-relaxed">{ref.impact}</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-[10px] text-gray-600 leading-relaxed">{check.remediation}</p>
                  )}
                </div>

                {/* Per-agent breakdown */}
                <div className="rounded-xl bg-white border border-gray-100 p-3.5">
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide flex items-center gap-1.5 mb-2">
                    <Users className="w-3 h-3 text-blue-400" />Per-Agent
                  </div>
                  <div className="space-y-1.5 max-h-28 overflow-y-auto">
                    {check.agent_results.map(r => {
                      const s = STATUS_CFG[r.status] ?? STATUS_CFG.unknown;
                      return (
                        <div key={r.hostname} className="flex items-center gap-2">
                          <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", s.dot)} />
                          <span className="text-[10px] font-medium text-gray-700 flex-1 truncate">{r.hostname}</span>
                          <span className={cn("px-1.5 py-0.5 rounded text-[8px] font-bold border", s.badge)}>{s.label}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Remediation steps */}
              {ref && !isPass && (
                <div className="rounded-xl border border-amber-200 bg-amber-50 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2.5 bg-amber-100/60 border-b border-amber-200">
                    <div className="flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-amber-700" />
                      <span className="text-[10px] font-black text-amber-800 uppercase tracking-wide">Remediation Steps</span>
                      <span className="text-[8px] text-amber-700 bg-amber-200 px-1.5 py-0.5 rounded font-semibold">{ref.refs[0]}</span>
                    </div>
                    {!aiText && (
                      <button onClick={handleAI} disabled={aiLoading}
                        className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white hover:bg-orange-50 border border-orange-200 text-orange-600 text-[9px] font-bold transition-all disabled:opacity-50">
                        <Sparkles className={cn("w-3 h-3", aiLoading && "animate-spin")} />
                        {aiLoading ? "Asking AI…" : "Simplify with AI"}
                      </button>
                    )}
                  </div>
                  <div className="p-4">
                    <ol className="space-y-2">
                      {ref.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2.5">
                          <span className="flex-shrink-0 w-4 h-4 rounded-full bg-orange-500 text-white text-[8px] font-black flex items-center justify-center mt-0.5">{i + 1}</span>
                          <p className="text-[10px] text-gray-700 font-mono bg-white/70 px-2 py-1 rounded border border-amber-100 flex-1 leading-relaxed">{step}</p>
                        </li>
                      ))}
                    </ol>

                    {(aiText || aiError) && (
                      <div className={cn("flex items-start gap-2 mt-3 p-3 rounded-xl border", aiError ? "bg-red-50 border-red-200" : "bg-white border-orange-200")}>
                        <Sparkles className={cn("w-3.5 h-3.5 flex-shrink-0 mt-0.5", aiError ? "text-red-500" : "text-orange-500")} />
                        <div className="flex-1">
                          <div className="text-[9px] font-black text-orange-600 uppercase tracking-wide mb-1">AI Summary (Plain English)</div>
                          <p className="text-[10px] text-gray-700 leading-relaxed">{aiError ? `AI unavailable: ${aiError}` : aiText}</p>
                        </div>
                        <button onClick={() => { setAiText(null); setAiError(null); }} className="text-gray-300 hover:text-gray-500">
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {isPass && (
                <div className="flex items-center gap-2 px-4 py-3 bg-green-50 border border-green-100 rounded-xl">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <p className="text-[11px] text-green-700 font-medium">Control properly configured on all agents — no action required.</p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Score ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, grade, size = 110 }: { score: number; grade: string; size?: number }) {
  const color = GRADE_COLOR[grade] ?? "#9ca3af";
  const r     = size / 2 - 9;
  const circ  = 2 * Math.PI * r;
  const cx    = size / 2;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth={8} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={`${(score / 100) * circ} ${circ}`}
          strokeDashoffset={circ * 0.25} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
        <text x={cx} y={cx - 3}  textAnchor="middle" fontSize={22} fontWeight={800} fill={color}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize={9}  fill="#94a3b8">/100</text>
      </svg>
      <span className="text-xs font-black" style={{ color }}>Grade {grade}</span>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CISCompliance() {
  const [agents,      setAgents]      = useState<AgentSummary[]>([]);
  const [fleetChecks, setFleetChecks] = useState<FleetCheck[]>([]);
  const [tracking,    setTrackingMap] = useState<Record<string, TrackingRecord>>(() => getTracking());
  const [loading,     setLoading]     = useState(true);
  const [lastFetch,   setLastFetch]   = useState(0);

  // Filters
  const [search,      setSearch]      = useState("");
  const [filterSev,   setFilterSev]   = useState<string>("all");
  const [filterStatus,setFilterStatus]= useState<string>("all");
  const [filterTrack, setFilterTrack] = useState<string>("all");
  const [filterIG,    setFilterIG]    = useState<string>("all");

  // Pagination
  const PAGE_SIZE = 10;
  const [page, setPage] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const ags: AgentSummary[] = await fetch(`${API}/agents`).then(r => r.ok ? r.json() : []);
      setAgents(ags);

      // Load details for all agents (max 8 for performance)
      const details: PostureDetail[] = (
        await Promise.all(
          ags.slice(0, 8).map(a =>
            fetch(`${API}/${a.agent_id}`).then(r => r.ok ? r.json() : null).catch(() => null)
          )
        )
      ).filter(Boolean);

      setFleetChecks(aggregateFleet(details));
      setLastFetch(Math.floor(Date.now() / 1000));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 120_000); return () => clearInterval(t); }, [load]);

  const updateTracking = useCallback((checkId: string, record: TrackingRecord) => {
    setTrackingMap(prev => {
      const next = { ...prev, [checkId]: record };
      setTracking(next);
      return next;
    });
  }, []);

  // ── Derived stats ──────────────────────────────────────────────────────────

  const passCount    = fleetChecks.filter(c => c.fleet_status === "pass").length;
  const failCount    = fleetChecks.filter(c => c.fleet_status === "fail").length;
  const warnCount    = fleetChecks.filter(c => c.fleet_status === "warn").length;
  const total        = fleetChecks.length;
  const compliancePct = total ? Math.round(((passCount + warnCount * 0.5) / total) * 100) : 0;
  const overallGrade  = compliancePct >= 90 ? "A" : compliancePct >= 75 ? "B" : compliancePct >= 60 ? "C" : compliancePct >= 40 ? "D" : "F";

  const trackCounts = useMemo(() => {
    const c = { open: 0, in_progress: 0, remediated: 0, risk_accepted: 0, false_positive: 0 };
    for (const check of fleetChecks) {
      if (check.fleet_status === "pass") continue;
      const st = tracking[check.id]?.status ?? "open";
      c[st] = (c[st] ?? 0) + 1;
    }
    return c;
  }, [fleetChecks, tracking]);

  // CIS control group compliance bars
  const groupStats = useMemo(() => {
    const map = new Map<string, { pass: number; total: number; label: string }>();
    for (const c of fleetChecks) {
      const ref  = CIS_REF[c.id];
      const key  = ref?.category ?? c.cis_label;
      if (!map.has(key)) map.set(key, { pass: 0, total: 0, label: key });
      map.get(key)!.total++;
      if (c.fleet_status === "pass") map.get(key)!.pass++;
    }
    return Array.from(map.values()).sort((a, b) => (a.pass / a.total) - (b.pass / b.total));
  }, [fleetChecks]);

  // Filtered checks — reset page when any filter changes
  const visibleChecks = useMemo(() => {
    setPage(0);
    return fleetChecks.filter(c => {
      if (filterSev    !== "all" && c.severity !== filterSev) return false;
      if (filterStatus !== "all" && c.fleet_status !== filterStatus) return false;
      if (filterIG     !== "all" && String(CIS_REF[c.id]?.ig ?? "") !== filterIG) return false;
      if (filterTrack  !== "all") {
        const ts = tracking[c.id]?.status ?? "open";
        if (ts !== filterTrack) return false;
      }
      if (search) {
        const q = search.toLowerCase();
        if (!c.name.toLowerCase().includes(q) &&
            !c.id.toLowerCase().includes(q) &&
            !(CIS_REF[c.id]?.category ?? "").toLowerCase().includes(q) &&
            !(CIS_REF[c.id]?.section ?? "").toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [fleetChecks, filterSev, filterStatus, filterIG, filterTrack, search, tracking]);

  const totalPages  = Math.max(1, Math.ceil(visibleChecks.length / PAGE_SIZE));
  const pageChecks  = visibleChecks.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const pageStart   = page * PAGE_SIZE + 1;
  const pageEnd     = Math.min((page + 1) * PAGE_SIZE, visibleChecks.length);

  return (
    <div className="space-y-4 pb-6">

      {/* ── Header ───────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <ClipboardList className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">CIS Compliance</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  CIS macOS Benchmark v3 · {total} controls · Fleet-wide worst-case aggregation · IG1/IG2/IG3 mapped
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => exportCSV(fleetChecks, tracking)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
                <Download className="w-3.5 h-3.5" />Export CSV
              </button>
              <button onClick={load}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
                <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
                {lastFetch ? relTime(lastFetch) : "Loading…"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Dashboard row: score + compliance bars + tracking summary ─────────── */}
      <div className="grid grid-cols-[auto_1fr_auto] gap-4 items-start">

        {/* Compliance score */}
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5 flex flex-col items-center gap-3">
          <ScoreRing score={compliancePct} grade={overallGrade} size={130} />
          <div className="grid grid-cols-3 gap-2 w-full text-center">
            <div className="rounded-xl bg-green-50 border border-green-100 py-2">
              <div className="text-base font-black text-green-700">{passCount}</div>
              <div className="text-[9px] text-green-600 font-semibold">Pass</div>
            </div>
            <div className="rounded-xl bg-amber-50 border border-amber-100 py-2">
              <div className="text-base font-black text-amber-700">{warnCount}</div>
              <div className="text-[9px] text-amber-600 font-semibold">Warn</div>
            </div>
            <div className="rounded-xl bg-red-50 border border-red-100 py-2">
              <div className="text-base font-black text-red-700">{failCount}</div>
              <div className="text-[9px] text-red-600 font-semibold">Fail</div>
            </div>
          </div>
          <div className="w-full border-t border-gray-100 pt-2 text-center">
            <div className="text-[9px] text-gray-400 font-medium">{agents.length} agent{agents.length !== 1 ? "s" : ""} · worst-case fleet</div>
          </div>
        </div>

        {/* Category compliance bars */}
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-orange-500" />
            <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">Control Categories</span>
          </div>
          <div className="space-y-3">
            {groupStats.map(g => {
              const pct   = g.total ? Math.round((g.pass / g.total) * 100) : 0;
              const color = pct >= 90 ? "#16a34a" : pct >= 60 ? "#d97706" : "#dc2626";
              return (
                <div key={g.label}>
                  <div className="flex items-center justify-between text-[10px] mb-1">
                    <span className="font-semibold text-gray-700">{g.label}</span>
                    <span className="font-black tabular-nums" style={{ color }}>{pct}% ({g.pass}/{g.total})</span>
                  </div>
                  <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Tracking summary */}
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5 min-w-[200px]">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-orange-500" />
            <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">Finding Tracker</span>
          </div>
          <div className="space-y-2">
            {(Object.entries(TRACK_CFG) as [TrackingStatus, typeof TRACK_CFG[TrackingStatus]][]).map(([k, c]) => {
              const count = k === "open"
                ? (failCount + warnCount) - Object.values(tracking).filter(t => t.status !== "open").length
                : Object.values(tracking).filter(t => t.status === k).length;
              return (
                <div key={k} className="flex items-center gap-2">
                  <span className={cn("w-2 h-2 rounded-full flex-shrink-0", c.dot)} />
                  <span className="text-[10px] text-gray-600 flex-1 font-medium">{c.label}</span>
                  <span className="text-[11px] font-black tabular-nums text-gray-700">{Math.max(0, count)}</span>
                </div>
              );
            })}
          </div>
          <div className="mt-3 pt-3 border-t border-gray-100">
            <div className="text-[9px] text-gray-400 text-center">Click any tracking badge to update</div>
          </div>
        </div>
      </div>

      {/* ── Check table ───────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

        {/* Filter / search bar */}
        <div className="flex items-center gap-2 px-5 py-3 border-b border-gray-100 bg-gray-50/70 flex-wrap">
          <Shield className="w-4 h-4 text-orange-500 flex-shrink-0" />
          <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide flex-shrink-0">CIS Benchmark Checks</span>

          <div className="ml-auto flex items-center gap-2 flex-wrap">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
              <input type="text" placeholder="Search checks…" value={search} onChange={e => setSearch(e.target.value)}
                className="pl-7 pr-3 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-1 focus:ring-orange-200 w-40" />
            </div>

            {/* Severity filter */}
            <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none">
              <option value="all">All severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Status filter */}
            <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none">
              <option value="all">All results</option>
              <option value="fail">Fail</option>
              <option value="warn">Warn</option>
              <option value="pass">Pass</option>
              <option value="unknown">Unknown</option>
            </select>

            {/* IG filter */}
            <select value={filterIG} onChange={e => setFilterIG(e.target.value)}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none">
              <option value="all">All IG</option>
              <option value="1">IG1 (Basic)</option>
              <option value="2">IG2 (Foundational)</option>
              <option value="3">IG3 (Org)</option>
            </select>

            {/* Tracking filter */}
            <select value={filterTrack} onChange={e => setFilterTrack(e.target.value)}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-600 focus:outline-none">
              <option value="all">All tracking</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="remediated">Remediated</option>
              <option value="risk_accepted">Risk Accepted</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          <span className="text-[10px] text-gray-400 flex-shrink-0">{visibleChecks.length} of {total} checks</span>
        </div>

        {loading && fleetChecks.length === 0 ? (
          <div className="py-20 text-center">
            <RefreshCw className="w-6 h-6 text-orange-400 animate-spin mx-auto mb-3" />
            <p className="text-sm text-gray-400 font-medium">Loading compliance data…</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-100">
                  <th className="pl-4 pr-2 py-2.5 w-10" />
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Check / CIS Reference</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider w-16">IG</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider w-20">Severity</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider w-20">Fleet</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider w-28">Agents</th>
                  <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider w-32">Tracking</th>
                  <th className="pr-3 py-2.5 w-6" />
                </tr>
              </thead>
              <tbody>
                {visibleChecks.length === 0 ? (
                  <tr><td colSpan={8} className="py-14 text-center text-[11px] text-gray-400">No checks match this filter</td></tr>
                ) : (
                  pageChecks.map(c => (
                    <CheckRow
                      key={c.id}
                      check={c}
                      tracking={tracking[c.id] ?? { status: "open", notes: "", assignee: "", due_date: "", updated_at: 0 }}
                      onTrackingUpdate={r => updateTracking(c.id, r)}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Pagination footer ──────────────────────────────────────────────── */}
        {visibleChecks.length > 0 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-gray-100 bg-gray-50/60">
            {/* Left: count */}
            <span className="text-[10px] text-gray-500 font-medium">
              Showing <span className="font-bold text-gray-700">{pageStart}–{pageEnd}</span> of{" "}
              <span className="font-bold text-gray-700">{visibleChecks.length}</span> checks
              {visibleChecks.length !== total && (
                <span className="text-gray-400"> (filtered from {total})</span>
              )}
            </span>

            {/* Center: page number buttons */}
            <div className="flex items-center gap-1">
              {/* Prev */}
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 px-3 py-1.5 text-[10px] font-semibold rounded-xl border border-gray-200 bg-white text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                ← Prev
              </button>

              {/* Page number chips */}
              {Array.from({ length: totalPages }, (_, i) => {
                const show = i === 0 || i === totalPages - 1 || Math.abs(i - page) <= 1;
                const ellipsisBefore = i === 2 && page > 3;
                const ellipsisAfter  = i === totalPages - 3 && page < totalPages - 4;
                if (!show) {
                  if (ellipsisBefore || ellipsisAfter) {
                    return <span key={`e${i}`} className="text-[10px] text-gray-400 px-1">…</span>;
                  }
                  return null;
                }
                return (
                  <button
                    key={i}
                    onClick={() => setPage(i)}
                    className={cn(
                      "w-7 h-7 rounded-lg text-[10px] font-bold transition-all border",
                      page === i
                        ? "bg-orange-500 text-white border-orange-500 shadow-sm"
                        : "bg-white text-gray-600 border-gray-200 hover:bg-orange-50 hover:border-orange-200 hover:text-orange-600"
                    )}
                  >
                    {i + 1}
                  </button>
                );
              })}

              {/* Next */}
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page === totalPages - 1}
                className="flex items-center gap-1 px-3 py-1.5 text-[10px] font-semibold rounded-xl border border-gray-200 bg-white text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                Next →
              </button>
            </div>

            {/* Right: page size label */}
            <span className="text-[10px] text-gray-400">
              Page <span className="font-bold text-gray-600">{page + 1}</span> of {totalPages}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
