/**
 * IdentityAccess — Enterprise IAM security module.
 *
 * Detection coverage: privileged accounts · auth anomalies · sudo escalation ·
 *   stale/orphaned accounts · service account misuse · SSH key exposure ·
 *   after-hours access · password policy violations · admin group changes
 *
 * Compliance: SOC 2 CC6 · ISO 27001 A.9 · NIST SP 800-53 AC/IA ·
 *   CIS Controls 5+6 · PCI DSS Req 7+8 · HIPAA §164.312(a)
 *
 * Actions per finding: Open → Acknowledge → Investigate → Remediate |
 *   Accept Risk (approver + justification) | False Positive | Escalate
 *
 * State: localStorage al_iam_actions_v2 + PATCH /api/v1/soc/findings/{id}
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Users, RefreshCw, AlertTriangle, Shield, Lock, Key,
  UserX, Clock, CheckCircle2, XCircle, AlertCircle,
  ChevronDown, ChevronRight, Search, Filter, Activity,
  FileText, User, Calendar, Zap, Target, BookOpen,
  GitBranch, Radio, TrendingUp, Save, RotateCcw,
  ShieldAlert, UserCheck, Eye, Send,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── Constants ─────────────────────────────────────────────────────────────────

const SOC_API    = "/api/v1/soc";
const DETECT_API = "/api/v1/detection";
const LS_KEY     = "al_iam_actions_v2";

// ── Types ─────────────────────────────────────────────────────────────────────

type Severity     = "critical" | "high" | "medium" | "low" | "info";
type ActionStatus = "open" | "acknowledged" | "investigating" | "remediated" | "risk_accepted" | "false_positive" | "escalated";

interface IAMFinding {
  id:                string;
  category:          string;
  severity:          Severity;
  score:             number;
  title:             string;
  description:       string;
  agent_id:          string;
  mitre_technique:   string;
  mitre_tactic:      string;
  compliance:        ComplianceRef[];
  evidence:          Record<string, unknown>;
  remediation:       string[];
  first_detected_at: number;
  last_detected_at:  number;
  validation:        string[];
  risk_if_ignored:   string;
}

interface ComplianceRef {
  framework: string;
  control:   string;
  label:     string;
}

interface HistoryEntry {
  status: ActionStatus;
  note:   string;
  by:     string;
  at:     number;
}

interface ActionRecord {
  status:        ActionStatus;
  notes:         string;
  assignee:      string;
  due_date:      string;
  approver:      string;
  justification: string;
  updated_at:    number;
  updated_by:    string;
  history:       HistoryEntry[];
}

interface AccountEntry {
  name:        string;
  uid:         number;
  gid:         number;
  type:        "human" | "service" | "system";
  groups:      string;
  shell:       string;
  last_login:  string;
  ssh_keys:    number;
  sudo_access: boolean;
  risk:        "critical" | "high" | "medium" | "ok";
  risk_reason: string;
}

// ── IAM Detection Blueprint ───────────────────────────────────────────────────

const IAM_CATEGORIES: Record<string, {
  label:      string;
  icon:       React.ReactNode;
  color:      string;
  compliance: ComplianceRef[];
  mitre:      string;
  tactic:     string;
  validation: string[];
  risk:       string;
  steps:      string[];
}> = {
  privileged_account: {
    label: "Privileged Account Anomaly",
    icon:  <ShieldAlert className="w-3.5 h-3.5" />,
    color: "bg-red-50 text-red-700 border-red-300",
    compliance: [
      { framework: "SOC 2",    control: "CC6.1",    label: "Logical Access Controls" },
      { framework: "ISO 27001",control: "A.9.2.3",  label: "Management of Privileged Access Rights" },
      { framework: "NIST",     control: "AC-2",     label: "Account Management" },
      { framework: "CIS",      control: "CIS-5.1",  label: "Establish and Maintain Inventory of Accounts" },
      { framework: "PCI DSS",  control: "Req 8.2",  label: "Proper Identification and Authentication" },
    ],
    mitre: "T1136.001", tactic: "Persistence",
    validation: ["Verify UID via: id -u <username>","Check /etc/passwd for uid=0 outside root","Confirm account not created by MDM/Installer package","Review /var/log/install.log for package association","Cross-reference with identity provider directory"],
    risk: "CRITICAL: A second UID=0 account gives attackers full root-equivalent access that persists across password resets and survives reboots. This is the highest-severity IAM indicator.",
    steps: ["Immediately disable account: sudo dscl . -create /Users/<name> AuthenticationAuthority DisabledUser","Audit all commands run by this account in auth.log","Determine how account was created (check /var/log/install.log)","Remove from admin/wheel groups if not disabled","File incident report if not authorized by IT"],
  },
  admin_change: {
    label: "Admin Group Membership Change",
    icon:  <UserCheck className="w-3.5 h-3.5" />,
    color: "bg-red-50 text-red-700 border-red-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.2",    label: "Least Privilege Access" },
      { framework: "ISO 27001",control: "A.9.2.2",  label: "User Access Provisioning" },
      { framework: "NIST",     control: "AC-6",     label: "Least Privilege" },
      { framework: "CIS",      control: "CIS-5.4",  label: "Restrict Administrator Privileges" },
      { framework: "PCI DSS",  control: "Req 7.1",  label: "Limit Access to System Components" },
    ],
    mitre: "T1548.003", tactic: "Privilege Escalation",
    validation: ["Check group membership before/after: dscl . -read /Groups/admin GroupMembership","Correlate with IT change tickets","Verify business hours (expected: Mon–Fri 09:00–17:00)","Check if requester and approver are different people","Review PAM logs for group modification event"],
    risk: "HIGH: Admin group membership grants full privilege escalation via sudo. Unauthorized changes enable lateral movement across all systems this user can access.",
    steps: ["Verify with IT if change was authorized","If unauthorized: dscl . -delete /Groups/admin GroupMembership <user>","Audit what the user did with elevated privileges","Check for persistence mechanisms created during privileged window","Require change ticket for all future admin group modifications"],
  },
  auth_failure: {
    label: "Authentication Brute Force",
    icon:  <Lock className="w-3.5 h-3.5" />,
    color: "bg-amber-50 text-amber-700 border-amber-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.7",    label: "Transmission and Movement of Information" },
      { framework: "ISO 27001",control: "A.9.4.2",  label: "Secure Log-on Procedures" },
      { framework: "NIST",     control: "IA-5",     label: "Authenticator Management" },
      { framework: "CIS",      control: "CIS-5.2",  label: "Use Unique Passwords" },
      { framework: "PCI DSS",  control: "Req 8.3",  label: "Secure Individual Authentication" },
      { framework: "HIPAA",    control: "§164.312(d)", label: "Person or Entity Authentication" },
    ],
    mitre: "T1110", tactic: "Credential Access",
    validation: ["Count failures in /var/log/auth.log for last 5 minutes","Identify source IP if SSH-based","Check if account eventually authenticated successfully (credential compromise)","Verify if target account is privileged","Check GreyNoise/AbuseIPDB for source IP reputation"],
    risk: "HIGH: Sustained brute force may indicate attacker has username list and is attempting credential stuffing. Successful auth after failures = confirmed compromise.",
    steps: ["Block source IP at firewall if external: sudo pfctl","Enable account lockout after N failures (PAM pam_faillock)","If SSH: ensure PasswordAuthentication no in sshd_config","Rotate affected account credentials immediately","Enable MFA for all interactive login methods"],
  },
  sudo_escalation: {
    label: "Sudo Privilege Escalation",
    icon:  <TrendingUp className="w-3.5 h-3.5" />,
    color: "bg-amber-50 text-amber-700 border-amber-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.3",    label: "Role Based Access Control" },
      { framework: "ISO 27001",control: "A.9.4.4",  label: "Use of Privileged Utility Programs" },
      { framework: "NIST",     control: "AC-6(1)",  label: "Authorize Access to Security Functions" },
      { framework: "CIS",      control: "CIS-6.1",  label: "Establish Access Granting Process" },
      { framework: "PCI DSS",  control: "Req 7.2",  label: "Establish Access Control System" },
    ],
    mitre: "T1548.003", tactic: "Privilege Escalation",
    validation: ["Inspect /etc/sudoers for NOPASSWD entries: sudo visudo -c","Verify which commands are allowed (ALL = full escalation)","Check if sudoers file was recently modified: ls -la /etc/sudoers","Confirm with IT if this is an authorized configuration","Review sudo usage log: /var/log/auth.log | grep sudo"],
    risk: "HIGH: NOPASSWD sudo grants passwordless root escalation. An attacker who compromises this account inherits instant root access without triggering any auth event.",
    steps: ["Remove NOPASSWD: sudo visudo → delete offending line","Set timestamp_timeout=5 (limit sudo credential cache)","Implement sudo logging: Defaults logfile=/var/log/sudo.log","Replace with specific command whitelist instead of ALL","Require MFA for sudo via pam_duo or similar"],
  },
  stale_account: {
    label: "Stale / Orphaned Account",
    icon:  <UserX className="w-3.5 h-3.5" />,
    color: "bg-blue-50 text-blue-700 border-blue-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.2",    label: "Access Provisioning and Deprovisioning" },
      { framework: "ISO 27001",control: "A.9.2.6",  label: "Removal or Adjustment of Access Rights" },
      { framework: "NIST",     control: "AC-2(3)",  label: "Disable Inactive Accounts" },
      { framework: "CIS",      control: "CIS-5.3",  label: "Disable Dormant Accounts" },
      { framework: "PCI DSS",  control: "Req 8.1",  label: "User Account Management" },
    ],
    mitre: "T1078", tactic: "Initial Access",
    validation: ["Confirm last login date: last <username>","Verify user is no longer employed/contracted","Check if account has any active sessions: who","Look for scheduled tasks/services running under this account","Confirm with HR/IT that user has offboarded"],
    risk: "MEDIUM: Stale accounts accumulate privilege over time and represent an attack surface for credential stuffing. Terminated employees may attempt re-access via retained credentials.",
    steps: ["Disable account: sudo dscl . -create /Users/<name> AuthenticationAuthority DisabledUser","Revoke SSH keys: clear ~/.ssh/authorized_keys","Audit all services/cron jobs running as this account","Archive home directory before deletion","Remove from all groups and IAM systems"],
  },
  after_hours: {
    label: "After-Hours Access Anomaly",
    icon:  <Clock className="w-3.5 h-3.5" />,
    color: "bg-blue-50 text-blue-700 border-blue-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.8",    label: "Authorized Users, Software, and Systems" },
      { framework: "ISO 27001",control: "A.9.4.5",  label: "Control of Operational Software" },
      { framework: "NIST",     control: "AC-17",    label: "Remote Access" },
      { framework: "CIS",      control: "CIS-6.4",  label: "Restrict Access Based on Least Privilege" },
      { framework: "PCI DSS",  control: "Req 10.2", label: "Audit Log All Access" },
    ],
    mitre: "T1078.003", tactic: "Defense Evasion",
    validation: ["Compare login timestamp against user's 90-day baseline","Verify user timezone vs login timestamp","Check source IP geolocation — impossible travel?","Confirm if on-call rotation or authorized remote work","Review what actions were performed during session"],
    risk: "MEDIUM: After-hours logins are a primary indicator of credential theft or insider threat. Attackers prefer off-hours access to avoid detection by security operations teams.",
    steps: ["Contact user immediately to verify authenticity","If unconfirmed: disable account and force password reset","Enable time-based access controls via PAM","Implement anomalous login alerting in SIEM","Consider geo-blocking for high-risk accounts"],
  },
  service_account: {
    label: "Service Account Interactive Login",
    icon:  <Activity className="w-3.5 h-3.5" />,
    color: "bg-purple-50 text-purple-700 border-purple-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.1",    label: "Logical Access Controls" },
      { framework: "ISO 27001",control: "A.9.2.5",  label: "Review of User Access Rights" },
      { framework: "NIST",     control: "AC-2(7)",  label: "Role-Based Schemes" },
      { framework: "CIS",      control: "CIS-5.6",  label: "Centralize Account Management" },
      { framework: "PCI DSS",  control: "Req 8.6",  label: "System/Application Accounts" },
    ],
    mitre: "T1078.003", tactic: "Defense Evasion",
    validation: ["Confirm account type: dscl . -read /Users/<name> NFSHomeDirectory","Service accounts should have shell=/usr/bin/false or /sbin/nologin","Check if account has SSH key enabling interactive login","Verify account is needed for its stated service","Review /var/log/auth.log for all commands run"],
    risk: "MEDIUM: Service accounts with interactive shell access break the principle of least privilege. They often have elevated permissions inherited from their service role.",
    steps: ["Set shell to /usr/bin/false: chsh -s /usr/bin/false <username>","Remove SSH authorized_keys if present","Lock password: sudo passwd -l <username>","Audit all services using this account — use dedicated service credentials","Implement just-in-time access for any legitimate service needs"],
  },
  ssh_key: {
    label: "SSH Authorized Key Exposure",
    icon:  <Key className="w-3.5 h-3.5" />,
    color: "bg-purple-50 text-purple-700 border-purple-200",
    compliance: [
      { framework: "SOC 2",    control: "CC6.6",    label: "Security Measures Against Threats" },
      { framework: "ISO 27001",control: "A.9.3.1",  label: "Use of Secret Authentication Information" },
      { framework: "NIST",     control: "IA-2",     label: "Identification and Authentication" },
      { framework: "CIS",      control: "CIS-5.5",  label: "Establish and Maintain an Inventory of Service Accounts" },
      { framework: "PCI DSS",  control: "Req 8.2",  label: "Individual Non-Consumer Users" },
    ],
    mitre: "T1098.004", tactic: "Persistence",
    validation: ["Review key content: cat ~/.ssh/authorized_keys","Identify key fingerprint: ssh-keygen -l -f <key>","Trace key to its owner — is owner still employed?","Check if key was authorized via IT workflow","Count total authorized keys (>2 per user = suspicious)"],
    risk: "MEDIUM: Unmanaged SSH authorized_keys files provide persistent access that survives password resets. Terminated employee keys that remain are a significant backdoor risk.",
    steps: ["Remove unauthorized keys immediately","Implement SSH Certificate Authority (CA) instead of static keys","Audit all authorized_keys files: find /Users -name authorized_keys","Enforce key expiry via SSH CA certificate validity","Require keys to be registered in identity management system"],
  },
};

// ── State management ──────────────────────────────────────────────────────────

function lsGet<T>(key: string, def: T): T {
  try { return JSON.parse(localStorage.getItem(key) ?? "") ?? def; } catch { return def; }
}
function lsSet(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }

function getActions(): Record<string, ActionRecord> { return lsGet(LS_KEY, {}); }

function defaultAction(): ActionRecord {
  return { status: "open", notes: "", assignee: "", due_date: "", approver: "", justification: "", updated_at: 0, updated_by: "", history: [] };
}

async function syncToAPI(findingId: string, record: ActionRecord) {
  try {
    await fetch(`${SOC_API}/findings/${findingId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: record.status, analyst_notes: record.notes, assignee: record.assignee }),
    });
  } catch { /* API optional — localStorage is source of truth */ }
}

// ── Rich mock findings ────────────────────────────────────────────────────────

function buildMockFindings(): IAMFinding[] {
  const now = Math.floor(Date.now() / 1000);
  return [
    {
      id: "iam-001", category: "privileged_account", severity: "critical", score: 9.8,
      title: "Undocumented UID=0 account 'svc_backup' detected",
      description: "Account 'svc_backup' (uid=0) was found in /etc/passwd but is not in the MDM-managed account baseline. This account has the same privileges as root and was created without an IT change ticket.",
      agent_id: "mac-c3d4", mitre_technique: "T1136.001", mitre_tactic: "Persistence",
      compliance: IAM_CATEGORIES.privileged_account.compliance,
      evidence: { username: "svc_backup", uid: 0, gid: 0, shell: "/bin/bash", last_login: "3h ago", created_at: "2026-05-16T22:14:33Z", in_mdm_baseline: false },
      remediation: IAM_CATEGORIES.privileged_account.steps,
      first_detected_at: now - 10800, last_detected_at: now - 300,
      validation: IAM_CATEGORIES.privileged_account.validation,
      risk_if_ignored: IAM_CATEGORIES.privileged_account.risk,
    },
    {
      id: "iam-002", category: "admin_change", severity: "high", score: 8.4,
      title: "Admin group membership added for 'jdoe' at 01:42 UTC (off-hours)",
      description: "User 'jdoe' (uid=502) was added to the 'admin' group at 01:42 UTC on a Tuesday. No IT change ticket correlates. The adding process was bash, not a system installer or MDM agent.",
      agent_id: "mac-a1b2", mitre_technique: "T1548.003", mitre_tactic: "Privilege Escalation",
      compliance: IAM_CATEGORIES.admin_change.compliance,
      evidence: { username: "jdoe", uid: 502, group_added: "admin", timestamp: "01:42 UTC", modified_by_process: "bash", change_ticket: null, is_business_hours: false },
      remediation: IAM_CATEGORIES.admin_change.steps,
      first_detected_at: now - 7200, last_detected_at: now - 3600,
      validation: IAM_CATEGORIES.admin_change.validation,
      risk_if_ignored: IAM_CATEGORIES.admin_change.risk,
    },
    {
      id: "iam-003", category: "sudo_escalation", severity: "high", score: 8.1,
      title: "NOPASSWD sudo entry grants passwordless root to uid=501",
      description: "sudoers contains: 'user ALL=(ALL) NOPASSWD: ALL' for user 'admin'. This provides instant root access without any authentication challenge. The entry was added 6 hours ago.",
      agent_id: "mac-e5f6", mitre_technique: "T1548.003", mitre_tactic: "Privilege Escalation",
      compliance: IAM_CATEGORIES.sudo_escalation.compliance,
      evidence: { sudoers_entry: "admin ALL=(ALL) NOPASSWD: ALL", username: "admin", uid: 501, entry_age_hours: 6, previous_value: "admin ALL=(ALL) ALL" },
      remediation: IAM_CATEGORIES.sudo_escalation.steps,
      first_detected_at: now - 21600, last_detected_at: now - 900,
      validation: IAM_CATEGORIES.sudo_escalation.validation,
      risk_if_ignored: IAM_CATEGORIES.sudo_escalation.risk,
    },
    {
      id: "iam-004", category: "auth_failure", severity: "high", score: 7.6,
      title: "47 failed sudo authentication attempts from 'guest' in 3 minutes",
      description: "User 'guest' generated 47 consecutive sudo authentication failures between 03:18–03:21 UTC. Pattern consistent with automated credential stuffing or brute force tool. No successful auth observed.",
      agent_id: "mac-c3d4", mitre_technique: "T1110", mitre_tactic: "Credential Access",
      compliance: IAM_CATEGORIES.auth_failure.compliance,
      evidence: { username: "guest", failure_count: 47, window_seconds: 180, last_failure: "03:21 UTC", source: "local_terminal", lockout_triggered: false },
      remediation: IAM_CATEGORIES.auth_failure.steps,
      first_detected_at: now - 3600, last_detected_at: now - 1800,
      validation: IAM_CATEGORIES.auth_failure.validation,
      risk_if_ignored: IAM_CATEGORIES.auth_failure.risk,
    },
    {
      id: "iam-005", category: "after_hours", severity: "medium", score: 6.7,
      title: "Interactive login for 'admin' at 03:21 UTC — outside baseline window",
      description: "User 'admin' authenticated interactively at 03:21 UTC (20:21 local). This user's 90-day login baseline shows 09:00–17:30 Mon–Fri. No on-call rotation or authorized remote work was scheduled.",
      agent_id: "mac-g7h8", mitre_technique: "T1078", mitre_tactic: "Defense Evasion",
      compliance: IAM_CATEGORIES.after_hours.compliance,
      evidence: { username: "admin", login_time: "03:21 UTC", baseline_window: "09:00-17:30 Mon-Fri", deviation_hours: 10.8, on_call_schedule: null, geo_ip: "192.168.1.42" },
      remediation: IAM_CATEGORIES.after_hours.steps,
      first_detected_at: now - 5400, last_detected_at: now - 4800,
      validation: IAM_CATEGORIES.after_hours.validation,
      risk_if_ignored: IAM_CATEGORIES.after_hours.risk,
    },
    {
      id: "iam-006", category: "service_account", severity: "medium", score: 6.2,
      title: "Service account '_postgres' (uid=70) used for interactive shell login",
      description: "The system service account '_postgres' logged in interactively via /bin/bash. Service accounts should have shell=/usr/bin/false or /sbin/nologin. This account has no operational need for interactive access.",
      agent_id: "mac-a1b2", mitre_technique: "T1078.003", mitre_tactic: "Defense Evasion",
      compliance: IAM_CATEGORIES.service_account.compliance,
      evidence: { username: "_postgres", uid: 70, shell: "/bin/bash", account_type: "service", last_login: "6h ago", login_method: "console" },
      remediation: IAM_CATEGORIES.service_account.steps,
      first_detected_at: now - 25200, last_detected_at: now - 21600,
      validation: IAM_CATEGORIES.service_account.validation,
      risk_if_ignored: IAM_CATEGORIES.service_account.risk,
    },
    {
      id: "iam-007", category: "ssh_key", severity: "medium", score: 5.9,
      title: "3 SSH authorized_keys found including 1 key for offboarded user",
      description: "~/.ssh/authorized_keys contains 3 public keys. One key fingerprint matches the SSH key of 'contractor_alice' who was offboarded 47 days ago. This key was never rotated during offboarding.",
      agent_id: "mac-e5f6", mitre_technique: "T1098.004", mitre_tactic: "Persistence",
      compliance: IAM_CATEGORIES.ssh_key.compliance,
      evidence: { key_count: 3, offboarded_key_owner: "contractor_alice", offboard_date: "2026-03-31", key_age_days: 47, key_fingerprint: "SHA256:abc123..." },
      remediation: IAM_CATEGORIES.ssh_key.steps,
      first_detected_at: now - 86400, last_detected_at: now - 3600,
      validation: IAM_CATEGORIES.ssh_key.validation,
      risk_if_ignored: IAM_CATEGORIES.ssh_key.risk,
    },
    {
      id: "iam-008", category: "stale_account", severity: "low", score: 4.5,
      title: "Account 'ex_employee_r.smith' inactive for 62 days — not deprovisioned",
      description: "Account 'ex_employee_r.smith' has not been used for 62 days. HR records show the employee left on 2026-03-15. Account was not disabled during offboarding and still has admin group membership.",
      agent_id: "mac-g7h8", mitre_technique: "T1078", mitre_tactic: "Initial Access",
      compliance: IAM_CATEGORIES.stale_account.compliance,
      evidence: { username: "ex_employee_r.smith", days_inactive: 62, offboard_date: "2026-03-15", admin_group: true, ssh_keys: 1, account_disabled: false },
      remediation: IAM_CATEGORIES.stale_account.steps,
      first_detected_at: now - 172800, last_detected_at: now - 7200,
      validation: IAM_CATEGORIES.stale_account.validation,
      risk_if_ignored: IAM_CATEGORIES.stale_account.risk,
    },
  ];
}

const MOCK_ACCOUNTS: AccountEntry[] = [
  { name: "root",                    uid: 0,  gid: 0,  type: "system",  groups: "wheel",              shell: "/bin/sh",       last_login: "never",           ssh_keys: 0, sudo_access: true,  risk: "ok",       risk_reason: "Standard root account — expected" },
  { name: "svc_backup",             uid: 0,  gid: 0,  type: "service", groups: "wheel,admin",         shell: "/bin/bash",     last_login: "3h ago",          ssh_keys: 0, sudo_access: true,  risk: "critical", risk_reason: "UID=0 outside MDM baseline" },
  { name: "admin",                   uid: 501,gid: 20, type: "human",   groups: "admin,staff",         shell: "/bin/zsh",      last_login: "03:21 UTC",       ssh_keys: 2, sudo_access: true,  risk: "high",     risk_reason: "After-hours login anomaly" },
  { name: "jdoe",                    uid: 502,gid: 20, type: "human",   groups: "admin,staff",         shell: "/bin/zsh",      last_login: "9h ago",          ssh_keys: 1, sudo_access: true,  risk: "high",     risk_reason: "Unauthorized admin group addition" },
  { name: "guest",                   uid: 201,gid: 201,type: "human",   groups: "guest",               shell: "/bin/bash",     last_login: "47 failures",     ssh_keys: 0, sudo_access: false, risk: "high",     risk_reason: "Brute force source account" },
  { name: "_postgres",               uid: 70, gid: 70, type: "service", groups: "postgres",            shell: "/bin/bash",     last_login: "6h ago",          ssh_keys: 0, sudo_access: false, risk: "medium",   risk_reason: "Interactive login for service account" },
  { name: "ex_employee_r.smith",    uid: 503,gid: 20, type: "human",   groups: "admin",               shell: "/bin/zsh",      last_login: "62d ago",         ssh_keys: 1, sudo_access: true,  risk: "medium",   risk_reason: "Stale account — employee offboarded" },
  { name: "_www",                    uid: 70, gid: 70, type: "system",  groups: "www",                 shell: "/usr/bin/false", last_login: "never",          ssh_keys: 0, sudo_access: false, risk: "ok",       risk_reason: "Web server system account — standard" },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function relTime(ts: number): string {
  if (!ts) return "—";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// Animated counter
function useCountUp(target: number): number {
  const [val, setVal] = useState(0);
  const ref = useRef(0);
  useEffect(() => {
    const diff = target - ref.current; const steps = 20; let i = 0;
    const t = setInterval(() => { i++; setVal(Math.round(ref.current + diff * (1 - Math.pow(1 - i/steps, 3)))); if (i >= steps) { clearInterval(t); ref.current = target; } }, 35);
    return () => clearInterval(t);
  }, [target]);
  return val;
}

// ── Design tokens ─────────────────────────────────────────────────────────────

const SEV_STYLE: Record<string, { badge: string; dot: string; bar: string; row: string }> = {
  critical: { badge: "bg-red-50 text-red-700 border-red-300",     dot: "bg-red-500",    bar: "bg-gradient-to-r from-red-500 to-red-600",     row: "row-critical al-glow-critical" },
  high:     { badge: "bg-amber-50 text-amber-700 border-amber-300",dot: "bg-amber-500", bar: "bg-gradient-to-r from-amber-400 to-amber-500", row: "row-high" },
  medium:   { badge: "bg-blue-50 text-blue-700 border-blue-300",   dot: "bg-blue-500",  bar: "bg-gradient-to-r from-blue-400 to-blue-500",   row: "row-medium" },
  low:      { badge: "bg-green-50 text-green-700 border-green-300", dot: "bg-green-500",bar: "bg-gradient-to-r from-green-400 to-green-500", row: "row-low" },
  info:     { badge: "bg-gray-100 text-gray-500 border-gray-200",  dot: "bg-gray-300",  bar: "bg-gray-300",                                   row: "row-info" },
};

const ACTION_CFG: Record<ActionStatus, { label: string; color: string; bg: string; icon: React.ReactNode }> = {
  open:           { label: "Open",           color: "text-gray-600",   bg: "bg-gray-100 border-gray-300",        icon: <AlertCircle className="w-3 h-3" /> },
  acknowledged:   { label: "Acknowledged",   color: "text-blue-700",   bg: "bg-blue-50 border-blue-300",         icon: <Eye className="w-3 h-3" /> },
  investigating:  { label: "Investigating",  color: "text-indigo-700", bg: "bg-indigo-50 border-indigo-300",     icon: <Search className="w-3 h-3" /> },
  remediated:     { label: "Remediated",     color: "text-green-700",  bg: "bg-green-50 border-green-300",       icon: <CheckCircle2 className="w-3 h-3" /> },
  risk_accepted:  { label: "Risk Accepted",  color: "text-amber-700",  bg: "bg-amber-50 border-amber-300",       icon: <Shield className="w-3 h-3" /> },
  false_positive: { label: "False Positive", color: "text-purple-700", bg: "bg-purple-50 border-purple-300",     icon: <XCircle className="w-3 h-3" /> },
  escalated:      { label: "Escalated",      color: "text-red-700",    bg: "bg-red-50 border-red-300",           icon: <Send className="w-3 h-3" /> },
};

const FRAMEWORK_COLORS: Record<string, string> = {
  "SOC 2":    "bg-blue-50 text-blue-700 border-blue-200",
  "ISO 27001":"bg-green-50 text-green-700 border-green-200",
  "NIST":     "bg-indigo-50 text-indigo-700 border-indigo-200",
  "CIS":      "bg-orange-50 text-orange-700 border-orange-200",
  "PCI DSS":  "bg-purple-50 text-purple-700 border-purple-200",
  "HIPAA":    "bg-red-50 text-red-700 border-red-200",
};

// ── Action Panel Component ────────────────────────────────────────────────────

function ActionPanel({
  finding, record, onSave, onClose,
}: {
  finding: IAMFinding;
  record: ActionRecord;
  onSave: (r: ActionRecord) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<ActionRecord>({ ...record });
  const upd = <K extends keyof ActionRecord>(k: K, v: ActionRecord[K]) => setForm(f => ({ ...f, [k]: v }));

  const needsApprover = form.status === "risk_accepted";
  const needsJustify  = form.status === "risk_accepted" || form.status === "false_positive";

  const handleSave = () => {
    const entry: HistoryEntry = {
      status: form.status,
      note:   form.notes || `Status changed to ${ACTION_CFG[form.status].label}`,
      by:     form.assignee || "analyst",
      at:     Math.floor(Date.now() / 1000),
    };
    const updated: ActionRecord = {
      ...form,
      updated_at: Math.floor(Date.now() / 1000),
      updated_by: form.assignee || "analyst",
      history: [entry, ...(record.history ?? [])].slice(0, 20),
    };
    onSave(updated);
  };

  return (
    <div className="mt-3 rounded-2xl border border-gray-200 bg-gray-50 overflow-hidden al-panel-in">
      <div className="flex items-center justify-between px-4 py-2.5 bg-white border-b border-gray-100">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3.5 h-3.5 text-orange-500" />
          <span className="text-[10px] font-black text-gray-800 uppercase tracking-wide">Manage Finding</span>
          <span className="px-2 py-0.5 bg-orange-50 text-orange-700 border border-orange-200 rounded text-[9px] font-bold">{finding.id}</span>
        </div>
        <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-100 transition-colors">
          <XCircle className="w-3.5 h-3.5 text-gray-400" />
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Status buttons */}
        <div>
          <div className="text-[9px] font-bold text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
            <Activity className="w-3 h-3" />Finding Status
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(Object.entries(ACTION_CFG) as [ActionStatus, typeof ACTION_CFG[ActionStatus]][]).map(([k, c]) => (
              <button key={k} onClick={() => upd("status", k)}
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-[10px] font-bold transition-all",
                  form.status === k
                    ? c.bg + " " + c.color + " shadow-sm ring-1 ring-current/20"
                    : "bg-white text-gray-500 border-gray-200 hover:bg-gray-50 hover:border-gray-300"
                )}>
                {c.icon}{c.label}
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
            <input type="text" placeholder="analyst@company.com" value={form.assignee}
              onChange={e => upd("assignee", e.target.value)}
              className="w-full px-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 transition-all" />
          </div>
          {/* Due date */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
              <Calendar className="w-3 h-3" />Due Date
            </label>
            <input type="date" value={form.due_date} onChange={e => upd("due_date", e.target.value)}
              className="w-full px-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 transition-all" />
          </div>
        </div>

        {/* Risk acceptance fields */}
        {needsApprover && (
          <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl space-y-2 al-row-in">
            <div className="flex items-center gap-1.5 text-[10px] font-bold text-amber-700">
              <Shield className="w-3 h-3" />Risk Acceptance — Management Sign-off Required
            </div>
            <input type="text" placeholder="Approver name (e.g. CISO / VP Engineering)"
              value={form.approver} onChange={e => upd("approver", e.target.value)}
              className="w-full px-3 py-1.5 text-[11px] border border-amber-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-amber-200" />
          </div>
        )}

        {/* Justification */}
        {needsJustify && (
          <div className="al-row-in">
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
              <FileText className="w-3 h-3" />{form.status === "false_positive" ? "False Positive Reason" : "Risk Acceptance Justification"}
            </label>
            <textarea rows={2}
              placeholder={form.status === "false_positive" ? "Why this is a false positive…" : "Business justification for accepting this risk…"}
              value={form.justification} onChange={e => upd("justification", e.target.value)}
              className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 resize-none transition-all" />
          </div>
        )}

        {/* Notes */}
        <div>
          <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wide flex items-center gap-1 mb-1">
            <FileText className="w-3 h-3" />Analyst Notes
          </label>
          <textarea rows={2} placeholder="Investigation notes, findings, context…"
            value={form.notes} onChange={e => upd("notes", e.target.value)}
            className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 resize-none transition-all" />
        </div>

        {/* Save / Reset */}
        <div className="flex items-center gap-2 justify-end pt-1">
          <button onClick={() => setForm({ ...record })}
            className="flex items-center gap-1 px-3 py-1.5 text-[10px] font-semibold text-gray-500 hover:text-gray-700 border border-gray-200 rounded-xl bg-white transition-colors">
            <RotateCcw className="w-3 h-3" />Reset
          </button>
          <button onClick={handleSave}
            className="flex items-center gap-1.5 px-4 py-1.5 text-[10px] font-bold bg-orange-500 hover:bg-orange-600 text-white rounded-xl transition-all shadow-sm hover:shadow-md">
            <Save className="w-3 h-3" />Save Changes
          </button>
        </div>

        {/* Action History */}
        {record.history && record.history.length > 0 && (
          <div className="border-t border-gray-200 pt-3">
            <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2">Action History</div>
            <div className="space-y-1.5 max-h-28 overflow-y-auto">
              {record.history.map((h, i) => {
                const ac = ACTION_CFG[h.status];
                return (
                  <div key={i} className="flex items-start gap-2 al-row-in" style={{ animationDelay: `${i * 30}ms` }}>
                    <span className={cn("p-1 rounded-lg flex-shrink-0 mt-0.5", ac.bg)}>
                      <span className={ac.color}>{ac.icon}</span>
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={cn("text-[9px] font-bold", ac.color)}>{ac.label}</span>
                        <span className="text-[9px] text-gray-400">by {h.by}</span>
                        <span className="ml-auto text-[9px] text-gray-400 flex-shrink-0">{relTime(h.at)}</span>
                      </div>
                      {h.note && <p className="text-[9px] text-gray-600 truncate">{h.note}</p>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Finding row ───────────────────────────────────────────────────────────────

function FindingRow({
  finding, action, onActionSave, delay,
}: {
  finding: IAMFinding;
  action: ActionRecord;
  onActionSave: (r: ActionRecord) => void;
  delay: number;
}) {
  const [expanded,  setExpanded]  = useState(false);
  const [showPanel, setShowPanel] = useState(false);
  const cat  = IAM_CATEGORIES[finding.category];
  const s    = SEV_STYLE[finding.severity] ?? SEV_STYLE.info;
  const ac   = ACTION_CFG[action.status];
  const isCrit = finding.severity === "critical";

  return (
    <div className={cn("border-b border-gray-100 al-row-in", isCrit && "al-glow-critical", s.row)} style={{ animationDelay: `${delay}ms` }}>
      {/* Main row */}
      <div
        onClick={() => { setExpanded(e => !e); setShowPanel(false); }}
        className={cn("flex items-center gap-3 px-4 py-3 cursor-pointer transition-all hover:bg-gray-50/80 group")}
      >
        {/* Severity dot */}
        <div className={cn("relative flex-shrink-0", isCrit && "al-sonar-dot")}>
          <div className={cn("w-2.5 h-2.5 rounded-full", s.dot)} />
        </div>

        {/* Title + badges */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-semibold text-gray-800 truncate">{finding.title}</span>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", s.badge)}>
              {finding.severity}
            </span>
            {cat && (
              <span className={cn("px-2 py-0.5 text-[9px] font-semibold rounded-full border flex items-center gap-1", cat.color)}>
                {cat.icon}{cat.label}
              </span>
            )}
            <span className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded text-[8px] font-mono font-semibold">
              {finding.mitre_technique}
            </span>
          </div>
        </div>

        {/* Score */}
        <div className="flex-shrink-0 text-center">
          <div className={cn("text-sm font-black tabular-nums", finding.score >= 8 ? "text-red-600" : finding.score >= 6 ? "text-amber-600" : "text-blue-600")}>
            {finding.score.toFixed(1)}
          </div>
          <div className="text-[8px] text-gray-400">/10</div>
        </div>

        {/* Action status badge */}
        <button
          onClick={e => { e.stopPropagation(); setShowPanel(p => !p); setExpanded(true); }}
          className={cn("flex items-center gap-1 px-2.5 py-1 rounded-xl border text-[9px] font-bold transition-all hover:shadow-sm flex-shrink-0", ac.bg, ac.color)}
        >
          {ac.icon}{ac.label}
        </button>

        {/* Agent + time */}
        <div className="flex-shrink-0 text-right hidden lg:block">
          <div className="text-[9px] font-mono text-gray-400">{finding.agent_id}</div>
          <div className="text-[9px] text-gray-400">{relTime(finding.last_detected_at)}</div>
        </div>

        <div className="flex-shrink-0 text-gray-300">
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 bg-gray-50/40">
          {showPanel ? (
            <ActionPanel
              finding={finding}
              record={action}
              onSave={r => { onActionSave(r); setShowPanel(false); }}
              onClose={() => setShowPanel(false)}
            />
          ) : (
            <div className="space-y-3 al-panel-in">
              {/* Description */}
              <p className="text-[11px] text-gray-700 leading-relaxed">{finding.description}</p>

              {/* 3-col grid */}
              <div className="grid grid-cols-3 gap-3">
                {/* Evidence */}
                <div className="bg-white rounded-xl border border-gray-100 p-3">
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2">Evidence</div>
                  <pre className="text-[9px] font-mono text-gray-600 bg-gray-50 rounded-lg p-2 overflow-auto max-h-28 whitespace-pre-wrap break-words">{JSON.stringify(finding.evidence, null, 2)}</pre>
                </div>

                {/* Compliance */}
                <div className="bg-white rounded-xl border border-gray-100 p-3">
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-2">Compliance Coverage</div>
                  <div className="space-y-1">
                    {finding.compliance.map((c, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className={cn("px-1.5 py-0.5 rounded text-[8px] font-bold flex-shrink-0", FRAMEWORK_COLORS[c.framework])}>{c.framework}</span>
                        <span className="text-[9px] text-gray-600">{c.control} · {c.label}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Risk + remediation */}
                <div className="bg-white rounded-xl border border-red-100 p-3">
                  <div className="text-[9px] font-bold text-red-500 uppercase tracking-wide mb-2">Risk if Ignored</div>
                  <p className="text-[9px] text-red-700 leading-relaxed bg-red-50 rounded-lg px-2 py-1.5 border border-red-100 mb-2">{finding.risk_if_ignored.slice(0, 120)}…</p>
                  <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide mb-1.5">Remediation Steps</div>
                  <ol className="space-y-1">
                    {finding.remediation.slice(0, 3).map((r, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="w-3.5 h-3.5 rounded-full bg-orange-500 text-white text-[7px] font-black flex items-center justify-center flex-shrink-0 mt-0.5">{i+1}</span>
                        <span className="text-[9px] text-gray-700">{r}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>

              {/* Action trigger */}
              <div className="flex items-center gap-2">
                <button onClick={() => setShowPanel(true)}
                  className="flex items-center gap-1.5 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-[10px] font-bold rounded-xl transition-all shadow-sm hover:shadow-md">
                  <Shield className="w-3.5 h-3.5" />Manage Finding
                </button>
                {action.status !== "open" && (
                  <div className={cn("flex items-center gap-1.5 px-3 py-2 rounded-xl border text-[10px] font-semibold", ac.bg, ac.color)}>
                    {ac.icon}
                    <span>Current status: <strong>{ac.label}</strong></span>
                    {action.assignee && <span className="text-gray-500">· {action.assignee}</span>}
                    {action.updated_at > 0 && <span className="text-gray-400">· {relTime(action.updated_at)}</span>}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Account Registry ──────────────────────────────────────────────────────────

function AccountRegistry() {
  const RISK_CFG: Record<string, { badge: string; dot: string }> = {
    critical: { badge: "bg-red-50 text-red-700 border-red-300",    dot: "bg-red-500 animate-pulse" },
    high:     { badge: "bg-amber-50 text-amber-700 border-amber-300", dot: "bg-amber-500" },
    medium:   { badge: "bg-blue-50 text-blue-700 border-blue-200",  dot: "bg-blue-400" },
    ok:       { badge: "bg-green-50 text-green-700 border-green-200",dot: "bg-green-500" },
  };

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
      <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
      <div className="flex items-center gap-2.5 px-5 py-3 border-b border-gray-100">
        <Users className="w-4 h-4 text-orange-500" />
        <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">Local Account Inventory</span>
        <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-[10px] font-bold">{MOCK_ACCOUNTS.length}</span>
        <div className="ml-auto flex items-center gap-3 text-[9px]">
          {[["critical","bg-red-500"],["high","bg-amber-500"],["medium","bg-blue-400"],["ok","bg-green-500"]].map(([l, c]) => (
            <span key={l} className="flex items-center gap-1 text-gray-500 capitalize">
              <span className={cn("w-1.5 h-1.5 rounded-full", c)} />{l}
            </span>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              {["Account","UID","Type","Groups","Shell","Last Login","SSH Keys","Sudo","Risk"].map(h => (
                <th key={h} className="px-3 py-2.5 text-left text-[9px] font-black text-gray-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MOCK_ACCOUNTS.map((a, idx) => {
              const rc = RISK_CFG[a.risk];
              const isCrit = a.risk === "critical";
              return (
                <tr key={a.name}
                  className={cn("border-b border-gray-50 transition-all al-row-in", isCrit ? "bg-red-50/30 row-critical" : "hover:bg-gray-50/60", a.risk === "high" && "row-high")}
                  style={{ animationDelay: `${idx * 40}ms` }}>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", rc.dot)} />
                      <span className="font-mono text-[11px] font-semibold text-gray-800">{a.name}</span>
                    </div>
                    <div className="text-[9px] text-gray-400 pl-3.5">{a.risk_reason}</div>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={cn("font-mono font-bold text-[11px]", a.uid === 0 ? "text-red-600" : "text-gray-600")}>{a.uid}</span>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={cn("px-2 py-0.5 rounded-full text-[9px] font-semibold border",
                      a.type === "human" ? "bg-blue-50 text-blue-700 border-blue-200" :
                      a.type === "service" ? "bg-purple-50 text-purple-700 border-purple-200" :
                      "bg-gray-100 text-gray-500 border-gray-200")}>
                      {a.type}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[10px] text-gray-500 max-w-[120px] truncate">{a.groups}</td>
                  <td className="px-3 py-2.5">
                    <span className={cn("font-mono text-[10px]", a.shell === "/usr/bin/false" || a.shell === "/sbin/nologin" ? "text-green-600" : "text-gray-600")}>{a.shell}</span>
                  </td>
                  <td className="px-3 py-2.5 text-[10px] text-gray-500">{a.last_login}</td>
                  <td className="px-3 py-2.5">
                    {a.ssh_keys > 0
                      ? <span className="px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded text-[9px] font-bold">{a.ssh_keys} key{a.ssh_keys > 1 ? "s" : ""}</span>
                      : <span className="text-gray-300 text-[10px]">—</span>}
                  </td>
                  <td className="px-3 py-2.5">
                    {a.sudo_access
                      ? <span className="px-1.5 py-0.5 bg-red-50 text-red-600 border border-red-200 rounded text-[9px] font-bold">YES</span>
                      : <span className="text-gray-400 text-[10px]">no</span>}
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={cn("px-2 py-0.5 rounded-full border text-[9px] font-bold uppercase", rc.badge)}>{a.risk}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Compliance Coverage ───────────────────────────────────────────────────────

function ComplianceCoverage({ findings }: { findings: IAMFinding[] }) {
  const controls = [
    { framework: "SOC 2",    controls: [{ id: "CC6.1", label: "Logical Access" },{ id: "CC6.2", label: "Least Privilege" },{ id: "CC6.3", label: "RBAC" },{ id: "CC6.7", label: "Transmission Security" },{ id: "CC6.8", label: "Authorized Users" }] },
    { framework: "ISO 27001",controls: [{ id: "A.9.2.2", label: "User Provisioning" },{ id: "A.9.2.3", label: "Privileged Rights" },{ id: "A.9.2.6", label: "Deprovisioning" },{ id: "A.9.4.2", label: "Secure Login" },{ id: "A.9.4.4", label: "Privileged Programs" }] },
    { framework: "NIST",     controls: [{ id: "AC-2", label: "Account Mgmt" },{ id: "AC-6", label: "Least Privilege" },{ id: "AC-17", label: "Remote Access" },{ id: "IA-2", label: "Identification" },{ id: "IA-5", label: "Authenticator Mgmt" }] },
    { framework: "PCI DSS",  controls: [{ id: "Req 7.1", label: "Limit Access" },{ id: "Req 7.2", label: "Access Control" },{ id: "Req 8.1", label: "User Mgmt" },{ id: "Req 8.2", label: "Authentication" },{ id: "Req 8.3", label: "Secure Auth" }] },
  ];

  const coveredIds = new Set(findings.flatMap(f => f.compliance.map(c => c.control)));

  return (
    <div className="space-y-4">
      {controls.map((fw, fi) => (
        <div key={fw.framework} className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden al-bounce-in" style={{ animationDelay: `${fi * 80}ms` }}>
          <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
          <div className="flex items-center gap-2.5 px-5 py-3 border-b border-gray-100">
            <span className={cn("px-2.5 py-1 rounded-lg text-[10px] font-black", FRAMEWORK_COLORS[fw.framework])}>{fw.framework}</span>
            <span className="text-[11px] font-bold text-gray-700">IAM Control Coverage</span>
            <div className="ml-auto text-[10px] text-gray-500">
              <span className="font-bold text-green-600">{fw.controls.filter(c => coveredIds.has(c.id)).length}</span>
              /{fw.controls.length} monitored
            </div>
          </div>
          <div className="p-4 grid grid-cols-5 gap-2">
            {fw.controls.map(c => {
              const covered = coveredIds.has(c.id);
              return (
                <div key={c.id}
                  className={cn("rounded-xl border p-3 text-center transition-all hover:shadow-sm", covered ? "bg-green-50 border-green-200" : "bg-gray-50 border-gray-200 opacity-60")}>
                  {covered ? <CheckCircle2 className="w-4 h-4 text-green-500 mx-auto mb-1.5" /> : <AlertCircle className="w-4 h-4 text-gray-300 mx-auto mb-1.5" />}
                  <div className="text-[9px] font-black text-gray-700 font-mono">{c.id}</div>
                  <div className="text-[8px] text-gray-500 mt-0.5">{c.label}</div>
                  <div className={cn("text-[8px] font-bold mt-1", covered ? "text-green-600" : "text-gray-400")}>{covered ? "Monitored" : "Not Covered"}</div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type PageTab = "findings" | "accounts" | "compliance";

export default function IdentityAccess() {
  const [findings,  setFindings]  = useState<IAMFinding[]>([]);
  const [actions,   setActionsMap]= useState<Record<string, ActionRecord>>(() => getActions());
  const [loading,   setLoading]   = useState(true);
  const [tab,       setTab]       = useState<PageTab>("findings");
  const [search,    setSearch]    = useState("");
  const [filterSev, setFilterSev] = useState("");
  const [filterSts, setFilterSts] = useState<ActionStatus | "">("");
  const [lastFetch, setLastFetch] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${DETECT_API}/identity?limit=50`);
      if (r.ok) {
        const body = await r.json();
        const data = body.findings ?? body ?? [];
        if (data.length > 0) { setFindings(data); setLastFetch(Math.floor(Date.now() / 1000)); return; }
      }
    } catch {}
    // Fallback to rich mock
    setFindings(buildMockFindings());
    setLastFetch(Math.floor(Date.now() / 1000));
    setLoading(false);
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 60_000); return () => clearInterval(t); }, [load]);

  const updateAction = useCallback((findingId: string, record: ActionRecord) => {
    setActionsMap(prev => {
      const next = { ...prev, [findingId]: record };
      lsSet(LS_KEY, next);
      syncToAPI(findingId, record);
      return next;
    });
  }, []);

  // Derived stats
  const total     = findings.length;
  const critical  = findings.filter(f => f.severity === "critical").length;
  const high      = findings.filter(f => f.severity === "high").length;
  const open      = findings.filter(f => (actions[f.id]?.status ?? "open") === "open").length;
  const remediated= Object.values(actions).filter(a => a.status === "remediated").length;

  const cnt_c = useCountUp(critical);
  const cnt_h = useCountUp(high);
  const cnt_o = useCountUp(open);
  const cnt_r = useCountUp(remediated);
  const cnt_t = useCountUp(total);

  const visibleFindings = findings.filter(f => {
    if (filterSev && f.severity !== filterSev) return false;
    if (filterSts) { const st = actions[f.id]?.status ?? "open"; if (st !== filterSts) return false; }
    if (search) { const q = search.toLowerCase(); return f.title.toLowerCase().includes(q) || f.category.includes(q) || f.agent_id.toLowerCase().includes(q); }
    return true;
  });

  const TABS: { id: PageTab; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: "findings",   label: "Findings",          icon: <AlertTriangle className="w-3.5 h-3.5" />, count: total },
    { id: "accounts",   label: "Account Registry",  icon: <Users className="w-3.5 h-3.5" />,         count: MOCK_ACCOUNTS.length },
    { id: "compliance", label: "Compliance Coverage",icon: <BookOpen className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="space-y-4 pb-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500 relative overflow-hidden">
          <div className="absolute inset-0 al-scan" style={{ background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.5),transparent)", width: "40%" }} />
        </div>
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <Users className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Identity & Access Management</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  Privileged accounts · auth anomalies · sudo escalation · stale accounts · SSH keys · SOC 2 · ISO 27001 · NIST · CIS · PCI DSS
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-xl">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 al-heartbeat flex-shrink-0" />
                <span className="text-[9px] text-gray-500 font-semibold uppercase tracking-wide">LIVE</span>
              </div>
              <button onClick={load}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-orange-50 hover:border-orange-200 border border-gray-200 text-gray-600 hover:text-orange-600 text-xs font-semibold transition-all">
                <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
                {lastFetch ? relTime(lastFetch) : "Loading…"}
              </button>
            </div>
          </div>

          {/* KPI strip */}
          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            {[
              { label: "Total Findings",  val: cnt_t, color: "text-gray-800",   bg: "bg-gray-50 border-gray-200",   icon: <Activity className="w-3 h-3" /> },
              { label: "Critical",        val: cnt_c, color: "text-red-700",    bg: "bg-red-50 border-red-200",     icon: <AlertTriangle className="w-3 h-3" /> },
              { label: "High",            val: cnt_h, color: "text-amber-700",  bg: "bg-amber-50 border-amber-200", icon: <ShieldAlert className="w-3 h-3" /> },
              { label: "Open Findings",   val: cnt_o, color: open > 0 ? "text-red-600" : "text-green-600", bg: open > 0 ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200", icon: <AlertCircle className="w-3 h-3" /> },
              { label: "Remediated",      val: cnt_r, color: "text-green-700",  bg: "bg-green-50 border-green-200", icon: <CheckCircle2 className="w-3 h-3" /> },
            ].map((k, i) => (
              <div key={k.label} className={cn("rounded-xl border p-3 text-center al-bounce-in", k.bg)} style={{ animationDelay: `${i * 60}ms` }}>
                <div className="flex justify-center mb-1 opacity-60 text-current">{k.icon}</div>
                <div className={cn("text-xl font-black tabular-nums leading-none", k.color)}>{k.val}</div>
                <div className="text-[9px] text-gray-500 font-medium mt-1">{k.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Tab bar ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-1 bg-white border border-gray-200 rounded-2xl p-1.5 shadow-sm">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-xl text-[11px] font-bold transition-all",
              tab === t.id
                ? "bg-orange-500 text-white shadow-sm"
                : "text-gray-500 hover:text-gray-700 hover:bg-gray-50"
            )}>
            {t.icon}{t.label}
            {t.count !== undefined && (
              <span className={cn("px-1.5 py-0.5 rounded-full text-[8px] font-black", tab === t.id ? "bg-white/20 text-white" : "bg-gray-100 text-gray-500")}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Findings tab ─────────────────────────────────────────────────────── */}
      {tab === "findings" && (
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
          <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

          {/* Filter bar */}
          <div className="flex items-center gap-2 px-5 py-3 border-b border-gray-100 bg-gray-50/60 flex-wrap">
            <Filter className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search findings…"
                className="pl-7 pr-3 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 w-44 transition-all" />
            </div>
            <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer">
              <option value="">All Severities</option>
              {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
            </select>
            <select value={filterSts} onChange={e => setFilterSts(e.target.value as ActionStatus | "")}
              className="px-2 py-1.5 text-[10px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-1 focus:ring-orange-200 cursor-pointer">
              <option value="">All Statuses</option>
              {(Object.entries(ACTION_CFG) as [ActionStatus, typeof ACTION_CFG[ActionStatus]][]).map(([k, c]) => (
                <option key={k} value={k}>{c.label}</option>
              ))}
            </select>
            <div className="ml-auto flex items-center gap-2 text-[10px] text-gray-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 al-heartbeat" />
              {visibleFindings.length} of {total} findings
            </div>
          </div>

          {/* Table header */}
          <div className="flex items-center gap-3 px-4 py-2 bg-gray-50/40 border-b border-gray-100">
            <div className="w-5 flex-shrink-0" />
            <div className="flex-1 text-[9px] font-black text-gray-400 uppercase tracking-wider">Finding</div>
            <div className="w-20 text-[9px] font-black text-gray-400 uppercase tracking-wider">Score</div>
            <div className="w-36 text-[9px] font-black text-gray-400 uppercase tracking-wider">Status</div>
            <div className="hidden lg:block w-24 text-[9px] font-black text-gray-400 uppercase tracking-wider">Agent · Time</div>
            <div className="w-5" />
          </div>

          {/* Findings */}
          {loading && findings.length === 0 ? (
            <div className="py-16 text-center">
              <RefreshCw className="w-6 h-6 text-orange-400 animate-spin mx-auto mb-3" />
              <p className="text-sm text-gray-400">Loading IAM findings…</p>
            </div>
          ) : visibleFindings.length === 0 ? (
            <div className="py-16 text-center">
              <Shield className="w-8 h-8 text-gray-200 mx-auto mb-3" />
              <p className="text-[11px] text-gray-400 font-medium">No findings match this filter</p>
            </div>
          ) : (
            visibleFindings.map((f, i) => (
              <FindingRow
                key={f.id}
                finding={f}
                action={actions[f.id] ?? defaultAction()}
                onActionSave={r => updateAction(f.id, r)}
                delay={Math.min(i * 40, 320)}
              />
            ))
          )}

          {/* Footer */}
          {findings.length > 0 && (
            <div className="px-5 py-2.5 border-t border-gray-100 bg-gray-50/60 flex items-center justify-between">
              <div className="flex items-center gap-3 text-[10px]">
                {critical > 0 && <span className="text-red-600 font-bold flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />{critical} critical</span>}
                {high > 0     && <span className="text-amber-600 font-semibold">{high} high</span>}
                <span className="text-gray-400">{open} open · {remediated} remediated</span>
              </div>
              <div className="flex items-center gap-3 text-[10px] text-gray-400">
                <span>Click status badge to manage · <kbd className="px-1 bg-gray-100 rounded text-[9px]">↓</kbd> expand detail</span>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === "accounts"   && <AccountRegistry />}
      {tab === "compliance" && <ComplianceCoverage findings={findings} />}
    </div>
  );
}
