/**
 * SecurityPosture — CIS Benchmark v8 · orange/amber theme · AI remediation.
 */
import { useState, useEffect, useCallback } from "react";
import {
  ShieldCheck, RefreshCw, ChevronDown, ChevronRight,
  AlertTriangle, X, Info, Sparkles, ArrowLeft, Target,
  CheckCircle2, XCircle, AlertCircle, HelpCircle,
  Server, Activity, BookOpen, Shield, Clock,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API    = "/api/v1/posture";
const HF_API = "https://api-inference.huggingface.co/models/google/flan-t5-base";

// ── Types ─────────────────────────────────────────────────────────────────────

type CheckStatus = "pass" | "fail" | "warn" | "unknown";

interface AgentSummary {
  agent_id: string; hostname: string; status: string;
  last_seen: number; score: number; grade: string;
  fail: number; warn: number; pass: number; total: number; has_data: boolean;
}

interface Check {
  id: string; name: string;
  cis_control: number; cis_label: string;
  severity: string; status: CheckStatus;
  actual: string; mitre: string; remediation: string;
}

interface CISGroup {
  cis_control: number; label: string;
  pass: number; fail: number; warn: number; unknown: number;
  total: number; pass_rate: number;
}

interface PostureDetail {
  agent_id: string; hostname: string; last_seen: number;
  score: { score: number; grade: string };
  checks: Check[]; groups: CISGroup[]; has_data: boolean;
  suspicious_configs: { path: string; content: string; suspicious: boolean }[];
  sysctl_security: { key: string; value: string }[];
}

// ── CIS control metadata ──────────────────────────────────────────────────────

const CIS_META: Record<number, { name: string; desc: string }> = {
  1:  { name: "Asset Inventory",      desc: "Track all hardware and software assets" },
  2:  { name: "Software Management",  desc: "Control authorized software and packages" },
  3:  { name: "Data Protection",      desc: "Encrypt sensitive data at rest & in transit" },
  4:  { name: "Secure Configuration", desc: "Harden OS, apps, and firmware settings" },
  5:  { name: "Account Management",   desc: "Manage user/service account lifecycle" },
  6:  { name: "Access Control",       desc: "Limit access on a least-privilege basis" },
  7:  { name: "Vulnerability Mgmt",   desc: "Identify and patch known vulnerabilities" },
  8:  { name: "Audit Logging",        desc: "Collect and review security-relevant logs" },
  10: { name: "Malware Defenses",     desc: "Detect and block malicious code execution" },
  12: { name: "Network Management",   desc: "Secure network infrastructure and firewall" },
  13: { name: "Network Monitoring",   desc: "Monitor for network-based attacks" },
};

// ── Accurate CIS remediation database ────────────────────────────────────────

const REMEDIATION_DB: Record<string, { expected: string; steps: string[]; ref: string }> = {
  firewall_enabled: {
    expected: "macOS Application Firewall enabled (globalstate = 1)",
    steps: [
      "System Settings → Network → Firewall → Turn On Firewall",
      "Enable 'Stealth Mode' to block unsolicited connection probes",
      "CLI: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
      "Verify: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
    ],
    ref: "CIS macOS Benchmark 3.5 · NIST SP 800-41",
  },
  filevault_enabled: {
    expected: "FileVault full-disk encryption enabled on all volumes",
    steps: [
      "System Settings → Privacy & Security → FileVault → Turn On FileVault",
      "Save the recovery key in institutional escrow or a secure password manager",
      "CLI: sudo fdesetup enable",
      "Verify: fdesetup status (should show 'FileVault is On')",
    ],
    ref: "CIS macOS Benchmark 2.5.1 · NIST SP 800-111",
  },
  sip_enabled: {
    expected: "System Integrity Protection enabled (integrity-protection: enabled)",
    steps: [
      "SIP can only be re-enabled from macOS Recovery Mode — never disable in production",
      "Reboot → hold Cmd+R (Intel) or hold Power (Apple Silicon) → Recovery Mode",
      "Open Terminal in Recovery → run: csrutil enable → reboot normally",
      "Verify after reboot: csrutil status",
    ],
    ref: "CIS macOS Benchmark 4.1 · Apple Platform Security Guide",
  },
  gatekeeper_enabled: {
    expected: "Gatekeeper assessments enabled (assessments-enabled: YES)",
    steps: [
      "System Settings → Privacy & Security → Allow apps from 'App Store and identified developers'",
      "CLI: sudo spctl --master-enable",
      "Verify: spctl --status (should return 'assessments enabled')",
    ],
    ref: "CIS macOS Benchmark 2.6.1 · Apple Security Guide",
  },
  auto_update_enabled: {
    expected: "Automatic updates enabled with all sub-options active",
    steps: [
      "System Settings → General → Software Update → Automatic Updates",
      "Enable all: Download, Install macOS updates, App Store updates, Security Responses & System Files",
      "CLI: sudo softwareupdate --schedule on",
      "Verify: sudo softwareupdate --list (should show scheduled)",
    ],
    ref: "CIS macOS Benchmark 1.1 · CISA KEV Guidance",
  },
  screen_lock_enabled: {
    expected: "Screen saver activates ≤ 5 min; password required immediately on wake",
    steps: [
      "System Settings → Lock Screen → 'Require password after screen saver begins': Immediately",
      "System Settings → Screen Saver → Start After: 5 minutes or less",
      "Add a Hot Corner (System Settings → Desktop & Dock → Hot Corners) to lock instantly",
    ],
    ref: "CIS macOS Benchmark 5.8 · NIST SP 800-53 AC-11",
  },
  guest_account_disabled: {
    expected: "Guest account disabled — no unauthenticated local access",
    steps: [
      "System Settings → Users & Groups → Guest User",
      "Toggle 'Allow guests to log in to this computer' OFF",
      "CLI: sudo sysadminctl -guestAccount off",
      "Verify: dscl . -read /Users/Guest AuthenticationAuthority (should fail)",
    ],
    ref: "CIS macOS Benchmark 5.6 · NIST SP 800-53 AC-2",
  },
  remote_login_disabled: {
    expected: "Remote Login (SSH) disabled unless operationally required",
    steps: [
      "System Settings → General → Sharing → toggle Remote Login OFF",
      "CLI: sudo systemsetup -setremotelogin off",
      "If SSH is required: restrict to named users, use key auth only, set PermitRootLogin no in /etc/ssh/sshd_config",
      "Verify: sudo systemsetup -getremotelogin",
    ],
    ref: "CIS macOS Benchmark 2.4.4 · NSA macOS Hardening Guide",
  },
  password_policy: {
    expected: "Passwords: min 12 chars, mixed case, numeric, special chars required",
    steps: [
      "System Settings → Users & Groups → Password Options (standalone Mac)",
      "Enterprise MDM: deploy password policy profile with minChars=12, requiresMixedCase=1, requiresSymbol=1",
      "CLI: pwpolicy -n /Local/Default setglobalpolicy 'minChars=12 requiresAlpha=1 requiresNumeric=1'",
      "NIST SP 800-63B recommendation: prefer long passphrases (16+ chars) over complex short passwords",
    ],
    ref: "CIS macOS Benchmark 5.2 · NIST SP 800-63B",
  },
  sudo_timeout: {
    expected: "sudo credential cache timeout ≤ 5 minutes (timestamp_timeout=5)",
    steps: [
      "Edit /etc/sudoers safely: sudo visudo",
      "Add or update line: Defaults timestamp_timeout=5",
      "This limits the privilege escalation window after authenticated sudo use",
      "Verify: sudo -k (clear cache) then check /etc/sudoers",
    ],
    ref: "CIS macOS Benchmark 5.4 · NIST SP 800-53 AC-6",
  },
  audit_enabled: {
    expected: "audit daemon running; security-relevant events logged and retained",
    steps: [
      "Start auditd: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist",
      "Verify running: sudo audit -n (silence = active)",
      "Configure /etc/security/audit_control: flags=lo,ad,fd,fm,-all; minfree=5; expire-after=60d",
      "Set log retention: policy=ahln (audit-all-high, log-nonattributable)",
    ],
    ref: "CIS macOS Benchmark 8.1 · NIST SP 800-92",
  },
  ssh_keys: {
    expected: "No unauthorized SSH authorized_keys present in any user home directory",
    steps: [
      "Audit all keys: find /Users -name 'authorized_keys' 2>/dev/null",
      "Review each entry — remove any unauthorized public keys",
      "Set in /etc/ssh/sshd_config: PermitRootLogin no, PasswordAuthentication no",
      "Restart SSH: sudo launchctl restart com.openssh.sshd",
    ],
    ref: "CIS macOS Benchmark 5.5 · NIST SP 800-53 IA-2",
  },
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

async function callHuggingFace(text: string): Promise<string> {
  const prompt = `Explain this security fix in 2 simple sentences for a non-technical user: ${text}`;
  const res = await fetch(HF_API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      inputs: prompt,
      parameters: { max_new_tokens: 120, temperature: 0.3, do_sample: false },
    }),
  });
  if (!res.ok) throw new Error(`HuggingFace API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  if (Array.isArray(data) && data[0]?.generated_text) return data[0].generated_text;
  if (typeof data?.generated_text === "string") return data.generated_text;
  if (data?.error) throw new Error(data.error);
  throw new Error("No generated text in response");
}

// ── Design constants ──────────────────────────────────────────────────────────

const GRADE_COLOR: Record<string, string> = {
  A: "#16a34a", B: "#2563eb", C: "#d97706", D: "#ea580c", F: "#dc2626",
};

const STATUS_CFG: Record<CheckStatus, { badge: string; dot: string; label: string; icon: React.ReactNode }> = {
  pass:    { badge: "bg-green-50 text-green-700 border-green-200",  dot: "bg-green-500",           label: "PASS",  icon: <CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> },
  fail:    { badge: "bg-red-50 text-red-700 border-red-200",        dot: "bg-red-500 animate-pulse",label: "FAIL",  icon: <XCircle     className="w-3.5 h-3.5 text-red-500" />   },
  warn:    { badge: "bg-amber-50 text-amber-700 border-amber-200",  dot: "bg-amber-500",            label: "WARN",  icon: <AlertCircle className="w-3.5 h-3.5 text-amber-500" /> },
  unknown: { badge: "bg-gray-100 text-gray-500 border-gray-200",    dot: "bg-gray-300",             label: "N/A",   icon: <HelpCircle  className="w-3.5 h-3.5 text-gray-400" />  },
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high:     "bg-amber-50 text-amber-700 border-amber-200",
  medium:   "bg-blue-50 text-blue-700 border-blue-200",
  low:      "bg-gray-100 text-gray-500 border-gray-200",
};

// ── Score ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, grade, size = 120 }: { score: number; grade: string; size?: number }) {
  const color = GRADE_COLOR[grade] ?? "#9ca3af";
  const r     = size / 2 - 10;
  const circ  = 2 * Math.PI * r;
  const cx    = size / 2;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth={9} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={9}
          strokeDasharray={`${(score / 100) * circ} ${circ}`}
          strokeDashoffset={circ * 0.25}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.8s cubic-bezier(.4,0,.2,1)" }}
        />
        <text x={cx} y={cx - 4}  textAnchor="middle" fontSize={size >= 120 ? 26 : 16} fontWeight={800} fill={color}>{score}</text>
        <text x={cx} y={cx + 13} textAnchor="middle" fontSize={9} fill="#94a3b8">/100</text>
      </svg>
      <span className="text-sm font-black" style={{ color }}>Grade {grade}</span>
    </div>
  );
}

// ── CIS group bar ─────────────────────────────────────────────────────────────

function GroupBar({ group }: { group: CISGroup }) {
  const total  = group.pass + group.fail + group.warn;
  const pW     = total ? (group.pass / total) * 100 : 0;
  const wW     = total ? (group.warn / total) * 100 : 0;
  const fW     = total ? (group.fail / total) * 100 : 0;
  const meta   = CIS_META[group.cis_control];
  const color  = group.pass_rate >= 90 ? "#16a34a" : group.pass_rate >= 60 ? "#d97706" : "#dc2626";

  return (
    <div className="flex items-center gap-3 py-2 group">
      <div className="w-6 h-6 rounded-lg bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
        <span className="text-[9px] font-black text-orange-600">{group.cis_control}</span>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-[10px] font-semibold text-gray-700 truncate">{meta?.name ?? group.label}</span>
          <span className="text-[10px] font-black tabular-nums ml-2 flex-shrink-0" style={{ color }}>{group.pass_rate}%</span>
        </div>
        <div className="h-2 bg-gray-100 rounded-full overflow-hidden flex">
          {pW > 0 && <div className="h-full bg-green-500 transition-all duration-700" style={{ width: `${pW}%` }} />}
          {wW > 0 && <div className="h-full bg-amber-400 transition-all duration-700" style={{ width: `${wW}%` }} />}
          {fW > 0 && <div className="h-full bg-red-500 transition-all duration-700"   style={{ width: `${fW}%` }} />}
        </div>
      </div>
      <div className="text-[9px] tabular-nums flex-shrink-0 w-20 text-right">
        <span className="text-green-600 font-semibold">{group.pass}✓</span>
        {group.fail > 0 && <span className="text-red-600 font-bold ml-1">{group.fail}✗</span>}
        {group.warn > 0 && <span className="text-amber-600 ml-1">{group.warn}!</span>}
      </div>
    </div>
  );
}

// ── Recommendation box with HuggingFace AI ───────────────────────────────────

function RecommendationBox({ check }: { check: Check }) {
  const db = REMEDIATION_DB[check.id];
  const [aiText,    setAiText]    = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError,   setAiError]   = useState<string | null>(null);

  const handleAI = async () => {
    const base = db
      ? `${db.expected}. Fix: ${db.steps.join(". ")}`
      : check.remediation;
    setAiLoading(true); setAiError(null);
    try   { setAiText(await callHuggingFace(base)); }
    catch (e) { setAiError(String(e)); }
    finally   { setAiLoading(false); }
  };

  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-amber-100/60 border-b border-amber-200">
        <div className="flex items-center gap-1.5">
          <BookOpen className="w-3.5 h-3.5 text-amber-700" />
          <span className="text-[10px] font-black text-amber-800 uppercase tracking-wide">Remediation</span>
          {db?.ref && (
            <span className="px-1.5 py-0.5 bg-amber-200 text-amber-900 rounded text-[8px] font-semibold">{db.ref}</span>
          )}
        </div>
        {!aiText && !aiError && (
          <button onClick={handleAI} disabled={aiLoading}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white hover:bg-orange-50 border border-orange-200 text-orange-600 text-[9px] font-bold transition-all hover:shadow-sm disabled:opacity-60">
            <Sparkles className={cn("w-3 h-3", aiLoading && "animate-spin")} />
            {aiLoading ? "Asking AI…" : "Simplify with AI"}
          </button>
        )}
      </div>

      <div className="p-4 space-y-3">
        {db?.expected && (
          <div className="flex items-start gap-2">
            <Target className="w-3.5 h-3.5 text-green-600 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-[9px] font-bold text-gray-500 uppercase tracking-wide mb-0.5">Expected State</div>
              <p className="text-[11px] text-gray-700 font-medium">{db.expected}</p>
            </div>
          </div>
        )}

        {db?.steps ? (
          <div>
            <div className="text-[9px] font-bold text-gray-500 uppercase tracking-wide mb-2">Fix Steps</div>
            <ol className="space-y-2">
              {db.steps.map((step, i) => (
                <li key={i} className="flex items-start gap-2.5">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full bg-orange-500 text-white text-[8px] font-black flex items-center justify-center mt-0.5">
                    {i + 1}
                  </span>
                  <p className="text-[10px] text-gray-700 leading-relaxed font-mono bg-white/60 px-2 py-1 rounded-lg border border-amber-100 flex-1">{step}</p>
                </li>
              ))}
            </ol>
          </div>
        ) : (
          <p className="text-[11px] text-amber-900 leading-relaxed">{check.remediation}</p>
        )}

        {(aiText || aiError) && (
          <div className={cn(
            "rounded-xl p-3 border flex items-start gap-2",
            aiError ? "bg-red-50 border-red-200" : "bg-white border-orange-200"
          )}>
            <Sparkles className={cn("w-3.5 h-3.5 flex-shrink-0 mt-0.5", aiError ? "text-red-500" : "text-orange-500")} />
            <div className="flex-1">
              <div className="text-[9px] font-black uppercase tracking-wide mb-1 text-orange-600">AI Plain-English Summary</div>
              <p className="text-[10px] text-gray-700 leading-relaxed">
                {aiError ? `Could not reach HuggingFace AI: ${aiError}` : aiText}
              </p>
            </div>
            <button onClick={() => { setAiText(null); setAiError(null); }}
              className="text-gray-300 hover:text-gray-500 flex-shrink-0">
              <X className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Check accordion row ───────────────────────────────────────────────────────

function CheckRow({ check }: { check: Check }) {
  const [open, setOpen] = useState(check.status === "fail");
  const st   = STATUS_CFG[check.status] ?? STATUS_CFG.unknown;
  const meta = CIS_META[check.cis_control];

  return (
    <>
      <tr
        onClick={() => setOpen(o => !o)}
        className={cn(
          "border-b border-gray-100 cursor-pointer transition-all group",
          check.status === "fail"
            ? "bg-red-50/40 hover:bg-red-50/70 shadow-[inset_3px_0_0_#ef4444]"
            : check.status === "warn"
            ? "hover:bg-amber-50/30"
            : "hover:bg-gray-50/80",
        )}
      >
        <td className="pl-4 pr-2 py-3 w-10">{st.icon}</td>
        <td className="px-3 py-3">
          <div className="text-[11px] font-semibold text-gray-800">{check.name}</div>
          {meta && <div className="text-[9px] text-gray-400 mt-0.5">{meta.desc}</div>}
        </td>
        <td className="px-3 py-3">
          <div className="flex items-center gap-1.5">
            <span className="w-5 h-5 rounded-md bg-orange-50 border border-orange-100 flex items-center justify-center text-[8px] font-black text-orange-600 flex-shrink-0">
              {check.cis_control}
            </span>
            <span className="text-[9px] text-gray-400 font-mono">CIS-{check.cis_control}</span>
          </div>
        </td>
        <td className="px-3 py-3">
          <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", SEV_BADGE[check.severity] ?? SEV_BADGE.low)}>
            {check.severity}
          </span>
        </td>
        <td className="px-3 py-3">
          <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border uppercase tracking-wide", st.badge)}>
            {st.label}
          </span>
        </td>
        <td className="px-3 py-3 max-w-[160px]">
          <span className="text-[10px] font-mono text-gray-600 truncate block">{check.actual}</span>
        </td>
        <td className="px-3 py-3">
          {check.mitre && (
            <span className="text-[9px] font-mono text-indigo-600 bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded whitespace-nowrap">
              {check.mitre}
            </span>
          )}
        </td>
        <td className="pr-3 py-3 w-6 text-gray-300">
          {open
            ? <ChevronDown className="w-3.5 h-3.5" />
            : <ChevronRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          }
        </td>
      </tr>

      {open && (
        <tr className="border-b border-gray-100 bg-gray-50/40">
          <td />
          <td colSpan={7} className="px-4 pb-4 pt-3">
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div className="rounded-xl bg-white border border-gray-100 p-3.5">
                <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide flex items-center gap-1.5 mb-2">
                  <Info className="w-3 h-3 text-blue-400" />Observed Value
                </div>
                <p className="font-mono text-[11px] text-gray-700 bg-gray-50 rounded-lg px-3 py-2 break-all">{check.actual || "—"}</p>
              </div>
              <div className="rounded-xl bg-white border border-gray-100 p-3.5">
                <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wide flex items-center gap-1.5 mb-2">
                  <Target className="w-3 h-3 text-indigo-400" />MITRE ATT&CK
                </div>
                <p className="text-[11px] text-indigo-700 font-semibold">{check.mitre || "—"}</p>
                <p className="text-[9px] text-gray-400 mt-1">Adversary technique this control mitigates</p>
              </div>
            </div>

            {check.status !== "pass" && check.status !== "unknown" && (
              <RecommendationBox check={check} />
            )}
            {check.status === "pass" && (
              <div className="flex items-center gap-2 px-4 py-3 bg-green-50 border border-green-100 rounded-xl">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <p className="text-[11px] text-green-700 font-medium">Control properly configured — no action required.</p>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ── Agent card ────────────────────────────────────────────────────────────────

function AgentCard({ agent, onSelect }: { agent: AgentSummary; onSelect: () => void }) {
  const total = agent.pass + agent.fail + agent.warn;
  const pW    = total ? (agent.pass / total) * 100 : 0;
  const wW    = total ? (agent.warn / total) * 100 : 0;
  const fW    = total ? (agent.fail / total) * 100 : 0;

  return (
    <div onClick={onSelect}
      className={cn(
        "bg-white border rounded-2xl shadow-sm p-4 cursor-pointer transition-all duration-200 hover:shadow-md group",
        agent.fail > 0 ? "border-red-200 hover:border-red-300" : "border-gray-200 hover:border-orange-300",
      )}
    >
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-center gap-2 min-w-0 pt-1">
          <div className={cn("w-2 h-2 rounded-full flex-shrink-0",
            agent.status === "online" ? "bg-green-500 animate-pulse" :
            agent.status === "stale"  ? "bg-amber-500" : "bg-gray-300"
          )} />
          <div className="min-w-0">
            <div className="font-bold text-[12px] text-gray-800 truncate">{agent.hostname}</div>
            <div className="text-[9px] font-mono text-gray-400 truncate">{agent.agent_id.slice(0, 20)}…</div>
          </div>
        </div>
        <ScoreRing score={agent.score} grade={agent.grade} size={72} />
      </div>

      <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden flex mb-2">
        {pW > 0 && <div className="h-full bg-green-500 transition-all" style={{ width: `${pW}%` }} />}
        {wW > 0 && <div className="h-full bg-amber-400 transition-all" style={{ width: `${wW}%` }} />}
        {fW > 0 && <div className="h-full bg-red-500 transition-all"   style={{ width: `${fW}%` }} />}
      </div>

      <div className="flex items-center justify-between text-[10px] mb-3">
        <div className="flex items-center gap-2.5">
          <span className="text-green-600 font-semibold">{agent.pass}✓</span>
          {agent.warn > 0 && <span className="text-amber-600 font-semibold">{agent.warn}!</span>}
          {agent.fail > 0 && <span className="text-red-600 font-bold">{agent.fail}✗</span>}
        </div>
        <span className="text-gray-400">{agent.total} checks</span>
      </div>

      {!agent.has_data && (
        <div className="mb-3 px-2 py-1 bg-amber-50 border border-amber-100 rounded-lg text-[9px] text-amber-700 font-medium">
          Awaiting first security report
        </div>
      )}

      <div className="flex items-center justify-between pt-2.5 border-t border-gray-100">
        <span className="text-[9px] text-gray-400 flex items-center gap-1">
          <Clock className="w-3 h-3" />{relTime(agent.last_seen)}
        </span>
        <span className="flex items-center gap-1 text-[9px] font-bold text-orange-500 group-hover:text-orange-600 transition-colors">
          View report <ChevronRight className="w-3 h-3" />
        </span>
      </div>
    </div>
  );
}

// ── Agent grid ────────────────────────────────────────────────────────────────

function AgentGrid({ agents, onSelect }: { agents: AgentSummary[]; onSelect: (id: string) => void }) {
  if (agents.length === 0) {
    return (
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm py-24 text-center">
        <Shield className="w-10 h-10 text-gray-200 mx-auto mb-3" />
        <p className="text-sm text-gray-400 font-semibold">No agents enrolled yet</p>
        <p className="text-[10px] text-gray-300 mt-1">Agents report security data every 60 seconds</p>
      </div>
    );
  }
  return (
    <div className="grid grid-cols-3 gap-3">
      {agents.map(a => <AgentCard key={a.agent_id} agent={a} onSelect={() => onSelect(a.agent_id)} />)}
    </div>
  );
}

// ── Detail view ───────────────────────────────────────────────────────────────

function DetailView({ detail, onBack }: { detail: PostureDetail; onBack: () => void }) {
  const [filter, setFilter] = useState<CheckStatus | "all">("all");
  const checks     = filter === "all" ? detail.checks : detail.checks.filter(c => c.status === filter);
  const failChecks = detail.checks.filter(c => c.status === "fail");
  const counts     = {
    all:     detail.checks.length,
    fail:    failChecks.length,
    warn:    detail.checks.filter(c => c.status === "warn").length,
    pass:    detail.checks.filter(c => c.status === "pass").length,
    unknown: detail.checks.filter(c => c.status === "unknown").length,
  };

  return (
    <div className="space-y-4">

      {/* Score + groups card */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
        <div className="p-5">
          <div className="flex items-center gap-3 mb-5">
            <button onClick={onBack}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold border border-gray-200 rounded-xl hover:bg-gray-50 text-gray-600 transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" />All Agents
            </button>
            <div className="flex-1 min-w-0">
              <h2 className="text-sm font-bold text-gray-900">{detail.hostname}</h2>
              <p className="text-[10px] text-gray-500 font-mono">{detail.agent_id} · {relTime(detail.last_seen)}</p>
            </div>
            {!detail.has_data && (
              <div className="px-3 py-1.5 bg-amber-50 border border-amber-200 rounded-xl text-[10px] text-amber-700 font-medium">
                No security data yet
              </div>
            )}
          </div>

          <div className="grid grid-cols-[auto_1fr] gap-8 items-start">
            <ScoreRing score={detail.score.score} grade={detail.score.grade} size={130} />
            <div>
              <div className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-3">CIS Control Coverage</div>
              <div className="divide-y divide-gray-50">
                {detail.groups.map(g => <GroupBar key={g.cis_control} group={g} />)}
              </div>
            </div>
          </div>

          {failChecks.length > 0 && (
            <div className="mt-4 pt-4 border-t border-gray-100">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-3.5 h-3.5 text-red-500" />
                <span className="text-[10px] font-black text-red-600 uppercase tracking-wide">
                  {failChecks.length} Failing — Immediate Action Required
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {failChecks.map(c => (
                  <span key={c.id}
                    className={cn("px-2 py-0.5 text-[9px] font-semibold rounded-full border", SEV_BADGE[c.severity] ?? SEV_BADGE.low)}>
                    {c.name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Check table */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-0.5 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
        <div className="flex items-center gap-2 px-5 py-3 border-b border-gray-100 bg-gray-50/70">
          <Activity className="w-4 h-4 text-orange-500" />
          <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">CIS Benchmark Checks</span>
          <div className="ml-auto flex items-center gap-1">
            {(["all","fail","warn","pass","unknown"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={cn(
                  "flex items-center gap-1 px-2.5 py-1 text-[10px] font-bold rounded-xl border transition-all",
                  filter === f
                    ? f === "fail"    ? "bg-red-500 text-white border-red-500"
                    : f === "warn"    ? "bg-amber-500 text-white border-amber-500"
                    : f === "pass"    ? "bg-green-500 text-white border-green-500"
                    : "bg-orange-500 text-white border-orange-500"
                    : "bg-white text-gray-500 border-gray-200 hover:bg-gray-50"
                )}>
                {f.toUpperCase()}
                <span className={cn("px-1.5 rounded-full text-[8px] font-black", filter === f ? "bg-white/20" : "bg-gray-100 text-gray-500")}>
                  {counts[f]}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-100">
                <th className="pl-4 pr-2 py-2.5 w-10" />
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Check</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">CIS Control</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Severity</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Result</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Actual Value</th>
                <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">MITRE</th>
                <th className="pr-3 py-2.5 w-6" />
              </tr>
            </thead>
            <tbody>
              {checks.length === 0 ? (
                <tr><td colSpan={8} className="py-14 text-center text-[11px] text-gray-400">No checks match this filter</td></tr>
              ) : (
                checks.map(c => <CheckRow key={c.id} check={c} />)
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Suspicious configs */}
      {detail.suspicious_configs.some(c => c.suspicious) && (
        <div className="bg-white border border-red-200 rounded-2xl shadow-sm overflow-hidden">
          <div className="h-0.5 bg-red-500" />
          <div className="flex items-center gap-2 px-5 py-3 border-b border-red-100 bg-red-50/60">
            <AlertTriangle className="w-4 h-4 text-red-500" />
            <span className="text-[11px] font-black text-red-700 uppercase tracking-wide">
              Suspicious Config Files ({detail.suspicious_configs.filter(c => c.suspicious).length})
            </span>
          </div>
          <div className="p-4 space-y-3">
            {detail.suspicious_configs.filter(c => c.suspicious).map(c => (
              <div key={c.path} className="border border-red-200 rounded-xl overflow-hidden">
                <div className="px-4 py-2 bg-red-50 border-b border-red-100">
                  <span className="font-mono text-[11px] font-semibold text-red-700">{c.path}</span>
                </div>
                <pre className="text-[10px] text-gray-600 bg-gray-50 p-3 overflow-x-auto max-h-28 leading-relaxed whitespace-pre-wrap break-words">
                  {c.content.slice(0, 400)}{c.content.length > 400 ? "…" : ""}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sysctl params */}
      {detail.sysctl_security.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-3 border-b border-gray-100">
            <Server className="w-4 h-4 text-gray-400" />
            <span className="text-[11px] font-black text-gray-600 uppercase tracking-wide">Security Kernel Parameters</span>
            <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-[10px] font-bold ml-1">{detail.sysctl_security.length}</span>
          </div>
          <table className="w-full">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-100">
                <th className="px-5 py-2 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Parameter</th>
                <th className="px-5 py-2 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider">Value</th>
              </tr>
            </thead>
            <tbody>
              {detail.sysctl_security.map(r => (
                <tr key={r.key} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-2.5 font-mono text-[10px] text-gray-600">{r.key}</td>
                  <td className="px-5 py-2.5 font-mono text-[10px] text-gray-800 font-semibold">{r.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── KPI tile ──────────────────────────────────────────────────────────────────

function KPITile({ label, value, sub, bg, color }: {
  label: string; value: string | number; sub?: string; bg: string; color: string;
}) {
  return (
    <div className={cn("rounded-xl border p-3 text-center", bg)}>
      <div className={cn("text-2xl font-black tabular-nums leading-none", color)}>{value}</div>
      <div className="text-[11px] font-semibold text-gray-600 mt-1">{label}</div>
      {sub && <div className="text-[9px] text-gray-400 mt-0.5">{sub}</div>}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function SecurityPosture() {
  const [agents,        setAgents]        = useState<AgentSummary[]>([]);
  const [detail,        setDetail]        = useState<PostureDetail | null>(null);
  const [loading,       setLoading]       = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error,         setError]         = useState<string | null>(null);
  const [lastFetch,     setLastFetch]     = useState(0);

  const loadAgents = useCallback(async () => {
    try {
      const r = await fetch(`${API}/agents`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setAgents(await r.json());
      setError(null);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); setLastFetch(Math.floor(Date.now() / 1000)); }
  }, []);

  const loadDetail = useCallback(async (agentId: string) => {
    setDetailLoading(true);
    try {
      const r = await fetch(`${API}/${agentId}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setDetail(await r.json());
    } catch (e) { setError(String(e)); }
    finally { setDetailLoading(false); }
  }, []);

  useEffect(() => {
    loadAgents();
    const t = setInterval(loadAgents, 60_000);
    return () => clearInterval(t);
  }, [loadAgents]);

  const avgScore   = agents.length ? Math.round(agents.reduce((s, a) => s + a.score, 0) / agents.length) : 0;
  const passRate   = agents.length ? Math.round(agents.reduce((s, a) => s + (a.pass / Math.max(a.total, 1)) * 100, 0) / agents.length) : 0;
  const agentFails = agents.filter(a => a.fail > 0).length;
  const avgGrade   = avgScore >= 90 ? "A" : avgScore >= 80 ? "B" : avgScore >= 65 ? "C" : avgScore >= 50 ? "D" : "F";

  return (
    <div className="space-y-4 pb-6">
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <ShieldCheck className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Security Posture</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  CIS Controls v8 · macOS hardening · 16 real-time checks per agent · MITRE ATT&CK mapped · AI remediation
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {detail && (
                <button onClick={() => setDetail(null)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
                  <X className="w-3.5 h-3.5" />Close Detail
                </button>
              )}
              <button onClick={loadAgents}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors">
                <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
                {lastFetch ? relTime(lastFetch) : "Loading…"}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            <KPITile
              label="Avg Posture Score" value={`${avgScore}/100`} sub={`Grade ${avgGrade}`}
              color={avgScore >= 75 ? "text-green-700" : avgScore >= 50 ? "text-amber-700" : "text-red-700"}
              bg={avgScore >= 75 ? "bg-green-50 border-green-100" : avgScore >= 50 ? "bg-amber-50 border-amber-100" : "bg-red-50 border-red-100"}
            />
            <KPITile label="Agents Enrolled" value={agents.length} sub="reporting posture"
              color="text-blue-700" bg="bg-blue-50 border-blue-100" />
            <KPITile
              label="Avg Pass Rate" value={`${passRate}%`} sub="checks passing"
              color={passRate >= 80 ? "text-green-700" : passRate >= 60 ? "text-amber-700" : "text-red-700"}
              bg={passRate >= 80 ? "bg-green-50 border-green-100" : "bg-amber-50 border-amber-100"}
            />
            <KPITile
              label="Agents with Fails" value={agentFails} sub="need attention"
              color={agentFails > 0 ? "text-red-700" : "text-green-700"}
              bg={agentFails > 0 ? "bg-red-50 border-red-100" : "bg-green-50 border-green-100"}
            />
            <KPITile
              label="No Data Yet" value={agents.filter(a => !a.has_data).length} sub="awaiting first report"
              color="text-gray-600" bg="bg-gray-50 border-gray-100"
            />
          </div>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-200 rounded-2xl text-xs text-red-700 flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />{error}
        </div>
      )}

      {detailLoading ? (
        <div className="bg-white border border-gray-200 rounded-2xl shadow-sm py-24 text-center">
          <RefreshCw className="w-6 h-6 text-orange-400 animate-spin mx-auto mb-3" />
          <p className="text-sm text-gray-400 font-medium">Loading posture report…</p>
        </div>
      ) : detail ? (
        <DetailView detail={detail} onBack={() => setDetail(null)} />
      ) : (
        <AgentGrid agents={agents} onSelect={loadDetail} />
      )}
    </div>
  );
}
