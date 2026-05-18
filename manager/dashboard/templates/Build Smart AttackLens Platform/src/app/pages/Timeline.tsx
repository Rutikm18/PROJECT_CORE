/**
 * Timeline & History — SOC performance, finding trends, scan history,
 * DB sync status, category breakdowns, and rich activity feed.
 *
 * APIs:
 *   GET /api/v1/soc/dashboard      → kpi, daily_trend, category_dist, status_dist, sla_compliance
 *   GET /api/v1/soc/metrics        → mttr_hours, wow_improvement_pct, fp_rate_pct
 *   GET /api/v1/soc/historical     → monthly_trend
 *   GET /api/v1/soc/findings       → recent findings list
 */
import { useState, useEffect, useCallback } from "react";
import {
  BarChart3, RefreshCw, AlertTriangle, CheckCircle2, Clock,
  Shield, TrendingUp, TrendingDown, Zap, Database, Activity,
  ChevronDown, ChevronRight, Info, Target, Bug, Network,
  Cpu, Eye, Lock, Wifi, Server, Users, X, ArrowRight,
  GitBranch, Flame, ShieldAlert, ShieldCheck, BookOpen,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { SevBadge, StatusBadge, MitreBadge, ts } from "./shared";
import type { Finding } from "./shared";

// ── API base paths ────────────────────────────────────────────────────────────

const SOC = "/api/v1/soc";

// ── Types ─────────────────────────────────────────────────────────────────────

interface DashStats {
  kpi: {
    total_active: number;
    new_today: number;
    remediated_today: number;
    critical_active: number;
    high_active: number;
    sla_breached: number;
  };
  severity_dist: { severity: string; count: number }[];
  status_dist: { status: string; count: number }[];
  category_dist: { category: string; count: number }[];
  top_agents: { agent_id: string; hostname: string; count: number }[];
  daily_trend: { date: string; critical: number; high: number; medium: number; low: number; total: number; remediated: number }[];
  sla_compliance: { severity: string; target_h: number; actual_h: number; status: string }[];
}

interface Metrics {
  mttr_hours: number;
  closed_this_week: number;
  closed_last_week: number;
  wow_improvement_pct: number;
  fp_rate_pct: number;
  fp_count_30d: number;
  accepted_risk: number;
  actions_this_week: Record<string, number>;
}

interface MonthlyPoint {
  month: string;
  critical: number;
  high: number;
  medium: number;
  total: number;
  remediated: number;
}

// ── Finding category intelligence map ────────────────────────────────────────
// What each category MEANS in plain English, why it's dangerous, and what to do.

interface CategoryIntel {
  icon: React.ReactNode;
  label: string;
  color: string;
  ring: string;
  bg: string;
  text: string;
  plain: string;
  threat: string;
  action: string;
  mitre: string;
}

const CAT_INTEL: Record<string, CategoryIntel> = {
  execution: {
    icon: <Zap className="w-3.5 h-3.5" />,
    label: "Execution",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "Malicious code ran on this system",
    threat: "Code execution is the core of most attacks. Once an attacker can run arbitrary code with privilege, the host is fully compromised. This maps to what attackers do right after they gain initial access.",
    action: "Isolate the host immediately. Capture memory image. Trace parent→child process chain. Check for lateral movement to other hosts.",
    mitre: "TA0002 · Execution",
  },
  persistence: {
    icon: <Lock className="w-3.5 h-3.5" />,
    label: "Persistence",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "Something was set up to survive a reboot",
    threat: "Attackers install persistence so they can return even if their initial foothold is cleaned up. LaunchDaemons, login items, cron jobs, and scheduled tasks are common vectors on macOS and Linux.",
    action: "Review all startup items. Diff against clean baseline. Remove unauthorized entries. Check if matching IOC appears in threat intel feeds.",
    mitre: "TA0003 · Persistence",
  },
  network: {
    icon: <Network className="w-3.5 h-3.5" />,
    label: "Network",
    color: "#d97706", ring: "ring-amber-200", bg: "bg-amber-50", text: "text-amber-700",
    plain: "Suspicious network communication detected",
    threat: "Unusual outbound connections may indicate command-and-control (C2) beaconing, data exfiltration, or lateral movement. Attackers use encrypted channels, legitimate cloud services, and DNS tunneling to evade detection.",
    action: "Block the destination IP/domain at the perimeter. Capture PCAP for forensics. Check if other hosts communicate with the same endpoint.",
    mitre: "TA0011 · Command and Control",
  },
  vulnerability: {
    icon: <Bug className="w-3.5 h-3.5" />,
    label: "Vulnerability",
    color: "#d97706", ring: "ring-amber-200", bg: "bg-amber-50", text: "text-amber-700",
    plain: "A known exploitable weakness found on this system",
    threat: "CVEs rated critical/high mean public exploit code likely exists. CISA's KEV list means it's actively being exploited in the wild right now. Unpatched systems are low-hanging fruit for ransomware groups.",
    action: "Apply vendor patch immediately for KEV entries. For others, assess exploitability (EPSS score). Implement compensating controls (WAF, network segmentation) while patching.",
    mitre: "TA0001 · Initial Access",
  },
  privilege_escalation: {
    icon: <ShieldAlert className="w-3.5 h-3.5" />,
    label: "Privilege Escalation",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "An account or process gained higher privileges than expected",
    threat: "UID=0 / SYSTEM-level access means the attacker can do anything: disable security tools, dump credentials, pivot to other systems. This is a critical escalation in attack severity.",
    action: "Immediately revoke the escalated account. Audit all sudo/su commands in the last 24h. Check for backdoor accounts. Engage Incident Response.",
    mitre: "TA0004 · Privilege Escalation",
  },
  credential_access: {
    icon: <Users className="w-3.5 h-3.5" />,
    label: "Credential Access",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "Credentials (passwords/tokens/keys) may have been stolen",
    threat: "Stolen credentials enable the attacker to log in legitimately, making them nearly invisible to many detection tools. Keychain access and browser credential theft are top macOS attack vectors.",
    action: "Rotate all credentials on the affected host immediately. Audit authentication logs across all services. Enable MFA everywhere it isn't already active.",
    mitre: "TA0006 · Credential Access",
  },
  defense_evasion: {
    icon: <Eye className="w-3.5 h-3.5" />,
    label: "Defense Evasion",
    color: "#7c3aed", ring: "ring-purple-200", bg: "bg-purple-50", text: "text-purple-700",
    plain: "Something tried to hide from security tools",
    threat: "Disabling logging, clearing event logs, or injecting into legitimate processes are tactics attackers use specifically to blind your detection capabilities. This finding means the attacker is aware of your defenses.",
    action: "Verify security tool integrity. Check for log tampering. Increase monitoring sensitivity. If SIEMs show gaps, treat the gap window as a potential active intrusion.",
    mitre: "TA0005 · Defense Evasion",
  },
  lateral_movement: {
    icon: <ArrowRight className="w-3.5 h-3.5" />,
    label: "Lateral Movement",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "An attacker is moving from one system to another",
    threat: "Lateral movement means a single compromised endpoint is now a launching point for wider network compromise. SSH key reuse, pass-the-hash, and remote service exploitation are common techniques.",
    action: "Isolate the source host. Audit all hosts that received connections from it. Revoke shared SSH keys. Enable network micro-segmentation.",
    mitre: "TA0008 · Lateral Movement",
  },
  exfiltration: {
    icon: <Server className="w-3.5 h-3.5" />,
    label: "Exfiltration",
    color: "#dc2626", ring: "ring-red-200", bg: "bg-red-50", text: "text-red-700",
    plain: "Data may be leaving your organization",
    threat: "Data exfiltration is often the final goal of an attack and triggers breach notification requirements. Large DNS queries, staged archives, and cloud upload traffic are indicators to watch.",
    action: "Block outbound transfer immediately. Identify what data was accessed. Notify legal/privacy team for breach assessment. Preserve evidence for forensics.",
    mitre: "TA0010 · Exfiltration",
  },
  reconnaissance: {
    icon: <Target className="w-3.5 h-3.5" />,
    label: "Reconnaissance",
    color: "#2563eb", ring: "ring-blue-200", bg: "bg-blue-50", text: "text-blue-700",
    plain: "Something is mapping your internal network",
    threat: "Port scanning, OS fingerprinting, and service enumeration are precursors to targeted attacks. Internal reconnaissance after initial access means the attacker is planning their next move.",
    action: "Identify the scanning source. If internal, the source host is compromised. Harden network segmentation and minimize inter-host trust.",
    mitre: "TA0007 · Discovery",
  },
};

function getCategoryIntel(category: string): CategoryIntel {
  const key = category?.toLowerCase().replace(/[^a-z_]/g, "_");
  return (
    CAT_INTEL[key] ??
    CAT_INTEL[Object.keys(CAT_INTEL).find(k => key?.includes(k)) ?? ""] ?? {
      icon: <Shield className="w-3.5 h-3.5" />,
      label: category || "Unknown",
      color: "#6b7280", ring: "ring-gray-200", bg: "bg-gray-100", text: "text-gray-600",
      plain: "Security event detected",
      threat: "Review the raw finding detail for context on this event type.",
      action: "Investigate the finding and assess impact based on host criticality.",
      mitre: "Unknown",
    }
  );
}

// ── Utility helpers ───────────────────────────────────────────────────────────

function timeAgo(unix: number): string {
  const s = Math.floor(Date.now() / 1000) - unix;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function fmtTime(unix: number): string {
  return new Date(unix * 1000).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
}

function fmtDate(unix: number): string {
  return new Date(unix * 1000).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function fmtDateTime(unix: number): string {
  return new Date(unix * 1000).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

// ── Severity color helpers ────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#dc2626", high: "#d97706", medium: "#2563eb", low: "#16a34a", info: "#6b7280",
};

const SEV_BG: Record<string, string> = {
  critical: "bg-red-500", high: "bg-amber-500", medium: "bg-blue-500", low: "bg-green-500", info: "bg-gray-400",
};

// ── Status workflow meaning ────────────────────────────────────────────────────

const STATUS_MEANING: Record<string, { label: string; desc: string; icon: React.ReactNode; color: string }> = {
  new:            { label: "New",            desc: "Detected but not yet reviewed by an analyst",              icon: <AlertTriangle className="w-3 h-3" />, color: "text-red-600" },
  triaging:       { label: "Triaging",       desc: "Analyst is assessing severity and impact",                  icon: <Eye className="w-3 h-3" />,           color: "text-amber-600" },
  investigating:  { label: "Investigating",  desc: "Active forensic investigation underway",                    icon: <Activity className="w-3 h-3" />,      color: "text-blue-600" },
  in_remediation: { label: "In Remediation", desc: "Fix is actively being applied to the system",              icon: <Zap className="w-3 h-3" />,           color: "text-purple-600" },
  remediated:     { label: "Remediated",     desc: "Fix applied — awaiting final verification",                 icon: <CheckCircle2 className="w-3 h-3" />,  color: "text-green-600" },
  verified:       { label: "Verified",       desc: "Fix confirmed working by second analyst",                   icon: <ShieldCheck className="w-3 h-3" />,   color: "text-green-700" },
  closed:         { label: "Closed",         desc: "Fully resolved and documented",                             icon: <X className="w-3 h-3" />,             color: "text-gray-500" },
  false_positive: { label: "False Positive", desc: "Reviewed and confirmed as a benign detection",              icon: <X className="w-3 h-3" />,             color: "text-gray-500" },
  accepted_risk:  { label: "Accepted Risk",  desc: "Risk acknowledged by ownership — no remediation planned",  icon: <BookOpen className="w-3 h-3" />,      color: "text-amber-600" },
};

// ── Sub-components ────────────────────────────────────────────────────────────

function Pill({ label, color }: { label: string; color: string }) {
  return (
    <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide border", color)}>
      {label}
    </span>
  );
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn("bg-gray-100 rounded-lg animate-pulse", className)} />;
}

// ── KPI card ──────────────────────────────────────────────────────────────────

function KPITile({
  label, value, sub, icon, color, trend,
}: {
  label: string; value: string | number; sub?: string;
  icon: React.ReactNode; color: string; trend?: "up" | "down" | "neutral";
}) {
  return (
    <div className={cn("bg-white border rounded-2xl p-4 shadow-sm hover:shadow-md transition-shadow", color)}>
      <div className="flex items-start justify-between mb-2">
        <div className={cn("p-2 rounded-xl", color.includes("red") ? "bg-red-50" : color.includes("amber") ? "bg-amber-50" : color.includes("green") ? "bg-green-50" : color.includes("blue") ? "bg-blue-50" : color.includes("purple") ? "bg-purple-50" : "bg-gray-100")}>
          {icon}
        </div>
        {trend && (
          <span className={cn("text-[10px] font-bold flex items-center gap-0.5", trend === "up" ? "text-green-600" : trend === "down" ? "text-red-600" : "text-gray-400")}>
            {trend === "up" ? <TrendingUp className="w-3 h-3" /> : trend === "down" ? <TrendingDown className="w-3 h-3" /> : null}
          </span>
        )}
      </div>
      <div className="text-2xl font-black text-gray-900 tabular-nums leading-none">{value}</div>
      <div className="text-[11px] font-semibold text-gray-500 mt-1">{label}</div>
      {sub && <div className="text-[10px] text-gray-400 mt-0.5">{sub}</div>}
    </div>
  );
}

// ── 7-day stacked bar chart ───────────────────────────────────────────────────

function DailyTrendChart({ data }: { data: DashStats["daily_trend"] }) {
  if (!data?.length) return <ChartSkeleton />;
  const maxVal = Math.max(...data.map(d => d.total), 1);
  const H = 130;

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="text-sm font-bold text-gray-800">Daily Finding Volume</p>
          <p className="text-[10px] text-gray-400 mt-0.5">7-day trend by severity</p>
        </div>
        <div className="flex items-center gap-3 text-[10px] text-gray-500">
          {[["Critical","bg-red-500"],["High","bg-amber-500"],["Medium","bg-blue-400"],["Remediated","bg-green-400"]].map(([l,c]) => (
            <span key={l} className="flex items-center gap-1">
              <span className={cn("w-2 h-2 rounded-sm inline-block", c)} />{l}
            </span>
          ))}
        </div>
      </div>

      <div className="flex items-end gap-2" style={{ height: H + 40 }}>
        {data.map((d, i) => {
          const total = d.total || 0;
          const rem   = d.remediated || 0;
          const toH = (v: number) => total > 0 ? Math.max(2, (v / maxVal) * H) : 0;
          return (
            <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
              {/* Total label */}
              <span className="text-[9px] font-bold text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity">{total}</span>
              {/* Stacked bar */}
              <div className="w-full flex flex-col justify-end gap-0 rounded-t-md overflow-hidden" style={{ height: H }}>
                <div title={`Critical: ${d.critical}`} className="w-full bg-red-500 transition-all duration-700 rounded-t-sm" style={{ height: toH(d.critical) }} />
                <div title={`High: ${d.high}`}     className="w-full bg-amber-500 transition-all duration-700" style={{ height: toH(d.high) }} />
                <div title={`Medium: ${d.medium}`} className="w-full bg-blue-400  transition-all duration-700" style={{ height: toH(d.medium) }} />
                <div title={`Low: ${d.low}`}       className="w-full bg-green-300 transition-all duration-700" style={{ height: toH(d.low ?? 0) }} />
              </div>
              {/* Remediated overlay indicator */}
              {rem > 0 && (
                <div className="w-full h-1 rounded-full bg-green-400 opacity-70" title={`Remediated: ${rem}`} />
              )}
              <span className="text-[9px] text-gray-400 font-medium whitespace-nowrap">{d.date}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ChartSkeleton() {
  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <Skeleton className="h-4 w-40 mb-4" />
      <div className="flex items-end gap-2 h-36">
        {Array.from({ length: 7 }).map((_, i) => (
          <Skeleton key={i} className="flex-1 rounded-t-md animate-pulse" style={{ height: `${40 + Math.random() * 60}%` }} />
        ))}
      </div>
    </div>
  );
}

// ── 6-month sparkline ─────────────────────────────────────────────────────────

function MonthlySparkline({ data }: { data: MonthlyPoint[] }) {
  if (!data?.length) return <Skeleton className="h-40" />;
  const W = 400; const H = 80;
  const maxT = Math.max(...data.map(d => d.total), 1);

  const pts = (key: keyof MonthlyPoint) =>
    data.map((d, i) => {
      const x = (i / (data.length - 1)) * (W - 20) + 10;
      const y = H - ((Number(d[key]) / maxT) * (H - 16)) - 8;
      return `${x},${y}`;
    }).join(" ");

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="flex items-center justify-between mb-3">
        <div>
          <p className="text-sm font-bold text-gray-800">6-Month Trend</p>
          <p className="text-[10px] text-gray-400 mt-0.5">Monthly finding history</p>
        </div>
      </div>
      <svg width="100%" viewBox={`0 0 ${W} ${H + 24}`} className="overflow-visible">
        {/* Grid */}
        {[0, 0.25, 0.5, 0.75, 1].map(f => (
          <line key={f} x1={10} y1={H - f * (H - 16) - 8} x2={W - 10} y2={H - f * (H - 16) - 8}
            stroke="#f1f5f9" strokeWidth={1} />
        ))}
        {/* Total area */}
        <polyline points={pts("total")} fill="none" stroke="#3b82f6" strokeWidth={2} strokeLinejoin="round" />
        {/* Critical line */}
        <polyline points={pts("critical")} fill="none" stroke="#ef4444" strokeWidth={1.5} strokeDasharray="4 2" strokeLinejoin="round" />
        {/* Remediated line */}
        <polyline points={pts("remediated")} fill="none" stroke="#22c55e" strokeWidth={1.5} strokeLinejoin="round" />
        {/* Month labels */}
        {data.map((d, i) => {
          const x = (i / (data.length - 1)) * (W - 20) + 10;
          return (
            <text key={i} x={x} y={H + 18} textAnchor="middle" fontSize={9} fill="#94a3b8" fontWeight={600}>
              {d.month}
            </text>
          );
        })}
      </svg>
      <div className="flex items-center gap-4 mt-1 text-[10px] text-gray-500">
        <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-blue-500 inline-block rounded" />Total</span>
        <span className="flex items-center gap-1"><span className="w-3 border-t-2 border-red-400 border-dashed inline-block" />Critical</span>
        <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-green-500 inline-block rounded" />Remediated</span>
      </div>
    </div>
  );
}

// ── MTTR panel ────────────────────────────────────────────────────────────────

const MTTR_TARGETS: Record<string, number> = { Critical: 4, High: 24, Medium: 168, Low: 720 };
const MTTR_MEANING: Record<string, string> = {
  Critical: "Must be resolved in 4 hours (IBM/NIST recommendation for actively-exploited criticals)",
  High:     "24-hour SLA is the SOC industry standard for exploitable high-severity findings",
  Medium:   "7-day (168h) window balances remediation workload with acceptable risk exposure",
  Low:      "30-day (720h) allows scheduled patching cycles for low-impact issues",
};

function MTTRPanel({ sla }: { sla: DashStats["sla_compliance"] }) {
  const rows = sla?.length
    ? sla
    : (["Critical","High","Medium","Low"] as const).map(s => ({
        severity: s, target_h: MTTR_TARGETS[s], actual_h: 0, status: "ON TRACK",
      }));

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="mb-4">
        <p className="text-sm font-bold text-gray-800">Mean Time To Remediate</p>
        <p className="text-[10px] text-gray-400 mt-0.5">SLA compliance by severity — lower is better</p>
      </div>
      <div className="space-y-4">
        {rows.map(m => {
          const isBreached = m.status === "BREACHED" || (m.actual_h > 0 && m.actual_h > m.target_h);
          const target = MTTR_TARGETS[m.severity] ?? m.target_h;
          const pct = m.actual_h > 0 ? Math.min(100, (m.actual_h / target) * 100) : 0;
          return (
            <div key={m.severity} className="group">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-bold text-gray-700">{m.severity}</span>
                  {isBreached && (
                    <span className="px-1.5 py-0.5 bg-red-50 text-red-600 border border-red-200 rounded-full text-[9px] font-bold uppercase">SLA BREACH</span>
                  )}
                </div>
                <div className="text-right">
                  <span className={cn("text-[11px] font-black tabular-nums", isBreached ? "text-red-600" : "text-green-600")}>
                    {m.actual_h > 0 ? `${m.actual_h}h` : "—"}
                  </span>
                  <span className="text-[10px] text-gray-400 ml-1">/ {target}h target</span>
                </div>
              </div>
              <div className="relative w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className={cn("h-full rounded-full transition-all duration-700", isBreached ? "bg-gradient-to-r from-red-500 to-red-600" : "bg-gradient-to-r from-green-400 to-green-500")}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <p className="text-[9px] text-gray-400 mt-1 hidden group-hover:block transition-all">
                {MTTR_MEANING[m.severity]}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── DB sync status card ───────────────────────────────────────────────────────

function DbSyncCard({ stats, metrics, lastFetch }: { stats: DashStats | null; metrics: Metrics | null; lastFetch: number }) {
  const sources = [
    { name: "Findings DB",     icon: <Database className="w-3.5 h-3.5" />, value: stats?.kpi.total_active ?? "—",    unit: "active findings",  fresh: true },
    { name: "Threat Intel",    icon: <Shield className="w-3.5 h-3.5" />,   value: "590K",                              unit: "IOCs loaded",      fresh: true },
    { name: "Agent Telemetry", icon: <Cpu className="w-3.5 h-3.5" />,      value: stats?.top_agents?.length ?? "—",   unit: "reporting agents", fresh: true },
    { name: "SLA Engine",      icon: <Clock className="w-3.5 h-3.5" />,    value: stats?.kpi.sla_breached ?? 0,        unit: "breached SLAs",    fresh: true },
  ];
  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <p className="text-sm font-bold text-gray-800">Database Status</p>
        </div>
        <span className="text-[10px] text-gray-400 font-medium">
          {lastFetch ? `Updated ${timeAgo(lastFetch)}` : "Loading…"}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2.5">
        {sources.map(s => (
          <div key={s.name} className="flex items-center gap-3 p-3 rounded-xl bg-gray-50 border border-gray-100">
            <div className="p-1.5 rounded-lg bg-white border border-gray-200 text-gray-500 flex-shrink-0">
              {s.icon}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-black text-gray-900 tabular-nums leading-none">{String(s.value)}</div>
              <div className="text-[10px] text-gray-500 truncate">{s.unit}</div>
              <div className="text-[9px] text-green-500 font-semibold mt-0.5">● Live</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Category distribution chart ───────────────────────────────────────────────

function CategoryChart({ data }: { data: DashStats["category_dist"] }) {
  if (!data?.length) return <Skeleton className="h-64" />;
  const maxC = Math.max(...data.map(d => d.count), 1);
  const top = [...data].sort((a, b) => b.count - a.count).slice(0, 8);

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="mb-4">
        <p className="text-sm font-bold text-gray-800">Findings by Category</p>
        <p className="text-[10px] text-gray-400 mt-0.5">What attack techniques are present — hover for meaning</p>
      </div>
      <div className="space-y-2.5">
        {top.map(d => {
          const intel = getCategoryIntel(d.category);
          const w = Math.max(4, (d.count / maxC) * 100);
          return (
            <div key={d.category} className="group">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className={cn("p-1 rounded-md text-xs", intel.bg, intel.text)}>{intel.icon}</span>
                  <span className="text-[11px] font-semibold text-gray-700 capitalize">{intel.label}</span>
                </div>
                <span className="text-[11px] font-black text-gray-900 tabular-nums">{d.count}</span>
              </div>
              <div className="relative w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${w}%`, backgroundColor: intel.color }}
                />
              </div>
              {/* Meaning tooltip on hover */}
              <p className="text-[9px] text-gray-400 mt-1 hidden group-hover:block leading-relaxed">
                {intel.plain} — {intel.mitre}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Status distribution donut ─────────────────────────────────────────────────

function StatusDonut({ data }: { data: DashStats["status_dist"] }) {
  if (!data?.length) return <Skeleton className="h-64" />;
  const total = data.reduce((s, d) => s + d.count, 0) || 1;
  const STATUS_COLORS: Record<string, string> = {
    new: "#ef4444", triaging: "#f59e0b", investigating: "#3b82f6",
    in_remediation: "#8b5cf6", remediated: "#22c55e", closed: "#9ca3af",
    false_positive: "#d1d5db", accepted_risk: "#fbbf24",
  };
  const SIZE = 140; const CX = SIZE / 2; const CY = SIZE / 2; const R = 52; const INNER_R = 34;
  const circ = 2 * Math.PI * R;

  let offset = 0;
  const arcs = data.filter(d => d.count > 0).map(d => {
    const frac = d.count / total;
    const arc = { d, frac, offset, dashArray: `${frac * circ} ${(1 - frac) * circ}` };
    offset += frac;
    return arc;
  });

  return (
    <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
      <div className="mb-4">
        <p className="text-sm font-bold text-gray-800">Status Distribution</p>
        <p className="text-[10px] text-gray-400 mt-0.5">SOC workflow — where findings stand now</p>
      </div>
      <div className="flex items-center gap-5">
        <svg width={SIZE} height={SIZE} className="flex-shrink-0">
          {arcs.map(({ d, dashArray, offset: off }) => (
            <circle
              key={d.status}
              cx={CX} cy={CY} r={R}
              fill="none"
              stroke={STATUS_COLORS[d.status] ?? "#9ca3af"}
              strokeWidth={INNER_R - 2}
              strokeDasharray={dashArray}
              strokeDashoffset={-off * circ}
              transform={`rotate(-90 ${CX} ${CY})`}
              style={{ transition: "stroke-dasharray 1s ease" }}
            />
          ))}
          <text x={CX} y={CY - 4} textAnchor="middle" dominantBaseline="middle" fontSize={18} fontWeight={800} fill="#111827">
            {total}
          </text>
          <text x={CX} y={CY + 12} textAnchor="middle" fontSize={8} fill="#9ca3af" fontWeight={600}>
            TOTAL
          </text>
        </svg>
        <div className="flex-1 space-y-1.5 min-w-0">
          {data.filter(d => d.count > 0).sort((a, b) => b.count - a.count).map(d => {
            const meaning = STATUS_MEANING[d.status];
            return (
              <div key={d.status} className="flex items-center gap-2 group">
                <div className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: STATUS_COLORS[d.status] ?? "#9ca3af" }} />
                <span className="text-[10px] font-semibold text-gray-600 flex-1 truncate">{meaning?.label ?? d.status}</span>
                <span className="text-[10px] font-black text-gray-900 tabular-nums">{d.count}</span>
              </div>
            );
          })}
        </div>
      </div>
      {/* Status flow legend */}
      <div className="mt-4 pt-4 border-t border-gray-100">
        <p className="text-[9px] text-gray-400 font-bold uppercase tracking-wider mb-2">SOC Workflow</p>
        <div className="flex items-center gap-1 flex-wrap">
          {["new","triaging","investigating","in_remediation","remediated","verified","closed"].map((s, i, arr) => (
            <span key={s} className="flex items-center gap-1">
              <span className="text-[9px] font-semibold text-gray-500 capitalize">{s.replace("_"," ")}</span>
              {i < arr.length - 1 && <ChevronRight className="w-2.5 h-2.5 text-gray-300" />}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Scan session card (derived from recent findings) ──────────────────────────

interface ScanSession {
  key: string;
  time: number;
  findings: Finding[];
  newCount: number;
  critical: number;
  high: number;
  agentIds: string[];
  topCategory: string;
}

function deriveScanSessions(findings: Finding[]): ScanSession[] {
  if (!findings.length) return [];
  const sorted = [...findings].sort((a, b) => b.last_detected_at - a.last_detected_at);
  const sessions: ScanSession[] = [];
  let current: Finding[] = [];
  let sessionTime = sorted[0].last_detected_at;

  for (const f of sorted) {
    if (sessionTime - f.last_detected_at > 120) {
      if (current.length) sessions.push(buildSession(current));
      current = [f];
      sessionTime = f.last_detected_at;
    } else {
      current.push(f);
    }
    if (sessions.length >= 5) break;
  }
  if (current.length && sessions.length < 5) sessions.push(buildSession(current));
  return sessions.slice(0, 5);
}

function buildSession(findings: Finding[]): ScanSession {
  const catMap: Record<string, number> = {};
  findings.forEach(f => { catMap[f.category] = (catMap[f.category] ?? 0) + 1; });
  const topCategory = Object.entries(catMap).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "unknown";
  const agentIds = [...new Set(findings.map(f => f.agent_id))];
  return {
    key: String(findings[0].last_detected_at),
    time: findings[0].last_detected_at,
    findings,
    newCount: findings.filter(f => f.status === "new").length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    agentIds,
    topCategory,
  };
}

function ScanSessionCard({ session, index }: { session: ScanSession; index: number }) {
  const [expanded, setExpanded] = useState(index === 0);
  const intel = getCategoryIntel(session.topCategory);
  const isLatest = index === 0;

  return (
    <div className={cn("relative bg-white rounded-2xl border shadow-sm overflow-hidden transition-all", isLatest ? "border-orange-200 shadow-orange-50" : "border-gray-200")}>
      {isLatest && <div className="h-0.5 bg-gradient-to-r from-orange-400 to-amber-400" />}
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-gray-50/50 transition-colors text-left"
      >
        {/* Timeline dot */}
        <div className="flex flex-col items-center flex-shrink-0">
          <div className={cn("w-3 h-3 rounded-full border-2 flex-shrink-0", isLatest ? "border-orange-400 bg-orange-100" : "border-gray-300 bg-gray-100")} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-black text-gray-800">{fmtDateTime(session.time)}</span>
            <span className="text-[10px] text-gray-400">({timeAgo(session.time)})</span>
            {isLatest && <span className="px-2 py-0.5 bg-orange-100 text-orange-600 border border-orange-200 rounded-full text-[9px] font-bold">LATEST</span>}
            {session.newCount > 0 && (
              <span className="px-2 py-0.5 bg-red-50 text-red-600 border border-red-200 rounded-full text-[9px] font-bold">
                {session.newCount} NEW
              </span>
            )}
          </div>
          <div className="flex items-center gap-4 mt-1.5">
            <span className="text-[10px] text-gray-500">{session.findings.length} findings across {session.agentIds.length} agent{session.agentIds.length > 1 ? "s" : ""}</span>
            {session.critical > 0 && <span className="text-[10px] text-red-600 font-bold">● {session.critical} critical</span>}
            {session.high > 0 && <span className="text-[10px] text-amber-600 font-bold">● {session.high} high</span>}
            <span className={cn("text-[10px] font-semibold", intel.text)}>Top: {intel.label}</span>
          </div>
        </div>

        {/* Severity chips */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {(["critical","high","medium","low"] as const).map(s => {
            const cnt = session.findings.filter(f => f.severity === s).length;
            if (!cnt) return null;
            return (
              <span key={s} className="px-2 py-0.5 rounded-full text-[9px] font-black" style={{ backgroundColor: SEV_COLOR[s] + "20", color: SEV_COLOR[s] }}>
                {cnt}
              </span>
            );
          })}
        </div>
        <ChevronDown className={cn("w-4 h-4 text-gray-400 flex-shrink-0 transition-transform", expanded && "rotate-180")} />
      </button>

      {expanded && (
        <div className="border-t border-gray-100 px-5 pb-4">
          <div className="mt-3 space-y-1.5 max-h-64 overflow-y-auto">
            {session.findings.map(f => {
              const fi = getCategoryIntel(f.category);
              return (
                <div key={f.id} className="flex items-start gap-2.5 py-2 px-3 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors">
                  <span className={cn("p-1 rounded-md flex-shrink-0 mt-0.5", fi.bg, fi.text)}>{fi.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SevBadge sev={f.severity} />
                      <span className="text-[11px] font-semibold text-gray-800 truncate">{f.title}</span>
                    </div>
                    <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2">{f.description || fi.plain}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1 flex-shrink-0">
                    <StatusBadge status={f.status} />
                    {f.mitre_technique && <MitreBadge id={f.mitre_technique} />}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── New finding card (expanded, with full meaning) ────────────────────────────

function NewFindingCard({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const intel = getCategoryIntel(f.category);
  const isNew = f.status === "new";

  return (
    <div className={cn(
      "bg-white border rounded-2xl shadow-sm overflow-hidden transition-all hover:shadow-md",
      f.severity === "critical" ? "border-red-200"
      : f.severity === "high"   ? "border-amber-200"
      : "border-gray-200"
    )}>
      {/* Severity stripe */}
      <div className="h-1" style={{ backgroundColor: SEV_COLOR[f.severity] ?? "#6b7280" }} />

      <div className="p-4">
        {/* Header row */}
        <div className="flex items-start gap-3">
          <div className={cn("p-2 rounded-xl flex-shrink-0 mt-0.5", intel.bg)}>
            <span className={intel.text}>{intel.icon}</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <SevBadge sev={f.severity} />
              <StatusBadge status={f.status} />
              {isNew && (
                <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-[9px] font-bold border border-red-200 animate-pulse">NEW</span>
              )}
              {f.kev && <span className="px-1.5 py-0.5 bg-red-100 text-red-700 border border-red-300 rounded text-[9px] font-bold">KEV</span>}
            </div>
            <h3 className="text-sm font-bold text-gray-900 leading-snug">{f.title}</h3>
            <p className="text-[11px] text-gray-500 mt-1 line-clamp-2">{f.description}</p>
          </div>
          <div className="flex flex-col items-end gap-1.5 flex-shrink-0 ml-2">
            <span className="text-[10px] text-gray-400 font-medium whitespace-nowrap">{fmtDateTime(f.last_detected_at)}</span>
            <span className="text-[10px] text-gray-500 font-mono">{f.agent_id}</span>
          </div>
        </div>

        {/* Meta chips */}
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          {f.mitre_technique && <MitreBadge id={f.mitre_technique} label={f.mitre_tactic} />}
          {f.cve_ids && (
            <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-[10px] font-mono font-semibold border border-gray-200">{f.cve_ids}</span>
          )}
          {f.epss_score !== undefined && f.epss_score > 0 && (
            <span className="px-2 py-0.5 bg-amber-50 text-amber-700 rounded text-[10px] font-semibold border border-amber-200">
              EPSS {Math.round(f.epss_score * 100)}%
            </span>
          )}
          <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded text-[10px] font-medium">{intel.label}</span>
        </div>

        {/* Expand button */}
        <button
          onClick={() => setOpen(o => !o)}
          className="mt-3 flex items-center gap-1 text-[11px] text-blue-600 font-semibold hover:text-blue-700 transition-colors"
        >
          <BookOpen className="w-3.5 h-3.5" />
          {open ? "Hide" : "What does this mean?"}
          <ChevronDown className={cn("w-3 h-3 transition-transform", open && "rotate-180")} />
        </button>

        {/* Expanded meaning */}
        {open && (
          <div className="mt-3 space-y-3 border-t border-gray-100 pt-3">
            <div className="grid grid-cols-3 gap-3">
              {/* What it is */}
              <div className="p-3 rounded-xl bg-blue-50 border border-blue-100">
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Info className="w-3.5 h-3.5 text-blue-500" />
                  <span className="text-[10px] font-bold text-blue-700 uppercase tracking-wide">What this is</span>
                </div>
                <p className="text-[11px] text-blue-800 leading-relaxed">{intel.plain}</p>
              </div>
              {/* Why it's dangerous */}
              <div className="p-3 rounded-xl bg-red-50 border border-red-100">
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Flame className="w-3.5 h-3.5 text-red-500" />
                  <span className="text-[10px] font-bold text-red-700 uppercase tracking-wide">Why it's dangerous</span>
                </div>
                <p className="text-[11px] text-red-800 leading-relaxed">{intel.threat}</p>
              </div>
              {/* What to do */}
              <div className="p-3 rounded-xl bg-green-50 border border-green-100">
                <div className="flex items-center gap-1.5 mb-1.5">
                  <Target className="w-3.5 h-3.5 text-green-600" />
                  <span className="text-[10px] font-bold text-green-700 uppercase tracking-wide">Recommended action</span>
                </div>
                <p className="text-[11px] text-green-800 leading-relaxed">{intel.action}</p>
              </div>
            </div>
            {/* MITRE context */}
            <div className="flex items-center gap-2 p-3 rounded-xl bg-indigo-50 border border-indigo-100">
              <GitBranch className="w-3.5 h-3.5 text-indigo-500 flex-shrink-0" />
              <div>
                <span className="text-[10px] font-bold text-indigo-700 uppercase tracking-wide">MITRE ATT&CK — </span>
                <span className="text-[11px] text-indigo-600">{intel.mitre}</span>
                {f.mitre_technique && (
                  <span className="ml-2 text-[11px] text-indigo-500 font-mono">
                    · Technique {f.mitre_technique}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Activity feed event ───────────────────────────────────────────────────────

interface ActivityEvent {
  time: number;
  type: "critical" | "high" | "medium" | "info" | "remediated" | "system";
  msg: string;
  actor: string;
  category?: string;
}

const EVENT_STYLE: Record<string, { dot: string; bg: string; text: string; icon: React.ReactNode }> = {
  critical:   { dot: "bg-red-500",    bg: "bg-red-50",    text: "text-red-700",   icon: <AlertTriangle className="w-3 h-3" /> },
  high:       { dot: "bg-amber-500",  bg: "bg-amber-50",  text: "text-amber-700", icon: <ShieldAlert className="w-3 h-3" /> },
  medium:     { dot: "bg-blue-400",   bg: "bg-blue-50",   text: "text-blue-700",  icon: <Activity className="w-3 h-3" /> },
  remediated: { dot: "bg-green-500",  bg: "bg-green-50",  text: "text-green-700", icon: <CheckCircle2 className="w-3 h-3" /> },
  info:       { dot: "bg-gray-400",   bg: "bg-gray-50",   text: "text-gray-600",  icon: <Info className="w-3 h-3" /> },
  system:     { dot: "bg-blue-300",   bg: "bg-blue-50",   text: "text-blue-600",  icon: <Database className="w-3 h-3" /> },
};

function ActivityEntry({ event, isLast }: { event: ActivityEvent; isLast: boolean }) {
  const style = EVENT_STYLE[event.type] ?? EVENT_STYLE.info;
  return (
    <div className="flex gap-3">
      {/* Timeline column */}
      <div className="flex flex-col items-center flex-shrink-0">
        <div className={cn("w-2.5 h-2.5 rounded-full border-2 border-white shadow-sm flex-shrink-0 mt-1", style.dot)} />
        {!isLast && <div className="w-0.5 flex-1 bg-gray-100 mt-1" />}
      </div>
      {/* Content */}
      <div className="flex-1 pb-4">
        <div className={cn("rounded-xl px-3 py-2.5 border", style.bg,
          event.type === "critical" ? "border-red-100" :
          event.type === "high" ? "border-amber-100" :
          event.type === "remediated" ? "border-green-100" : "border-gray-100"
        )}>
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-start gap-2 flex-1 min-w-0">
              <span className={cn("mt-0.5 flex-shrink-0", style.text)}>{style.icon}</span>
              <span className="text-[11px] font-medium text-gray-800 leading-snug">{event.msg}</span>
            </div>
            <div className="flex flex-col items-end flex-shrink-0 gap-0.5">
              <span className="text-[10px] font-mono text-gray-400">{fmtTime(event.time)}</span>
              <span className="text-[9px] text-gray-400 font-medium">{event.actor}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── SOC performance metrics bar ───────────────────────────────────────────────

function MetricsBar({ metrics }: { metrics: Metrics | null }) {
  if (!metrics) return null;
  const wow = metrics.wow_improvement_pct;
  return (
    <div className="grid grid-cols-4 gap-3">
      {[
        { label: "MTTR (avg)", value: metrics.mttr_hours > 0 ? `${metrics.mttr_hours}h` : "—", sub: "mean time to remediate", color: "text-blue-600", bg: "bg-blue-50 border-blue-100", icon: <Clock className="w-4 h-4 text-blue-500" /> },
        { label: "Closed This Week", value: metrics.closed_this_week, sub: `vs ${metrics.closed_last_week} last week`, color: "text-green-600", bg: "bg-green-50 border-green-100", icon: <CheckCircle2 className="w-4 h-4 text-green-500" /> },
        { label: "WoW Change", value: wow >= 0 ? `+${wow}%` : `${wow}%`, sub: "week-over-week closures", color: wow >= 0 ? "text-green-600" : "text-red-600", bg: wow >= 0 ? "bg-green-50 border-green-100" : "bg-red-50 border-red-100", icon: wow >= 0 ? <TrendingUp className="w-4 h-4 text-green-500" /> : <TrendingDown className="w-4 h-4 text-red-500" /> },
        { label: "False Positive Rate", value: `${metrics.fp_rate_pct}%`, sub: `${metrics.fp_count_30d} FPs in 30 days`, color: metrics.fp_rate_pct > 20 ? "text-red-600" : "text-gray-700", bg: metrics.fp_rate_pct > 20 ? "bg-red-50 border-red-100" : "bg-gray-50 border-gray-100", icon: <X className="w-4 h-4 text-gray-400" /> },
      ].map(m => (
        <div key={m.label} className={cn("rounded-2xl p-4 border shadow-sm flex items-start gap-3", m.bg)}>
          <div className="p-2 bg-white rounded-xl shadow-sm flex-shrink-0">{m.icon}</div>
          <div>
            <div className={cn("text-xl font-black leading-none tabular-nums", m.color)}>{String(m.value)}</div>
            <div className="text-[11px] font-semibold text-gray-600 mt-1">{m.label}</div>
            <div className="text-[10px] text-gray-400 mt-0.5">{m.sub}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Section header ────────────────────────────────────────────────────────────

function SectionHeader({ title, sub, count, icon, color = "orange" }: {
  title: string; sub?: string; count?: number; icon: React.ReactNode; color?: string;
}) {
  return (
    <div className="flex items-center gap-3 mb-3">
      <div className={cn("p-2 rounded-xl", color === "orange" ? "bg-orange-50" : color === "blue" ? "bg-blue-50" : color === "red" ? "bg-red-50" : "bg-gray-100")}>
        <span className={cn(color === "orange" ? "text-orange-500" : color === "blue" ? "text-blue-500" : color === "red" ? "text-red-500" : "text-gray-500")}>
          {icon}
        </span>
      </div>
      <div>
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-black text-gray-900">{title}</h2>
          {count !== undefined && (
            <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-[10px] font-bold">{count}</span>
          )}
        </div>
        {sub && <p className="text-[10px] text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Timeline() {
  const [dash, setDash]         = useState<DashStats | null>(null);
  const [metrics, setMetrics]   = useState<Metrics | null>(null);
  const [monthly, setMonthly]   = useState<MonthlyPoint[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading]   = useState(true);
  const [lastFetch, setLastFetch] = useState(0);
  const [actFilter, setActFilter] = useState<"all"|"critical"|"high"|"remediated"|"system">("all");

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [dashR, metricsR, monthlyR, findingsR] = await Promise.allSettled([
        fetch(`${SOC}/dashboard`).then(r => r.ok ? r.json() : null),
        fetch(`${SOC}/metrics`).then(r => r.ok ? r.json() : null),
        fetch(`${SOC}/historical?months=6`).then(r => r.ok ? r.json() : null),
        fetch(`${SOC}/findings?sort_by=last_detected_at&limit=50&active_only=false`).then(r => r.ok ? r.json() : null),
      ]);
      if (dashR.status === "fulfilled"    && dashR.value)    setDash(dashR.value);
      if (metricsR.status === "fulfilled" && metricsR.value) setMetrics(metricsR.value);
      if (monthlyR.status === "fulfilled" && monthlyR.value?.monthly_trend) setMonthly(monthlyR.value.monthly_trend);
      if (findingsR.status === "fulfilled" && findingsR.value?.findings)    setFindings(findingsR.value.findings);
      setLastFetch(Math.floor(Date.now() / 1000));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 60_000);
    return () => clearInterval(t);
  }, [fetchAll]);

  // Derive scan sessions from recent findings
  const scanSessions = deriveScanSessions(findings);
  const newFindings  = findings.filter(f => f.status === "new").slice(0, 10);

  // Build activity events from findings data
  const activityEvents: ActivityEvent[] = findings
    .sort((a, b) => b.last_detected_at - a.last_detected_at)
    .slice(0, 50)
    .map(f => ({
      time: f.last_detected_at,
      type: (["critical","high","medium","info"].includes(f.severity) ? f.severity : "info") as ActivityEvent["type"],
      msg: f.status === "remediated" || f.status === "closed"
        ? `[Remediated] ${f.title} — ${f.agent_id}`
        : `${f.title} — ${f.agent_id}`,
      actor: f.assignee ?? "system",
      category: f.category,
    }));

  const filteredActivity = actFilter === "all"
    ? activityEvents
    : activityEvents.filter(e => e.type === actFilter);

  const kpi = dash?.kpi;

  return (
    <div className="space-y-5 pb-6">

      {/* ── Page header ───────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500" />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center flex-shrink-0">
                <BarChart3 className="w-5 h-5 text-blue-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Timeline & History</h1>
                <p className="text-xs text-gray-500 mt-0.5 max-w-2xl">
                  Detect faster. Remediate sooner. Breach less.
                </p>
              </div>
            </div>
            <button
              onClick={fetchAll}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-semibold transition-colors flex-shrink-0"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
              Refresh
            </button>
          </div>

          {/* KPI strip */}
          {kpi && (
            <div className="grid grid-cols-6 gap-2.5 mt-4 pt-4 border-t border-gray-100">
              <div className="col-span-1 rounded-xl p-3 bg-gray-50 border border-gray-100 text-center">
                <div className="text-xl font-black text-gray-900 tabular-nums">{kpi.total_active}</div>
                <div className="text-[10px] text-gray-500 font-semibold mt-0.5">Active Findings</div>
              </div>
              <div className="col-span-1 rounded-xl p-3 bg-amber-50 border border-amber-100 text-center">
                <div className="text-xl font-black text-amber-700 tabular-nums">{kpi.new_today}</div>
                <div className="text-[10px] text-amber-600 font-semibold mt-0.5">New Today</div>
              </div>
              <div className="col-span-1 rounded-xl p-3 bg-green-50 border border-green-100 text-center">
                <div className="text-xl font-black text-green-700 tabular-nums">{kpi.remediated_today}</div>
                <div className="text-[10px] text-green-600 font-semibold mt-0.5">Remediated Today</div>
              </div>
              <div className="col-span-1 rounded-xl p-3 bg-red-50 border border-red-100 text-center">
                <div className="text-xl font-black text-red-700 tabular-nums">{kpi.critical_active}</div>
                <div className="text-[10px] text-red-600 font-semibold mt-0.5">Critical Active</div>
              </div>
              <div className="col-span-1 rounded-xl p-3 bg-amber-50 border border-amber-100 text-center">
                <div className="text-xl font-black text-amber-700 tabular-nums">{kpi.high_active}</div>
                <div className="text-[10px] text-amber-600 font-semibold mt-0.5">High Active</div>
              </div>
              <div className={cn("col-span-1 rounded-xl p-3 border text-center", kpi.sla_breached > 0 ? "bg-red-50 border-red-200" : "bg-gray-50 border-gray-100")}>
                <div className={cn("text-xl font-black tabular-nums", kpi.sla_breached > 0 ? "text-red-700" : "text-gray-700")}>{kpi.sla_breached}</div>
                <div className={cn("text-[10px] font-semibold mt-0.5", kpi.sla_breached > 0 ? "text-red-600" : "text-gray-500")}>SLA Breaches</div>
              </div>
            </div>
          )}
          {!kpi && loading && (
            <div className="grid grid-cols-6 gap-2.5 mt-4 pt-4 border-t border-gray-100">
              {Array.from({length:6}).map((_,i) => <Skeleton key={i} className="h-14 rounded-xl" />)}
            </div>
          )}
        </div>
      </div>

      {/* ── SOC performance metrics ────────────────────────────────────────── */}
      <MetricsBar metrics={metrics} />

      {/* ── DB status + Daily trend ────────────────────────────────────────── */}
      <div className="grid grid-cols-[320px_1fr] gap-4">
        <DbSyncCard stats={dash} metrics={metrics} lastFetch={lastFetch} />
        <DailyTrendChart data={dash?.daily_trend ?? []} />
      </div>

      {/* ── 6-month trend + MTTR ──────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4">
        <MonthlySparkline data={monthly} />
        <MTTRPanel sla={dash?.sla_compliance ?? []} />
      </div>

      {/* ── Category + Status distribution ────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4">
        <CategoryChart data={dash?.category_dist ?? []} />
        <StatusDonut   data={dash?.status_dist   ?? []} />
      </div>

      {/* ── Last 5 scan sessions ──────────────────────────────────────────── */}
      <div>
        <SectionHeader
          title="Last 5 Scan Sessions"
          sub="Grouped detection events — expand to see individual findings per session"
          count={scanSessions.length}
          icon={<Database className="w-4 h-4" />}
          color="blue"
        />
        {loading && !scanSessions.length ? (
          <div className="space-y-2">
            {Array.from({length:3}).map((_,i) => <Skeleton key={i} className="h-16 rounded-2xl" />)}
          </div>
        ) : scanSessions.length === 0 ? (
          <div className="bg-white border border-gray-200 rounded-2xl p-10 text-center">
            <Database className="w-8 h-8 text-gray-300 mx-auto mb-3" />
            <p className="text-sm text-gray-500">No scan sessions yet — findings will appear here once agents report.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {scanSessions.map((s, i) => (
              <ScanSessionCard key={s.key} session={s} index={i} />
            ))}
          </div>
        )}
      </div>

      {/* ── New findings (with full meaning) ─────────────────────────────── */}
      <div>
        <SectionHeader
          title="New Findings"
          sub="Unreviewed detections — click 'What does this mean?' for plain-English explanation, threat context, and recommended action"
          count={newFindings.length}
          icon={<AlertTriangle className="w-4 h-4" />}
          color="red"
        />
        {loading && !newFindings.length ? (
          <div className="space-y-3">
            {Array.from({length:3}).map((_,i) => <Skeleton key={i} className="h-28 rounded-2xl" />)}
          </div>
        ) : newFindings.length === 0 ? (
          <div className="bg-white border border-green-200 rounded-2xl p-8 text-center bg-green-50">
            <ShieldCheck className="w-8 h-8 text-green-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-green-700">No new unreviewed findings</p>
            <p className="text-[11px] text-green-600 mt-1">All detections have been acknowledged by an analyst.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {newFindings.map(f => <NewFindingCard key={f.id} finding={f} />)}
          </div>
        )}
      </div>

      {/* ── Activity timeline feed ─────────────────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <SectionHeader
            title="Activity Feed"
            sub="Chronological event stream — all detections and analyst actions"
            count={activityEvents.length}
            icon={<Activity className="w-4 h-4" />}
            color="orange"
          />
          {/* Filter pills */}
          <div className="flex items-center gap-1.5">
            {(["all","critical","high","remediated","system"] as const).map(f => (
              <button
                key={f}
                onClick={() => setActFilter(f)}
                className={cn(
                  "px-3 py-1 rounded-full text-[10px] font-bold capitalize transition-all",
                  actFilter === f
                    ? f === "critical" ? "bg-red-500 text-white"
                    : f === "high"     ? "bg-amber-500 text-white"
                    : f === "remediated" ? "bg-green-500 text-white"
                    : "bg-gray-800 text-white"
                    : "bg-gray-100 text-gray-500 hover:bg-gray-200"
                )}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {filteredActivity.length === 0 ? (
          <div className="bg-white border border-gray-200 rounded-2xl p-10 text-center">
            <Activity className="w-7 h-7 text-gray-300 mx-auto mb-2" />
            <p className="text-sm text-gray-400">No events match this filter.</p>
          </div>
        ) : (
          <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-5">
            <div className="space-y-0">
              {filteredActivity.slice(0, 40).map((e, i) => (
                <ActivityEntry key={i} event={e} isLast={i === filteredActivity.length - 1} />
              ))}
            </div>
            {filteredActivity.length > 40 && (
              <div className="text-center mt-3">
                <span className="text-[11px] text-gray-400">Showing 40 of {filteredActivity.length} events</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Top agents by finding count ────────────────────────────────────── */}
      {dash?.top_agents && dash.top_agents.length > 0 && (
        <div>
          <SectionHeader
            title="Most Active Agents"
            sub="Hosts with the highest finding counts — may indicate compromise or misconfiguration"
            icon={<Server className="w-4 h-4" />}
            color="blue"
          />
          <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-100">
                  <th className="px-4 py-2.5 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Host</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Agent ID</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Findings</th>
                  <th className="px-4 py-2.5 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Risk Share</th>
                </tr>
              </thead>
              <tbody>
                {dash.top_agents.map((a, i) => {
                  const total = dash.top_agents.reduce((s, x) => s + x.count, 0) || 1;
                  const pct = Math.round((a.count / total) * 100);
                  return (
                    <tr key={a.agent_id} className="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-gray-100 text-[9px] font-black text-gray-500 flex items-center justify-center">{i+1}</span>
                          <span className="font-semibold text-gray-800">{a.hostname || a.agent_id}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-[10px] text-gray-500">{a.agent_id}</td>
                      <td className="px-4 py-3 font-black text-gray-900 tabular-nums">{a.count}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                            <div className="h-full rounded-full bg-gradient-to-r from-orange-400 to-amber-500 transition-all duration-700" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-[10px] font-bold text-gray-600 w-8 text-right">{pct}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
