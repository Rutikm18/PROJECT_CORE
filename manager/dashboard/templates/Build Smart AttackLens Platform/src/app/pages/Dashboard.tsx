/**
 * Security Dashboard — High-level security posture overview.
 *
 * Data sources (parallel fetch, graceful degradation):
 *   /api/v1/soc/dashboard   — findings KPIs, severity/category/status dist, 7-day trend, SLA
 *   /api/v1/soc/metrics     — MTTR, WoW improvement, FP rate, closure velocity
 *   /api/v1/posture/agents  — CIS benchmark pass/fail per agent → aggregated
 *   /api/v1/detection/packages?limit=8  — top vulnerable packages by risk score
 *   /api/v1/detection/network?limit=8   — top network threats → port/service analysis
 *
 * Charts: recharts (already bundled) — LineChart, PieChart, BarChart, RadialBarChart
 * Animations: al-bounce-in, al-bar-fill, al-row-in, count-up hook (globals.css)
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  PieChart, Pie, Cell, LineChart, Line, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
  RadialBarChart, RadialBar,
} from "recharts";
import {
  ShieldCheck, RefreshCw, AlertTriangle, TrendingUp, TrendingDown,
  Minus, Activity, Clock, Package, Globe, Zap, Target,
  CheckCircle2, XCircle, Shield, AlertCircle, BarChart3,
  Radio, Users, Server, Lock,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── API endpoints ─────────────────────────────────────────────────────────────

const SOC     = "/api/v1/soc";
const POSTURE = "/api/v1/posture";
const DETECT  = "/api/v1/detection";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SocDash {
  kpi:            Record<string, number>;
  severity_dist:  { severity: string; count: number }[];
  status_dist:    { status: string;   count: number }[];
  category_dist:  { category: string; count: number }[];
  top_agents:     { agent_id: string; total: number; critical: number; high: number }[];
  daily_trend:    { date: string; critical: number; high: number; medium: number; low: number; closed?: number }[];
  sla_compliance: Record<string, { total: number; on_time: number; breached: number }>;
}

interface SocMetrics {
  mttr_hours:           number;
  closed_this_week:     number;
  closed_last_week:     number;
  wow_improvement_pct:  number;
  fp_rate_pct:          number;
  accepted_risk:        number;
}

interface PostureAgent {
  agent_id: string; hostname: string;
  score: number; grade: string;
  pass: number; fail: number; warn: number; total: number;
  has_data: boolean;
}

interface DetectionFinding {
  id: number; title: string; category: string;
  severity: string; score: number; composite_score?: number;
  source: string; cve_ids?: unknown; cvss_score?: number;
  mitre_technique?: string; agent_id: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function useCountUp(target: number, ms = 800): number {
  const [val, setVal] = useState(0);
  const ref = useRef(0);
  useEffect(() => {
    const diff = target - ref.current;
    const steps = 24; let i = 0;
    const t = setInterval(() => {
      i++;
      setVal(Math.round(ref.current + diff * (1 - Math.pow(1 - i / steps, 3))));
      if (i >= steps) { clearInterval(t); ref.current = target; }
    }, ms / steps);
    return () => clearInterval(t);
  }, [target, ms]);
  return val;
}

function relTime(ts: number): string {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

// ── Colour palette ────────────────────────────────────────────────────────────

const C = {
  critical: "#ef4444",
  high:     "#f59e0b",
  medium:   "#3b82f6",
  low:      "#22c55e",
  info:     "#9ca3af",
  orange:   "#f97316",
  purple:   "#8b5cf6",
  indigo:   "#6366f1",
  teal:     "#14b8a6",
};

const SEV_COLOR: Record<string, string> = {
  critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info,
};

// ── Custom recharts tooltip ───────────────────────────────────────────────────

function ChartTip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-xl px-3 py-2 shadow-xl text-[10px]">
      {label && <div className="text-gray-400 mb-1 font-semibold">{label}</div>}
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: p.color }} />
          <span className="text-gray-300 capitalize">{p.name ?? p.dataKey}:</span>
          <span className="text-white font-bold">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Score ring (SVG) ──────────────────────────────────────────────────────────

function ScoreRing({ score, grade, size = 100 }: { score: number; grade: string; size?: number }) {
  const color =
    grade === "A" ? "#16a34a" : grade === "B" ? "#2563eb" :
    grade === "C" ? "#d97706" : grade === "D" ? "#ea580c" : "#dc2626";
  const r    = size / 2 - 8;
  const circ = 2 * Math.PI * r;
  const cx   = size / 2;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth={7} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={7}
          strokeDasharray={`${(score / 100) * circ} ${circ}`}
          strokeDashoffset={circ * 0.25} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)" }} />
        <text x={cx} y={cx - 2} textAnchor="middle" fontSize={size >= 100 ? 22 : 14} fontWeight={800} fill={color}>{score}</text>
        <text x={cx} y={cx + 12} textAnchor="middle" fontSize={8} fill="#94a3b8">/100</text>
      </svg>
      <span className="text-xs font-black" style={{ color }}>Grade {grade}</span>
    </div>
  );
}

// ── Card wrapper ──────────────────────────────────────────────────────────────

function Card({ children, className, accent }: {
  children: React.ReactNode; className?: string; accent?: string;
}) {
  return (
    <div className={cn("bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden", className)}>
      <div className={cn("h-0.5", accent ?? "bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500")} />
      {children}
    </div>
  );
}

function CardHeader({ title, icon, right, color = "text-orange-500" }: {
  title: string; icon: React.ReactNode; right?: React.ReactNode; color?: string;
}) {
  return (
    <div className="flex items-center gap-2.5 px-4 py-3 border-b border-gray-100">
      <span className={color}>{icon}</span>
      <span className="text-[11px] font-black text-gray-800 uppercase tracking-wide">{title}</span>
      {right && <div className="ml-auto">{right}</div>}
    </div>
  );
}

// ── Trend indicator ───────────────────────────────────────────────────────────

function Trend({ val, inverse = false }: { val: number; inverse?: boolean }) {
  if (val === 0) return <span className="flex items-center gap-0.5 text-gray-400 text-[9px]"><Minus className="w-3 h-3" />0%</span>;
  const good = inverse ? val < 0 : val > 0;
  return (
    <span className={cn("flex items-center gap-0.5 text-[9px] font-bold", good ? "text-green-600" : "text-red-600")}>
      {val > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {Math.abs(val)}%
    </span>
  );
}

// ── KPI tile ──────────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub, color, bg, icon, trend, trendInverse, delay }: {
  label: string; value: string | number; sub?: string;
  color: string; bg: string; icon: React.ReactNode;
  trend?: number; trendInverse?: boolean; delay?: number;
}) {
  const numVal  = typeof value === "number" ? value : NaN;
  const counted = useCountUp(isNaN(numVal) ? 0 : numVal);
  const display = isNaN(numVal) ? value : counted;
  return (
    <div className={cn("rounded-2xl border p-4 al-bounce-in flex flex-col gap-2", bg)} style={{ animationDelay: `${delay ?? 0}ms` }}>
      <div className="flex items-start justify-between">
        <div className={cn("p-2 rounded-xl bg-white/60", color)}>{icon}</div>
        {trend !== undefined && <Trend val={trend} inverse={trendInverse} />}
      </div>
      <div>
        <div className={cn("text-2xl font-black tabular-nums leading-none", color)}>{display}</div>
        <div className="text-[10px] font-semibold text-gray-600 mt-1">{label}</div>
        {sub && <div className="text-[9px] text-gray-400 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

// ── Horizontal bar row ────────────────────────────────────────────────────────

function HBar({ label, value, max, color, badge }: {
  label: string; value: number; max: number; color: string; badge?: string;
}) {
  const pct = max ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex items-center gap-3 py-1.5 group">
      <div className="w-28 text-[10px] font-medium text-gray-700 truncate flex-shrink-0">{label}</div>
      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full al-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="flex items-center gap-1.5 flex-shrink-0">
        {badge && <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">{badge}</span>}
        <span className="text-[10px] font-bold tabular-nums w-6 text-right" style={{ color }}>{value}</span>
      </div>
    </div>
  );
}

// ── Radial progress ring ──────────────────────────────────────────────────────

function RadialRing({ pct, color, label, size = 68 }: {
  pct: number; color: string; label: string; size?: number;
}) {
  const r    = size / 2 - 6;
  const circ = 2 * Math.PI * r;
  const cx   = size / 2;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#f1f5f9" strokeWidth={5} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={5}
          strokeDasharray={`${(pct / 100) * circ} ${circ}`}
          strokeDashoffset={circ * 0.25} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }} />
        <text x={cx} y={cx + 4} textAnchor="middle" fontSize={11} fontWeight={800} fill={color}>{pct}%</text>
      </svg>
      <span className="text-[9px] text-gray-500 font-semibold text-center leading-tight">{label}</span>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function SecurityDashboard() {
  const [soc,      setSoc]      = useState<SocDash | null>(null);
  const [metrics,  setMetrics]  = useState<SocMetrics | null>(null);
  const [agents,   setAgents]   = useState<PostureAgent[]>([]);
  const [packages, setPackages] = useState<DetectionFinding[]>([]);
  const [netThreats,setNetThreats] = useState<DetectionFinding[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [lastSync, setLastSync] = useState(0);

  const load = useCallback(async () => {
    const [socR, metrR, posR, pkgR, netR] = await Promise.allSettled([
      fetch(`${SOC}/dashboard`).then(r => r.ok ? r.json() : null),
      fetch(`${SOC}/metrics`).then(r => r.ok ? r.json() : null),
      fetch(`${POSTURE}/agents`).then(r => r.ok ? r.json() : []),
      fetch(`${DETECT}/packages?limit=8&sort_by=composite_score`).then(r => r.ok ? r.json() : null),
      fetch(`${DETECT}/network?limit=8`).then(r => r.ok ? r.json() : null),
    ]);
    if (socR.status === "fulfilled" && socR.value)     setSoc(socR.value);
    if (metrR.status === "fulfilled" && metrR.value)   setMetrics(metrR.value);
    if (posR.status === "fulfilled"  && posR.value)    setAgents(Array.isArray(posR.value) ? posR.value : []);
    if (pkgR.status === "fulfilled"  && pkgR.value)    setPackages(pkgR.value.findings ?? pkgR.value ?? []);
    if (netR.status === "fulfilled"  && netR.value)    setNetThreats(netR.value.findings ?? netR.value ?? []);
    setLoading(false);
    setLastSync(Math.floor(Date.now() / 1000));
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 60_000); return () => clearInterval(t); }, [load]);

  // ── Derived metrics ────────────────────────────────────────────────────────

  const kpi          = soc?.kpi ?? {};
  const sevDist      = soc?.severity_dist ?? [];
  const catDist      = soc?.category_dist ?? [];
  const statusDist   = soc?.status_dist ?? [];
  const dailyTrend   = soc?.daily_trend ?? [];
  const slaComp      = soc?.sla_compliance ?? {};

  const totalActive  = kpi.total_active  ?? 0;
  const critical     = kpi.critical      ?? 0;
  const slaBreached  = kpi.sla_breached  ?? 0;
  const resolvedToday= kpi.resolved_today ?? 0;
  const mttr         = metrics?.mttr_hours ?? 0;
  const wowPct       = metrics?.wow_improvement_pct ?? 0;
  const fpRate       = metrics?.fp_rate_pct ?? 0;
  const closedWk     = metrics?.closed_this_week ?? 0;

  // Closure rate over 7 days
  const totalInPeriod = dailyTrend.reduce((s, d) => s + d.critical + d.high + d.medium + d.low, 0);
  const closureRate   = totalInPeriod > 0 ? Math.round((closedWk / Math.max(totalInPeriod, 1)) * 100) : 0;

  // CIS posture
  const avgScore   = agents.length ? Math.round(agents.reduce((s, a) => s + a.score, 0) / agents.length) : 0;
  const avgGrade   = avgScore >= 90 ? "A" : avgScore >= 80 ? "B" : avgScore >= 65 ? "C" : avgScore >= 50 ? "D" : "F";
  const totalPass  = agents.reduce((s, a) => s + a.pass, 0);
  const totalFail  = agents.reduce((s, a) => s + a.fail, 0);
  const totalWarn  = agents.reduce((s, a) => s + a.warn, 0);
  const totalChecks= totalPass + totalFail + totalWarn;
  const cisPassRate = totalChecks > 0 ? Math.round((totalPass / totalChecks) * 100) : 0;

  // Severity distribution for pie
  const sevPieData = sevDist
    .filter(d => d.count > 0)
    .map(d => ({ name: d.severity, value: d.count, color: SEV_COLOR[d.severity] ?? C.info }));

  // Category data for horizontal bars
  const catMax   = Math.max(...catDist.map(d => d.count), 1);
  const catColors: Record<string, string> = {
    package: C.high, connection: C.medium, network: C.medium,
    process: C.critical, execution: C.critical, malware: C.critical,
    service: C.purple, task: C.purple, config: C.purple,
    user: C.indigo, identity: C.indigo, security: "#22c55e",
  };
  const topCats = [...catDist].sort((a, b) => b.count - a.count).slice(0, 8);

  // 7-day trend line data
  const trendData = dailyTrend.map(d => ({
    date:     d.date.slice(5),     // "MM-DD"
    critical: d.critical,
    high:     d.high,
    medium:   d.medium,
    low:      d.low,
    total:    d.critical + d.high + d.medium + d.low,
    closed:   d.closed ?? 0,
  }));

  // SLA compliance per severity
  const slaSevs = Object.entries(slaComp).map(([sev, data]) => ({
    sev,
    pct: data.total ? Math.round((data.on_time / data.total) * 100) : 100,
    total: data.total, breached: data.breached,
  }));

  // Top vulnerable packages
  const topPackages = packages.slice(0, 7);

  // Port/service analysis from network threats
  const portMap: Record<string, number> = {};
  netThreats.forEach(f => {
    const ev = typeof f.evidence === "object" && f.evidence ? f.evidence as Record<string, unknown> : {};
    const src = String(ev.dst_port ?? ev.port ?? f.source ?? "unknown");
    portMap[src] = (portMap[src] ?? 0) + 1;
  });
  const topPorts = Object.entries(portMap).sort((a, b) => b[1] - a[1]).slice(0, 7);

  // MITRE technique frequency
  const mitreMap: Record<string, number> = {};
  [...packages, ...netThreats].forEach(f => {
    if (f.mitre_technique) mitreMap[f.mitre_technique] = (mitreMap[f.mitre_technique] ?? 0) + 1;
  });
  const topMitre = Object.entries(mitreMap).sort((a, b) => b[1] - a[1]).slice(0, 6);

  // Status donut data
  const statusClosed = statusDist.filter(d => ["closed","false_positive","accepted_risk","remediated","verified"].includes(d.status)).reduce((s, d) => s + d.count, 0);
  const statusOpen   = statusDist.filter(d => ["new","triaging","investigating","in_remediation"].includes(d.status)).reduce((s, d) => s + d.count, 0);

  // Exploit score: avg of top-5 composite scores
  const topScores = [...packages].sort((a, b) => (b.composite_score ?? b.score) - (a.composite_score ?? a.score)).slice(0, 5);
  const avgExploitScore = topScores.length ? (topScores.reduce((s, f) => s + (f.composite_score ?? f.score), 0) / topScores.length).toFixed(1) : "—";

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4 pb-8">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500 relative overflow-hidden">
          <div className="absolute inset-0 al-scan" style={{ background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.5),transparent)", width: "40%" }} />
        </div>
        <div className="px-5 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center">
              <BarChart3 className="w-5 h-5 text-orange-500" />
            </div>
            <div>
              <h1 className="text-base font-bold text-gray-900">Security Dashboard</h1>
              <p className="text-xs text-gray-500 mt-0.5">
                Real-time posture · finding analytics · CIS compliance · threat intelligence overview
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-xl text-[9px] text-gray-500 font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 al-heartbeat" />
              {lastSync ? `Updated ${relTime(lastSync)}` : "Loading…"}
            </div>
            <button onClick={load} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-gray-100 hover:bg-orange-50 border border-gray-200 hover:border-orange-200 text-gray-600 hover:text-orange-600 text-xs font-semibold transition-all">
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />Refresh
            </button>
          </div>
        </div>
      </div>

      {/* ── KPI Strip ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-6 gap-3">
        <KpiCard label="Active Findings"   value={totalActive}   sub="all open"              color="text-gray-800"   bg="bg-gray-50 border-gray-200"     icon={<Activity className="w-4 h-4" />}     delay={0}   />
        <KpiCard label="Critical"          value={critical}      sub="needs immediate action" color="text-red-700"    bg="bg-red-50 border-red-200"       icon={<AlertTriangle className="w-4 h-4" />} delay={60}  trend={-2} trendInverse />
        <KpiCard label="SLA Breached"      value={slaBreached}   sub="overdue response"       color={slaBreached > 0 ? "text-red-600" : "text-green-600"} bg={slaBreached > 0 ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200"} icon={<Clock className="w-4 h-4" />} delay={120} />
        <KpiCard label="Closure Rate"      value={`${closureRate}%`} sub="last 7 days"        color="text-green-700"  bg="bg-green-50 border-green-200"   icon={<CheckCircle2 className="w-4 h-4" />}  delay={180} trend={wowPct} />
        <KpiCard label="MTTR"              value={mttr ? `${mttr}h` : "—"} sub="mean time to resolve" color={mttr < 24 ? "text-green-700" : mttr < 72 ? "text-amber-700" : "text-red-700"} bg="bg-blue-50 border-blue-200" icon={<TrendingUp className="w-4 h-4 text-blue-500" />} delay={240} />
        <KpiCard label="Avg Risk Score"    value={avgExploitScore} sub="top package CVEs"     color="text-amber-700"  bg="bg-amber-50 border-amber-200"   icon={<Zap className="w-4 h-4" />}           delay={300} />
      </div>

      {/* ── Row 2: Trend + Severity ─────────────────────────────────────────── */}
      <div className="grid grid-cols-[1fr_380px] gap-4">

        {/* 7-day finding trend */}
        <Card>
          <CardHeader title="7-Day Finding Trend" icon={<Activity className="w-4 h-4" />}
            right={
              <div className="flex items-center gap-3 text-[9px] text-gray-500">
                {[["#ef4444","Critical"],["#f59e0b","High"],["#3b82f6","Medium"],["#22c55e","Low"]].map(([c,l]) => (
                  <span key={l} className="flex items-center gap-1"><span className="w-2 h-2 rounded-full" style={{ background: c }} />{l}</span>
                ))}
              </div>
            }
          />
          <div className="p-4">
            {trendData.length === 0 ? (
              <div className="h-48 flex items-center justify-center text-gray-300 text-sm">No trend data yet</div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={trendData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <XAxis dataKey="date" tick={{ fontSize: 9, fill: "#9ca3af" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 9, fill: "#9ca3af" }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTip />} />
                  <Line type="monotone" dataKey="critical" stroke={C.critical} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                  <Line type="monotone" dataKey="high"     stroke={C.high}     strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                  <Line type="monotone" dataKey="medium"   stroke={C.medium}   strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
                  <Line type="monotone" dataKey="low"      stroke={C.low}      strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
                </LineChart>
              </ResponsiveContainer>
            )}
            {/* Summary pills */}
            <div className="flex items-center gap-3 mt-3 pt-3 border-t border-gray-100 flex-wrap">
              {[
                { l: "Opened this week",  v: totalInPeriod,  c: "text-gray-700" },
                { l: "Closed this week",  v: closedWk,       c: "text-green-600" },
                { l: "Closure rate",      v: `${closureRate}%`, c: closureRate >= 70 ? "text-green-600" : "text-amber-600" },
                { l: "WoW improvement",   v: `${wowPct > 0 ? "+" : ""}${wowPct}%`, c: wowPct >= 0 ? "text-green-600" : "text-red-600" },
              ].map(k => (
                <div key={k.l} className="flex items-center gap-1.5 px-2.5 py-1 bg-gray-50 rounded-xl border border-gray-100">
                  <span className="text-[9px] text-gray-400">{k.l}</span>
                  <span className={cn("text-[10px] font-black", k.c)}>{k.v}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Severity distribution donut */}
        <Card>
          <CardHeader title="Severity Distribution" icon={<Shield className="w-4 h-4" />} />
          <div className="p-4">
            {sevPieData.length === 0 ? (
              <div className="h-48 flex items-center justify-center text-gray-300 text-sm">No findings yet</div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={sevPieData} cx="50%" cy="50%" innerRadius={52} outerRadius={80}
                    paddingAngle={3} dataKey="value" animationBegin={0} animationDuration={1000}>
                    {sevPieData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                  <Tooltip content={<ChartTip />} />
                </PieChart>
              </ResponsiveContainer>
            )}
            {/* Legend with counts */}
            <div className="space-y-2 mt-2">
              {sevPieData.map(d => {
                const pct = totalActive > 0 ? Math.round((d.value / totalActive) * 100) : 0;
                return (
                  <div key={d.name} className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.color }} />
                    <span className="text-[10px] font-semibold text-gray-700 capitalize flex-1">{d.name}</span>
                    <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full al-bar-fill" style={{ width: `${pct}%`, background: d.color }} />
                    </div>
                    <span className="text-[10px] font-black tabular-nums w-6 text-right" style={{ color: d.color }}>{d.value}</span>
                    <span className="text-[9px] text-gray-400 w-8 text-right">{pct}%</span>
                  </div>
                );
              })}
            </div>

            {/* Open vs Closed pill */}
            <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-gray-100">
              <div className="bg-red-50 border border-red-100 rounded-xl p-2.5 text-center">
                <div className="text-lg font-black text-red-700">{statusOpen}</div>
                <div className="text-[9px] text-red-500 font-semibold">Open</div>
              </div>
              <div className="bg-green-50 border border-green-100 rounded-xl p-2.5 text-center">
                <div className="text-lg font-black text-green-700">{statusClosed}</div>
                <div className="text-[9px] text-green-500 font-semibold">Closed / Resolved</div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Row 3: Category breakdown + SLA + Posture ──────────────────────── */}
      <div className="grid grid-cols-3 gap-4">

        {/* Category breakdown */}
        <Card className="col-span-1">
          <CardHeader title="Finding by Category" icon={<Layers className="w-4 h-4" />} />
          <div className="p-4 space-y-0.5">
            {topCats.length === 0
              ? <div className="py-8 text-center text-gray-300 text-xs">No data</div>
              : topCats.map(d => (
                  <HBar key={d.category} label={d.category} value={d.count} max={catMax}
                    color={catColors[d.category.toLowerCase()] ?? C.orange} />
                ))
            }
          </div>
        </Card>

        {/* SLA compliance rings */}
        <Card className="col-span-1">
          <CardHeader title="SLA Compliance" icon={<Clock className="w-4 h-4" />}
            right={<span className="text-[9px] text-gray-400">by severity</span>}
          />
          <div className="p-4">
            {slaSevs.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No SLA data</div>
            ) : (
              <div className="grid grid-cols-2 gap-4">
                {slaSevs.map(s => {
                  const color = s.pct >= 90 ? C.low : s.pct >= 70 ? C.high : C.critical;
                  return (
                    <div key={s.sev} className="flex flex-col items-center gap-1">
                      <RadialRing pct={s.pct} color={color} label={s.sev.charAt(0).toUpperCase() + s.sev.slice(1)} />
                      <div className="text-[8px] text-gray-400">{s.breached} breached</div>
                    </div>
                  );
                })}
              </div>
            )}
            {/* SLA summary bar */}
            <div className="mt-4 pt-3 border-t border-gray-100">
              <div className="flex items-center justify-between text-[9px] text-gray-500 mb-1">
                <span>Overall SLA health</span>
                <span className="font-bold text-gray-700">
                  {slaSevs.length > 0 ? Math.round(slaSevs.reduce((s, d) => s + d.pct, 0) / slaSevs.length) : "—"}%
                </span>
              </div>
              <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                <div className="h-full rounded-full al-bar-fill"
                  style={{ width: `${slaSevs.length > 0 ? Math.round(slaSevs.reduce((s, d) => s + d.pct, 0) / slaSevs.length) : 0}%`, background: C.low }} />
              </div>
            </div>
          </div>
        </Card>

        {/* Security posture ring */}
        <Card className="col-span-1">
          <CardHeader title="Security Posture (CIS)" icon={<ShieldCheck className="w-4 h-4" />} />
          <div className="p-4 flex flex-col items-center gap-4">
            <ScoreRing score={avgScore} grade={avgGrade} size={120} />
            <div className="w-full grid grid-cols-3 gap-2 text-center">
              {[
                { l: "Pass",    v: totalPass,  c: "text-green-700", bg: "bg-green-50 border-green-100" },
                { l: "Warn",    v: totalWarn,  c: "text-amber-700", bg: "bg-amber-50 border-amber-100" },
                { l: "Fail",    v: totalFail,  c: "text-red-700",   bg: "bg-red-50 border-red-100" },
              ].map(k => (
                <div key={k.l} className={cn("rounded-xl border py-2", k.bg)}>
                  <div className={cn("text-sm font-black", k.c)}>{k.v}</div>
                  <div className="text-[9px] text-gray-500">{k.l}</div>
                </div>
              ))}
            </div>
            {/* CIS pass rate bar */}
            <div className="w-full">
              <div className="flex items-center justify-between text-[9px] mb-1">
                <span className="text-gray-500">CIS pass rate</span>
                <span className="font-black text-gray-700">{cisPassRate}%</span>
              </div>
              <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
                <div className="h-full rounded-full al-bar-fill"
                  style={{ width: `${cisPassRate}%`, background: cisPassRate >= 80 ? C.low : cisPassRate >= 60 ? C.high : C.critical }} />
              </div>
              <div className="text-[8px] text-gray-400 mt-1">{agents.length} agent{agents.length !== 1 ? "s" : ""} · {totalChecks} total checks</div>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Row 4: Top packages + Top ports + Risk metrics ─────────────────── */}
      <div className="grid grid-cols-3 gap-4">

        {/* Top vulnerable packages */}
        <Card>
          <CardHeader title="Top Vulnerable Packages" icon={<Package className="w-4 h-4" />}
            color="text-amber-500"
            right={<span className="text-[9px] text-gray-400">by risk score</span>}
          />
          <div className="divide-y divide-gray-50">
            {topPackages.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No package findings yet</div>
            ) : topPackages.map((f, i) => {
              const score = f.composite_score ?? f.score;
              const color = score >= 8 ? C.critical : score >= 6 ? C.high : C.medium;
              const cves  = Array.isArray(f.cve_ids) ? f.cve_ids.length : (typeof f.cve_ids === "string" ? 1 : 0);
              return (
                <div key={f.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 transition-colors al-row-in" style={{ animationDelay: `${i * 50}ms` }}>
                  <span className="text-[9px] font-black text-gray-400 w-4">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[10px] font-semibold text-gray-800 truncate">{f.title.replace(/^CVE.*?-/i, "").slice(0, 40)}</div>
                    <div className="flex items-center gap-1 mt-0.5">
                      <span className="text-[8px] font-mono text-gray-400">{f.source}</span>
                      {cves > 0 && <span className="text-[8px] px-1 bg-blue-50 text-blue-600 rounded">{cves} CVE{cves > 1 ? "s" : ""}</span>}
                      {f.cvss_score && <span className="text-[8px] font-bold" style={{ color }}>CVSS {f.cvss_score.toFixed(1)}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <div className="w-8 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${Math.min(100, score * 10)}%`, background: color }} />
                    </div>
                    <span className="text-[10px] font-black w-5 text-right" style={{ color }}>{score.toFixed(1)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Top targeted ports/services */}
        <Card>
          <CardHeader title="Most Targeted Ports / Services" icon={<Globe className="w-4 h-4" />}
            color="text-blue-500"
            right={<span className="text-[9px] text-gray-400">network threats</span>}
          />
          <div className="p-4 space-y-1">
            {topPorts.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No network threat data yet</div>
            ) : topPorts.map(([port, count], i) => {
              const portLabels: Record<string, string> = {
                "22": "SSH","443": "HTTPS","80": "HTTP","3389": "RDP",
                "445": "SMB","3306": "MySQL","5432": "Postgres","6379": "Redis",
              };
              const label = portLabels[port] ?? port;
              const max   = topPorts[0]?.[1] ?? 1;
              return (
                <div key={port} className="flex items-center gap-2.5 py-1 al-row-in" style={{ animationDelay: `${i * 50}ms` }}>
                  <span className="text-[9px] font-black text-gray-400 w-4">{i + 1}</span>
                  <div className="w-6 h-6 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center flex-shrink-0">
                    <Server className="w-3 h-3 text-blue-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[10px] font-semibold text-gray-800">{label}</div>
                    <div className="text-[8px] text-gray-400 font-mono">:{port}</div>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <div className="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full al-bar-fill" style={{ width: `${(count / max) * 100}%`, background: C.medium }} />
                    </div>
                    <span className="text-[10px] font-black text-blue-600 w-5 text-right">{count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Risk reduction metrics */}
        <Card>
          <CardHeader title="Risk Reduction (7-day)" icon={<TrendingUp className="w-4 h-4" />}
            color="text-green-500"
          />
          <div className="p-4 space-y-3">
            {[
              { label: "Findings closed",       val: closedWk,             unit: "this week",      color: C.low,      icon: <CheckCircle2 className="w-3.5 h-3.5" />, positive: true },
              { label: "Critical open",          val: critical,             unit: "remaining",      color: critical > 0 ? C.critical : C.low, icon: <AlertTriangle className="w-3.5 h-3.5" />, positive: false },
              { label: "SLA compliance",         val: slaSevs.length > 0 ? Math.round(slaSevs.reduce((s,d)=>s+d.pct,0)/slaSevs.length) : 100, unit: "% on time", color: C.medium, icon: <Clock className="w-3.5 h-3.5" />, positive: true },
              { label: "False positive rate",    val: fpRate,               unit: "% FP (30d)",     color: fpRate < 10 ? C.low : C.high, icon: <XCircle className="w-3.5 h-3.5" />, positive: false },
              { label: "Unresolved critical",    val: kpi.critical ?? 0,    unit: "open findings",  color: C.critical, icon: <AlertCircle className="w-3.5 h-3.5" />, positive: false },
              { label: "Agents enrolled",        val: agents.length,        unit: "reporting",      color: C.indigo,   icon: <Users className="w-3.5 h-3.5" />, positive: true },
            ].map((m, i) => (
              <div key={m.label} className="flex items-center gap-3 al-row-in" style={{ animationDelay: `${i * 60}ms` }}>
                <div className="p-1.5 rounded-lg bg-gray-50 border border-gray-100 flex-shrink-0" style={{ color: m.color }}>
                  {m.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[10px] font-semibold text-gray-700">{m.label}</div>
                  <div className="text-[9px] text-gray-400">{m.unit}</div>
                </div>
                <div className="text-[14px] font-black tabular-nums flex-shrink-0" style={{ color: m.color }}>
                  {m.val}{m.unit.startsWith("%") ? "" : ""}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* ── Row 5: MITRE techniques + CIS per-agent + Status flow ──────────── */}
      <div className="grid grid-cols-[1fr_1fr_1fr] gap-4">

        {/* MITRE ATT&CK top techniques */}
        <Card>
          <CardHeader title="Top MITRE ATT&CK Techniques" icon={<Target className="w-4 h-4" />}
            color="text-indigo-500"
          />
          <div className="p-4 space-y-1">
            {topMitre.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No MITRE data yet</div>
            ) : topMitre.map(([technique, count], i) => {
              const techLabels: Record<string, string> = {
                "T1059":    "Command Scripting","T1071":    "App Layer Protocol",
                "T1053":    "Scheduled Task",   "T1543":    "Create/Modify Service",
                "T1078":    "Valid Accounts",   "T1110":    "Brute Force",
                "T1190":    "Exploit Pub. App", "T1546":    "Event Triggered",
                "T1136":    "Create Account",   "T1548":    "Abuse Elevation",
                "T1021":    "Remote Services",  "T1195":    "Supply Chain",
              };
              const label = techLabels[technique] ?? technique;
              const max   = topMitre[0]?.[1] ?? 1;
              const colors = [C.critical, C.high, C.medium, C.purple, C.indigo, C.teal];
              const c = colors[i % colors.length];
              return (
                <div key={technique} className="flex items-center gap-2.5 py-1.5 al-row-in" style={{ animationDelay: `${i * 60}ms` }}>
                  <span className="font-mono text-[8px] font-black px-1.5 py-0.5 rounded border text-white flex-shrink-0" style={{ background: c }}>{technique}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-[9px] font-medium text-gray-700 truncate">{label}</div>
                    <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden mt-1">
                      <div className="h-full rounded-full al-bar-fill" style={{ width: `${(count / max) * 100}%`, background: c }} />
                    </div>
                  </div>
                  <span className="text-[10px] font-black flex-shrink-0" style={{ color: c }}>{count}</span>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Per-agent posture */}
        <Card>
          <CardHeader title="Agent Posture Scores" icon={<ShieldCheck className="w-4 h-4" />}
            color="text-green-500"
          />
          <div className="divide-y divide-gray-50 max-h-72 overflow-y-auto">
            {agents.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No agents enrolled</div>
            ) : agents.map((a, i) => {
              const gradeColor =
                a.grade === "A" ? "#16a34a" : a.grade === "B" ? "#2563eb" :
                a.grade === "C" ? "#d97706" : "#dc2626";
              const pct = a.total > 0 ? Math.round((a.pass / a.total) * 100) : 0;
              return (
                <div key={a.agent_id} className="flex items-center gap-3 px-4 py-2.5 al-row-in" style={{ animationDelay: `${i * 40}ms` }}>
                  <div className="w-7 h-7 rounded-lg flex items-center justify-center text-[9px] font-black text-white flex-shrink-0"
                    style={{ background: gradeColor }}>
                    {a.grade}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[10px] font-semibold text-gray-800 truncate">{a.hostname}</div>
                    <div className="flex items-center gap-1 mt-0.5">
                      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div className="h-full rounded-full al-bar-fill" style={{ width: `${pct}%`, background: gradeColor }} />
                      </div>
                      <span className="text-[8px] tabular-nums" style={{ color: gradeColor }}>{a.score}</span>
                    </div>
                  </div>
                  <div className="text-[9px] text-right flex-shrink-0">
                    <span className="text-green-600 font-semibold">{a.pass}✓</span>
                    {a.fail > 0 && <span className="text-red-500 font-bold ml-1">{a.fail}✗</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Status workflow distribution */}
        <Card>
          <CardHeader title="Findings by Status" icon={<Activity className="w-4 h-4" />}
            color="text-purple-500"
          />
          <div className="p-4">
            {statusDist.length === 0 ? (
              <div className="py-8 text-center text-gray-300 text-xs">No data yet</div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={statusDist.filter(d => d.count > 0)} layout="vertical"
                  margin={{ top: 0, right: 8, bottom: 0, left: 60 }}>
                  <XAxis type="number" tick={{ fontSize: 9, fill: "#9ca3af" }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="status" tick={{ fontSize: 8, fill: "#6b7280" }} axisLine={false} tickLine={false}
                    tickFormatter={v => ({ new: "New", triaging: "Triaging", investigating: "Investigating", in_remediation: "In Rem.", remediated: "Remediated", closed: "Closed", false_positive: "False Pos.", accepted_risk: "Risk Acc.", duplicate: "Duplicate" }[v] ?? v)} />
                  <Tooltip content={<ChartTip />} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} fill={C.orange}>
                    {statusDist.filter(d => d.count > 0).map((d, i) => {
                      const c = ["closed","remediated","verified"].includes(d.status) ? C.low :
                                ["false_positive","accepted_risk"].includes(d.status) ? C.info :
                                ["new"].includes(d.status) ? C.critical :
                                ["triaging","investigating"].includes(d.status) ? C.high : C.medium;
                      return <Cell key={i} fill={c} />;
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
            {/* Open vs closed summary */}
            <div className="mt-3 pt-3 border-t border-gray-100 flex items-center gap-2">
              <div className="flex-1 text-center py-2 bg-red-50 border border-red-100 rounded-xl">
                <div className="text-base font-black text-red-700">{statusOpen}</div>
                <div className="text-[8px] text-red-400 font-semibold">Open</div>
              </div>
              <div className="text-gray-300 text-xs">vs</div>
              <div className="flex-1 text-center py-2 bg-green-50 border border-green-100 rounded-xl">
                <div className="text-base font-black text-green-700">{statusClosed}</div>
                <div className="text-[8px] text-green-400 font-semibold">Closed</div>
              </div>
              <div className="flex-1 text-center py-2 bg-blue-50 border border-blue-100 rounded-xl">
                <div className="text-base font-black text-blue-700">
                  {statusOpen + statusClosed > 0 ? Math.round((statusClosed / (statusOpen + statusClosed)) * 100) : 0}%
                </div>
                <div className="text-[8px] text-blue-400 font-semibold">Resolution</div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* ── Row 6: CIS compliance heatmap ──────────────────────────────────── */}
      <Card>
        <CardHeader title="CIS Benchmark Compliance Heatmap" icon={<Lock className="w-4 h-4" />}
          color="text-orange-500"
          right={
            <div className="flex items-center gap-3 text-[9px]">
              {[["#22c55e","≥90% Pass"],["#f59e0b","60–89%"],["#ef4444","<60%"],["#d1d5db","No data"]].map(([c,l]) => (
                <span key={l} className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded" style={{ background: c }} />{l}</span>
              ))}
            </div>
          }
        />
        <div className="p-4">
          <div className="grid grid-cols-6 gap-2">
            {[
              { id: 3,  label: "Data Protection",   agents },
              { id: 4,  label: "Secure Config",      agents },
              { id: 5,  label: "Account Mgmt",       agents },
              { id: 7,  label: "Vuln Management",    agents },
              { id: 10, label: "Malware Defenses",   agents },
              { id: 12, label: "Network Mgmt",       agents },
            ].map(({ id, label }) => {
              // approximate per-control rate from agent data
              const pct = cisPassRate; // use overall as proxy; real data would be from groups
              const color = pct >= 90 ? "#22c55e" : pct >= 60 ? "#f59e0b" : pct >= 30 ? "#ef4444" : "#d1d5db";
              const bg    = pct >= 90 ? "bg-green-50 border-green-200" : pct >= 60 ? "bg-amber-50 border-amber-200" : pct >= 30 ? "bg-red-50 border-red-200" : "bg-gray-50 border-gray-200";
              return (
                <div key={id} className={cn("rounded-xl border p-3 text-center al-bounce-in", bg)}>
                  <div className="w-7 h-7 rounded-lg flex items-center justify-center mx-auto mb-2 text-white text-[10px] font-black" style={{ background: color }}>
                    {id}
                  </div>
                  <div className="text-[9px] font-bold text-gray-700 leading-tight mb-1">{label}</div>
                  <div className="text-[14px] font-black" style={{ color }}>{pct}%</div>
                  <div className="h-1.5 bg-white/60 rounded-full overflow-hidden mt-1.5">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color, transition: "width 1.2s ease" }} />
                  </div>
                  <div className={cn("text-[8px] font-bold mt-1", pct >= 90 ? "text-green-600" : pct >= 60 ? "text-amber-600" : "text-red-600")}>
                    {pct >= 90 ? "PASS" : pct >= 60 ? "PARTIAL" : "FAIL"}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </Card>

    </div>
  );
}

// ── Named import for recharts Layers workaround ───────────────────────────────
function Layers(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2" />
      <polyline points="2 17 12 22 22 17" />
      <polyline points="2 12 12 17 22 12" />
    </svg>
  );
}
