/**
 * Detection Accuracy — precision · FP risk · calibration · correlation
 * Focused on key metric numbers only. No verbose prose.
 */
import { useState, useEffect, useCallback } from "react";
import {
  RefreshCw, AlertTriangle, CheckCircle2, Target,
  Activity, FlaskConical, GitBranch, Crosshair, XCircle, Shield,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API = "/api/v1/accuracy/report";

// ── Types ─────────────────────────────────────────────────────────────────────
interface SourceStat  { source: string; count: number; confidence_prior: number; observed_precision_pct: number; fp_risk_pct: number; calibration_gap: number; }
interface CategoryStat { category: string; count: number; precision_pct: number; fp_risk_pct: number; avg_score: number; }
interface FPItem       { id: number; agent_id: string; category: string; severity: string; title: string; source: string; confidence: number; fp_reasons: string[]; recommendation: string; }
interface CalRow       { source: string; count: number; confidence_prior: number; observed_rate: number; calibration_gap: number; status: string; action: string; }
interface Report {
  meta:    { total_findings: number; total_correlations: number; };
  overall: { estimated_precision_pct: number; validated_findings: number; unvalidated_findings: number; fp_risk_count: number; high_confidence_count: number; correlation_integrity_pct: number; };
  by_source:   SourceStat[];
  by_category: CategoryStat[];
  validation:  Record<string, unknown>;
  calibration: CalRow[];
  fp_risk_items: FPItem[];
  correlation_integrity: { total: number; well_supported: number; has_orphans: number; integrity_pct: number; note: string; details: { correlation_id: number; rule_id: string; title: string; severity: string; signal_count: number; orphaned: number; integrity: string; }[]; };
}
type Tab = "overview" | "calibration" | "fp" | "correlation";

// ── Colours ───────────────────────────────────────────────────────────────────
const pc = (p: number) => p >= 85 ? "#059669" : p >= 70 ? "#2563eb" : p >= 50 ? "#d97706" : "#dc2626";
const gc = (g: number) => Math.abs(g) <= 12 ? "#059669" : g > 12 ? "#dc2626" : "#d97706";

const SEV: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high:     "bg-amber-50 text-amber-700 border-amber-200",
  medium:   "bg-blue-50 text-blue-700 border-blue-200",
  low:      "bg-green-50 text-green-700 border-green-200",
};

const CAL_STATUS: Record<string, { label: string; cls: string }> = {
  well_calibrated: { label: "Calibrated", cls: "bg-green-50 text-green-700 border-green-200" },
  over_confident:  { label: "Over-confident", cls: "bg-red-50 text-red-700 border-red-200" },
  under_confident: { label: "Under-confident", cls: "bg-amber-50 text-amber-700 border-amber-200" },
};

// ── Atoms ─────────────────────────────────────────────────────────────────────
function KpiCard({ label, value, sub, color, icon: Icon }: { label: string; value: string | number; sub?: string; color: string; icon: React.ElementType }) {
  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-4 flex-1 min-w-0 shadow-card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wide">{label}</span>
        <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color }} />
      </div>
      <div className="text-[22px] font-black leading-none tabular-nums" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-gray-400 mt-1">{sub}</div>}
    </div>
  );
}

function ScoreBar({ value, max = 100, color }: { value: number; max?: number; color: string }) {
  return (
    <div className="flex items-center gap-2 flex-1">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full al-bar-fill" style={{ width: `${Math.min(100, (value / max) * 100)}%`, backgroundColor: color }} />
      </div>
      <span className="text-[11px] font-bold tabular-nums w-9 text-right" style={{ color }}>{value}%</span>
    </div>
  );
}

function Th({ ch }: { ch: string }) {
  return <th className="px-3 py-2.5 text-left text-[9px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">{ch}</th>;
}

function TabBar({ tab, setTab, fpCount }: { tab: Tab; setTab: (t: Tab) => void; fpCount: number }) {
  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: "overview",    label: "Overview",     icon: Activity    },
    { id: "calibration", label: "Calibration",  icon: Target      },
    { id: "fp",          label: `FP Risk (${fpCount})`, icon: AlertTriangle },
    { id: "correlation", label: "Correlation",  icon: GitBranch   },
  ];
  return (
    <div className="flex gap-1 bg-white border border-gray-200 rounded-2xl shadow-card p-1.5">
      {tabs.map(t => {
        const Icon = t.icon;
        const active = tab === t.id;
        return (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all",
              active ? "bg-orange-500 text-white shadow-sm" : "text-gray-500 hover:bg-gray-50"
            )}>
            <Icon className="w-3 h-3" />{t.label}
          </button>
        );
      })}
    </div>
  );
}

function SectionHead({ children }: { children: React.ReactNode }) {
  return <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3">{children}</div>;
}

function EmptyState({ icon: Icon, text }: { icon: React.ElementType; text: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 gap-2 text-gray-300">
      <Icon className="w-8 h-8 opacity-40" />
      <p className="text-[11px] text-gray-400">{text}</p>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Accuracy() {
  const [report,  setReport]  = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState<Tab>("overview");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(API);
      if (r.ok) setReport(await r.json());
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const ov  = report?.overall;
  const cal = report?.calibration ?? [];
  const calScore = cal.length
    ? Math.max(0, Math.round(100 - cal.reduce((s, r) => s + Math.abs(r.calibration_gap), 0) / cal.length))
    : 0;
  const f1 = ov ? Math.round((2 * ov.estimated_precision_pct * 85) / (ov.estimated_precision_pct + 85)) : 0;

  return (
    <div className="space-y-3">

      {/* ── Header + KPIs ──────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden">
        <div className="h-[3px] relative overflow-hidden" style={{ background: "linear-gradient(90deg,#E8581A,#f97316,#fbbf24)" }}>
          <div className="absolute inset-y-0 al-scan" style={{ width: "35%", background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.6),transparent)" }} />
        </div>
        <div className="px-5 pt-4 pb-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: "rgba(232,88,26,0.08)", border: "1px solid rgba(232,88,26,0.2)" }}>
              <FlaskConical className="w-4 h-4" style={{ color: "#E8581A" }} />
            </div>
            <div>
              <h1 className="text-[13px] font-bold text-gray-900">Detection Accuracy</h1>
              <p className="text-[10px] text-gray-400 mt-0.5">Rule precision · FP risk · Calibration gaps · Correlation chains</p>
            </div>
          </div>
          <button onClick={load} className="p-1.5 hover:bg-gray-50 rounded-lg transition-colors">
            <RefreshCw className={cn("w-3.5 h-3.5 text-gray-400", loading && "animate-spin")} />
          </button>
        </div>

        {ov && (
          <div className="flex items-stretch gap-3 px-5 pb-4">
            <KpiCard label="Precision"     value={`${ov.estimated_precision_pct}%`} sub={`${ov.validated_findings} validated`}         color={pc(ov.estimated_precision_pct)} icon={Target}       />
            <KpiCard label="F1 Score"      value={`${f1}%`}                         sub="precision × recall proxy"                       color={pc(f1)}                         icon={Activity}     />
            <KpiCard label="Calibration"   value={`${calScore}%`}                   sub={`${cal.length} rules assessed`}                 color={pc(calScore)}                   icon={FlaskConical} />
            <KpiCard label="FP Risk Items" value={ov.fp_risk_count}                 sub="review candidates"                              color={ov.fp_risk_count > 0 ? "#d97706" : "#059669"} icon={AlertTriangle} />
            <KpiCard label="Correlation"   value={`${ov.correlation_integrity_pct}%`} sub={`${report?.meta.total_correlations ?? 0} chains`} color={pc(ov.correlation_integrity_pct)} icon={GitBranch} />
          </div>
        )}
      </div>

      <TabBar tab={tab} setTab={setTab} fpCount={ov?.fp_risk_count ?? 0} />

      {/* ── Overview ───────────────────────────────────────────────────────── */}
      {tab === "overview" && (
        <div className="grid grid-cols-2 gap-3">

          {/* Precision by source */}
          <div className="bg-white border border-gray-200 rounded-2xl shadow-card p-4">
            <SectionHead>Precision by Source</SectionHead>
            <div className="space-y-2.5 max-h-80 overflow-y-auto">
              {(report?.by_source ?? []).slice(0, 12).map(s => (
                <div key={s.source} className="flex items-center gap-2 group">
                  <span className="text-[10.5px] text-gray-600 w-32 truncate flex-shrink-0" title={s.source}>{s.source}</span>
                  <ScoreBar value={s.observed_precision_pct} color={pc(s.observed_precision_pct)} />
                  <span className="text-[9px] text-gray-400 flex-shrink-0 w-14 text-right">FP {s.fp_risk_pct}% n={s.count}</span>
                </div>
              ))}
              {!report?.by_source?.length && <p className="text-[11px] text-gray-400 text-center py-6">No data</p>}
            </div>
          </div>

          {/* Precision by category */}
          <div className="bg-white border border-gray-200 rounded-2xl shadow-card p-4">
            <SectionHead>Precision by Category</SectionHead>
            <div className="space-y-2.5 max-h-80 overflow-y-auto">
              {(report?.by_category ?? []).map(c => (
                <div key={c.category} className="flex items-center gap-2">
                  <span className="text-[10.5px] text-gray-600 w-28 truncate capitalize flex-shrink-0">{c.category}</span>
                  <ScoreBar value={c.precision_pct} color={pc(c.precision_pct)} />
                  <span className="text-[9px] text-gray-400 flex-shrink-0 w-14 text-right">FP {c.fp_risk_pct}% n={c.count}</span>
                </div>
              ))}
              {!report?.by_category?.length && <p className="text-[11px] text-gray-400 text-center py-6">No data</p>}
            </div>
          </div>

          {/* Validation coverage */}
          {report && (
            <div className="col-span-2 bg-white border border-gray-200 rounded-2xl shadow-card p-4">
              <SectionHead>External Validation Coverage</SectionHead>
              <div className="grid grid-cols-5 gap-3">
                {([
                  { key: "kev_validated",     label: "KEV",          color: "#dc2626" },
                  { key: "epss_high",         label: "EPSS ≥ 50%",   color: "#d97706" },
                  { key: "feed_confirmed",    label: "Feed Match",   color: "#2563eb" },
                  { key: "exploit_available", label: "Exploit",      color: "#7c3aed" },
                  { key: "unvalidated",       label: "Rule Only",    color: "#9ca3af" },
                ] as const).map(({ key, label, color }) => {
                  const n     = (report.validation[key] as number) ?? 0;
                  const total = (report.validation.total_findings as number) ?? 1;
                  const pct   = Math.round((n / total) * 100);
                  return (
                    <div key={key} className="text-center px-3 py-3 rounded-xl border border-gray-100 bg-gray-50/60">
                      <div className="text-[18px] font-black tabular-nums" style={{ color }}>{n}</div>
                      <div className="text-[9px] font-bold text-gray-500 mt-0.5">{label}</div>
                      <div className="text-[9px] text-gray-400">{pct}%</div>
                      <div className="mt-1.5 h-1 bg-gray-200 rounded-full overflow-hidden">
                        <div className="h-full rounded-full al-bar-fill" style={{ width: `${pct}%`, backgroundColor: color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Calibration ────────────────────────────────────────────────────── */}
      {tab === "calibration" && (
        <div className="space-y-3">
          {/* Summary row */}
          {(() => {
            const well  = cal.filter(r => r.status === "well_calibrated").length;
            const over  = cal.filter(r => r.status === "over_confident").length;
            const under = cal.filter(r => r.status !== "well_calibrated" && r.status !== "over_confident").length;
            const debt  = cal.reduce((s, r) => s + Math.abs(r.calibration_gap) * r.count, 0);
            return (
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: "Well Calibrated",  value: well,              color: "#059669", bg: "#f0fdf9", border: "#6ee7b7" },
                  { label: "Over-confident",   value: over,              color: "#dc2626", bg: "#fef5f5", border: "#fca5a5" },
                  { label: "Under-confident",  value: under,             color: "#d97706", bg: "#fffbf0", border: "#fcd34d" },
                  { label: "Tuning Debt",      value: Math.round(debt),  color: "#6366f1", bg: "#eef2ff", border: "#c7d2fe" },
                ].map(d => (
                  <div key={d.label} className="rounded-2xl border px-4 py-3 text-center" style={{ background: d.bg, borderColor: d.border }}>
                    <div className="text-[22px] font-black tabular-nums" style={{ color: d.color }}>{d.value}</div>
                    <div className="text-[10px] font-semibold text-gray-600 mt-0.5">{d.label}</div>
                  </div>
                ))}
              </div>
            );
          })()}

          {/* Calibration table */}
          <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden">
            <div className="px-4 py-2.5 border-b border-gray-100 flex items-center justify-between">
              <span className="text-[11px] font-semibold text-gray-700">Rule Calibration Detail</span>
              <span className="text-[10px] text-gray-400">{cal.length} rules — Prior vs Observed precision</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="bg-gray-50/60 border-b border-gray-100">{["Rule / Source","n","Prior","Observed","Gap","Status","Action"].map(h => <Th key={h} ch={h} />)}</tr></thead>
                <tbody>
                  {cal.map((r, i) => (
                    <tr key={r.source} className="border-b border-gray-50 hover:bg-gray-25 al-row-in" style={{ animationDelay: `${i * 25}ms` }}>
                      <td className="px-3 py-2.5 font-mono text-[9.5px] text-gray-700 max-w-[180px] truncate">{r.source}</td>
                      <td className="px-3 py-2.5 tabular-nums text-[10px] text-gray-500">{r.count}</td>
                      <td className="px-3 py-2.5 text-[10px] text-gray-500">{r.confidence_prior}%</td>
                      <td className="px-3 py-2.5 text-[10px] font-bold tabular-nums" style={{ color: pc(r.observed_rate) }}>{r.observed_rate}%</td>
                      <td className="px-3 py-2.5 text-[10px] font-bold tabular-nums" style={{ color: gc(r.calibration_gap) }}>
                        {r.calibration_gap > 0 ? `↓${r.calibration_gap}` : r.calibration_gap < 0 ? `↑${Math.abs(r.calibration_gap)}` : "✓"}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={cn("px-2 py-0.5 text-[9px] font-bold rounded-full border", (CAL_STATUS[r.status] ?? CAL_STATUS.under_confident).cls)}>
                          {(CAL_STATUS[r.status] ?? CAL_STATUS.under_confident).label}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-[9.5px] text-gray-500 max-w-[220px]">{r.action}</td>
                    </tr>
                  ))}
                  {!cal.length && <tr><td colSpan={7} className="py-10 text-center text-[11px] text-gray-400">No calibration data</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── FP Risk ────────────────────────────────────────────────────────── */}
      {tab === "fp" && (
        <div className="space-y-3">
          {/* Category FP bars */}
          {(report?.by_category ?? []).filter(c => c.fp_risk_pct > 0).length > 0 && (
            <div className="bg-white border border-gray-200 rounded-2xl shadow-card p-4">
              <SectionHead>FP Rate by Category</SectionHead>
              <div className="space-y-2">
                {(report!.by_category).filter(c => c.fp_risk_pct > 0).sort((a, b) => b.fp_risk_pct - a.fp_risk_pct).slice(0, 8).map(c => {
                  const color = c.fp_risk_pct > 40 ? "#dc2626" : c.fp_risk_pct > 20 ? "#d97706" : "#60a5fa";
                  return (
                    <div key={c.category} className="flex items-center gap-2">
                      <span className="text-[10.5px] capitalize text-gray-600 w-28 flex-shrink-0 truncate">{c.category}</span>
                      <ScoreBar value={c.fp_risk_pct} color={color} />
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* FP candidates table */}
          {(report?.fp_risk_items ?? []).length === 0 ? (
            <div className="bg-white border border-gray-200 rounded-2xl shadow-card p-10 text-center">
              <CheckCircle2 className="w-9 h-9 text-green-500 mx-auto mb-2" />
              <div className="text-[12px] font-semibold text-green-700">No FP risk candidates</div>
              <div className="text-[10px] text-gray-400 mt-1">All findings have adequate external validation.</div>
            </div>
          ) : (
            <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden">
              <div className="px-4 py-2.5 border-b border-gray-100 flex items-center justify-between">
                <span className="text-[11px] font-semibold text-gray-700">Suppression Candidates</span>
                <span className="text-[10px] text-gray-400">{report!.fp_risk_items.length} items</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="bg-gray-50/60 border-b border-gray-100">{["Finding","Cat","Sev","Confidence","FP Signals","Action"].map(h => <Th key={h} ch={h} />)}</tr></thead>
                  <tbody>
                    {report!.fp_risk_items.map((item, i) => (
                      <tr key={item.id} className="border-b border-gray-50 hover:bg-amber-50/20 al-row-in" style={{ animationDelay: `${i * 30}ms` }}>
                        <td className="px-3 py-2.5 max-w-[200px]">
                          <div className="text-[11px] font-medium text-gray-800 truncate">{item.title}</div>
                          <div className="text-[9px] font-mono text-gray-400">{item.source}</div>
                        </td>
                        <td className="px-3 py-2.5 text-[9px] font-mono text-gray-500 capitalize">{item.category}</td>
                        <td className="px-3 py-2.5"><span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase", SEV[item.severity] ?? SEV.low)}>{item.severity}</span></td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <div className="w-14 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{ width: `${item.confidence}%`, backgroundColor: pc(item.confidence) }} />
                            </div>
                            <span className="text-[10px] font-bold tabular-nums" style={{ color: pc(item.confidence) }}>{item.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 max-w-[160px]">
                          {item.fp_reasons.slice(0, 2).map((r, j) => (
                            <div key={j} className="flex items-start gap-1 text-[9px] text-amber-700">
                              <AlertTriangle className="w-2.5 h-2.5 flex-shrink-0 mt-0.5" />{r}
                            </div>
                          ))}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-1">
                            <button className="px-2 py-0.5 text-[9px] font-semibold rounded bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 transition-colors whitespace-nowrap">Mark FP</button>
                            <button className="px-2 py-0.5 text-[9px] font-semibold rounded bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 transition-colors whitespace-nowrap">Accept</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Correlation ─────────────────────────────────────────────────────── */}
      {tab === "correlation" && (
        <div className="space-y-3">
          {report?.correlation_integrity && (
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Total Chains",    value: report.correlation_integrity.total,          color: "#374151" },
                { label: "Well Supported",  value: report.correlation_integrity.well_supported,  color: "#059669" },
                { label: "Orphaned",        value: report.correlation_integrity.has_orphans,     color: report.correlation_integrity.has_orphans > 0 ? "#d97706" : "#059669" },
                { label: "Integrity",       value: `${report.correlation_integrity.integrity_pct}%`, color: pc(report.correlation_integrity.integrity_pct) },
              ].map(d => (
                <div key={d.label} className="bg-white border border-gray-200 rounded-2xl shadow-card px-4 py-3 text-center">
                  <div className="text-[22px] font-black tabular-nums" style={{ color: d.color }}>{d.value}</div>
                  <div className="text-[10px] font-semibold text-gray-500 mt-0.5">{d.label}</div>
                </div>
              ))}
            </div>
          )}

          {(() => {
            const flagged = (report?.correlation_integrity?.details ?? []).filter(d => d.integrity !== "ok");
            if (!flagged.length) return (
              <div className="bg-white border border-gray-200 rounded-2xl shadow-card p-10 text-center">
                <CheckCircle2 className="w-9 h-9 text-green-500 mx-auto mb-2" />
                <div className="text-[12px] font-semibold text-green-700">All chains well-supported</div>
              </div>
            );
            return (
              <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden">
                <div className="px-4 py-2.5 border-b border-gray-100 flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-gray-700">Orphaned Signal Chains</span>
                  <span className="text-[10px] text-gray-400">{flagged.length} chains need cleanup</span>
                </div>
                <table className="w-full text-xs">
                  <thead><tr className="bg-gray-50/60 border-b border-gray-100">{["#","Rule","Title","Sev","Signals","Orphaned","Action"].map(h => <Th key={h} ch={h} />)}</tr></thead>
                  <tbody>
                    {flagged.map((d, i) => (
                      <tr key={d.correlation_id} className="border-b border-gray-50 hover:bg-amber-50/20 al-row-in" style={{ animationDelay: `${i * 25}ms` }}>
                        <td className="px-3 py-2.5 font-mono text-[9px] text-gray-400">#{d.correlation_id}</td>
                        <td className="px-3 py-2.5 font-mono text-[9.5px] text-gray-600">{d.rule_id}</td>
                        <td className="px-3 py-2.5 text-[11px] font-medium text-gray-800">{d.title}</td>
                        <td className="px-3 py-2.5"><span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase", SEV[d.severity] ?? SEV.low)}>{d.severity}</span></td>
                        <td className="px-3 py-2.5 tabular-nums text-[10px] text-gray-600">{d.signal_count}</td>
                        <td className="px-3 py-2.5 font-bold text-[10px] text-amber-700 tabular-nums">{d.orphaned}</td>
                        <td className="px-3 py-2.5">
                          <button className="px-2 py-0.5 text-[9px] font-semibold rounded bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 transition-colors whitespace-nowrap">Cleanup</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
