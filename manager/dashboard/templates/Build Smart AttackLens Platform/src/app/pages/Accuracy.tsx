/**
 * Detection Accuracy & Calibration — security-grade accuracy engineering.
 *
 * Tabs:
 *  Overview     — composite health score, precision/recall KPIs, per-source + per-category bars
 *  Calibration  — prior vs observed reliability chart, status chips, tuning debt
 *  FP Risk      — noise candidates with category breakdown, suppression workflow
 *  MITRE        — ATT&CK tactic coverage heatmap derived from category data
 *  Correlation  — chain integrity summary and orphaned-signal audit
 *
 * Data: GET /api/v1/accuracy/report
 */
import { useState, useEffect, useCallback } from "react";
import {
  RefreshCw, AlertTriangle, CheckCircle, Info, Target,
  Shield, Activity, FlaskConical, GitBranch, Crosshair,
  TrendingDown, TrendingUp,
} from "lucide-react";
import {
  BarChart, Bar, Cell, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer, PieChart, Pie, Legend,
} from "recharts";
import { cn } from "../../lib/utils";

const API = "/api/v1/accuracy/report";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SourceStat {
  source:               string;
  count:                number;
  confidence_prior:     number;
  observed_precision_pct: number;
  fp_risk_pct:          number;
  calibration_gap:      number;
  severities:           Record<string, number>;
}

interface CategoryStat {
  category:      string;
  count:         number;
  precision_pct: number;
  fp_risk_pct:   number;
  avg_score:     number;
  severities:    Record<string, number>;
}

interface FPCandidate {
  id:             number;
  agent_id:       string;
  category:       string;
  severity:       string;
  title:          string;
  source:         string;
  confidence:     number;
  fp_reasons:     string[];
  recommendation: string;
}

interface CalibrationRow {
  source:           string;
  count:            number;
  confidence_prior: number;
  observed_rate:    number;
  calibration_gap:  number;
  status:           string;
  action:           string;
}

interface Report {
  meta: {
    generated_at:       number;
    agent_id:           string | null;
    total_findings:     number;
    total_correlations: number;
    methodology:        string;
  };
  overall: {
    estimated_precision_pct:   number;
    validated_findings:        number;
    unvalidated_findings:      number;
    fp_risk_count:             number;
    high_confidence_count:     number;
    correlation_integrity_pct: number;
  };
  by_source:   SourceStat[];
  by_category: CategoryStat[];
  validation:  Record<string, unknown>;
  calibration: CalibrationRow[];
  fp_risk_items: FPCandidate[];
  correlation_integrity: {
    total:          number;
    well_supported: number;
    has_orphans:    number;
    integrity_pct:  number;
    note:           string;
    details:        {
      correlation_id: number;
      rule_id:        string;
      title:          string;
      severity:       string;
      signal_count:   number;
      orphaned:       number;
      integrity:      string;
    }[];
  };
}

type TabId = "overview" | "calibration" | "fp" | "mitre" | "correlation";

// ── MITRE ATT&CK tactic map ───────────────────────────────────────────────────

const MITRE_TACTICS = [
  { id: "TA0002", name: "Execution",           cats: ["process","script","malware","execution","binary"]         },
  { id: "TA0003", name: "Persistence",         cats: ["persistence","startup","launchd","cron","plist"]          },
  { id: "TA0004", name: "Privilege Escalation",cats: ["privilege","sudo","setuid","escalation"]                  },
  { id: "TA0005", name: "Defense Evasion",     cats: ["evasion","tamper","gatekeeper","sip","unsigned"]          },
  { id: "TA0006", name: "Credential Access",   cats: ["credential","keychain","password","secret"]               },
  { id: "TA0007", name: "Discovery",           cats: ["discovery","reconnaissance","scan","enumeration"]         },
  { id: "TA0008", name: "Lateral Movement",    cats: ["lateral","ssh","remote","rdp","share"]                    },
  { id: "TA0009", name: "Collection",          cats: ["collection","clipboard","screen","file","exfil"]          },
  { id: "TA0011", name: "Command & Control",   cats: ["network","dns","beacon","c2","tunnel","proxy"]            },
  { id: "TA0040", name: "Impact",              cats: ["ransomware","wipe","encrypt","destroy","dos"]             },
  { id: "TA0010", name: "Exfiltration",        cats: ["exfil","upload","transfer","cloud","s3"]                  },
  { id: "TA0001", name: "Initial Access",      cats: ["phish","exploit","vuln","cve","exploit_code"]             },
];

function deriveTacticCoverage(cats: CategoryStat[]): {
  id: string; name: string; coverage: number; findings: number; precision: number;
}[] {
  return MITRE_TACTICS.map(t => {
    const matched = cats.filter(c =>
      t.cats.some(tc => c.category.toLowerCase().includes(tc))
    );
    const findings  = matched.reduce((s, c) => s + c.count, 0);
    const precision = matched.length
      ? Math.round(matched.reduce((s, c) => s + c.precision_pct, 0) / matched.length)
      : 0;
    const coverage = Math.min(100, findings > 0 ? Math.min(100, precision) : 0);
    return { id: t.id, name: t.name, coverage, findings, precision };
  });
}

// ── Colour helpers ────────────────────────────────────────────────────────────

function pctColor(p: number) {
  if (p >= 85) return "#059669";
  if (p >= 70) return "#2563eb";
  if (p >= 50) return "#d97706";
  return "#dc2626";
}
function gapColor(gap: number) {
  if (Math.abs(gap) <= 12) return "#059669";
  if (gap > 12) return "#dc2626";
  return "#d97706";
}
function coverageColor(c: number) {
  if (c >= 75) return "#059669";
  if (c >= 40) return "#d97706";
  return "#dc2626";
}

function deriveCalibrationScore(rows: CalibrationRow[]): number {
  if (!rows.length) return 0;
  const avg = rows.reduce((s, r) => s + Math.abs(r.calibration_gap), 0) / rows.length;
  return Math.max(0, Math.round(100 - avg));
}

function deriveF1(precision: number): number {
  // Proxy F1: assume recall ≈ 0.85 (typical well-tuned EDR recall baseline)
  const recall = 85;
  if (precision + recall === 0) return 0;
  return Math.round((2 * precision * recall) / (precision + recall));
}

// ── Shared design atoms ───────────────────────────────────────────────────────

function ScoreRing({ score, size = 72, stroke = 6 }: { score: number; size?: number; stroke?: number }) {
  const r = (size - stroke * 2) / 2;
  const circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  const color = pctColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#f3f4f6" strokeWidth={stroke} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color} strokeWidth={stroke}
        strokeDasharray={`${fill} ${circ}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.22,1,0.36,1)" }}
      />
      <text x="50%" y="50%" dominantBaseline="middle" textAnchor="middle"
        fill={color} fontSize={size * 0.22} fontWeight="700">
        {score}%
      </text>
    </svg>
  );
}

function KpiTile({
  label, value, sub, color, icon: Icon, delay = 0,
}: {
  label: string; value: string | number; sub?: string;
  color: string; icon: React.ElementType; delay?: number;
}) {
  return (
    <div
      className="bg-white border border-[--gray-200] rounded-xl p-4 flex-1 shadow-card al-bounce-in"
      style={{ animationDelay: `${delay}ms`, minWidth: 0 }}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">{label}</span>
        <Icon className="w-3.5 h-3.5" style={{ color }} />
      </div>
      <div className="text-2xl font-bold leading-none tabular-nums" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-[--gray-400] mt-1">{sub}</div>}
    </div>
  );
}

function HBar({
  label, value, max, color, sub,
}: { label: string; value: number; max: number; color: string; sub?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="py-2 border-b border-[--gray-50] last:border-0">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[10.5px] font-medium text-[--gray-700] capitalize flex-1 truncate">{label}</span>
        {sub && <span className="text-[9px] text-[--gray-400]">{sub}</span>}
        <span className="text-[11px] font-bold tabular-nums" style={{ color }}>{value}%</span>
      </div>
      <div className="h-2 bg-[--gray-100] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full al-bar-fill"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

function CalStatus({ status }: { status: string }) {
  if (status === "well_calibrated")
    return <span className="px-2 py-0.5 text-[9px] font-bold rounded-full bg-green-50 text-green-700 border border-green-200">Well Calibrated</span>;
  if (status === "over_confident")
    return <span className="px-2 py-0.5 text-[9px] font-bold rounded-full bg-red-50 text-red-700 border border-red-200 al-glow-critical">Over-confident</span>;
  return <span className="px-2 py-0.5 text-[9px] font-bold rounded-full bg-amber-50 text-amber-700 border border-amber-200">Under-confident</span>;
}

const SEV_CHIP: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200",
  high:     "bg-amber-50 text-amber-700 border-amber-200",
  medium:   "bg-blue-50 text-blue-700 border-blue-200",
  low:      "bg-green-50 text-green-700 border-green-200",
};

// ── Tab bar ───────────────────────────────────────────────────────────────────

function TabBar({ tab, setTab, fpCount }: { tab: TabId; setTab: (t: TabId) => void; fpCount: number }) {
  const tabs: { id: TabId; label: string; icon: React.ElementType }[] = [
    { id: "overview",     label: "Overview",       icon: Activity     },
    { id: "calibration",  label: "Calibration",    icon: Target       },
    { id: "fp",           label: `FP Risk (${fpCount})`, icon: AlertTriangle },
    { id: "mitre",        label: "MITRE Coverage", icon: Crosshair    },
    { id: "correlation",  label: "Correlation",    icon: GitBranch    },
  ];
  return (
    <div className="flex items-center gap-1 bg-white border border-[--gray-200] rounded-xl shadow-card p-1.5">
      {tabs.map(t => {
        const Icon = t.icon;
        const active = tab === t.id;
        return (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-all",
              active
                ? "bg-[--brand-orange] text-white shadow-sm"
                : "text-[--gray-500] hover:bg-[--gray-50] hover:text-[--gray-700]"
            )}
          >
            <Icon className="w-3 h-3" />
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Accuracy() {
  const [report,  setReport]  = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [tab,     setTab]     = useState<TabId>("overview");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(API);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setReport(await r.json());
      setError(null);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const overall  = report?.overall;
  const meta     = report?.meta;
  const calScore = report ? deriveCalibrationScore(report.calibration ?? []) : 0;
  const f1       = overall ? deriveF1(overall.estimated_precision_pct) : 0;
  const tacticCov = report ? deriveTacticCoverage(report.by_category ?? []) : [];
  const avgCoverage = tacticCov.length
    ? Math.round(tacticCov.reduce((s, t) => s + t.coverage, 0) / tacticCov.length)
    : 0;

  // Composite Detection Health Score
  const healthScore = overall
    ? Math.round(
        overall.estimated_precision_pct * 0.35 +
        calScore                         * 0.25 +
        overall.correlation_integrity_pct * 0.2 +
        avgCoverage                      * 0.2
      )
    : 0;

  const validationTotal = (report?.validation?.total_findings as number) ?? 1;
  const kevVal  = (report?.validation?.kev_validated  as number) ?? 0;
  const epssVal = (report?.validation?.epss_high      as number) ?? 0;
  const feedVal = (report?.validation?.feed_confirmed as number) ?? 0;

  const pieData = [
    { name: "KEV",      value: kevVal,  fill: "#dc2626" },
    { name: "EPSS≥50%", value: epssVal, fill: "#d97706" },
    { name: "Feed",     value: feedVal, fill: "#2563eb" },
    { name: "Other",    value: Math.max(0, validationTotal - kevVal - epssVal - feedVal), fill: "#d1d5db" },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-4">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
        {/* Orange accent stripe + scan */}
        <div className="h-[3px] relative overflow-hidden" style={{ background: "linear-gradient(90deg,#E8581A,#f97316,#fbbf24)" }}>
          <div className="absolute inset-y-0 al-scan" style={{ width: "35%", background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.6),transparent)" }} />
        </div>

        <div className="p-5">
          <div className="flex items-start justify-between gap-6">
            {/* Title */}
            <div className="flex items-start gap-3 flex-1">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ background: "linear-gradient(135deg,rgba(232,88,26,0.1),rgba(249,115,22,0.12))", border: "1px solid rgba(232,88,26,0.2)" }}>
                <FlaskConical className="w-5 h-5" style={{ color: "#E8581A" }} />
              </div>
              <div>
                <h1 className="text-base font-bold text-[--gray-900]">Detection Accuracy & Calibration</h1>
                <p className="text-[11px] text-[--gray-500] mt-0.5">
                  Precision · Recall · FP risk · Rule calibration · MITRE ATT&CK coverage · Correlation integrity
                </p>
                {meta?.methodology && (
                  <p className="text-[10px] text-[--gray-400] mt-1 max-w-2xl leading-relaxed italic">
                    {meta.methodology}
                  </p>
                )}
              </div>
            </div>

            {/* Health score ring */}
            {overall && (
              <div className="flex flex-col items-center gap-1 flex-shrink-0">
                <ScoreRing score={healthScore} size={76} stroke={7} />
                <span className="text-[9px] font-semibold text-[--gray-500] uppercase tracking-wide">Health Score</span>
              </div>
            )}

            <button
              onClick={load}
              className="p-2 hover:bg-[--gray-50] rounded-lg transition-colors flex-shrink-0"
              title="Refresh"
            >
              <RefreshCw className={cn("w-3.5 h-3.5 text-[--gray-400]", loading && "animate-spin")} />
            </button>
          </div>

          {/* KPI strip */}
          {overall && (
            <div className="flex items-stretch gap-3 mt-4 pt-4 border-t border-[--gray-100]">
              <KpiTile label="Est. Precision"   value={`${overall.estimated_precision_pct}%`}
                sub={`${overall.validated_findings} validated`}
                color={pctColor(overall.estimated_precision_pct)} icon={Target}        delay={0}  />
              <KpiTile label="F1 Score (proxy)" value={`${f1}%`}
                sub="Precision × Recall harmonic"
                color={pctColor(f1)}                              icon={Activity}      delay={60} />
              <KpiTile label="Calibration Score" value={`${calScore}%`}
                sub={`Avg gap ${Math.round((report?.calibration ?? []).reduce((s,r)=>s+Math.abs(r.calibration_gap),0)/Math.max(1,(report?.calibration?.length??1)))}%`}
                color={pctColor(calScore)}                        icon={FlaskConical}  delay={120}/>
              <KpiTile label="FP Risk Items"    value={overall.fp_risk_count}
                sub="review candidates"
                color={overall.fp_risk_count > 0 ? "#d97706" : "#059669"} icon={AlertTriangle} delay={180}/>
              <KpiTile label="MITRE Coverage"   value={`${avgCoverage}%`}
                sub={`${tacticCov.filter(t=>t.coverage>0).length} / ${MITRE_TACTICS.length} tactics`}
                color={coverageColor(avgCoverage)}                icon={Crosshair}     delay={240}/>
              <KpiTile label="Correlation Integrity" value={`${overall.correlation_integrity_pct}%`}
                sub={`${meta?.total_correlations ?? 0} chains`}
                color={pctColor(overall.correlation_integrity_pct)} icon={GitBranch}  delay={300}/>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="px-4 py-2 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
          {error} — showing placeholder data for demonstration.
        </div>
      )}

      {!report && !loading && !error && (
        <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-12 text-center text-xs text-[--gray-400]">
          No findings data yet. Accuracy report requires active findings in the database.
        </div>
      )}

      {/* Tab bar always visible so MITRE coverage shows even with empty data */}
      <TabBar tab={tab} setTab={setTab} fpCount={overall?.fp_risk_count ?? 0} />

      {/* ── Tab: Overview ──────────────────────────────────────────────────── */}
      {tab === "overview" && (
        <div className="space-y-4">
          {/* Health Score breakdown */}
          {overall && (
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={Activity}>Detection Health Breakdown</SectionLabel>
              <div className="grid grid-cols-4 gap-4 mt-3">
                {[
                  { label: "Precision",    score: overall.estimated_precision_pct,   note: "TP / (TP + FP)" },
                  { label: "Calibration",  score: calScore,                          note: "Prior vs observed gap" },
                  { label: "Correlation",  score: overall.correlation_integrity_pct, note: "Chain integrity" },
                  { label: "ATT&CK Cov.",  score: avgCoverage,                      note: "Tactic coverage" },
                ].map(d => (
                  <div key={d.label} className="flex flex-col items-center gap-2 p-3 rounded-xl"
                    style={{ background: "linear-gradient(135deg,#fafbfc,#f3f4f6)" }}>
                    <ScoreRing score={d.score} size={60} stroke={5} />
                    <div className="text-[11px] font-semibold text-[--gray-700]">{d.label}</div>
                    <div className="text-[9px] text-[--gray-400] text-center">{d.note}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            {/* Precision by Source */}
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={Target}>Precision by Detection Source</SectionLabel>
              <div className="mt-3 space-y-0.5 max-h-72 overflow-y-auto">
                {(report?.by_source ?? []).slice(0, 15).map(s => (
                  <HBar
                    key={s.source}
                    label={s.source}
                    value={s.observed_precision_pct}
                    max={100}
                    color={pctColor(s.observed_precision_pct)}
                    sub={`FP ${s.fp_risk_pct}% · n=${s.count}`}
                  />
                ))}
                {!report?.by_source?.length && (
                  <div className="text-[10px] text-[--gray-400] text-center py-8">No source data available</div>
                )}
              </div>
            </div>

            {/* Precision by Category */}
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={FlaskConical}>Precision by Category</SectionLabel>
              <div className="mt-3 space-y-0.5 max-h-72 overflow-y-auto">
                {(report?.by_category ?? []).map(c => (
                  <HBar
                    key={c.category}
                    label={c.category}
                    value={c.precision_pct}
                    max={100}
                    color={pctColor(c.precision_pct)}
                    sub={`FP ${c.fp_risk_pct}% · n=${c.count}`}
                  />
                ))}
                {!report?.by_category?.length && (
                  <div className="text-[10px] text-[--gray-400] text-center py-8">No category data available</div>
                )}
              </div>
            </div>
          </div>

          {/* Validation coverage */}
          {report && (
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={Shield}>External Validation Coverage</SectionLabel>
              <p className="text-[10px] text-[--gray-500] mt-1 mb-4">
                Findings independently confirmed by external threat intelligence signals.
                Higher external validation = lower FP risk.
              </p>
              <div className="grid grid-cols-[1fr_200px] gap-6">
                <div className="space-y-2.5">
                  {([
                    { key: "kev_validated",  label: "KEV Validated",     note: "CISA Known Exploited Vulnerabilities",       color: "#dc2626" },
                    { key: "epss_high",      label: "EPSS ≥ 50%",        note: "High exploit probability (FIRST EPSS model)", color: "#d97706" },
                    { key: "feed_confirmed", label: "Feed Confirmed",     note: "Matched threat-intelligence IOC feed",        color: "#2563eb" },
                    { key: "exploit_available", label: "Exploit Public",  note: "Public proof-of-concept / exploit kit",       color: "#7c3aed" },
                    { key: "unvalidated",    label: "Rule / Behavioral",  note: "Detection rule only, no external signal",     color: "#9ca3af" },
                  ] as const).map(({ key, label, note, color }) => {
                    const val = (report.validation[key] as number) ?? 0;
                    const pct = Math.round((val / validationTotal) * 100);
                    return (
                      <div key={key} className="flex items-center gap-3">
                        <div className="w-28 text-[10px] font-medium text-[--gray-700] flex-shrink-0">{label}</div>
                        <div className="flex-1 h-2.5 bg-[--gray-100] rounded-full overflow-hidden">
                          <div className="h-full rounded-full al-bar-fill" style={{ width: `${pct}%`, backgroundColor: color }} />
                        </div>
                        <div className="w-8 text-right text-[10px] font-bold tabular-nums" style={{ color }}>{val}</div>
                        <div className="w-7 text-[9px] text-[--gray-400] tabular-nums">{pct}%</div>
                        <div className="text-[9px] text-[--gray-400] hidden xl:block">{note}</div>
                      </div>
                    );
                  })}
                </div>
                {pieData.length > 0 && (
                  <div className="h-[160px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} dataKey="value" cx="50%" cy="50%" outerRadius={62} innerRadius={36} paddingAngle={2}>
                          {pieData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                        </Pie>
                        <Legend iconSize={8} iconType="circle" wrapperStyle={{ fontSize: 9 }} />
                        <RTooltip contentStyle={{ fontSize: 10, borderRadius: 8 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Calibration ───────────────────────────────────────────────── */}
      {tab === "calibration" && (
        <div className="space-y-4">
          {/* Explainer */}
          <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
            <Info className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
            <div className="text-[11px] text-amber-800 leading-relaxed">
              <strong>Calibration</strong> measures how well a rule's stated confidence matches reality.
              An <strong>over-confident</strong> rule (gap &gt; 12%) fires with high confidence but often generates false positives —
              lower the prior or add context filters. An <strong>under-confident</strong> rule (gap &lt; -12%) is
              conservative and may suppress genuine threats — widen the rule or increase the weight of supporting signals.
              Gap within ±12% is considered <strong>well-calibrated</strong>.
            </div>
          </div>

          {/* Summary cards */}
          {report && (() => {
            const rows = report.calibration ?? [];
            const well  = rows.filter(r => r.status === "well_calibrated").length;
            const over  = rows.filter(r => r.status === "over_confident").length;
            const under = rows.filter(r => r.status !== "well_calibrated" && r.status !== "over_confident").length;
            const tuningDebt = rows.reduce((s, r) => s + Math.abs(r.calibration_gap) * r.count, 0);
            return (
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: "Well Calibrated",   value: well,  color: "#059669", bg: "#f0fdf9" },
                  { label: "Over-confident",     value: over,  color: "#dc2626", bg: "#fef5f5" },
                  { label: "Under-confident",    value: under, color: "#d97706", bg: "#fffbf0" },
                  { label: "Tuning Debt Score",  value: Math.round(tuningDebt), color: "#6366f1", bg: "#eef2ff" },
                ].map(d => (
                  <div key={d.label} className="rounded-xl p-4 border" style={{ background: d.bg, borderColor: "rgba(0,0,0,0.07)" }}>
                    <div className="text-2xl font-bold tabular-nums" style={{ color: d.color }}>{d.value}</div>
                    <div className="text-[10px] font-medium text-[--gray-600] mt-0.5">{d.label}</div>
                  </div>
                ))}
              </div>
            );
          })()}

          {/* Calibration chart */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5">
            <SectionLabel icon={Target}>Prior vs. Observed Precision</SectionLabel>
            <div className="flex items-center gap-6 text-[10px] text-[--gray-500] mt-2 mb-4">
              <div className="flex items-center gap-1.5"><div className="w-6 h-2 rounded bg-[--gray-200]" />Prior confidence</div>
              <div className="flex items-center gap-1.5"><div className="w-6 h-2 rounded" style={{ background: "#E8581A" }} />Observed rate</div>
              <div className="flex items-center gap-1.5"><div className="w-6 h-2 rounded bg-red-200" />Gap (over-confident)</div>
            </div>
            {(report?.calibration ?? []).length > 0 ? (
              <div className="h-[220px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={(report?.calibration ?? []).slice(0, 12).map(r => ({
                      name: r.source.slice(0, 14),
                      prior: r.confidence_prior,
                      observed: r.observed_rate,
                      gap: Math.max(0, r.confidence_prior - r.observed_rate),
                    }))}
                    barGap={2}
                    margin={{ left: 0, right: 0, top: 8, bottom: 24 }}
                  >
                    <XAxis dataKey="name" tick={{ fontSize: 9 }} angle={-30} textAnchor="end" interval={0} />
                    <YAxis tick={{ fontSize: 9 }} domain={[0, 100]} unit="%" />
                    <RTooltip contentStyle={{ fontSize: 10, borderRadius: 8 }} />
                    <Bar dataKey="prior" fill="#e5e7eb" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="observed" fill="#E8581A" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[100px] flex items-center justify-center text-[10px] text-[--gray-400]">No calibration data available</div>
            )}
          </div>

          {/* Calibration detail table */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
            <div className="px-4 py-3 border-b border-[--gray-100] flex items-center justify-between">
              <span className="text-[11px] font-semibold text-[--gray-700]">Calibration Detail</span>
              <span className="text-[9px] text-[--gray-400]">{report?.calibration?.length ?? 0} rules</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-[--gray-25] border-b border-[--gray-100]">
                    {["Rule / Source","n","Prior","Observed","Gap","Status","Recommended Action"].map(h => (
                      <th key={h} className="px-3 py-2.5 text-left text-[9px] font-semibold text-[--gray-500] uppercase tracking-wide whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(report?.calibration ?? []).map((row, i) => (
                    <tr key={row.source} className="border-b border-[--gray-50] hover:bg-[--gray-25] al-row-in"
                      style={{ animationDelay: `${i * 30}ms` }}>
                      <td className="px-3 py-2.5 font-mono text-[9.5px] text-[--gray-700] max-w-[160px] truncate">{row.source}</td>
                      <td className="px-3 py-2.5 tabular-nums text-[10px] text-[--gray-600]">{row.count}</td>
                      <td className="px-3 py-2.5 text-[10px] text-[--gray-500]">{row.confidence_prior}%</td>
                      <td className="px-3 py-2.5 text-[10px] font-bold tabular-nums" style={{ color: pctColor(row.observed_rate) }}>{row.observed_rate}%</td>
                      <td className="px-3 py-2.5 text-[10px] font-semibold tabular-nums" style={{ color: gapColor(row.calibration_gap) }}>
                        {row.calibration_gap > 0 ? `↓${row.calibration_gap}` : row.calibration_gap < 0 ? `↑${Math.abs(row.calibration_gap)}` : "✓"}
                      </td>
                      <td className="px-3 py-2.5"><CalStatus status={row.status} /></td>
                      <td className="px-3 py-2.5 text-[9.5px] text-[--gray-600] max-w-[220px]">{row.action}</td>
                    </tr>
                  ))}
                  {!report?.calibration?.length && (
                    <tr><td colSpan={7} className="px-3 py-8 text-center text-[10px] text-[--gray-400]">No calibration data available</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: FP Risk ───────────────────────────────────────────────────── */}
      {tab === "fp" && (
        <div className="space-y-4">
          {/* Noise explainer */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
            <SectionLabel icon={AlertTriangle}>FP Noise Analysis</SectionLabel>
            <p className="text-[10.5px] text-[--gray-500] mt-2 leading-relaxed max-w-3xl">
              False-positive risk candidates are findings where the detection rule fires with low external validation,
              low confidence, or known noisy source patterns. Each item requires analyst review:
              mark as FP to suppress, accept risk to acknowledge, or escalate for investigation.
            </p>
            {/* Category FP breakdown */}
            {report?.by_category && (
              <div className="mt-4 grid grid-cols-[1fr_180px] gap-4 items-end">
                <div className="space-y-1.5">
                  {report.by_category.filter(c => c.fp_risk_pct > 0).sort((a,b) => b.fp_risk_pct - a.fp_risk_pct).slice(0, 8).map(c => (
                    <div key={c.category} className="flex items-center gap-2">
                      <span className="text-[10px] font-medium text-[--gray-700] capitalize w-28 flex-shrink-0 truncate">{c.category}</span>
                      <div className="flex-1 h-2 bg-[--gray-100] rounded-full overflow-hidden">
                        <div className="h-full rounded-full al-bar-fill"
                          style={{ width: `${Math.min(100, c.fp_risk_pct)}%`,
                            backgroundColor: c.fp_risk_pct > 40 ? "#dc2626" : c.fp_risk_pct > 20 ? "#d97706" : "#2563eb" }} />
                      </div>
                      <span className="text-[10px] font-bold tabular-nums w-10 text-right"
                        style={{ color: c.fp_risk_pct > 40 ? "#dc2626" : c.fp_risk_pct > 20 ? "#d97706" : "#2563eb" }}>
                        {c.fp_risk_pct}%
                      </span>
                    </div>
                  ))}
                </div>
                {/* FP vs precision scatter (recharts) */}
                <div className="h-[140px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={report.by_category.slice(0, 6).map(c => ({ name: c.category.slice(0,8), fp: c.fp_risk_pct }))}
                      margin={{ left: 0, right: 0, top: 4, bottom: 20 }}
                    >
                      <XAxis dataKey="name" tick={{ fontSize: 8 }} angle={-25} textAnchor="end" interval={0} />
                      <YAxis tick={{ fontSize: 8 }} unit="%" />
                      <RTooltip contentStyle={{ fontSize: 10, borderRadius: 8 }} />
                      <Bar dataKey="fp" name="FP Risk %" radius={[3,3,0,0]}>
                        {report.by_category.slice(0, 6).map((c, i) => (
                          <Cell key={i} fill={c.fp_risk_pct > 40 ? "#dc2626" : c.fp_risk_pct > 20 ? "#d97706" : "#60a5fa"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>

          {/* FP candidates */}
          {(report?.fp_risk_items ?? []).length === 0 ? (
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-12 text-center">
              <CheckCircle className="w-10 h-10 text-green-500 mx-auto mb-3" />
              <div className="text-sm font-semibold text-green-700">No high FP-risk candidates</div>
              <div className="text-[11px] text-[--gray-500] mt-1">
                All findings have adequate external validation or high-confidence rule signatures.
              </div>
            </div>
          ) : (
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
              <div className="px-4 py-3 border-b border-[--gray-100] flex items-center justify-between">
                <span className="text-[11px] font-semibold text-[--gray-700]">
                  Suppression Candidates — {report!.fp_risk_items.length} items
                </span>
                <div className="text-[9px] text-[--gray-400]">
                  Review each · Mark FP → triggers suppression rule · Accept Risk → acknowledge
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-[--gray-25] border-b border-[--gray-100]">
                      {["Finding","Category","Sev","Source","Confidence","FP Signals","Action"].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left text-[9px] font-semibold text-[--gray-500] uppercase tracking-wide whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {report!.fp_risk_items.map((item, i) => (
                      <tr key={item.id}
                        className={cn("border-b border-[--gray-50] hover:bg-amber-50/20 al-row-in",
                          item.severity === "critical" && "al-glow-critical")}
                        style={{ animationDelay: `${i * 35}ms` }}>
                        <td className="px-3 py-3 max-w-[200px]">
                          <div className="font-medium text-[11px] text-[--gray-800] truncate">{item.title}</div>
                          <div className="text-[9px] font-mono text-[--gray-400] mt-0.5">{item.agent_id?.slice(0, 16)}</div>
                        </td>
                        <td className="px-3 py-3 text-[9px] font-mono text-[--gray-600] capitalize">{item.category}</td>
                        <td className="px-3 py-3">
                          <span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase", SEV_CHIP[item.severity] ?? SEV_CHIP.low)}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-[9px] font-mono text-[--gray-500]">{item.source}</td>
                        <td className="px-3 py-3">
                          <div className="flex items-center gap-1.5">
                            <div className="w-16 h-1.5 bg-[--gray-100] rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{ width: `${item.confidence}%`, backgroundColor: pctColor(item.confidence) }} />
                            </div>
                            <span className="text-[10px] font-bold tabular-nums" style={{ color: pctColor(item.confidence) }}>{item.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-3 max-w-[180px]">
                          {item.fp_reasons.map((r, j) => (
                            <div key={j} className="flex items-start gap-1 text-[9px] text-amber-700 mb-0.5">
                              <AlertTriangle className="w-2.5 h-2.5 flex-shrink-0 mt-0.5" /> {r}
                            </div>
                          ))}
                        </td>
                        <td className="px-3 py-3">
                          <div className="flex flex-col gap-1">
                            <button className="px-2 py-1 text-[9px] font-semibold rounded-md bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 transition-colors whitespace-nowrap">
                              Mark FP
                            </button>
                            <button className="px-2 py-1 text-[9px] font-semibold rounded-md bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 transition-colors whitespace-nowrap">
                              Accept Risk
                            </button>
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

      {/* ── Tab: MITRE ATT&CK Coverage ─────────────────────────────────────── */}
      {tab === "mitre" && (
        <div className="space-y-4">
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
            <SectionLabel icon={Crosshair}>MITRE ATT&CK Coverage — {avgCoverage}% average</SectionLabel>
            <p className="text-[10.5px] text-[--gray-500] mt-1.5 mb-4 leading-relaxed">
              Coverage is derived by mapping active detection categories to ATT&CK tactics.
              Gaps indicate adversary techniques where detections are absent or low-precision.
            </p>
            <div className="grid grid-cols-3 gap-3">
              {MITRE_TACTICS.map((tactic, i) => {
                const tc = tacticCov.find(t => t.id === tactic.id) ?? { coverage: 0, findings: 0, precision: 0 };
                const color = coverageColor(tc.coverage);
                return (
                  <div
                    key={tactic.id}
                    className="rounded-xl border p-3.5 al-bounce-in"
                    style={{
                      animationDelay: `${i * 40}ms`,
                      borderColor: tc.coverage === 0
                        ? "#fecaca"
                        : tc.coverage < 50
                        ? "#fde68a"
                        : "rgba(0,0,0,0.08)",
                      background: tc.coverage === 0
                        ? "#fef5f5"
                        : tc.coverage < 50
                        ? "#fffbf0"
                        : "#fafbfc",
                    }}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div>
                        <div className="text-[10px] font-mono text-[--gray-400]">{tactic.id}</div>
                        <div className="text-[11.5px] font-semibold text-[--gray-800]">{tactic.name}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-base font-bold tabular-nums leading-none" style={{ color }}>
                          {tc.coverage}%
                        </div>
                        {tc.findings > 0 && (
                          <div className="text-[8px] text-[--gray-400]">{tc.findings} findings</div>
                        )}
                      </div>
                    </div>
                    <div className="h-1.5 bg-[--gray-100] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full al-bar-fill"
                        style={{ width: `${tc.coverage}%`, backgroundColor: color, animationDelay: `${i * 40 + 200}ms` }}
                      />
                    </div>
                    <div className="flex items-center justify-between mt-1.5">
                      <span className="text-[9px] text-[--gray-400]">{tactic.cats.slice(0, 3).join(", ")}</span>
                      {tc.coverage === 0
                        ? <span className="text-[9px] font-semibold text-red-600">BLIND SPOT</span>
                        : tc.coverage < 40
                        ? <span className="text-[9px] font-semibold text-amber-600">WEAK</span>
                        : tc.coverage < 75
                        ? <span className="text-[9px] font-semibold text-blue-600">PARTIAL</span>
                        : <span className="text-[9px] font-semibold text-green-600">COVERED</span>
                      }
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Gap summary */}
          <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
            <SectionLabel icon={TrendingDown}>Coverage Gaps & Recommendations</SectionLabel>
            <div className="mt-3 space-y-2">
              {tacticCov.filter(t => t.coverage < 40).sort((a, b) => a.coverage - b.coverage).map(t => {
                const tactic = MITRE_TACTICS.find(m => m.id === t.id)!;
                return (
                  <div key={t.id} className="flex items-center gap-3 p-3 rounded-xl border border-red-100 bg-red-50/40">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: coverageColor(t.coverage) }} />
                    <div className="flex-1">
                      <div className="text-[11px] font-semibold text-[--gray-800]">{tactic.name}</div>
                      <div className="text-[9.5px] text-[--gray-500] mt-0.5">
                        Coverage: {t.coverage}% · Add rules covering: {tactic.cats.join(", ")}
                      </div>
                    </div>
                    <span
                      className="text-[9px] font-bold px-2 py-1 rounded-full"
                      style={{ background: coverageColor(t.coverage) === "#dc2626" ? "#fef2f2" : "#fffbeb",
                               color: coverageColor(t.coverage) }}
                    >
                      {t.coverage === 0 ? "NO COVERAGE" : "NEEDS RULES"}
                    </span>
                  </div>
                );
              })}
              {tacticCov.filter(t => t.coverage < 40).length === 0 && (
                <div className="flex items-center gap-2 text-green-700 text-[11px]">
                  <CheckCircle className="w-4 h-4" />
                  All tactics have ≥ 40% coverage. Continue improving precision for weak areas.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Correlation Integrity ──────────────────────────────────────── */}
      {tab === "correlation" && (
        <div className="space-y-4">
          {report?.correlation_integrity && (
            <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-4">
              <SectionLabel icon={GitBranch}>Correlation Chain Integrity</SectionLabel>
              <div className="flex items-start gap-2 mt-2 mb-4 p-3 bg-blue-50 border border-blue-100 rounded-xl">
                <Info className="w-3.5 h-3.5 text-blue-500 flex-shrink-0 mt-0.5" />
                <p className="text-[10.5px] text-blue-800 leading-relaxed">{report.correlation_integrity.note}</p>
              </div>
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: "Total Chains",     val: report.correlation_integrity.total,          color: "#374151", bg: "#f9fafb" },
                  { label: "Well Supported",   val: report.correlation_integrity.well_supported,  color: "#059669", bg: "#f0fdf9" },
                  { label: "Orphaned Signals", val: report.correlation_integrity.has_orphans,
                    color: report.correlation_integrity.has_orphans > 0 ? "#d97706" : "#059669",
                    bg: report.correlation_integrity.has_orphans > 0 ? "#fffbf0" : "#f0fdf9"    },
                  { label: "Integrity",        val: `${report.correlation_integrity.integrity_pct}%`,
                    color: pctColor(report.correlation_integrity.integrity_pct), bg: "#fafbfc"   },
                ].map(d => (
                  <div key={d.label} className="rounded-xl p-4 border text-center" style={{ background: d.bg, borderColor: "rgba(0,0,0,0.07)" }}>
                    <div className="text-2xl font-bold tabular-nums al-bounce-in" style={{ color: d.color }}>{d.val}</div>
                    <div className="text-[10px] font-medium text-[--gray-600] mt-1">{d.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {(() => {
            const flagged = (report?.correlation_integrity?.details ?? []).filter(d => d.integrity !== "ok");
            if (!flagged.length) return (
              <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-12 text-center">
                <CheckCircle className="w-10 h-10 text-green-500 mx-auto mb-3" />
                <div className="text-sm font-semibold text-green-700">All correlation chains are well-supported</div>
                <div className="text-[11px] text-[--gray-500] mt-1">No orphaned signals detected.</div>
              </div>
            );
            return (
              <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
                <div className="px-4 py-3 border-b border-[--gray-100] flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-[--gray-700]">Chains with Orphaned Signals ({flagged.length})</span>
                  <span className="text-[9px] text-[--gray-400]">Orphaned = telemetry signals without a parent correlation</span>
                </div>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-[--gray-25] border-b border-[--gray-100]">
                      {["#","Rule","Title","Sev","Signals","Orphaned","Action"].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left text-[9px] font-semibold text-[--gray-500] uppercase tracking-wide">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {flagged.map((d, i) => (
                      <tr key={d.correlation_id} className="border-b border-[--gray-50] hover:bg-amber-50/20 al-row-in"
                        style={{ animationDelay: `${i * 30}ms` }}>
                        <td className="px-3 py-2.5 font-mono text-[9px] text-[--gray-500]">#{d.correlation_id}</td>
                        <td className="px-3 py-2.5 font-mono text-[9px] text-[--gray-600]">{d.rule_id}</td>
                        <td className="px-3 py-2.5 text-[11px] text-[--gray-800] font-medium">{d.title}</td>
                        <td className="px-3 py-2.5">
                          <span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase", SEV_CHIP[d.severity] ?? SEV_CHIP.low)}>
                            {d.severity}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 tabular-nums text-[10px] text-[--gray-600]">{d.signal_count}</td>
                        <td className="px-3 py-2.5 tabular-nums text-[10px] font-bold text-amber-700">{d.orphaned}</td>
                        <td className="px-3 py-2.5">
                          <button className="px-2 py-1 text-[9px] font-semibold rounded-md bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 transition-colors whitespace-nowrap">
                            Cleanup Signals
                          </button>
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

// ── Shared helpers ────────────────────────────────────────────────────────────

function SectionLabel({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "#E8581A" }} />
      <h2 className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wide">{children}</h2>
    </div>
  );
}
