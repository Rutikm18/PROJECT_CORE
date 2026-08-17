/**
 * ValidationPipelinePanel — Settings → Validation Pipeline.
 *
 * The Validation tab answers "what threshold applies?". This one answers the
 * four questions that tab cannot:
 *
 *   Pipeline      — what actually runs, in what order, and which sections does
 *                   each stage decide?
 *   Data accuracy — is the output correct? Precision, FP rate by rule, and the
 *                   findings the engine could not even place in a terrain.
 *   Integrations  — what does validation depend on, and is it healthy?
 *   Debug         — for one specific finding, which criterion is holding it
 *                   below the threshold?
 *
 * Everything is read from GET /api/v1/settings/validation/pipeline, which
 * derives the stage list from the engine itself, so this page cannot drift out
 * of sync with the code that scores findings.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, Bug, CheckCircle2, ChevronDown, ChevronRight,
  Cpu, Layers, Plug, RefreshCw, Search, ShieldCheck, Target, XCircle,
} from "lucide-react";
import { cn } from "../../../lib/utils";

const PAPI = "/api/v1/settings/validation/pipeline";
const DAPI = "/api/v1/settings/validation/debug";

// ── Types ───────────────────────────────────────────────────────────────────

export interface StageConfig {
  key: string; source: string; description: string;
  value: unknown; error: string;
}
export interface StageCheck {
  id: string; order: number; label: string; description: string;
  weight?: number; required?: boolean; short_circuits?: boolean;
  criteria?: { name: string; label: string; description: string; weight: number; is_anchor: boolean }[];
  criteria_count?: number; weight_total?: number; anchor_count?: number;
}
export interface ErrorPolicy {
  stage: string;
  on_failure_default: { state: string; action: string };
  on_failure_high_severity: { state: string; action: string };
  with_authoritative_evidence: { state: string; action: string };
  fails_closed: boolean;
}
export interface PipelineStage {
  order: number; id: string; name: string; kind: string; module: string;
  purpose: string; covers: string[]; error_policy: ErrorPolicy | null;
  config: StageConfig[]; checks: StageCheck[]; check_count: number;
  check_error: string;
}
export interface RuleRate {
  rule_id: string; tp: number; fp: number; false_positive_rate: number | null;
}
export interface PipelineReport {
  window_hours: number;
  stages: PipelineStage[];
  stage_count: number;
  stages_error: string;
  accuracy: {
    current_states: Record<string, number>;
    decisions: Record<string, number>;
    abstentions: number;
    unknown_terrain: number;
    analyst_overrides: number;
    precision_overall: number | null;
    precision_by_rule: { rule_id: string; precision?: number }[];
    rejected_by_gate: { gate?: string; n?: number }[];
    worst_rules: RuleRate[];
    false_positive_by_rule: RuleRate[];
    error: string;
  };
  integrations: {
    providers: { provider: string; model: string; calls: number; tokens: number; cost_usd: number; latency_ms: number }[];
    registry: Record<string, unknown>;
    ingest: Record<string, unknown>;
  };
  failures: {
    errors: Record<string, number>;
    recompute_jobs: Record<string, number>;
    alerts: { code: string; severity: string; count: number }[];
  };
  observed_at: number;
}

type PanelTab = "pipeline" | "accuracy" | "integrations" | "debug";

// ── Pure helpers (exported for test) ────────────────────────────────────────

/** Stage kinds grouped into the phase an operator thinks in. */
export const KIND_PHASE: Record<string, string> = {
  schema: "Intake", allowlist: "Intake",
  gate: "Decide", scoring: "Decide", model: "Decide", threshold: "Decide",
  enrichment: "Enrich",
  policy: "Govern", ledger: "Govern", orchestration: "Govern",
};

export function phaseFor(kind: string): string {
  return KIND_PHASE[kind] ?? "Other";
}

/** Format a config value for display without ever rendering "[object Object]". */
export function formatConfigValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Total open failures across error classes and recompute jobs. Drives the
 * badge on the Debug tab — an operator should see there is something to look
 * at without opening every tab.
 */
export function countFailures(failures: PipelineReport["failures"] | undefined): number {
  if (!failures) return 0;
  const errors = Object.values(failures.errors ?? {}).reduce((a, b) => a + b, 0);
  const jobs = Number(failures.recompute_jobs?.error ?? 0);
  return errors + jobs;
}

// ── Small presentational pieces ─────────────────────────────────────────────

function SectionLabel({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "#7C3AED" }} />
      <h2 className="text-[11px] font-bold text-[--gray-700] uppercase tracking-wide">{children}</h2>
    </div>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card p-5 space-y-4">
      {children}
    </div>
  );
}

function Metric({ label, value, tone = "neutral", sub }: {
  label: string; value: string | number; sub?: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const toneCls = {
    neutral: "text-[--gray-800]",
    good:    "text-emerald-600",
    warn:    "text-amber-600",
    bad:     "text-red-600",
  }[tone];
  return (
    <div className="flex-1 min-w-[110px] rounded-xl border border-[--gray-100] px-3 py-2.5 bg-white">
      <div className={cn("text-lg font-black tabular-nums leading-none", toneCls)}>{value}</div>
      {sub && <div className="text-[9px] text-[--gray-400] mt-0.5 font-medium">{sub}</div>}
      <div className="text-[10px] text-[--gray-500] font-semibold mt-1">{label}</div>
    </div>
  );
}

function Pill({ children, tone = "gray" }: { children: React.ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    gray:    "bg-[--gray-100] text-[--gray-600] border-[--gray-200]",
    purple:  "bg-purple-50 text-purple-700 border-purple-200",
    red:     "bg-red-50 text-red-700 border-red-200",
    amber:   "bg-amber-50 text-amber-700 border-amber-200",
    emerald: "bg-emerald-50 text-emerald-700 border-emerald-200",
    blue:    "bg-blue-50 text-blue-700 border-blue-200",
  };
  return (
    <span className={cn("text-[9px] font-semibold px-1.5 py-0.5 rounded-full border whitespace-nowrap", tones[tone] ?? tones.gray)}>
      {children}
    </span>
  );
}

// ── Stage row ───────────────────────────────────────────────────────────────

function StageRow({ stage }: { stage: PipelineStage }) {
  const [open, setOpen] = useState(false);
  const Chevron = open ? ChevronDown : ChevronRight;
  const policy = stage.error_policy;

  return (
    <div className="border border-[--gray-200] rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-start gap-3 px-3 py-2.5 text-left hover:bg-[--gray-50] transition-colors"
      >
        <span className="text-[10px] font-black tabular-nums text-[--gray-300] mt-0.5 w-5 flex-shrink-0">
          {String(stage.order).padStart(2, "0")}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[12px] font-bold text-[--gray-800]">{stage.name}</span>
            <Pill tone="purple">{phaseFor(stage.kind)}</Pill>
            <Pill>{stage.kind}</Pill>
            {stage.check_count > 0 && <Pill tone="blue">{stage.check_count} checks</Pill>}
            {policy?.fails_closed && <Pill tone="red">fails closed</Pill>}
          </div>
          <p className="text-[10px] text-[--gray-500] mt-1 leading-relaxed">{stage.purpose}</p>
          <div className="flex items-center gap-1 flex-wrap mt-1.5">
            <span className="text-[9px] text-[--gray-400] font-semibold uppercase tracking-wide mr-0.5">Covers</span>
            {stage.covers.map(c => (
              <Pill key={c} tone={c === "*" ? "gray" : "emerald"}>{c === "*" ? "all sections" : c}</Pill>
            ))}
          </div>
        </div>
        <Chevron className="w-4 h-4 text-[--gray-400] flex-shrink-0 mt-0.5" />
      </button>

      {open && (
        <div className="border-t border-[--gray-100] bg-[--gray-50] px-3 py-3 space-y-3">
          <div className="text-[9px] font-mono text-[--gray-400] break-all">{stage.module}</div>

          {/* Configuration */}
          {stage.config.length > 0 && (
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">Configuration</div>
              <div className="space-y-1">
                {stage.config.map(c => (
                  <div key={c.key} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <code className="text-[10px] font-mono font-semibold text-[--gray-700] break-all">{c.key}</code>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <Pill>{c.source}</Pill>
                        <code className={cn(
                          "text-[10px] font-mono font-bold tabular-nums",
                          c.error ? "text-red-600" : "text-purple-700",
                        )}>
                          {c.error ? "error" : formatConfigValue(c.value)}
                        </code>
                      </div>
                    </div>
                    <div className="text-[9px] text-[--gray-400] mt-0.5 leading-relaxed">{c.description}</div>
                    {c.error && <div className="text-[9px] text-red-600 mt-0.5">{c.error}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Failure behaviour */}
          {policy && (
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">On failure</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                {[
                  ["Default", policy.on_failure_default],
                  ["High severity", policy.on_failure_high_severity],
                  ["Authoritative evidence", policy.with_authoritative_evidence],
                ].map(([label, decision]) => {
                  const d = decision as { state: string; action: string };
                  return (
                    <div key={label as string} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                      <div className="text-[9px] text-[--gray-400] font-semibold">{label as string}</div>
                      <div className={cn(
                        "text-[10px] font-bold mt-0.5",
                        d.state === "error" ? "text-red-600"
                          : d.state === "needs_review" ? "text-amber-600" : "text-emerald-600",
                      )}>
                        {d.state}
                      </div>
                      <code className="text-[9px] font-mono text-[--gray-400]">{d.action}</code>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Sub-checks */}
          {stage.checks.length > 0 && (
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
                Checks performed
              </div>
              <div className="space-y-1">
                {stage.checks.map(check => (
                  <div key={check.id} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-semibold text-[--gray-700]">{check.label}</span>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        {check.weight !== undefined && <Pill tone="purple">w {check.weight}</Pill>}
                        {check.anchor_count !== undefined && check.anchor_count > 0 && (
                          <Pill tone="red">{check.anchor_count} anchor</Pill>
                        )}
                        {check.criteria_count !== undefined && <Pill tone="blue">{check.criteria_count} criteria</Pill>}
                        {check.required && <Pill tone="amber">required</Pill>}
                      </div>
                    </div>
                    {check.description && (
                      <div className="text-[9px] text-[--gray-400] mt-0.5 leading-relaxed">{check.description}</div>
                    )}
                    {/* Terrain rubrics nest their criteria one level deeper. */}
                    {check.criteria && (
                      <div className="mt-1.5 space-y-0.5 border-l-2 border-[--gray-100] pl-2">
                        {check.criteria.map(cr => (
                          <div key={cr.name} className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <span className="text-[9px] font-semibold text-[--gray-600]">{cr.label}</span>
                              {cr.is_anchor && <span className="ml-1"><Pill tone="red">anchor</Pill></span>}
                              <div className="text-[9px] text-[--gray-400] leading-snug">{cr.description}</div>
                            </div>
                            <code className="text-[9px] font-mono tabular-nums text-purple-700 flex-shrink-0">
                              {cr.weight}
                            </code>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {stage.check_error && (
            <div className="text-[10px] text-red-600">Could not enumerate checks: {stage.check_error}</div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Debug console ───────────────────────────────────────────────────────────

interface DebugTrace {
  finding: Record<string, unknown>;
  terrain: string;
  evaluation: {
    score: number; percentage: number; summary: string;
    anchor_hit: boolean; ai_ran: boolean; met_count: number; total_count: number;
    criteria: { name: string; label: string; description: string; weight: number;
                met: number; status: string; contribution: number;
                is_anchor: boolean; skipped: boolean }[];
  };
  eval_error: string;
  ai_ran: boolean;
  thresholds: {
    agent?: { agent_id: string; value: number | null };
    terrain?: { terrain_id: string; value: number | null };
    global?: { value: number };
    effective?: number; source?: string; error?: string;
  };
  passes_threshold: boolean;
  blocking_criteria: { name: string; label: string; weight: number; status: string }[];
  validation_runs: Record<string, unknown>[];
  run_count: number;
}

function DebugConsole() {
  const [query, setQuery]     = useState("");
  const [trace, setTrace]     = useState<DebugTrace | null>(null);
  const [busy,  setBusy]      = useState(false);
  const [error, setError]     = useState<string | null>(null);

  const run = async () => {
    const id = query.trim().replace(/^AL-F-0*/i, "");
    if (!id) return;
    setBusy(true); setError(null);
    try {
      const r = await fetch(`${DAPI}/${encodeURIComponent(id)}`);
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(typeof d.detail === "string" ? d.detail : `HTTP ${r.status}`);
      }
      setTrace(await r.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setTrace(null);
    } finally { setBusy(false); }
  };

  return (
    <Card>
      <SectionLabel icon={Bug}>Finding Trace</SectionLabel>
      <p className="text-[10px] text-[--gray-500] leading-relaxed">
        Re-runs terrain scoring against a finding as it is stored right now and shows the
        criterion-by-criterion breakdown next to the threshold that applies to it. This is a
        read-only recomputation — nothing is written, so it is safe to run on production findings.
      </p>

      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-[--gray-300] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") void run(); }}
            placeholder="Finding ID (42) or external ID (AL-F-00000042)"
            className="w-full pl-8 pr-3 py-2 text-[12px] border border-[--gray-200] rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-purple-200 focus:border-purple-300 transition-all placeholder:text-[--gray-300]"
          />
        </div>
        <button
          onClick={() => void run()}
          disabled={busy || !query.trim()}
          className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[11px] font-bold rounded-xl transition-colors flex-shrink-0"
        >
          {busy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Bug className="w-3.5 h-3.5" />}
          Trace
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded-xl">
          <XCircle className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
          <span className="text-[10px] text-red-800">{error}</span>
        </div>
      )}

      {trace && (
        <div className="space-y-3">
          {/* Verdict header */}
          <div className={cn(
            "rounded-xl border px-3 py-2.5",
            trace.passes_threshold ? "bg-emerald-50 border-emerald-200" : "bg-amber-50 border-amber-200",
          )}>
            <div className="flex items-center gap-2 flex-wrap">
              {trace.passes_threshold
                ? <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                : <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />}
              <span className={cn(
                "text-[11px] font-bold",
                trace.passes_threshold ? "text-emerald-800" : "text-amber-800",
              )}>
                {trace.passes_threshold ? "Passes threshold" : "Below threshold"}
              </span>
              <span className="text-[11px] font-black tabular-nums text-[--gray-700]">
                {trace.evaluation.percentage}%
              </span>
              <span className="text-[10px] text-[--gray-500]">
                vs {Math.round((trace.thresholds.effective ?? 0) * 100)}% ({trace.thresholds.source})
              </span>
              <Pill tone="blue">{trace.terrain}</Pill>
              {trace.evaluation.anchor_hit && <Pill tone="red">anchor floor applied</Pill>}
              {!trace.ai_ran && <Pill tone="amber">AI abstained — weight dropped</Pill>}
            </div>
            <div className="text-[10px] text-[--gray-600] mt-1">
              {String(trace.finding.title ?? "")} · {trace.evaluation.summary}
            </div>
          </div>

          {/* Threshold chain */}
          <div className="grid grid-cols-3 gap-1.5">
            {[
              ["Per-agent", trace.thresholds.agent?.value, "agent"],
              ["Per-terrain", trace.thresholds.terrain?.value, "terrain"],
              ["Global", trace.thresholds.global?.value, "global"],
            ].map(([label, value, key]) => (
              <div key={key as string} className={cn(
                "rounded-lg border px-2.5 py-1.5",
                trace.thresholds.source === key
                  ? "bg-purple-50 border-purple-300"
                  : "bg-white border-[--gray-200]",
              )}>
                <div className="text-[9px] text-[--gray-400] font-semibold">{label as string}</div>
                <div className="text-[11px] font-black tabular-nums text-[--gray-700]">
                  {value == null ? "—" : `${Math.round(Number(value) * 100)}%`}
                </div>
                {trace.thresholds.source === key && <Pill tone="purple">applied</Pill>}
              </div>
            ))}
          </div>

          {/* Blocking criteria — the actionable part */}
          {trace.blocking_criteria.length > 0 && (
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
                Holding this finding back — highest weight first
              </div>
              <div className="space-y-1">
                {trace.blocking_criteria.slice(0, 5).map(c => (
                  <div key={c.name} className="flex items-center justify-between gap-2 bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                    <span className="text-[10px] font-semibold text-[--gray-700]">{c.label}</span>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <Pill tone={c.status === "partial" ? "amber" : "red"}>{c.status}</Pill>
                      <code className="text-[10px] font-mono tabular-nums text-[--gray-500]">−{c.weight}</code>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Full criterion table */}
          <div>
            <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
              All criteria ({trace.evaluation.met_count} of {trace.evaluation.total_count} met)
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-[10px]">
                <thead>
                  <tr className="text-[9px] text-[--gray-400] uppercase tracking-wide border-b border-[--gray-200]">
                    <th className="text-left py-1 pr-2 font-semibold">Criterion</th>
                    <th className="text-right py-1 px-2 font-semibold">Weight</th>
                    <th className="text-right py-1 px-2 font-semibold">Met</th>
                    <th className="text-right py-1 px-2 font-semibold">Contribution</th>
                    <th className="text-left py-1 pl-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {trace.evaluation.criteria.map(c => (
                    <tr key={c.name} className="border-b border-[--gray-100] last:border-0">
                      <td className="py-1.5 pr-2">
                        <span className="font-semibold text-[--gray-700]">{c.label}</span>
                        {c.is_anchor && <span className="ml-1"><Pill tone="red">anchor</Pill></span>}
                      </td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-[--gray-500]">{c.weight}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums text-[--gray-500]">{c.met}</td>
                      <td className="py-1.5 px-2 text-right tabular-nums font-semibold text-purple-700">{c.contribution}</td>
                      <td className="py-1.5 pl-2">
                        <Pill tone={
                          c.skipped ? "gray"
                            : c.status === "met" ? "emerald"
                            : c.status === "partial" ? "amber" : "red"
                        }>
                          {c.skipped ? "n/a — weight dropped" : c.status}
                        </Pill>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Decision ledger */}
          <div>
            <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
              Decision ledger ({trace.run_count} {trace.run_count === 1 ? "run" : "runs"})
            </div>
            {trace.run_count === 0 ? (
              <div className="text-[10px] text-[--gray-400]">
                No recorded runs — this finding has not been through the validation ledger yet.
              </div>
            ) : (
              <div className="space-y-1">
                {trace.validation_runs.slice(0, 5).map((run, i) => (
                  <div key={String(run.run_uid ?? i)} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5 flex items-center gap-2 flex-wrap">
                    <Pill tone={String(run.status) === "validated" ? "emerald" : "amber"}>{String(run.status ?? "—")}</Pill>
                    {run.provider ? <Pill tone="blue">{String(run.provider)}/{String(run.model ?? "")}</Pill> : null}
                    <code className="text-[9px] font-mono text-[--gray-400]">
                      score {String(run.validation_score ?? "—")} · threshold {String(run.threshold_used ?? "—")}
                    </code>
                    {run.error_class ? <Pill tone="red">{String(run.error_class)}</Pill> : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

// ── Main panel ──────────────────────────────────────────────────────────────

export default function ValidationPipelinePanel() {
  const [data,    setData]    = useState<PipelineReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [tab,     setTab]     = useState<PanelTab>("pipeline");
  const [hours,   setHours]   = useState(24);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${PAPI}?hours=${hours}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  }, [hours]);

  useEffect(() => { void load(); }, [load]);

  const failureCount = useMemo(() => countFailures(data?.failures), [data]);

  const TABS: { id: PanelTab; label: string; icon: React.ElementType; badge?: number }[] = [
    { id: "pipeline",     label: "Pipeline",      icon: Layers },
    { id: "accuracy",     label: "Data Accuracy", icon: Target },
    { id: "integrations", label: "Integrations",  icon: Plug },
    { id: "debug",        label: "Debug",         icon: Bug, badge: failureCount },
  ];

  if (loading && !data) {
    return (
      <div className="bg-white border border-[--gray-200] rounded-2xl p-8 text-center text-[11px] text-[--gray-400]">
        <RefreshCw className="w-4 h-4 animate-spin inline mr-2" />Loading validation pipeline…
      </div>
    );
  }

  return (
    <div className="space-y-4">

      {/* ── Header + window control ────────────────────────────────────── */}
      <Card>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <SectionLabel icon={ShieldCheck}>Validation Pipeline</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed mt-1.5">
              Every validation engine point across all sections — what runs, how it is configured,
              what it depends on, and where it is currently failing. The stage list is derived from
              the engine at request time, so it cannot drift from the code that scores findings.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <select
              value={hours}
              onChange={e => setHours(Number(e.target.value))}
              className="px-2.5 py-1.5 text-[11px] border border-[--gray-200] rounded-xl bg-white cursor-pointer focus:outline-none focus:ring-2 focus:ring-purple-200"
            >
              <option value={1}>Last hour</option>
              <option value={24}>Last 24 hours</option>
              <option value={168}>Last 7 days</option>
              <option value={720}>Last 30 days</option>
            </select>
            <button
              onClick={() => void load()}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-[--gray-200] text-[--gray-600] text-[11px] font-bold rounded-xl hover:border-purple-300 hover:text-purple-700 transition-colors"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />Refresh
            </button>
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded-xl">
            <XCircle className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
            <span className="text-[10px] text-red-800">Could not load pipeline report: {error}</span>
          </div>
        )}

        {/* Alerts from the backend, surfaced above everything else */}
        {(data?.failures.alerts.length ?? 0) > 0 && (
          <div className="space-y-1">
            {data!.failures.alerts.map(a => (
              <div key={a.code} className={cn(
                "flex items-center gap-2 px-3 py-2 rounded-xl border",
                a.severity === "high" ? "bg-red-50 border-red-200" : "bg-amber-50 border-amber-200",
              )}>
                <AlertTriangle className={cn(
                  "w-3.5 h-3.5 flex-shrink-0",
                  a.severity === "high" ? "text-red-600" : "text-amber-600",
                )} />
                <span className={cn(
                  "text-[10px] font-semibold",
                  a.severity === "high" ? "text-red-900" : "text-amber-900",
                )}>
                  {ALERT_COPY[a.code] ?? a.code} — {a.count}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="flex items-center gap-1 flex-wrap pt-1">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-bold border transition-all",
                tab === t.id
                  ? "bg-purple-600 text-white border-purple-600 shadow-sm"
                  : "bg-white text-[--gray-500] border-[--gray-200] hover:border-purple-300 hover:text-purple-700",
              )}
            >
              <t.icon className="w-3.5 h-3.5" />{t.label}
              {t.badge ? (
                <span className={cn(
                  "text-[8px] font-black px-1 rounded",
                  tab === t.id ? "bg-white/20 text-white" : "bg-red-100 text-red-700",
                )}>{t.badge}</span>
              ) : null}
            </button>
          ))}
        </div>
      </Card>

      {/* ── Pipeline stages ────────────────────────────────────────────── */}
      {tab === "pipeline" && data && (
        <Card>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <SectionLabel icon={Layers}>Stages ({data.stage_count})</SectionLabel>
            <span className="text-[9px] text-[--gray-400]">Expand a stage for its configuration, failure policy, and checks.</span>
          </div>
          {data.stages_error && (
            <div className="text-[10px] text-red-600">Inventory error: {data.stages_error}</div>
          )}
          <div className="space-y-1.5">
            {data.stages.map(stage => <StageRow key={stage.id} stage={stage} />)}
          </div>
        </Card>
      )}

      {/* ── Data accuracy ──────────────────────────────────────────────── */}
      {tab === "accuracy" && data && (
        <>
          <Card>
            <SectionLabel icon={Target}>Output Accuracy</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Precision comes from analyst dispositions, so it is only meaningful once findings have
              been triaged. Unclassified findings are the ones the engine could not place in a terrain —
              they fall back to the generic rubric and are the first thing to fix.
            </p>
            <div className="flex gap-2 flex-wrap">
              <Metric
                label="Overall precision"
                value={data.accuracy.precision_overall == null ? "—" : `${Math.round(data.accuracy.precision_overall * 100)}%`}
                sub="from analyst dispositions"
                tone={
                  data.accuracy.precision_overall == null ? "neutral"
                    : data.accuracy.precision_overall >= 0.9 ? "good"
                    : data.accuracy.precision_overall >= 0.75 ? "warn" : "bad"
                }
              />
              <Metric label="Unclassified" value={data.accuracy.unknown_terrain}
                sub="no terrain assigned"
                tone={data.accuracy.unknown_terrain > 0 ? "bad" : "good"} />
              <Metric label="AI abstentions" value={data.accuracy.abstentions}
                sub="weight dropped, not zeroed" tone="neutral" />
              <Metric label="Analyst overrides" value={data.accuracy.analyst_overrides}
                sub="marked false positive" tone="neutral" />
            </div>

            {/* Current validation states */}
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
                Active findings by validation state
              </div>
              {Object.keys(data.accuracy.current_states).length === 0 ? (
                <div className="text-[10px] text-[--gray-400]">No active findings recorded.</div>
              ) : (
                <div className="flex gap-1.5 flex-wrap">
                  {Object.entries(data.accuracy.current_states).map(([state, n]) => (
                    <div key={state} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                      <div className="text-[11px] font-black tabular-nums text-[--gray-700]">{n}</div>
                      <div className="text-[9px] text-[--gray-400] font-semibold">{state}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Decisions in window */}
            <div>
              <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
                Decisions in the last {data.window_hours}h
              </div>
              {Object.keys(data.accuracy.decisions).length === 0 ? (
                <div className="text-[10px] text-[--gray-400]">
                  No validation runs recorded in this window.
                </div>
              ) : (
                <div className="flex gap-1.5 flex-wrap">
                  {Object.entries(data.accuracy.decisions).map(([status, n]) => (
                    <Pill key={status} tone={status === "validated" ? "emerald" : "amber"}>{status}: {n}</Pill>
                  ))}
                </div>
              )}
            </div>

            {data.accuracy.error && (
              <div className="text-[10px] text-amber-700 bg-amber-50 border border-amber-200 rounded-xl px-3 py-2">
                Some accuracy metrics were unavailable: {data.accuracy.error}
              </div>
            )}
          </Card>

          {/* Worst rules */}
          <Card>
            <SectionLabel icon={AlertTriangle}>Rules Driving False Positives</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Ranked by false-positive rate across analyst dispositions. A rule near the top is
              either mis-tuned or needs an allowlist entry — both are configuration, not code.
            </p>
            {data.accuracy.worst_rules.length === 0 ? (
              <div className="text-[10px] text-[--gray-400]">
                No dispositioned rules yet — FP rates appear once analysts start closing findings.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[10px]">
                  <thead>
                    <tr className="text-[9px] text-[--gray-400] uppercase tracking-wide border-b border-[--gray-200]">
                      <th className="text-left py-1 pr-2 font-semibold">Rule</th>
                      <th className="text-right py-1 px-2 font-semibold">TP</th>
                      <th className="text-right py-1 px-2 font-semibold">FP</th>
                      <th className="text-right py-1 pl-2 font-semibold">FP rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.accuracy.worst_rules.map(r => {
                      const rate = r.false_positive_rate ?? 0;
                      return (
                        <tr key={r.rule_id} className="border-b border-[--gray-100] last:border-0">
                          <td className="py-1.5 pr-2 font-mono text-[--gray-700]">{r.rule_id}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-emerald-600">{r.tp}</td>
                          <td className="py-1.5 px-2 text-right tabular-nums text-red-600">{r.fp}</td>
                          <td className={cn(
                            "py-1.5 pl-2 text-right tabular-nums font-bold",
                            rate >= 0.5 ? "text-red-600" : rate >= 0.2 ? "text-amber-600" : "text-[--gray-500]",
                          )}>
                            {Math.round(rate * 100)}%
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Rejections by gate */}
          <Card>
            <SectionLabel icon={Activity}>Rejections by Gate</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Which of the eight deterministic gates is discarding clusters. A single gate dominating
              this list usually means its window or threshold is mis-set, not that the data is bad.
            </p>
            {data.accuracy.rejected_by_gate.length === 0 ? (
              <div className="text-[10px] text-[--gray-400]">No gate rejections recorded.</div>
            ) : (
              <div className="space-y-1">
                {data.accuracy.rejected_by_gate.map((g, i) => (
                  <div key={String(g.gate ?? i)} className="flex items-center justify-between gap-2 bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                    <code className="text-[10px] font-mono font-semibold text-[--gray-700]">{g.gate ?? "—"}</code>
                    <span className="text-[10px] font-black tabular-nums text-[--gray-600]">{g.n ?? 0}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      )}

      {/* ── Integrations ───────────────────────────────────────────────── */}
      {tab === "integrations" && data && (
        <>
          <Card>
            <SectionLabel icon={Cpu}>Model Usage</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Per-provider validation calls in the selected window, from the decision ledger.
              A row labelled <code className="font-mono">deterministic</code> means the score was
              produced without any model call.
            </p>
            {data.integrations.providers.length === 0 ? (
              <div className="text-[10px] text-[--gray-400]">
                No validation model calls in this window.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[10px]">
                  <thead>
                    <tr className="text-[9px] text-[--gray-400] uppercase tracking-wide border-b border-[--gray-200]">
                      <th className="text-left py-1 pr-2 font-semibold">Provider / model</th>
                      <th className="text-right py-1 px-2 font-semibold">Calls</th>
                      <th className="text-right py-1 px-2 font-semibold">Tokens</th>
                      <th className="text-right py-1 px-2 font-semibold">Cost</th>
                      <th className="text-right py-1 pl-2 font-semibold">Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.integrations.providers.map((p, i) => (
                      <tr key={`${p.provider}:${p.model}:${i}`} className="border-b border-[--gray-100] last:border-0">
                        <td className="py-1.5 pr-2">
                          <span className="font-semibold text-[--gray-700]">{p.provider}</span>
                          {p.model && <span className="text-[--gray-400] font-mono"> / {p.model}</span>}
                        </td>
                        <td className="py-1.5 px-2 text-right tabular-nums">{p.calls}</td>
                        <td className="py-1.5 px-2 text-right tabular-nums">{p.tokens.toLocaleString()}</td>
                        <td className="py-1.5 px-2 text-right tabular-nums">${p.cost_usd.toFixed(4)}</td>
                        <td className="py-1.5 pl-2 text-right tabular-nums">{Math.round(p.latency_ms)}ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card>
            <SectionLabel icon={Plug}>Dependency Health</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Circuit-breaker and error-rate state for every external dependency validation relies on —
              threat-intel feeds, the AI provider, and enrichment sources. An open breaker means that
              input is currently unavailable and the stages depending on it are degrading.
            </p>
            <IntegrationRegistryView registry={data.integrations.registry} />
          </Card>

          <Card>
            <SectionLabel icon={Activity}>Telemetry Intake</SectionLabel>
            <p className="text-[10px] text-[--gray-500] leading-relaxed">
              Per-stage ingest counters and payload-schema gaps. An empty criterion is often missing
              telemetry rather than a failed check — this is where you tell the two apart.
            </p>
            <IngestView ingest={data.integrations.ingest} />
          </Card>
        </>
      )}

      {/* ── Debug ──────────────────────────────────────────────────────── */}
      {tab === "debug" && (
        <>
          <DebugConsole />
          {data && (
            <Card>
              <SectionLabel icon={AlertTriangle}>Current Failures</SectionLabel>
              <div className="flex gap-2 flex-wrap">
                <Metric label="Validation errors" value={Object.values(data.failures.errors).reduce((a, b) => a + b, 0)}
                  sub={`last ${data.window_hours}h`}
                  tone={Object.keys(data.failures.errors).length ? "bad" : "good"} />
                <Metric label="Recompute backlog"
                  value={(data.failures.recompute_jobs.pending ?? 0) + (data.failures.recompute_jobs.running ?? 0)}
                  sub="pending + running"
                  tone={(data.failures.recompute_jobs.pending ?? 0) > 0 ? "warn" : "good"} />
                <Metric label="Failed jobs" value={data.failures.recompute_jobs.error ?? 0}
                  sub="need a resume" tone={(data.failures.recompute_jobs.error ?? 0) > 0 ? "bad" : "good"} />
              </div>

              <div>
                <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
                  Error classes
                </div>
                {Object.keys(data.failures.errors).length === 0 ? (
                  <div className="text-[10px] text-emerald-600 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />No validation errors in this window.
                  </div>
                ) : (
                  <div className="space-y-1">
                    {Object.entries(data.failures.errors).map(([cls, n]) => (
                      <div key={cls} className="flex items-center justify-between gap-2 bg-red-50 border border-red-200 rounded-lg px-2.5 py-1.5">
                        <code className="text-[10px] font-mono font-semibold text-red-800">{cls}</code>
                        <span className="text-[10px] font-black tabular-nums text-red-700">{n}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

const ALERT_COPY: Record<string, string> = {
  unknown_terrain:    "Findings with no terrain assigned — scored against the generic rubric",
  validation_errors:  "Validation runs failed",
  validation_backlog: "Recompute jobs still queued",
};

// ── Sub-views for loosely-typed backend blobs ───────────────────────────────

function IntegrationRegistryView({ registry }: { registry: Record<string, unknown> }) {
  if (registry?.error) {
    return <div className="text-[10px] text-amber-700">Registry unavailable: {String(registry.error)}</div>;
  }
  const rows = Array.isArray(registry?.integrations)
    ? registry.integrations as Record<string, unknown>[]
    : [];
  if (rows.length === 0) {
    return (
      <div className="text-[10px] text-[--gray-400]">
        No external dependency has been called yet this process — the registry populates on first use.
      </div>
    );
  }
  return (
    <div className="space-y-1">
      {rows.map((row, i) => {
        const status = String(row.status ?? "healthy");
        const tone = status === "down" ? "red" : status === "degraded" ? "amber" : "emerald";
        return (
          <div key={String(row.name ?? i)} className="flex items-center justify-between gap-2 bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5 flex-wrap">
            <div className="flex items-center gap-1.5 min-w-0">
              <code className="text-[10px] font-mono font-semibold text-[--gray-700]">{String(row.name ?? "—")}</code>
              <Pill tone={tone}>{status}</Pill>
              {row.breaker_state ? <Pill>breaker: {String(row.breaker_state)}</Pill> : null}
            </div>
            <code className="text-[9px] font-mono text-[--gray-400] flex-shrink-0">
              {String(row.calls ?? 0)} calls · {Math.round(Number(row.error_rate ?? 0) * 100)}% errors
            </code>
          </div>
        );
      })}
    </div>
  );
}

function IngestView({ ingest }: { ingest: Record<string, unknown> }) {
  if (ingest?.error) {
    return <div className="text-[10px] text-amber-700">Ingest stats unavailable: {String(ingest.error)}</div>;
  }
  const stages = (ingest?.stages ?? {}) as Record<string, unknown>;
  const gaps = (ingest?.schema_gaps ?? {}) as Record<string, number>;
  const stageEntries = Object.entries(stages).filter(([, v]) => typeof v === "number");
  const gapEntries = Object.entries(gaps).sort((a, b) => b[1] - a[1]).slice(0, 12);

  return (
    <div className="space-y-3">
      <div>
        <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">Ingest stages</div>
        {stageEntries.length === 0 ? (
          <div className="text-[10px] text-[--gray-400]">No payloads received since boot.</div>
        ) : (
          <div className="flex gap-1.5 flex-wrap">
            {stageEntries.map(([k, v]) => (
              <div key={k} className="bg-white border border-[--gray-200] rounded-lg px-2.5 py-1.5">
                <div className="text-[11px] font-black tabular-nums text-[--gray-700]">{String(v)}</div>
                <div className="text-[9px] text-[--gray-400] font-semibold">{k}</div>
              </div>
            ))}
          </div>
        )}
      </div>
      <div>
        <div className="text-[9px] font-bold text-[--gray-500] uppercase tracking-wide mb-1.5">
          Payload schema gaps
        </div>
        {gapEntries.length === 0 ? (
          <div className="text-[10px] text-emerald-600 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />No missing fields observed since boot.
          </div>
        ) : (
          <div className="flex gap-1.5 flex-wrap">
            {gapEntries.map(([field, n]) => (
              <Pill key={field} tone="amber">{field}: {n}</Pill>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
