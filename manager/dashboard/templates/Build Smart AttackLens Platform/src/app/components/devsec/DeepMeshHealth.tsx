/**
 * DeepMeshHealth — accuracy / coverage view for the developer_security snapshot.
 *
 * Answers "is all the required data coming, and coming accurately?" for one
 * agent's latest snapshot: section freshness, per-capability presence/errors,
 * and the collector's own partial/error/issue signals. Pure/presentational —
 * computed entirely from the payload via computeHealth (no extra backend call).
 */
import {
  CheckCircle2, XCircle, AlertTriangle, MinusCircle, Clock, Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  computeHealth, relativeAge, str,
  type CapStatus, type DeepMeshHealthReport,
} from "./devsecShared";

const STATUS_META: Record<CapStatus, { label: string; cls: string; Icon: React.ElementType }> = {
  ok:      { label: "OK",      cls: "text-green-600",  Icon: CheckCircle2 },
  empty:   { label: "Empty",   cls: "text-gray-400",   Icon: MinusCircle },
  error:   { label: "Error",   cls: "text-red-600",    Icon: XCircle },
  missing: { label: "Missing", cls: "text-amber-600",  Icon: AlertTriangle },
};

const OVERALL_META: Record<DeepMeshHealthReport["overall"], { label: string; cls: string }> = {
  healthy:   { label: "Healthy",   cls: "bg-green-50 border-green-200 text-green-700" },
  degraded:  { label: "Degraded",  cls: "bg-amber-50 border-amber-200 text-amber-700" },
  unhealthy: { label: "Unhealthy", cls: "bg-red-50 border-red-200 text-red-700" },
  absent:    { label: "No data",   cls: "bg-gray-50 border-gray-200 text-gray-500" },
};

export default function DeepMeshHealth({ data, collectedAt }: { data: unknown; collectedAt: number | null }) {
  const h = computeHealth(data, collectedAt);
  const overall = OVERALL_META[h.overall];

  return (
    <div className="space-y-3 p-3">
      {/* Summary banner */}
      <div className={cn("rounded-xl border px-4 py-3 flex flex-wrap items-center gap-x-5 gap-y-2", overall.cls)}>
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4" />
          <span className="text-[13px] font-bold">Data Health: {overall.label}</span>
        </div>
        <div className="text-[11px] font-semibold">
          {h.okCount}/{h.requiredCount} capabilities reporting
        </div>
        <div className="flex items-center gap-1 text-[11px]">
          <Clock className="w-3 h-3" />
          {h.present
            ? <span>collected {relativeAge(h.ageSec)}{h.fresh ? "" : " · STALE"}</span>
            : <span>no snapshot yet</span>}
        </div>
        {h.durationMs != null && <div className="text-[11px] opacity-80">scan {h.durationMs}ms</div>}
        {h.partial && <div className="text-[11px] font-bold">PARTIAL</div>}
        {h.truncated && <div className="text-[11px] font-bold">TRUNCATED</div>}
      </div>

      {/* Per-capability grid */}
      <div className="rounded-xl border border-gray-200 overflow-hidden bg-white">
        <div className="px-3.5 py-2 bg-gray-50/60 border-b border-gray-100 text-[11px] font-bold text-gray-700">
          Required capabilities
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 divide-y sm:divide-y-0 divide-gray-50">
          {h.capabilities.map(c => {
            const m = STATUS_META[c.status];
            const Icon = m.Icon;
            return (
              <div key={c.key}
                className="flex items-center justify-between gap-2 px-3.5 py-2 border-b border-gray-50 sm:border-r"
                title={c.error ? `${c.label}: ${c.error}` : c.label}>
                <div className="flex items-center gap-2 min-w-0">
                  <Icon className={cn("w-3.5 h-3.5 flex-shrink-0", m.cls)} />
                  <span className="text-[11px] text-gray-700 truncate">{c.label}</span>
                </div>
                <span className={cn("text-[10px] font-bold tabular-nums flex-shrink-0", m.cls)}>
                  {c.status === "error" ? (c.error || "Error")
                    : c.count != null ? c.count
                    : m.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Collector errors */}
      {h.errors.length > 0 && (
        <div className="rounded-xl border border-red-200 bg-red-50/50 px-3.5 py-2.5">
          <div className="flex items-center gap-2 text-[11px] font-semibold text-red-700 mb-1">
            <XCircle className="w-3.5 h-3.5" /> Capability errors ({h.errors.length})
          </div>
          <div className="text-[10px] font-mono text-red-600 space-y-0.5">
            {h.errors.slice(0, 12).map((e, i) => <div key={i}>{e.capability}: {e.error}</div>)}
          </div>
        </div>
      )}

      {/* Operational issues (timeouts, permission, invalid json, budget) */}
      {h.issues.length > 0 && (
        <div className="rounded-xl border border-amber-200 bg-amber-50/50 px-3.5 py-2.5">
          <div className="flex items-center gap-2 text-[11px] font-semibold text-amber-700 mb-1">
            <AlertTriangle className="w-3.5 h-3.5" /> Operational issues ({h.issues.length})
          </div>
          <div className="text-[10px] font-mono text-amber-700 space-y-0.5">
            {h.issues.slice(0, 12).map((it, i) => <div key={i}>{str(it.path)} — {str(it.error)}</div>)}
          </div>
        </div>
      )}

      {!h.present && (
        <div className="text-center text-[11px] text-gray-400 py-6">
          No developer_security snapshot to score — the agent hasn't reported this section yet.
        </div>
      )}
    </div>
  );
}
