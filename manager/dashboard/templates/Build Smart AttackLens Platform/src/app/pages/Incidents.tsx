/**
 * Incidents.tsx — "All Incidents"
 *
 * Single aggregated view of every active finding detected across the three
 * attack-terrain surfaces — Origin (vulnerabilities / packages / config),
 * Vector (network / ports / IOC) and Citadels (execution / persistence) —
 * served by GET /api/v1/detection/all.
 *
 * Reuses TerrainDetectionPage, so it inherits the full toolset: quick filters,
 * the advanced field+operator filter, and the FindingDetail drawer with its
 * remediation / validation / triage actions.
 *
 * Toggle: [All Incidents] [Validated Findings]
 *   Validated Findings applies validated_only=true — findings whose precision_score
 *   meets or exceeds the configured per-agent / per-terrain / global threshold.
 */
import React, { useState } from "react";
import { Layers, CheckCircle2 } from "lucide-react";
import { cn } from "../../lib/utils";
import { TerrainDetectionPage, TerrainChip, type DetectionFinding } from "./DetectionShared";

function CategoryCell({ f }: { f: DetectionFinding }) {
  return (
    <div className="flex items-center gap-1.5">
      <TerrainChip terrain={f.terrain} />
      {f.category && <span className="text-[10px] text-gray-500 capitalize">{f.category}</span>}
    </div>
  );
}

function RiskScore({ f }: { f: DetectionFinding }) {
  const s     = f.composite_score ?? f.score;
  const color = s >= 8 ? "text-red-600" : s >= 6 ? "text-amber-600" : "text-blue-600";
  const bg    = s >= 8 ? "bg-red-50 border-red-200" : s >= 6 ? "bg-amber-50 border-amber-200" : "bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", color, bg)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

export default function Incidents() {
  const [validatedOnly, setValidatedOnly] = useState(false);

  return (
    <div className="space-y-2">
      {/* ── View Toggle: All Incidents / Validated Findings ────────────── */}
      <div className="flex items-center gap-3 px-5 pt-4">
        <div className="inline-flex bg-gray-100 rounded-lg p-0.5" role="group" aria-label="View mode">
          <button
            onClick={() => setValidatedOnly(false)}
            className={cn(
              "px-3.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
              !validatedOnly
                ? "bg-white text-orange-600 shadow-sm"
                : "text-gray-500 hover:text-gray-700",
            )}
          >
            All Incidents
          </button>
          <button
            onClick={() => setValidatedOnly(true)}
            className={cn(
              "px-3.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
              validatedOnly
                ? "bg-white text-emerald-600 shadow-sm"
                : "text-gray-500 hover:text-gray-700",
            )}
          >
            Validated Findings
          </button>
        </div>
        {validatedOnly && (
          <span className="text-[9px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
            <CheckCircle2 className="w-3 h-3" />
            precision_score ≥ configured threshold
          </span>
        )}
      </div>

      <TerrainDetectionPage
        title="All Incidents"
        subtitle={validatedOnly
          ? "Findings that passed the configured Validation threshold — auto-promoted by Detection Confidence"
          : "Every active finding across Origin, Vector & Citadels — one unified, filterable queue"}
        apiUrl={validatedOnly
          ? "/api/v1/detection/all?validated_only=true"
          : "/api/v1/detection/all"}
        accent="red"
        icon={<Layers className="w-5 h-5 text-orange-500" />}
        emptyMsg={validatedOnly
          ? "No validated findings. Findings are promoted when precision_score ≥ configured threshold. Adjust thresholds in Settings → Validation."
          : "No active incidents. Findings from Origin, Vector and Citadels surface here as they are detected."}
        columns={
          validatedOnly
            ? [
                { key: "category",        label: "Terrain",  render: (f: DetectionFinding) => <CategoryCell f={f} /> },
                { key: "composite_score", label: "Risk",     render: (f: DetectionFinding) => <RiskScore f={f} /> },
              ]
            : [
                { key: "category",        label: "Terrain",  render: (f: DetectionFinding) => <CategoryCell f={f} /> },
                { key: "composite_score", label: "Risk",     render: (f: DetectionFinding) => <RiskScore f={f} /> },
              ]
        }
      />
    </div>
  );
}
