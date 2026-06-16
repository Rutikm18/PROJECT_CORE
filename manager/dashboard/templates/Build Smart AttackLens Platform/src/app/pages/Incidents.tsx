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
 */
import { Layers } from "lucide-react";
import { TerrainDetectionPage, type DetectionFinding } from "./DetectionShared";
import { cn } from "../../lib/utils";

// Map a raw finding category to its attack-terrain label + colour.
const TERRAIN: Record<string, { label: string; cls: string }> = {
  // Citadels — execution / persistence
  execution:   { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  malware:     { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  process:     { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  script:      { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  container:   { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  persistence: { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  service:     { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  task:        { label: "Citadels", cls: "bg-red-50 text-red-700 border-red-200" },
  // Vector — network
  network:     { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  connection:  { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  port:        { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  arp:         { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  covert:      { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  lateral:     { label: "Vector", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  // Origin — supply chain / config
  package:       { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  vulnerability: { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  sbom:          { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  config:        { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  binary:        { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
  sysctl:        { label: "Origin", cls: "bg-amber-50 text-amber-700 border-amber-200" },
};

function terrainOf(cat: string) {
  const key = (cat || "").toLowerCase();
  return TERRAIN[key]
    ?? Object.entries(TERRAIN).find(([k]) => key.includes(k))?.[1]
    ?? { label: cat || "Other", cls: "bg-gray-100 text-gray-600 border-gray-200" };
}

function TerrainChip({ f }: { f: DetectionFinding }) {
  const t = terrainOf(f.category ?? "");
  return (
    <span className={cn("text-[9px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap", t.cls)}>
      {t.label}
    </span>
  );
}

function CategoryCell({ f }: { f: DetectionFinding }) {
  return (
    <div className="flex items-center gap-1.5">
      <TerrainChip f={f} />
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
  return (
    <TerrainDetectionPage
      title="All Incidents"
      subtitle="Every active finding across Origin, Vector & Citadels — one unified, filterable queue"
      apiUrl="/api/v1/detection/all"
      accent="red"
      icon={<Layers className="w-5 h-5 text-orange-500" />}
      emptyMsg="No active incidents. Findings from Origin, Vector and Citadels surface here as they are detected."
      columns={[
        { key: "category",        label: "Terrain", render: f => <CategoryCell f={f} /> },
        { key: "composite_score", label: "Risk",    render: f => <RiskScore f={f} /> },
      ]}
    />
  );
}
