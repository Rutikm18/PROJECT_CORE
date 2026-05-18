import { Terminal } from "lucide-react";
import { GenericDetectionPage, type DetectionFinding } from "./DetectionShared";
import { cn } from "../../lib/utils";

function RiskScore({ f }: { f: DetectionFinding }) {
  const s = f.composite_score ?? f.score;
  const color = s >= 8 ? "text-red-600" : s >= 6 ? "text-amber-600" : "text-blue-600";
  const bg    = s >= 8 ? "bg-red-50 border-red-200" : s >= 6 ? "bg-amber-50 border-amber-200" : "bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", color, bg)}>
      {s.toFixed(1)}
      <span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

function ConfPct({ f }: { f: DetectionFinding }) {
  const pct   = f.confidence_pct ?? 70;
  const color = pct >= 85 ? "text-green-600" : pct >= 70 ? "text-blue-600" : "text-amber-600";
  return <span className={cn("text-[10px] font-bold tabular-nums", color)}>{pct}%</span>;
}

function CategoryChip({ f }: { f: DetectionFinding }) {
  const colors: Record<string, string> = {
    malware:   "bg-red-50 text-red-700 border-red-200",
    execution: "bg-orange-50 text-orange-700 border-orange-200",
    script:    "bg-purple-50 text-purple-700 border-purple-200",
    process:   "bg-blue-50 text-blue-700 border-blue-200",
  };
  const key = Object.keys(colors).find(k => f.category.toLowerCase().includes(k)) ?? "process";
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border", colors[key])}>
      {f.category}
    </span>
  );
}

export default function ExecutionThreats() {
  return (
    <GenericDetectionPage
      title="Execution & Malware"
      subtitle="Process-based detections · offensive tools · obfuscation · parent-child spawn analysis · binary entropy"
      apiUrl="/api/v1/detection/processes"
      accent="red"
      icon={<Terminal className="w-5 h-5 text-orange-500" />}
      emptyMsg="No execution threat findings yet. Findings appear when agent processes match detection rules."
      columns={[
        { key: "category",        label: "Category",   render: f => <CategoryChip f={f} /> },
        { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
        { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
        { key: "source",          label: "Rule",       render: f => <span className="text-[9px] font-mono text-gray-500">{f.source}</span> },
      ]}
    />
  );
}
