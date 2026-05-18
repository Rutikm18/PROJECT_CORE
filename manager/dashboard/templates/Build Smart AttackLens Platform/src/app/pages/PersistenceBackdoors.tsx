import { Anchor } from "lucide-react";
import { GenericDetectionPage, type DetectionFinding } from "./DetectionShared";
import { cn } from "../../lib/utils";

const CAT_COLORS: Record<string, string> = {
  service: "bg-purple-50 text-purple-700 border-purple-200",
  task:    "bg-amber-50 text-amber-700 border-amber-200",
  config:  "bg-red-50 text-red-700 border-red-200",
  binary:  "bg-blue-50 text-blue-700 border-blue-200",
  cron:    "bg-orange-50 text-orange-700 border-orange-200",
  launch:  "bg-indigo-50 text-indigo-700 border-indigo-200",
};

function CatChip({ f }: { f: DetectionFinding }) {
  const key   = Object.keys(CAT_COLORS).find(k => f.category.toLowerCase().includes(k)) ?? "binary";
  const icons: Record<string, string> = { service: "⚙", task: "⏱", config: "📄", binary: "⬡", cron: "🕐", launch: "🚀" };
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border flex items-center gap-1 w-fit", CAT_COLORS[key])}>
      <span className="text-[10px]">{icons[key]}</span>{f.category}
    </span>
  );
}

function RiskScore({ f }: { f: DetectionFinding }) {
  const s     = f.composite_score ?? f.score;
  const color = s >= 8 ? "text-red-600" : s >= 6 ? "text-amber-700" : "text-blue-600";
  const bg    = s >= 8 ? "bg-red-50 border-red-200" : s >= 6 ? "bg-amber-50 border-amber-200" : "bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", color, bg)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

export default function PersistenceBackdoors() {
  return (
    <GenericDetectionPage
      title="Persistence & Backdoors"
      subtitle="LaunchDaemons · cron/launchd tasks · shell config injection · SUID binaries · world-writable PATH"
      apiUrl="/api/v1/detection/persistence"
      accent="amber"
      icon={<Anchor className="w-5 h-5 text-orange-500" />}
      emptyMsg="No persistence findings yet. Agent needs to report services, tasks, configs, and binaries sections."
      columns={[
        { key: "category",        label: "Type",  render: f => <CatChip f={f} /> },
        { key: "composite_score", label: "Risk",  render: f => <RiskScore f={f} /> },
        { key: "source",          label: "Rule",  render: f => <span className="text-[9px] font-mono text-gray-500">{f.source}</span> },
      ]}
    />
  );
}
