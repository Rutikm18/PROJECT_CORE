import { Globe } from "lucide-react";
import { GenericDetectionPage, type DetectionFinding } from "./DetectionShared";
import { cn } from "../../lib/utils";

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

function FeedChip({ f }: { f: DetectionFinding }) {
  const src    = f.source ?? "";
  const isFeed = src.startsWith("feed:");
  const feedName = isFeed ? src.replace("feed:", "") : src;
  const feedColors: Record<string, string> = {
    feodo:    "bg-red-50 text-red-700 border-red-300",
    urlhaus:  "bg-purple-50 text-purple-700 border-purple-200",
    emerging: "bg-amber-50 text-amber-700 border-amber-200",
  };
  const colorKey = Object.keys(feedColors).find(k => feedName.toLowerCase().includes(k));
  const cls = isFeed ? (feedColors[colorKey ?? ""] ?? "bg-red-50 text-red-700 border-red-200") : "bg-gray-100 text-gray-600 border-gray-200";
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border flex items-center gap-1", cls)}>
      {isFeed && <span className="w-1 h-1 rounded-full bg-current animate-pulse" />}
      {feedName}
    </span>
  );
}

function ConfPct({ f }: { f: DetectionFinding }) {
  const pct   = f.confidence_pct ?? 70;
  const color = pct >= 90 ? "text-green-600" : pct >= 70 ? "text-blue-600" : "text-amber-600";
  return <span className={cn("text-[10px] font-bold tabular-nums", color)}>{pct}%</span>;
}

export default function NetworkThreats() {
  return (
    <GenericDetectionPage
      title="Network Threats"
      subtitle="Active connections matched against threat feeds · IOC correlation · JA3 fingerprinting · beacon detection"
      apiUrl="/api/v1/detection/network"
      accent="red"
      icon={<Globe className="w-5 h-5 text-orange-500" />}
      emptyMsg="No network threat findings yet. Findings appear when agent connections match threat feed IOCs."
      columns={[
        { key: "source",         label: "Feed Source", render: f => <FeedChip f={f} /> },
        { key: "confidence_pct", label: "Confidence",  render: f => <ConfPct f={f} /> },
        { key: "composite_score",label: "Risk",        render: f => <RiskScore f={f} /> },
      ]}
    />
  );
}
