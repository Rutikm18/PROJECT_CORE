import { cn } from "../../lib/utils";

interface CTEMStage {
  id: string;
  number: string;
  name: string;
  subtitle: string;
  count: number;
  active?: boolean;
}

const stages: CTEMStage[] = [
  { id: "scoping", number: "01", name: "SCOPING", subtitle: "Asset Surface · 21 sections monitored", count: 21 },
  { id: "discovery", number: "02", name: "DISCOVERY", subtitle: "Exposures Found · across 6 domains", count: 43 },
  { id: "prioritization", number: "03", name: "PRIORITIZATION", subtitle: "Action Queue · CVSS + EPSS scored", count: 12, active: true },
  { id: "validation", number: "04", name: "VALIDATION", subtitle: "Verified Active · exploit confirmed", count: 7 },
  { id: "mobilization", number: "05", name: "MOBILIZATION", subtitle: "In Remediation · playbooks active", count: 3 },
];

export function CTEMPipeline() {
  return (
    <div className="bg-gradient-to-br from-white to-[--gray-25] border border-[--gray-200] rounded-lg flex shadow-card hover:shadow-elevated transition-shadow duration-200">
      {stages.map((stage, index) => (
        <div
          key={stage.id}
          className={cn(
            "flex-1 p-4 relative transition-all duration-200",
            index < stages.length - 1 && "border-r border-[--gray-200]",
            stage.active && "bg-gradient-to-br from-[--brand-orange-50] to-white border-b-2 border-b-[--brand-orange]"
          )}
        >
          <div className={cn(
            "text-[11px] font-semibold uppercase tracking-wider mb-1",
            stage.active ? "text-[--brand-orange-700]" : "text-[--gray-400]"
          )}>
            {stage.number} · {stage.name}
          </div>
          <div className={cn(
            "text-[13px] font-bold mb-1",
            stage.active ? "text-[--brand-orange-800]" : "text-[--gray-800]"
          )}>
            {stage.subtitle.split(" · ")[0]}
          </div>
          <div className="text-xs text-[--gray-500] mb-2 font-medium">
            {stage.subtitle.split(" · ")[1]}
          </div>
          <div className={cn(
            "text-xl font-bold",
            stage.active ? "bg-gradient-to-r from-[--brand-orange-600] to-[--brand-orange-700] bg-clip-text text-transparent" : "text-[--gray-900]"
          )}>
            {stage.count}
          </div>
        </div>
      ))}
    </div>
  );
}
